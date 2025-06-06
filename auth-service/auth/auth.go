package auth

import (
	"errors"
	"fmt"
	"log"
	"main/controllers"
	"main/db"
	"main/encrypt"
	"main/structs"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

func HandleSignUp(ctx *gin.Context) {
	key := os.Getenv("RAND_IV")
	var data structs.Payload

	log.Println(ctx.ClientIP(), ctx.RemoteIP())

	if err := ctx.BindJSON(&data); err != nil {
		ctx.JSON(400, gin.H{"success": false, "message": err.Error()})
		return
	}

	if err := data.ValidateFields(); err != nil {
		ctx.JSON(400, gin.H{"success": false, "message": err.Error()})
		return
	}

	client := db.GetClient()

	userEmail, err := encrypt.EncryptDataStaticIV(data.Email, key)
	if err != nil {
		log.Println("Error encrypting user email: ", err)
		ctx.JSON(500, gin.H{"success": false, "message": "Internal error"})
		return
	}

	var userExists bool

	err = client.QueryRow(ctx.Request.Context(), "SELECT EXISTS (SELECT 1  FROM users WHERE email = $1)", userEmail).Scan(&userExists)
	if err != nil {
		log.Println("DB error:", err)
		ctx.JSON(500, gin.H{"success": false, "message": "Internal error"})
		return
	}

	if userExists {
		log.Println("Email already exists")
		ctx.JSON(400, gin.H{"success": false, "message": "Email already exists, try signin in"})
		return
	}

	payload := structs.Payload{FullName: data.FullName, Email: data.Email, Password: data.Password}

	err = controllers.CreateUserController(payload, ctx.ClientIP(), client, ctx.GetHeader("User-Agent"))
	if err != nil {
		log.Println("Error creating user: ", err.Error())
	}

	ctx.JSON(201, gin.H{
		"success": true,
		"message": fmt.Sprintf("User created successfully, welcome onboard %s", data.FullName),
	})
}

func HandleSignin(ctx *gin.Context) {
	key := os.Getenv("RAND_IV")
	var data structs.Payload
	client := db.GetClient()

	if err := ctx.BindJSON(&data); err != nil {
		ctx.JSON(400, gin.H{"success": false, "message": err.Error()})
		return
	}

	if data.Email == "" || data.Password == "" {
		ctx.JSON(400, gin.H{"success": false, "message": "All fields must be filled"})
		return
	}

	encryptedEmail, err := encrypt.EncryptDataStaticIV(data.Email, key)
	if err != nil {
		log.Println("Error encrypting user email: ", err)
		ctx.JSON(500, gin.H{"success": false, "message": "Internal error"})
		return
	}

	var user db.DbData

	err = client.QueryRow(ctx.Request.Context(), "SELECT uuid, full_name, email, password  FROM users WHERE email = $1", encryptedEmail).Scan(
		&user.UUID,
		&user.Full_Name,
		&user.Email,
		&user.Password,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		ctx.JSON(404, gin.H{"success": false, "message": "User not found"})
		return
	} else if err != nil {
		log.Println("DB error:", err)
		ctx.JSON(500, gin.H{"success": false, "message": "Internal error"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data.Password)); err != nil {
		ctx.JSON(400, gin.H{"success": false, "message": "Incorrect password"})
		return
	}

	decData, err := structs.Payload{Email: user.Email, FullName: user.Full_Name}.DecryptPayload(key)
	if err != nil {
		ctx.JSON(500, gin.H{"success": false, "message": "Internal error"})
		return
	}

	ctx.JSON(200, gin.H{
		"success": true,
		"message": fmt.Sprintf("Welcome back, %s", decData.FullName),
	})
}

func HandleOauth(ctx *gin.Context) {
	key := os.Getenv("RAND_IV")
	var data structs.Payload

	client := db.GetClient()

	if err := ctx.BindJSON(&data); err != nil {
		ctx.JSON(400, gin.H{"success": false, "message": err.Error()})
		return
	}

	encryptedEmail, err := encrypt.EncryptDataStaticIV(data.Email, key)
	if err != nil {
		log.Println("Error encrypting user email: ", err)
		ctx.JSON(500, gin.H{"success": false, "message": "Internal error"})
		return
	}

	var user db.DbData

	err = client.QueryRow(ctx.Request.Context(), "SELECT uuid, full_name, email, password  FROM users WHERE email = $1", encryptedEmail).Scan(
		&user.UUID,
		&user.Full_Name,
		&user.Email,
		&user.Password,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		err = controllers.CreateUserController(data, ctx.ClientIP(), client, ctx.GetHeader("User-Agent"))
		if err != nil {
			log.Println("Error creating user: ", err.Error())
		}

		ctx.JSON(201, gin.H{
			"success": true,
			"message": fmt.Sprintf("User created successfully, welcome onboard %s", data.FullName),
		})
		return
	} else if err != nil {
		log.Println("DB error:", err)
		ctx.JSON(500, gin.H{"success": false, "message": "Internal error"})
		return
	}

	// decryptedData, err := structs.Payload{FullName: user.Full_Name, Email: user.Email}.DecryptPayload(key)
	// if err != nil {
	// 	log.Println("Error decrypting data")
	// 	ctx.JSON(500, gin.H{"success": false, "message": "Internal error"})
	// 	return
	// }

	resUser := structs.ResUser{FullName: data.FullName, UUID: user.UUID}

	ctx.JSON(201, gin.H{"success": true, "message": "Welcome onboard " + data.FullName, "user": resUser})
}

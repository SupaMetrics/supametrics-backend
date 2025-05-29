package auth

import (
	"encoding/json"
	"fmt"
	"main/encrypt"
	"os"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type Payload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"fullName"`
}

type StoredUser struct {
	EncryptedData string
	PasswordHash  string
}

var dummyDB = make(map[string]StoredUser)

func HandleSignUp(ctx *gin.Context) {
	key := os.Getenv("RAND_IV")
	var data Payload

	if err := ctx.BindJSON(&data); err != nil {
		ctx.JSON(400, gin.H{"success": false, "message": err.Error()})
		return
	}

	if data.Email == "" || data.FullName == "" || data.Password == "" {
		ctx.JSON(400, gin.H{"success": false, "message": "All fields must be filled"})
		return
	}

	if _, exists := dummyDB[data.Email]; exists {
		ctx.JSON(400, gin.H{"success": false, "message": "User already exists"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.JSON(500, gin.H{"success": false, "message": "Could not hash password"})
		return
	}

	encData, err := encryptPayload(Payload{FullName: data.FullName, Email: data.Email}, key)
	if err != nil {
		ctx.JSON(500, gin.H{"success": false, "message": "Could not encrypt data"})
		return
	}

	dummyDB[data.Email] = StoredUser{
		EncryptedData: encData,
		PasswordHash:  string(hash),
	}

	ctx.JSON(201, gin.H{
		"success": true,
		"message": fmt.Sprintf("User created successfully, welcome onboard %s", data.FullName),
	})
}

func HandleSignin(ctx *gin.Context) {
	key := os.Getenv("RAND_IV")
	var data Payload

	if err := ctx.BindJSON(&data); err != nil {
		ctx.JSON(400, gin.H{"success": false, "message": err.Error()})
		return
	}

	if data.Email == "" || data.Password == "" {
		ctx.JSON(400, gin.H{"success": false, "message": "All fields must be filled"})
		return
	}

	storedUser, exists := dummyDB[data.Email]
	if !exists {
		ctx.JSON(404, gin.H{"success": false, "message": "User not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedUser.PasswordHash), []byte(data.Password)); err != nil {
		ctx.JSON(400, gin.H{"success": false, "message": "Incorrect password"})
		return
	}

	decData, err := decryptPayload(storedUser.EncryptedData, key)
	if err != nil {
		ctx.JSON(500, gin.H{"success": false, "message": "Could not decrypt user data"})
		return
	}

	ctx.JSON(200, gin.H{
		"success": true,
		"message": fmt.Sprintf("Welcome back, %s", decData.FullName),
	})
}

func HandleOauth(ctx *gin.Context) {
	key := os.Getenv("RAND_IV")
	var data Payload

	if err := ctx.BindJSON(&data); err != nil {
		ctx.JSON(400, gin.H{"success": false, "message": err.Error()})
		return
	}

	if stored, exists := dummyDB[data.Email]; exists {
		user, _ := decryptPayload(stored.EncryptedData, key)
		ctx.JSON(200, gin.H{"success": true, "message": "Welcome back " + user.FullName})
		return
	}

	encData, err := encryptPayload(Payload{FullName: data.FullName, Email: data.Email}, key)
	if err != nil {
		ctx.JSON(500, gin.H{"success": false, "message": "Encryption failed"})
		return
	}

	dummyDB[data.Email] = StoredUser{
		EncryptedData: encData,
		PasswordHash:  "",
	}

	ctx.JSON(201, gin.H{"success": true, "message": "Welcome onboard " + data.FullName})
}

func encryptPayload(data Payload, key string) (string, error) {
	plainBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return encrypt.EncryptDataRandomIV(string(plainBytes), key)
}

func decryptPayload(encrypted, key string) (Payload, error) {
	var result Payload
	dec, err := encrypt.DecryptDataRandomIV(encrypted, key)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal([]byte(dec), &result)
	return result, err
}

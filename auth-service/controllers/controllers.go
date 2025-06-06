package controllers

import (
	"context"
	"log"
	"main/structs"
	"main/utils"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

func CreateUserController(payload structs.Payload, ip string, client *pgx.Conn, userAgent string) error {
	key := os.Getenv("RAND_IV")
	var hash []byte

	if payload.Password != "" {
		var err error
		hash, err = bcrypt.GenerateFromPassword([]byte(payload.Password), 12)
		if err != nil {
			return err
		}
	}

	encData, err := payload.EncryptPayload(key)
	if err != nil {
		log.Println("Error Could not encrypt data ", err.Error())
		return err
	}

	userCountry, err := utils.GetCountryFromIP(ip)
	if err != nil {
		log.Println("Error getting user country", err.Error())
		return err
	}

	_, err = client.Exec(context.Background(), utils.InsertString, uuid.NewString(), encData.FullName, encData.Email, string(hash), userCountry, ip, userAgent)
	if err != nil {
		log.Println("Error inserting user", err.Error())
		return err
	}
	return nil
}

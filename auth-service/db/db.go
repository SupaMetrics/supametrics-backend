package db

import (
	"context"
	"log"
	"os"
	"sync"

	"github.com/jackc/pgx/v5"
)

var (
	client *pgx.Conn
	once   sync.Once
)

type DbData struct {
	UUID      string
	Full_Name string
	Email     string
	Password  string
	Country   string
	Ip        string
	UserAgent string
}

func GetClient() *pgx.Conn {
	once.Do(func() {
		connStr := os.Getenv("NEON_URL")
		var err error
		client, err = pgx.Connect(context.Background(), connStr)
		if err != nil {
			log.Panicln("Error connecting to db: ", err.Error())

		}
		_, err = client.Exec(context.Background(), "CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, uuid TEXT, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password TEXT, country Text,  IP TEXT, user_agent TEXT);")
		if err != nil {
			panic(err)
		}

		log.Println("Db connected successfully")
	})

	return client

}

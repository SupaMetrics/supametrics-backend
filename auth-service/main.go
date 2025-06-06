package main

import (
	"log"
	"main/auth"

	"github.com/joho/godotenv"

	"github.com/gin-gonic/gin"
)

func main() {
	app := gin.Default()
	app.SetTrustedProxies([]string{"0.0.0.0/0"})

	err := godotenv.Load()
	if err != nil {
		log.Fatalln("Error loading env", err.Error())
	}

	app.GET("/", func(ctx *gin.Context) {
		log.Println(ctx.ClientIP())
		ctx.JSON(200, gin.H{
			"success": true, "message": "connected!",
		})
	})

	auths := app.Group("/auth")
	auths.POST("/signin", auth.HandleSignin)
	auths.POST("/signup", auth.HandleSignUp)
	auths.POST("/oauth", auth.HandleOauth)

	log.Println("Server running on port 8080")
	app.Run("localhost:8080")
}

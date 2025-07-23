package middleware

import (
	"fmt"
	"go-jwt/initializers"
	"go-jwt/models"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func RequiredAuth(c *gin.Context) {
	// Get the cookie off the req
	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		fmt.Println("cookie not found")
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	hmacSampleSecret := os.Getenv("SECRET")

	// Validate it
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (any, error) {
			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return []byte(hmacSampleSecret), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		log.Fatal(err)
		fmt.Println("token validation failed")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Check expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			fmt.Println("token is expired")
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// Find user with token
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			fmt.Println("validated user ID mismatch")
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// Attach to req
		c.Set("user", user)

		// Continue
		c.Next()
	} else {
		fmt.Println(err)
		c.AbortWithStatus(http.StatusUnauthorized)
	}

}

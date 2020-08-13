package main

import (
	"git.51.nb/mc/es_server/src/auth"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"time"
)

func main() {

	logger, _ := zap.NewProduction()

	authMiddleware, err := auth.NewMiddleware("testtt", "/Users/aside/.ssh/zwb_rsa")
	if err != nil {
		panic(err)
	}


	router := gin.Default()
	// Simple group: v1
	v1 := router.Group("/v1")
	{
		v1.POST("/login", authMiddleware.Login)
	}

	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	// Add a ginzap middleware, which:
	//   - Logs all requests, like a combined access and error log.
	//   - Logs to stdout.
	//   - RFC3339 with UTC time format.
	router.Use(ginzap.Ginzap(logger, time.RFC3339, true))

	// Logs all panic to error log
	//   - stack means whether output the stack info.
	router.Use(ginzap.RecoveryWithZap(logger, true))

	router.Run("0.0.0.0:9990") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

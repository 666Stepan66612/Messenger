package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"key-service/handlers"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func main() {
	// Database connection
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "postgres")
	dbPassword := getEnv("DB_PASSWORD", "postgres")
	dbName := getEnv("DB_NAME", "key_db")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Connected to database successfully")

	serverPort := getEnv("SERVER_PORT", "8081")
	serverSalt := getEnv("SERVER_SALT", "change-this-in-production")

	router := gin.Default()

	// CORS
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", getEnv("CORS_ORIGIN", "*"))
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Initialize handlers
	keyHandler := handlers.NewKeyHandler(db, serverSalt)

	// Simple auth middleware (validates user_id from header)
	// In production: validate JWT or session from auth-service
	authMiddleware := func(c *gin.Context) {
		userIDStr := c.GetHeader("X-User-ID")
		if userIDStr == "" {
			c.JSON(401, gin.H{"error": "Not authenticated"})
			c.Abort()
			return
		}

		// Validate UUID format
		if _, err := uuid.Parse(userIDStr); err != nil {
			c.JSON(401, gin.H{"error": "Invalid user ID"})
			c.Abort()
			return
		}

		c.Set("user_id", userIDStr)
		c.Next()
	}

	// Public routes (require auth)
	api := router.Group("/")
	api.Use(authMiddleware)
	{
		// Key management
		api.POST("/keys/upload", keyHandler.UploadKeys)
		api.GET("/keys/status", keyHandler.GetKeyStatus)
		api.GET("/keys/:userId", keyHandler.GetKeys)

		// Chat key management
		api.POST("/chat/key", keyHandler.CreateChatKey)
		api.GET("/chat/key/:chatId", keyHandler.GetChatKey)
	}

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "key-service",
		})
	})

	addr := ":" + serverPort
	log.Printf("Starting key-service on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

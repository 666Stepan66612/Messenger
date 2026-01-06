package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"auth-service/business"
	"auth-service/handlers"
	"auth-service/middleware"
	"auth-service/security"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

func main() {
	// download configuration from environment variables
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "postgres")
	dbPassword := getEnv("DB_PASSWORD", "postgres")
	dbName := getEnv("DB_NAME", "messenger_auth")
	serverPort := getEnv("SERVER_PORT", "8080")

	// Connect to the database
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// check the database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Successfully connected to database")

	// Set Gin mode
	if getEnv("GIN_MODE", "debug") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Security middleware
	router.Use(security.SecureHeadersMiddleware())

	// CORS middleware (use security package version)
	allowedOrigins := []string{}
	if origin := getEnv("CORS_ORIGIN", ""); origin != "" && origin != "*" {
		allowedOrigins = append(allowedOrigins, origin)
	}
	router.Use(security.CORSMiddleware(allowedOrigins))

	// Rate limiting middleware
	serverSalt := getEnv("SERVER_SALT", "change-this-in-production-to-random-value")
	rateLimiter := security.NewRateLimiter(db, serverSalt)
	defer rateLimiter.Stop()
	router.Use(security.RateLimitMiddleware(rateLimiter))

	// initialize handlers and business logic
	authHandler := handlers.NewAuthHandler(db)
	sessionBiz := business.NewSessionBusiness(db)

	// Public routes
	router.POST("/register", authHandler.Register)
	router.POST("/login", authHandler.Login)
	router.POST("/refresh", authHandler.Refresh)

	// Protected routes
	protected := router.Group("/")
	protected.Use(middleware.AuthMiddleware(sessionBiz))
	{
		protected.POST("/logout", authHandler.Logout)
		protected.POST("/change-password", authHandler.ChangePassword)
		protected.GET("/validate", authHandler.Validate)

		// 2FA routes
		protected.POST("/2fa/setup", authHandler.Setup2FA)
		protected.POST("/2fa/enable", authHandler.Enable2FA)
		protected.POST("/2fa/disable", authHandler.Disable2FA)
		protected.POST("/2fa/verify", authHandler.Verify2FA)

		// Security audit
		protected.GET("/security/events", authHandler.GetSecurityEvents)
	}

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "auth-service",
		})
	})

	// start the server
	addr := ":" + serverPort
	log.Printf("Starting server on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// getEnv retrieves environment variable or returns default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

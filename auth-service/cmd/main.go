package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"auth-service/business"
	"auth-service/handlers"
	"auth-service/middleware"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

func main() {
	// Загрузка конфигурации из переменных окружения
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "postgres")
	dbPassword := getEnv("DB_PASSWORD", "postgres")
	dbName := getEnv("DB_NAME", "messenger_auth")
	serverPort := getEnv("SERVER_PORT", "8080")

	// Подключение к базе данных
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Проверка подключения к БД
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Successfully connected to database")

	// Настройка Gin
	if getEnv("GIN_MODE", "debug") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", getEnv("CORS_ORIGIN", "*"))
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Инициализация handlers
	authHandler := handlers.NewAuthHandler(db)
	sessionBiz := business.NewSessionBusiness(db)

	// Публичные маршруты
	router.POST("/register", authHandler.Register)
	router.POST("/login", authHandler.Login)
	router.POST("/refresh", authHandler.Refresh)

	// Защищенные маршруты
	protected := router.Group("/")
	protected.Use(middleware.AuthMiddleware(sessionBiz))
	{
		protected.POST("/logout", authHandler.Logout)
		protected.POST("/change-password", authHandler.ChangePassword)
		protected.GET("/validate", authHandler.Validate)
	}

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "auth-service",
		})
	})

	// Запуск сервера
	addr := ":" + serverPort
	log.Printf("Starting server on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// getEnv получает переменную окружения или возвращает значение по умолчанию
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

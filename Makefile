.PHONY: build run test clean docker-up docker-down migrate

# Build the application
build:
	go build -o auth-service ./cmd/main.go

# Run the application
run:
	go run ./cmd/main.go

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -f auth-service
	rm -f cmd/auth-service

# Start Docker containers
docker-up:
	docker-compose up -d

# Stop Docker containers
docker-down:
	docker-compose down

# Rebuild and restart Docker containers
docker-rebuild:
	docker-compose down
	docker-compose build
	docker-compose up -d

# View logs
logs:
	docker-compose logs -f auth-service

# Format code
fmt:
	go fmt ./...

# Run linter
lint:
	golangci-lint run

# Download dependencies
deps:
	go mod download
	go mod tidy

# Database migrations
migrate:
	psql -h localhost -U postgres -d messenger_auth -f migrations/migrations.sql

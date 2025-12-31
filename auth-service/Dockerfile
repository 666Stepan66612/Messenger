FROM golang:1.25.5-alpine

WORKDIR /app

COPY go.mod ./

RUN go mod download

COPY . .

RUN go mod tidy

RUN go build -o main ./cmd/main.go

EXPOSE 8080

CMD ["./main"]
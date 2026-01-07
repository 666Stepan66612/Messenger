# Key Service

Микросервис для управления криптографическими ключами в мессенджере.

## Функциональность

- **Хранение публичных ключей** (Identity, PreKey, One-Time Keys)
- **Обмен ключами** между пользователями (для создания E2E чатов)
- **Зашифрованные ключи чатов** (приватные, расшифровываются на клиенте)
- **Privacy-preserving lookup** (HMAC для скрытия графа общения)

## API Endpoints

### `POST /keys/upload`
Загрузка публичных ключей пользователя
```json
{
  "identity_key": "base64...",
  "signed_prekey": "base64...",
  "prekey_signature": "base64...",
  "one_time_keys": ["base64...", "base64...", ...]
}
```

### `GET /keys/:userId`
Получение публичных ключей пользователя (для создания чата)

### `POST /chat/key`
Сохранение зашифрованного ключа чата
```json
{
  "chat_id": "uuid",
  "encrypted_key": "base64...",
  "encrypted_peer_id": "base64...",
  "nonce": "base64..."
}
```

### `GET /chat/key/:chatId`
Получение зашифрованного ключа чата

### `GET /keys/status`
Статус ключей пользователя (кол-во оставшихся one-time keys)

## Запуск

```bash
# Создать БД
createdb key_db

# Применить миграции
psql -U postgres -d key_db -f migrations/migrations.sql

# Установить зависимости
go mod tidy

# Запуск
go run cmd/main.go
```

## Docker

```bash
docker build -t key-service .
docker run -p 8081:8081 key-service
```

## Безопасность

- ✅ Публичные ключи хранятся открыто (для обмена)
- ✅ Приватные ключи НЕ хранятся на сервере
- ✅ Ключи чатов зашифрованы паролем пользователя
- ✅ HMAC для скрытия кто с кем общается
- ✅ One-time keys для forward secrecy (базовая защита)

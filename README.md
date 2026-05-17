# spring-boot-4-starter-security

Minimal Spring Boot 4 backend that supports JWT-based signup and login.

## Requirements

- Java 21
- Maven 3.9+

## Run locally

```bash
export JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
mvn spring-boot:run
```

The app uses `security.jwt.secret` for signing tokens. By default it generates an in-memory development secret for each startup. Set `JWT_SECRET` to provide your own stable key.

## API

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/auth/me` with `Authorization: Bearer <token>`

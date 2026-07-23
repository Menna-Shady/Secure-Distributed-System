# 🔐 Secure Distributed File Management System

A secure distributed file management system built using a Dockerized microservices architecture. The platform provides authenticated file upload and download, encryption, integrity verification, role-based access control (RBAC), and asynchronous background processing through RabbitMQ.

## Architecture

                  Client
                     │
             Nginx API Gateway
                     │
        ┌────────────┴────────────┐
        │                         │
  Authentication Service      API Services
        │                  (api1 / api2 / api3)
        └────────────┬────────────┘
                     │
          RabbitMQ Queue → Worker
                     │
                PostgreSQL

## ✨ Features

- Secure file upload & download
- JWT & Google OAuth authentication
- Role-Based Access Control (RBAC)
- File encryption using Fernet
- SHA-256 integrity verification
- RSA digital signatures
- RabbitMQ background processing
- Dockerized microservices
- Nginx reverse proxy
- Audit logging

## Services

| Service | Role |
|---|---|
| nginx | Gateway — TLS, rate limiting, security headers |
| auth-service | Register/login, JWT, Google OAuth |
| api1–api3 | File upload/download, RBAC, encryption, signing |
| worker | Async job processing (via RabbitMQ) |
| db | PostgreSQL — users, roles, files, audit logs |
| rabbitmq | Message queue |

## Security Highlights

- JWT auth + bcrypt password hashing
- Google OAuth 2.0 login
- RBAC (admin / user) with DB-backed roles & permissions
- Files: validated → encrypted (Fernet) → SHA-256 hashed → RSA-signed
- Nginx + Flask-Limiter rate limiting, HTTPS-only, security headers
- Internal `X-Internal-Key` for service-to-service calls
- Full audit logging (logins, uploads, downloads, unauthorized access)
- Secrets via `.env` only — never hardcoded

## Getting Started

1. Create a `.env` file with: `POSTGRES_*`, `JWT_SECRET`, `SECRET_KEY`, `GOOGLE_CLIENT_ID/SECRET`, `RABBITMQ_*`, `FILE_ENCRYPTION_KEY`, `INTERNAL_API_KEY`
2. Run:
   ```bash
   docker compose up --build
   ```
3. Access:
   - API/Gateway: `https://localhost`
   - Admin dashboard: `https://localhost/dashboard`
   - User dashboard: `https://localhost/user`

Default admin: `admin@test.com` / `Admin1234!` (change in production)

## Key Endpoints

| Endpoint | Description |
|---|---|
| `POST /register`, `/login` | Auth |
| `POST /upload`, `GET /download/<file>` | Secure file handling |
| `GET /my/files` | User's own files |
| `GET /admin/users`, `/admin/files`, `/admin/logs` | Admin-only |

## Tech Stack

Flask · PostgreSQL · RabbitMQ · Nginx · Docker Compose · PyJWT · bcrypt · Authlib · cryptography

## License

Built for academic purposes — Secure Distributed System Design course.
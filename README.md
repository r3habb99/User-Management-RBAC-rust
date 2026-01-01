# User Management API

A comprehensive REST API for user management built with Rust, featuring authentication, authorization, profile management, and admin functionalities.

## 📋 Overview

The User Management System is a production-ready backend API that provides complete user lifecycle management including registration, authentication, profile management, and administrative controls. Built with performance and security in mind using Rust's Actix-web framework and MongoDB.

### Key Features

- **🔐 Authentication & Authorization** - JWT-based authentication with role-based access control (RBAC)
- **👤 User Management** - Full CRUD operations for user accounts
- **📝 Profile Management** - Extended user profiles with avatar uploads
- **👑 Admin Functions** - User statistics, role management, bulk operations
- **🛡️ Security** - Rate limiting, password hashing, token blacklisting
- **📚 API Documentation** - Interactive Swagger UI documentation
- **🐳 Docker Ready** - Complete containerization with Docker Compose

## 🛠️ Technology Stack

| Technology | Purpose |
|------------|---------|
| **Rust** | Core programming language |
| **Actix-web 4** | High-performance async web framework |
| **MongoDB** | NoSQL database for flexible document storage |
| **JWT (jsonwebtoken)** | Secure token-based authentication |
| **bcrypt** | Industry-standard password hashing |
| **utoipa + Swagger UI** | OpenAPI documentation |
| **Docker** | Containerization and deployment |

## 📁 Project Structure

```
user_management/
├── src/
│   ├── main.rs              # Application entry point, server setup
│   ├── openapi.rs           # OpenAPI/Swagger configuration
│   ├── config/
│   │   └── mod.rs           # Environment configuration (CONFIG singleton)
│   ├── constants/
│   │   ├── collections.rs   # MongoDB collection names
│   │   ├── error_codes.rs   # API error code constants
│   │   ├── errors.rs        # Error message constants
│   │   ├── messages.rs      # Success message constants
│   │   ├── pagination.rs    # Pagination defaults and limits
│   │   └── roles.rs         # User role constants
│   ├── errors/
│   │   └── mod.rs           # Custom API error types and handling
│   ├── handlers/
│   │   ├── admin_handler.rs # Admin-only endpoints (stats, bulk ops)
│   │   ├── auth_handler.rs  # Authentication (register, login, logout)
│   │   ├── avatar_handler.rs# Avatar upload/delete handlers
│   │   └── user_handler.rs  # User CRUD and profile management
│   ├── middleware/
│   │   ├── auth_middleware.rs   # JWT authentication middleware
│   │   ├── auth_helpers.rs      # Auth helper functions
│   │   ├── rate_limiter.rs      # Rate limiting configuration
│   │   └── request_ext.rs       # Request extension utilities
│   ├── models/
│   │   ├── claims.rs        # JWT claims structure
│   │   ├── user.rs          # User and UserProfile models
│   │   ├── requests/        # Request DTOs (auth, user updates)
│   │   └── responses/       # Response DTOs (API, pagination, user)
│   ├── repositories/
│   │   └── user_repository.rs   # MongoDB user data access layer
│   ├── routes/
│   │   └── mod.rs           # Route configuration and health check
│   ├── services/
│   │   ├── auth_service.rs      # Authentication business logic
│   │   ├── avatar_service.rs    # Avatar management logic
│   │   ├── file_service.rs      # File upload/storage handling
│   │   ├── token_blacklist.rs   # JWT token blacklisting
│   │   └── user_service.rs      # User business logic and admin seeding
│   ├── utils/
│   │   └── log_sanitizer.rs # Log sanitization utilities
│   └── validators/
│       ├── common.rs        # Common validation helpers
│       └── user.rs          # User-specific validations
├── uploads/                 # Avatar file storage directory
├── Cargo.toml               # Rust dependencies
├── Dockerfile               # Multi-stage Docker build
├── docker-compose.yml       # Full stack orchestration
└── README.md                # This file
```

## 📦 Dependencies

### Web Framework
| Crate | Version | Purpose |
|-------|---------|---------|
| `actix-web` | 4 | High-performance async HTTP server |
| `actix-rt` | 2 | Actix runtime |
| `actix-cors` | 0.7 | Cross-Origin Resource Sharing middleware |
| `actix-files` | 0.6.9 | Static file serving (avatar uploads) |
| `actix-multipart` | 0.7.2 | Multipart form handling for file uploads |
| `actix-governor` | 0.10.0 | Rate limiting middleware |

### Database
| Crate | Version | Purpose |
|-------|---------|---------|
| `mongodb` | 3.4.1 | Official MongoDB driver |
| `bson` | 3.1.0 | BSON serialization with chrono support |

### Authentication & Security
| Crate | Version | Purpose |
|-------|---------|---------|
| `jsonwebtoken` | 10.2.0 | JWT creation and validation |
| `bcrypt` | 0.17.1 | Password hashing (bcrypt algorithm) |

### Serialization & Validation
| Crate | Version | Purpose |
|-------|---------|---------|
| `serde` | 1 | Serialization/deserialization framework |
| `serde_json` | 1.0.148 | JSON serialization |
| `validator` | 0.20.0 | Request validation with derive macros |

### Utilities
| Crate | Version | Purpose |
|-------|---------|---------|
| `chrono` | 0.4 | Date/time handling with serde support |
| `uuid` | 1 | UUID v4 generation for unique identifiers |
| `dotenv` | 0.15 | Environment variable loading from .env |
| `thiserror` | 2.0.17 | Error type derivation |
| `lazy_static` | 1.4 | Lazy static initialization (CONFIG) |
| `regex` | 1.12.2 | Regular expression validation |
| `dashmap` | 6.1.0 | Concurrent hashmap for token blacklist |

### Logging
| Crate | Version | Purpose |
|-------|---------|---------|
| `log` | 0.4 | Logging facade |
| `env_logger` | 0.11.8 | Environment-based log configuration |

### API Documentation
| Crate | Version | Purpose |
|-------|---------|---------|
| `utoipa` | 5.4.0 | OpenAPI spec generation from code |
| `utoipa-swagger-ui` | 9.0.2 | Swagger UI integration |

### Async Runtime
| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | 1 | Async runtime with full features |
| `tokio-util` | 0.7.17 | Tokio utilities |
| `futures` | 0.3 | Async utilities and combinators |

## 🌐 API Endpoints

### Health Check
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Server health check |

### Authentication (Rate Limited)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a new user account |
| POST | `/api/auth/login` | Authenticate and get JWT token |
| POST | `/api/auth/logout` | Logout and invalidate token (🔒) |

### Users (Protected)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users` | List users with pagination, filters, search |
| GET | `/api/users/me` | Get current authenticated user profile |
| GET | `/api/users/{id}` | Get specific user by ID |
| PUT | `/api/users/{id}` | Update user profile |
| DELETE | `/api/users/{id}` | Delete user account |
| PATCH | `/api/users/{id}/password` | Change password |
| PATCH | `/api/users/{id}/role` | Update user role (👑 Admin only) |
| PATCH | `/api/users/{id}/status` | Activate/deactivate user (👑 Admin only) |
| POST | `/api/users/{id}/avatar` | Upload avatar image |
| DELETE | `/api/users/{id}/avatar` | Delete avatar image |

### Admin (Protected, Admin Only)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/stats` | Get user statistics |
| PATCH | `/api/admin/users/bulk-status` | Bulk update user status |

> 🔒 = Requires authentication | 👑 = Requires admin role

### Swagger UI

Interactive API documentation is available at:
```
http://localhost:8080/swagger-ui/
```

## 🚀 Setup & Installation

### Prerequisites

- **Rust** 1.83+ (for local development)
- **MongoDB** 7.0+ (local or Docker)
- **Docker** & **Docker Compose** (for containerized deployment)

### Environment Configuration

Create a `.env` file in the project root:

```env
# Server Configuration
SERVER_HOST=127.0.0.1
SERVER_PORT=8080

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017
DATABASE_NAME=user_management

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRATION_HOURS=24

# File Upload
UPLOAD_DIR=./uploads

# Admin Seeding (creates initial admin user)
SEED_ADMIN=true
ADMIN_EMAIL=admin@example.com
ADMIN_USERNAME=admin
ADMIN_PASSWORD=Admin@123456

# CORS Configuration (comma-separated origins)
CORS_ORIGINS=http://localhost:8080,http://127.0.0.1:8080

# Logging
RUST_LOG=info
```

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd user_management
   ```

2. **Install Rust** (if not installed)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

3. **Start MongoDB** (using Docker)
   ```bash
   docker run -d --name mongodb -p 27017:27017 mongo:7.0
   ```

4. **Create `.env` file** (see configuration above)

5. **Run the application**
   ```bash
   cargo run
   ```

6. **Access the API**
   - API Base: `http://localhost:8080/api`
   - Swagger UI: `http://localhost:8080/swagger-ui/`

### Docker Deployment

1. **Start all services**
   ```bash
   docker-compose up -d
   ```

2. **With MongoDB Express (development UI)**
   ```bash
   docker-compose --profile dev up -d
   ```

3. **Stop services**
   ```bash
   docker-compose down
   ```

4. **View logs**
   ```bash
   docker-compose logs -f api
   ```

#### Docker Services

| Service | Port | Description |
|---------|------|-------------|
| `api` | 8080 | User Management API |
| `mongodb` | 27017 | MongoDB database |
| `mongo-express` | 8081 | MongoDB admin UI (dev profile) |

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_HOST` | `127.0.0.1` | Server bind address |
| `SERVER_PORT` | `8080` | Server port |
| `MONGODB_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `DATABASE_NAME` | `user_management` | Database name |
| `JWT_SECRET` | (unsafe default) | Secret key for JWT signing |
| `JWT_EXPIRATION_HOURS` | `24` | Token validity period |
| `UPLOAD_DIR` | `./uploads` | Avatar storage directory |
| `SEED_ADMIN` | `true` | Auto-create admin user on startup |
| `ADMIN_EMAIL` | `admin@test.com` | Seeded admin email |
| `ADMIN_USERNAME` | `admin` | Seeded admin username |
| `ADMIN_PASSWORD` | `Admin@2026` | Seeded admin password |
| `CORS_ORIGINS` | `http://localhost:8080,...` | Allowed CORS origins |
| `RUST_LOG` | `info` | Log level (debug, info, warn, error) |

### Security Considerations

⚠️ **Important for Production:**
- Change `JWT_SECRET` to a strong, unique secret
- Use secure `ADMIN_PASSWORD` and change after first login
- Configure `CORS_ORIGINS` to only allow your frontend domains
- Use HTTPS in production (via reverse proxy)
- Consider using environment secrets management

## 🔐 Features

### Authentication & Authorization

- **JWT-based Authentication**: Stateless token authentication
- **Token Blacklisting**: Logout invalidates tokens server-side
- **Role-Based Access Control (RBAC)**: Admin and User roles
- **Password Hashing**: bcrypt with salt for secure password storage

### Rate Limiting

Auth endpoints are rate-limited to prevent brute-force attacks:
- **5 requests** burst capacity
- **10 requests per minute** sustained rate
- Based on client IP address

### User Profile Management

Users can manage their profiles including:
- First name, last name
- Phone number, bio
- Location, website URL
- Date of birth
- Avatar image upload

### Avatar Uploads

- Supported formats: JPEG, PNG, GIF, WebP
- Maximum file size: 5MB
- Stored in configurable uploads directory
- Served as static files at `/uploads/`

### Admin Capabilities

Administrators can:
- View user statistics (total users, active/inactive counts, role distribution)
- Manage user roles (promote/demote)
- Activate/deactivate user accounts
- Perform bulk status updates (up to 100 users per request)

### Admin Seeding

On startup, the system can automatically create an admin user:
- Enable with `SEED_ADMIN=true`
- Only creates if no admin exists
- Configure credentials via environment variables

## 📝 Usage Examples

### Register a New User

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "newuser",
    "password": "SecurePass123!"
  }'
```

### Login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "...",
    "email": "user@example.com",
    "username": "newuser",
    "role": "user"
  }
}
```

### Get Current User Profile

```bash
curl http://localhost:8080/api/users/me \
  -H "Authorization: Bearer <your-token>"
```

### Update Profile

```bash
curl -X PUT http://localhost:8080/api/users/{user_id} \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe",
    "bio": "Software Developer"
  }'
```

### Upload Avatar

```bash
curl -X POST http://localhost:8080/api/users/{user_id}/avatar \
  -H "Authorization: Bearer <your-token>" \
  -F "file=@/path/to/avatar.jpg"
```

### List Users with Filters

```bash
# Paginated list
curl "http://localhost:8080/api/users?page=1&per_page=10" \
  -H "Authorization: Bearer <your-token>"

# Filter by role
curl "http://localhost:8080/api/users?role=admin" \
  -H "Authorization: Bearer <your-token>"

# Search users
curl "http://localhost:8080/api/users?search=john" \
  -H "Authorization: Bearer <your-token>"
```

### Admin: Get User Statistics

```bash
curl http://localhost:8080/api/admin/stats \
  -H "Authorization: Bearer <admin-token>"
```

### Logout

```bash
curl -X POST http://localhost:8080/api/auth/logout \
  -H "Authorization: Bearer <your-token>"
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.


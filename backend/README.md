# Albus Recon - Backend

A production-ready network reconnaissance and vulnerability scanning platform built with FastAPI.

## Features

- **JWT Authentication** with role-based access control (Admin/Analyst)
- **Layered Architecture** with proper separation of concerns
- **PostgreSQL Database** with SQLAlchemy ORM
- **Rate Limiting** and secure CORS configuration
- **Structured Logging** with security and audit trails
- **Request Validation** using Pydantic schemas
- **Vulnerability Scanning** with multiple scan types
- **Network Tools** (subdomain enumeration, port scanning)
- **Production Ready** with Docker and Gunicorn support

## Architecture

```
backend/
├── core/                 # Core components
│   ├── auth.py          # Authentication & authorization
│   ├── database.py      # Database configuration
│   ├── models.py        # SQLAlchemy models
│   ├── schemas.py       # Pydantic schemas
│   └── logging.py       # Logging configuration
├── repositories/         # Data access layer
│   ├── user_repository.py
│   ├── scan_repository.py
│   ├── vulnerability_repository.py
│   └── recon_repository.py
├── services/            # Business logic layer
│   ├── auth_service.py
│   ├── scan_service.py
│   ├── recon_service.py
│   ├── vulnerability_service.py
│   └── tools_service.py
├── routes/              # API endpoints
│   ├── auth.py
│   ├── scan.py
│   ├── recon.py
│   ├── tools.py
│   └── vulnerabilities.py
├── security/            # Security scanning modules
├── main.py             # FastAPI application
├── config.py           # Configuration management
├── gunicorn.conf.py    # Gunicorn configuration
└── Dockerfile          # Docker configuration
```

## Setup

### Prerequisites

- Python 3.11+
- PostgreSQL 12+
- Redis (optional, for caching)

### 1. Environment Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit environment variables
nano .env
```

### 2. Database Setup

```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt-get install postgresql postgresql-contrib

# Create database
sudo -u postgres createdb albus_recon

# Create user (optional)
sudo -u postgres createuser albus_recon
```

### 3. Install Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### 4. Database Migrations

```bash
# Initialize Alembic
alembic init alembic

# Create initial migration
alembic revision --autogenerate -m "Initial migration"

# Apply migrations
alembic upgrade head
```

### 5. Run Application

#### Development

```bash
# Run with Uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Or run directly
python main.py
```

#### Production

```bash
# Run with Gunicorn
gunicorn --config gunicorn.conf.py main:app

# Or with Docker
docker build -t albus-recon-backend .
docker run -p 8000:8000 --env-file .env albus-recon-backend
```

## API Documentation

Once running, visit:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## Authentication

The API uses JWT tokens for authentication:

1. **Register** a new user: `POST /api/auth/register`
2. **Login** to get tokens: `POST /api/auth/login`
3. Use `Authorization: Bearer <token>` header for protected endpoints

### Roles

- **Admin**: Full access to all resources
- **Analyst**: Can create scans and view own data

## Main Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh access token
- `GET /api/auth/me` - Get current user profile

### Scanning
- `POST /api/scans` - Create new scan
- `GET /api/scans` - List user scans
- `GET /api/scans/{scan_id}` - Get scan details
- `POST /api/scans/{scan_id}/cancel` - Cancel running scan

### Reconnaissance
- `POST /api/recon` - Create URL reconnaissance
- `GET /api/recon` - List reconnaissance results
- `GET /api/recon/{recon_id}` - Get recon details

### Tools
- `POST /api/tools/subdomains` - Subdomain enumeration
- `POST /api/tools/port-scan` - Port scanning
- `GET /api/tools/dns-info/{domain}` - DNS information

### Vulnerabilities
- `GET /api/vulnerabilities` - List vulnerabilities
- `GET /api/vulnerabilities/{vuln_id}` - Get vulnerability details
- `PUT /api/vulnerabilities/{vuln_id}` - Update vulnerability
- `POST /api/vulnerabilities/{vuln_id}/assign` - Assign vulnerability

## Environment Variables

Key environment variables (see `.env.example`):

```bash
# Application
APP_NAME="Albus Recon"
DEBUG=false
SECRET_KEY="your-secret-key"

# Database
DATABASE_URL="postgresql://user:pass@localhost:5432/albus_recon"

# JWT
JWT_SECRET_KEY="your-jwt-secret"
JWT_ACCESS_TOKEN_EXPIRES=3600

# CORS
CORS_ORIGINS="http://localhost:3000,https://yourdomain.com"

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

## Security Features

- **Password Hashing** with bcrypt
- **JWT Token** authentication
- **Rate Limiting** to prevent abuse
- **CORS Protection** with configurable origins
- **Input Validation** with Pydantic
- **SQL Injection Prevention** with SQLAlchemy
- **Audit Logging** for security events
- **Role-Based Access Control**

## Monitoring & Logging

- **Structured JSON Logging** for easy parsing
- **Security Logs** for authentication events
- **Audit Trail** for user actions
- **Request/Response Logging** with timing
- **Error Tracking** with full context
- **Health Checks** at `/api/health`

## Development

### Code Quality

```bash
# Format code
black .
isort .

# Lint code
flake8 .

# Run tests
pytest

# Run tests with coverage
pytest --cov=.
```

### Database Migrations

```bash
# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

## Production Deployment

### Docker

```bash
# Build image
docker build -t albus-recon-backend .

# Run container
docker run -d \
  --name albus-recon \
  -p 8000:8000 \
  --env-file .env \
  albus-recon-backend
```

### Docker Compose

```yaml
version: '3.8'
services:
  backend:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/albus_recon
    depends_on:
      - db
  
  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=albus_recon
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### Performance Tuning

- **Gunicorn Workers**: `2 * CPU cores + 1`
- **Database Pooling**: Configure connection pool size
- **Caching**: Add Redis for session/token storage
- **Load Balancing**: Use Nginx or cloud load balancer

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Ensure code quality checks pass
5. Submit pull request

## License

This project is licensed under the MIT License.

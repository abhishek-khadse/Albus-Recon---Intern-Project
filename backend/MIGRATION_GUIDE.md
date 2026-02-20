# Migration Guide: Flask to FastAPI Refactoring

This guide helps you migrate from the old Flask backend to the new FastAPI backend while preserving all functionality.

## Overview of Changes

### Architecture Changes
- **From**: Single-file Flask app with global state
- **To**: Layered FastAPI architecture with proper separation of concerns

### Key Improvements
1. **Authentication**: JWT-based with role-based access control
2. **Database**: PostgreSQL with proper connection pooling
3. **Validation**: Pydantic schemas for request/response validation
4. **Security**: Rate limiting, CORS, input sanitization
5. **Logging**: Structured JSON logging with audit trails
6. **Production**: Docker, Gunicorn, Nginx configuration

## API Endpoint Mapping

### Authentication
| Old Flask Endpoint | New FastAPI Endpoint | Notes |
|-------------------|---------------------|-------|
| None | `POST /api/auth/register` | New user registration |
| None | `POST /api/auth/login` | JWT login |
| None | `GET /api/auth/me` | Get current user |

### Reconnaissance
| Old Flask Endpoint | New FastAPI Endpoint | Notes |
|-------------------|---------------------|-------|
| `POST /api/recon` | `POST /api/recon` | Same functionality |
| `GET /api/recon` | `GET /api/recon` | Requires authentication |
| None | `GET /api/recon/{recon_id}` | Get specific recon |
| None | `DELETE /api/recon/{recon_id}` | Delete recon |

### Scanning
| Old Flask Endpoint | New FastAPI Endpoint | Notes |
|-------------------|---------------------|-------|
| `GET /api/scan/{scan_id}` | `GET /api/scans/{scan_id}` | Pluralized path |
| `GET /api/vulnerabilities` | `GET /api/vulnerabilities` | Same path |
| `GET /api/vulnerabilities/{vuln_id}` | `GET /api/vulnerabilities/{vuln_id}` | Same path |
| `PUT /api/vulnerabilities/{vuln_id}` | `PUT /api/vulnerabilities/{vuln_id}` | Same path |
| None | `POST /api/scans` | Create new scan |
| None | `GET /api/scans` | List scans |

### Tools
| Old Flask Endpoint | New FastAPI Endpoint | Notes |
|-------------------|---------------------|-------|
| `GET /api/tools/subdomains` | `GET /api/tools/subdomains` | Same functionality |
| None | `POST /api/tools/subdomains` | POST version available |
| `POST /api/tools/port-scan` | `POST /api/tools/port-scan` | Same functionality |
| None | `GET /api/tools/dns-info/{domain}` | New DNS info endpoint |
| None | `GET /api/tools/http-headers/{url}` | New HTTP headers endpoint |

## Frontend Migration Steps

### 1. Update Authentication
```javascript
// Old: No authentication
// New: JWT-based authentication

// Login
const loginResponse = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password })
});
const { access_token } = await loginResponse.json();
localStorage.setItem('token', access_token);

// Add token to requests
const headers = {
  'Authorization': `Bearer ${localStorage.getItem('token')}`,
  'Content-Type': 'application/json'
};
```

### 2. Update API Calls
```javascript
// Old: GET /api/recon
// New: GET /api/recon (with auth)

const response = await fetch('/api/recon', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});
```

### 3. Handle New Response Formats
```javascript
// New endpoints return structured responses with pagination
const { items, pagination, summary } = await response.json();

// Error handling
if (!response.ok) {
  const { error, details } = await response.json();
  console.error('API Error:', error, details);
}
```

### 4. Update Form Submissions
```javascript
// Old: Form data or URL parameters
// New: JSON payloads

// Create recon
const reconResponse = await fetch('/api/recon', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ url: 'https://example.com' })
});
```

## Database Migration

### 1. Export Existing Data
```bash
# From old SQLite database
sqlite3 albus_recon.db .dump > old_data.sql
```

### 2. Set up PostgreSQL
```bash
# Using Docker Compose
docker-compose up db

# Or manual setup
createdb albus_recon
```

### 3. Run Migrations
```bash
# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head
```

### 4. Import Data (Manual)
You'll need to write a script to convert SQLite data to PostgreSQL format, considering the new schema structure.

## Configuration Changes

### Environment Variables
```bash
# Copy new environment template
cp .env.example .env

# Update with your values
DATABASE_URL=postgresql://user:pass@localhost:5432/albus_recon
JWT_SECRET_KEY=your-jwt-secret
SECRET_KEY=your-app-secret
```

### Port Changes
- **Old**: Flask on port 5000
- **New**: FastAPI on port 8000

## Testing the Migration

### 1. Start New Backend
```bash
# Development
uvicorn main:app --reload

# Production
docker-compose up
```

### 2. Run Endpoint Tests
```bash
# Test all endpoints
python test_endpoints.py
```

### 3. Verify Frontend Integration
1. Update frontend API base URL to port 8000
2. Add authentication flow
3. Update request headers
4. Test all functionality

## Breaking Changes

### Required Changes
1. **Authentication**: All endpoints now require JWT authentication
2. **Port**: Backend runs on port 8000 instead of 5000
3. **Request Format**: JSON payloads instead of form data
4. **Response Format**: Structured JSON responses

### Optional Enhancements
1. **Pagination**: List endpoints support pagination
2. **Filtering**: Enhanced filtering options
3. **Search**: New search functionality
4. **Statistics**: New statistics endpoints

## Rollback Plan

If you need to rollback:
1. Stop new backend: `docker-compose down`
2. Start old Flask app: `python app.py`
3. Restore database from backup
4. Update frontend to use old endpoints

## Support

For issues during migration:
1. Check logs: `docker-compose logs backend`
2. Run tests: `python test_endpoints.py`
3. Verify database: Check PostgreSQL connection
4. Review API docs: Visit `http://localhost:8000/docs`

## Timeline

1. **Phase 1**: Deploy new backend alongside old one
2. **Phase 2**: Update frontend authentication
3. **Phase 3**: Migrate database
4. **Phase 4**: Switch to new backend
5. **Phase 5**: Decommission old backend

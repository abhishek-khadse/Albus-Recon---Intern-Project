# Albus Recon - Backend

A simple web reconnaissance API that fetches URLs and extracts their titles.

## Setup

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application**:
   ```bash
   python app.py
   ```

3. **Using Docker**:
   ```bash
   docker build -t albus-recon-backend .
   docker run -p 5000:5000 albus-recon-backend
   ```

## API Endpoints

- `GET /` - Welcome message
- `POST /api/recon` - Submit a URL to scan
  - Request body: `{"url": "https://example.com"}`
- `GET /api/recon` - List all scans

## Environment Variables

- `DATABASE_URL` - Database connection URL (default: `sqlite:///db.sqlite3`)

## Development

For development, you can use the built-in Flask server:

```bash
FLASK_APP=app.py flask run --reload
```

"""Simple startup script for development with SQLite."""
import os
import sys
import uvicorn

# Set environment for development
os.environ['DATABASE_URL'] = 'sqlite:///./albus_recon_simple.db'
os.environ['DEBUG'] = 'true'
os.environ['SECRET_KEY'] = 'dev-secret-key'
os.environ['JWT_SECRET_KEY'] = 'dev-jwt-secret'
os.environ['CORS_ORIGINS'] = '["http://localhost:3000"]'

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("🚀 Starting Albus Recon Backend (Development Mode)")
    print("📍 Database: SQLite (albus_recon_simple.db)")
    print("🌐 Server: http://localhost:8000")
    print("📚 API Docs: http://localhost:8000/docs")
    print("🔧 Debug Mode: ON")
    print()
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

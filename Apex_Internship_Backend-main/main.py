import os
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import logging
from typing import List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import routers
from auth.routes import router as auth_router
from auth.courses import router as courses_router
from auth.video import router as video_router
from auth.config import settings

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title="Apex Auth API", version="1.0.0")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "x-admin-key"],
    expose_headers=["Content-Type", "Content-Length"],
    max_age=600  # 10 minutes
)

# Middleware to log all requests and responses
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Log request
    logger.info(f"Incoming request: {request.method} {request.url}")
    logger.info(f"Headers: {dict(request.headers)}")
    
    # Handle preflight requests
    if request.method == "OPTIONS":
        origin = request.headers.get("Origin", "")
        if origin in settings.BACKEND_CORS_ORIGINS or "*" in settings.BACKEND_CORS_ORIGINS:
            response = Response(
                status_code=status.HTTP_200_OK,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization, x-admin-key",
                    "Access-Control-Allow-Credentials": "true",
                    "Access-Control-Max-Age": "600",  # 10 minutes
                }
            )
            return response
    
    # Process the request
    response = await call_next(request)
    
    # Add CORS headers to all responses
    origin = request.headers.get("Origin", "")
    if origin in settings.BACKEND_CORS_ORIGINS or "*" in settings.BACKEND_CORS_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    else:
        response.headers["Access-Control-Allow-Origin"] = settings.BACKEND_CORS_ORIGINS[0] if settings.BACKEND_CORS_ORIGINS else "http://localhost:5173"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    
    # Log response
    logger.info(f"Response status: {response.status_code}")
    logger.info(f"Response headers: {dict(response.headers)}")
    
    return response

# Include routers with /api prefix
app.include_router(auth_router, prefix="/api", tags=["authentication"])
app.include_router(courses_router, prefix="/api", tags=["courses"])
app.include_router(video_router, prefix="/video", tags=["video"])

# Test endpoint
@app.get("/api/test")
async def test_endpoint():
    return {"message": "CORS test successful"}

# Health check
@app.get("/health")
async def health_check():
    return {"status": "ok"}

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Apex Auth Service - Healthy",
        "endpoints": [
            {"path": "/api/test", "methods": ["GET"]},
            {"path": "/api/auth/challenge", "methods": ["GET"]},
            {"path": "/api/auth/login", "methods": ["POST"]},
            {"path": "/api/auth/verify", "methods": ["GET"]},
            {"path": "/video/{video_id}/access", "methods": ["GET"]},
            {"path": "/health", "methods": ["GET"]}
        ]
    }

# Add Mangum handler for AWS Lambda
from mangum import Mangum
handler = Mangum(app)

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="debug"
    )

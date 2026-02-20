"""Main FastAPI application."""
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import time
import os

from config import settings
from core.database import init_db, close_db
from core.logging import setup_logging, get_logger, log_request_response
from routes import auth, recon, scan, tools, vulnerabilities

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Network reconnaissance and vulnerability scanning platform",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

# Add trusted host middleware for production
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]  # Configure with your actual domains in production
    )


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add processing time header and log requests."""
    start_time = time.time()
    
    # Get user info if available
    user_id = None
    try:
        # Try to extract user from token if present
        authorization = request.headers.get("authorization")
        if authorization and authorization.startswith("Bearer "):
            from core.auth import verify_token
            token = authorization.split(" ")[1]
            payload = verify_token(token)
            if payload:
                user_id = payload.get("sub")
    except Exception:
        pass
    
    response = await call_next(request)
    
    # Calculate processing time
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    
    # Log request/response
    log_request_response(
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        duration=process_time,
        user_id=user_id,
        ip_address=request.client.host
    )
    
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with proper logging."""
    logger.warning(
        f"HTTP {exc.status_code}: {exc.detail}",
        extra={
            "status_code": exc.status_code,
            "detail": exc.detail,
            "url": str(request.url),
            "method": request.method,
            "ip_address": request.client.host
        }
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions with proper logging."""
    logger.error(
        f"Unhandled exception: {str(exc)}",
        extra={
            "url": str(request.url),
            "method": request.method,
            "ip_address": request.client.host,
            "exception_type": type(exc).__name__
        },
        exc_info=True
    )
    
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "status_code": 500}
    )


# Include routers
app.include_router(auth.router)
app.include_router(recon.router)
app.include_router(scan.router)
app.include_router(tools.router)
app.include_router(vulnerabilities.router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": f"✅ {settings.APP_NAME} Backend is running successfully!",
        "status": "OK",
        "version": settings.APP_VERSION,
        "docs": "/docs" if settings.DEBUG else "Documentation disabled in production"
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    from datetime import datetime
    
    # Check database connection
    db_status = "ok"
    try:
        from core.database import get_db
        next(get_db())
    except Exception as e:
        db_status = f"error: {str(e)}"
        logger.error(f"Database health check failed: {e}")
    
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": db_status,
        "debug": settings.DEBUG
    }


@app.on_event("startup")
async def startup_event():
    """Application startup event."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    
    # Initialize database
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    
    # Create upload directory
    os.makedirs(settings.UPLOAD_FOLDER, exist_ok=True)
    
    # Log startup
    logger.info("Application startup completed")


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown event."""
    logger.info("Shutting down application")
    
    # Close database connections
    try:
        close_db()
        logger.info("Database connections closed")
    except Exception as e:
        logger.error(f"Error closing database connections: {e}")


# Development-only endpoints
if settings.DEBUG:
    @app.get("/api/debug/info")
    async def debug_info():
        """Debug information endpoint (development only)."""
        return {
            "settings": {
                "app_name": settings.APP_NAME,
                "version": settings.APP_VERSION,
                "debug": settings.DEBUG,
                "cors_origins": settings.CORS_ORIGINS,
                "database_url": settings.DATABASE_URL.split("@")[-1] if "@" in settings.DATABASE_URL else "configured",
                "log_level": settings.LOG_LEVEL,
            }
        }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )

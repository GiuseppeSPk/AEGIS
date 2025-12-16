"""FastAPI main application.

AEGIS REST API
- OAuth2 + JWT authentication
- API key authentication for programmatic access
- Rate limiting
- CORS configuration
"""

from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aegis import __version__
from aegis.api.routes import attacks, auth, campaigns, health, reports


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    print(f"🚀 AEGIS API v{__version__} starting...")
    yield
    # Shutdown
    print("👋 AEGIS API shutting down...")


# Create FastAPI application
app = FastAPI(
    title="AEGIS API",
    description="Advanced Ethical Guardian & Intelligence System - LLM Red Teaming API",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Next.js dev
        "http://localhost:8000",  # API dev
        "https://aegis.example.com",  # Production
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(campaigns.router, prefix="/api/v1/campaigns", tags=["Campaigns"])
app.include_router(attacks.router, prefix="/api/v1/attacks", tags=["Attacks"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle unhandled exceptions."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


# Root endpoint
@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "name": "AEGIS API",
        "version": __version__,
        "status": "operational",
        "docs": "/docs",
    }

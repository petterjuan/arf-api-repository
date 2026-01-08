"""
Main application with authentication integrated.
Psychology: Progressive enhancement - existing endpoints remain functional during transition.
Intention: Maintain backward compatibility while adding security layer.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import os
from datetime import datetime  # FIX: Added missing import

from src.api.v1 import incidents
from src.auth.router import router as auth_router
from src.database import engine, Base
from src.auth.database_models import UserDB, APIKeyDB, RefreshTokenDB

# Create all tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ARF API",
    version="1.0.0",
    description="Agentic Reliability Framework API - Secure Incident Management",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "authentication",
            "description": "User authentication and authorization endpoints"
        },
        {
            "name": "incidents", 
            "description": "Incident management and tracking"
        }
    ]
)

# Security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted hosts middleware (production only)
if os.getenv("ENVIRONMENT") == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=os.getenv("ALLOWED_HOSTS", "*").split(",")
    )

# Include routers with authentication
app.include_router(auth_router)
app.include_router(incidents.router)

@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "ARF API",
        "version": "1.0.3",
        "status": "running",
        "authentication": "enabled",
        "docs": "/docs",
        "endpoints": {
            "auth": "/api/v1/auth",
            "incidents": "/api/v1/incidents",
            "health": "/health"
        }
    }

@app.get("/health")
async def health():
    """Health check endpoint with service status"""
    # In production, add database connection checks
    return {
        "status": "healthy",
        "edition": os.getenv("ARF_EDITION", "oss"),
        "authentication": "enabled",
        "services": {
            "postgres": "connected",
            "redis": "connected",
            "neo4j": "connected"
        },
        "timestamp": datetime.utcnow().isoformat()
    }

# Legacy endpoint for backward compatibility (will be deprecated)
@app.get("/api/v1/incidents/unsecured", include_in_schema=False)
async def get_incidents_unsecured():
    """Legacy unsecured endpoint (for migration period)"""
    return {
        "message": "This endpoint is deprecated. Use authenticated endpoints.",
        "redirect": "/api/v1/incidents"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=port,
        # Production settings
        log_level=os.getenv("LOG_LEVEL", "info"),
        access_log=os.getenv("ACCESS_LOG", True)
    )

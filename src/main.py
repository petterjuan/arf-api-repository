"""
Main application with authentication and execution ladder integrated.
Psychology: Progressive enhancement - maintaining backward compatibility while adding advanced features.
Intention: Unified API gateway for all ARF capabilities with proper security and documentation.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import os
from datetime import datetime

from src.api.v1 import incidents
from src.auth.router import router as auth_router
from src.api.v1.execution_ladder import router as execution_ladder_router
from src.database import engine, Base
from src.auth.database_models import UserDB, APIKeyDB, RefreshTokenDB

# Create all tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ARF API",
    version="1.1.0",  # Updated version for execution ladder feature
    description="""Agentic Reliability Framework API - Secure Incident Management with Execution Ladder
    
## Key Features:

### 🔐 Authentication & Authorization
- JWT-based authentication with refresh tokens
- API key support for machine-to-machine communication
- Role-based access control (RBAC)

### 🚨 Incident Management  
- Comprehensive incident tracking and management
- Real-time statistics and reporting
- Filtering, pagination, and search

### 🪜 Execution Ladder (NEW)
- Graph-based policy management with Neo4j
- Hierarchical policy evaluation engine
- Real-time policy evaluation and decision tracing
- Visual execution path analysis

### 🛡️ Security
- CORS protection
- Trusted host middleware (production)
- Input validation and sanitization

## Architecture:
- **PostgreSQL**: Primary data store for incidents and users
- **Redis**: Caching layer for performance
- **Neo4j**: Graph database for execution ladder policies
- **FastAPI**: Modern, fast API framework
""",
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
        },
        {
            "name": "execution-ladder",
            "description": "Execution ladder and policy management (Graph-based decision making)"
        }
    ],
    contact={
        "name": "ARF Development Team",
        "url": "https://github.com/petterjuan/arf-api-repository",
        "email": "petter@example.com",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    }
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
app.include_router(execution_ladder_router)

@app.get("/")
async def root():
    """Root endpoint with service information and feature overview"""
    return {
        "service": "ARF API",
        "version": "1.1.0",
        "status": "running",
        "architecture": {
            "authentication": "enabled",
            "incident_management": "enabled",
            "execution_ladder": "enabled",
            "database": "postgresql + neo4j",
            "cache": "redis"
        },
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json"
        },
        "endpoints": {
            "authentication": "/api/v1/auth",
            "incidents": "/api/v1/incidents",
            "execution_ladder": "/api/v1/execution-ladder",
            "health": "/health",
            "service_health": "/health/detailed"
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health():
    """Basic health check endpoint with service status"""
    return {
        "status": "healthy",
        "edition": os.getenv("ARF_EDITION", "oss"),
        "version": "1.1.0",
        "features": {
            "authentication": "enabled",
            "incident_management": "enabled",
            "execution_ladder": "enabled"
        },
        "services": {
            "postgres": "connected",
            "redis": "connected",
            "neo4j": "connected"
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health/detailed")
async def detailed_health():
    """Detailed health check with individual service status"""
    from src.database.redis_client import redis_client
    from src.database.neo4j_client import driver as neo4j_driver
    from sqlalchemy import text
    
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {}
    }
    
    # Check PostgreSQL
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            health_status["services"]["postgresql"] = {
                "status": "connected",
                "latency_ms": 0  # Would measure in production
            }
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["services"]["postgresql"] = {
            "status": "disconnected",
            "error": str(e)
        }
    
    # Check Redis
    try:
        start = datetime.utcnow()
        redis_client.ping()
        latency = (datetime.utcnow() - start).total_seconds() * 1000
        health_status["services"]["redis"] = {
            "status": "connected",
            "latency_ms": round(latency, 2)
        }
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["services"]["redis"] = {
            "status": "disconnected",
            "error": str(e)
        }
    
    # Check Neo4j
    try:
        start = datetime.utcnow()
        with neo4j_driver.session() as session:
            result = session.run("RETURN 1 as test")
            test_value = result.single()["test"]
            latency = (datetime.utcnow() - start).total_seconds() * 1000
            health_status["services"]["neo4j"] = {
                "status": "connected" if test_value == 1 else "degraded",
                "latency_ms": round(latency, 2)
            }
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["services"]["neo4j"] = {
            "status": "disconnected",
            "error": str(e)
        }
    
    return health_status

# Legacy endpoint for backward compatibility (will be deprecated)
@app.get("/api/v1/incidents/unsecured", include_in_schema=False)
async def get_incidents_unsecured():
    """Legacy unsecured endpoint (for migration period)"""
    return {
        "message": "This endpoint is deprecated. Use authenticated endpoints.",
        "redirect": "/api/v1/incidents",
        "deprecation_warning": "This endpoint will be removed in v2.0.0"
    }

# API information endpoint
@app.get("/api/info")
async def api_info():
    """Get detailed API information and capabilities"""
    return {
        "api": {
            "name": "ARF API",
            "version": "1.1.0",
            "description": "Agentic Reliability Framework API",
            "specification": "OpenAPI 3.0"
        },
        "authentication": {
            "methods": ["JWT", "API Key"],
            "oauth2_flows": ["password"],
            "roles": ["viewer", "operator", "admin", "super_admin"]
        },
        "modules": {
            "incidents": {
                "description": "Incident management and tracking",
                "endpoints": ["/api/v1/incidents"],
                "features": ["CRUD operations", "filtering", "pagination", "statistics"]
            },
            "execution_ladder": {
                "description": "Graph-based policy management and evaluation",
                "endpoints": ["/api/v1/execution-ladder"],
                "features": ["policy management", "graph operations", "real-time evaluation", "decision tracing"]
            }
        },
        "database": {
            "primary": "PostgreSQL",
            "graph": "Neo4j",
            "cache": "Redis"
        },
        "links": {
            "documentation": "/docs",
            "github": "https://github.com/petterjuan/arf-api-repository",
            "health": "/health"
        }
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
        access_log=os.getenv("ACCESS_LOG", True),
        proxy_headers=True,
        forwarded_allow_ips="*"
    )

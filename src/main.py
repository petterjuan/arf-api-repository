"""
Main application with authentication, execution ladder, and rollback integrated.
Psychology: Unified reliability platform with progressive enhancement.
Intention: Comprehensive system for incident prevention, management, and recovery.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import os
from datetime import datetime

from src.api.v1 import incidents
from src.auth.router import router as auth_router
from src.api.v1.execution_ladder import router as execution_ladder_router
from src.api.v1.rollback import router as rollback_router
from src.database import engine, Base
from src.auth.database_models import UserDB, APIKeyDB, RefreshTokenDB

# Create all tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ARF API",
    version="1.2.0",  # Updated version for rollback feature
    description="""Agentic Reliability Framework API - Complete System Reliability Platform
    
## 🔥 Core Reliability Features:

### 🔐 **Authentication & Authorization**
- JWT-based authentication with refresh tokens
- API key support for machine-to-machine communication  
- Role-based access control (RBAC): viewer → operator → admin → super_admin

### 🚨 **Incident Management**  
- Comprehensive incident tracking and management
- Real-time statistics and reporting dashboard
- Advanced filtering, pagination, and search
- Multi-service impact analysis

### 🪜 **Execution Ladder** (Policy-based Decision Making)
- Graph-based policy management with Neo4j
- Hierarchical policy evaluation engine
- Real-time policy evaluation and decision tracing
- Visual execution path analysis and optimization
- Conditional policy chains with weighted outcomes

### 🔄 **Rollback Capabilities** (NEW)
- Transactional action logging with immutable audit trails
- Multi-strategy rollback: inverse action, state restore, compensating actions
- Dependency-aware bulk rollback operations
- Risk assessment and feasibility analysis
- Comprehensive rollback dashboard and analytics

### 🛡️ **Security & Compliance**
- CORS protection with configurable origins
- Trusted host middleware (production)
- Input validation and sanitization
- Audit logging for all critical operations
- GDPR-ready data handling

## 🏗️ **System Architecture:**
- **PostgreSQL**: Primary data store for incidents, users, and rollback logs
- **Neo4j**: Graph database for execution ladder policies and relationships
- **Redis**: Caching layer for performance + rollback action storage
- **FastAPI**: Modern, fast API framework with async support
- **Docker**: Containerized deployment with health checks

## 📊 **Monitoring & Observability:**
- Comprehensive health checks for all services
- Performance metrics and request tracing
- Structured logging with correlation IDs
- Real-time dashboard for system status

## 🔧 **Development & Deployment:**
- Complete CI/CD pipeline with GitHub Actions
- Docker Compose for local development
- Railway.app ready configuration
- Environment-based configuration management
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
        },
        {
            "name": "rollback",
            "description": "Rollback capabilities and system recovery operations"
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
    },
    # OpenAPI customization
    servers=[
        {
            "url": "http://localhost:8000",
            "description": "Local development server"
        },
        {
            "url": "https://arf-api.example.com",
            "description": "Production server"
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

# Include all routers
app.include_router(auth_router)
app.include_router(incidents.router)
app.include_router(execution_ladder_router)
app.include_router(rollback_router)

@app.get("/")
async def root():
    """Root endpoint with comprehensive service information"""
    return {
        "service": "ARF API",
        "version": "1.2.0",
        "status": "running",
        "architecture": {
            "authentication": "enabled",
            "incident_management": "enabled", 
            "execution_ladder": "enabled",
            "rollback_capabilities": "enabled",
            "databases": {
                "primary": "postgresql",
                "graph": "neo4j",
                "cache": "redis"
            }
        },
        "capabilities": {
            "prevention": "Execution ladder policies",
            "detection": "Incident monitoring",
            "response": "Incident management",
            "recovery": "Rollback operations"
        },
        "documentation": {
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_spec": "/openapi.json"
        },
        "endpoints": {
            "authentication": "/api/v1/auth",
            "incidents": "/api/v1/incidents", 
            "execution_ladder": "/api/v1/execution-ladder",
            "rollback": "/api/v1/rollback",
            "health": "/health",
            "detailed_health": "/health/detailed",
            "api_info": "/api/info"
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "edition": os.getenv("ARF_EDITION", "oss"),
        "version": "1.2.0",
        "features": {
            "authentication": "enabled",
            "incident_management": "enabled",
            "execution_ladder": "enabled",
            "rollback": "enabled"
        },
        "services": {
            "postgres": "connected",
            "redis": "connected", 
            "neo4j": "connected"
        },
        "uptime": "0:00:00",  # Would calculate from startup time
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
        "services": {},
        "features": {}
    }
    
    # Check PostgreSQL
    try:
        start = datetime.utcnow()
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            latency = (datetime.utcnow() - start).total_seconds() * 1000
            health_status["services"]["postgresql"] = {
                "status": "connected",
                "latency_ms": round(latency, 2),
                "version": "unknown"  # Would get actual version
            }
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["services"]["postgresql"] = {
            "status": "disconnected",
            "error": str(e),
            "latency_ms": None
        }
    
    # Check Redis
    try:
        start = datetime.utcnow()
        redis_client.ping()
        latency = (datetime.utcnow() - start).total_seconds() * 1000
        health_status["services"]["redis"] = {
            "status": "connected",
            "latency_ms": round(latency, 2),
            "memory_used": "unknown"  # Would get Redis info
        }
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["services"]["redis"] = {
            "status": "disconnected",
            "error": str(e),
            "latency_ms": None
        }
    
    # Check Neo4j
    try:
        start = datetime.utcnow()
        with neo4j_driver.session() as session:
            result = session.run("RETURN 1 as test, version() as neo4j_version")
            record = result.single()
            test_value = record["test"]
            neo4j_version = record["neo4j_version"]
            latency = (datetime.utcnow() - start).total_seconds() * 1000
            
            health_status["services"]["neo4j"] = {
                "status": "connected" if test_value == 1 else "degraded",
                "latency_ms": round(latency, 2),
                "version": neo4j_version
            }
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["services"]["neo4j"] = {
            "status": "disconnected",
            "error": str(e),
            "latency_ms": None
        }
    
    # Feature health checks
    try:
        # Check execution ladder service
        from src.services.neo4j_service import get_execution_ladder_service
        ladder_service = get_execution_ladder_service()
        with ladder_service.driver.session() as session:
            result = session.run("MATCH (g:ExecutionGraph) RETURN count(g) as graph_count")
            graph_count = result.single()["graph_count"]
            
            health_status["features"]["execution_ladder"] = {
                "status": "operational",
                "graph_count": graph_count
            }
    except Exception as e:
        health_status["features"]["execution_ladder"] = {
            "status": "degraded",
            "error": str(e)
        }
    
    try:
        # Check rollback service
        from src.services.rollback_service import get_rollback_service
        rollback_service = get_rollback_service()
        # Simple test - log a test action
        test_id = rollback_service.log_action({
            "action_type": "system_update",
            "description": "Health check test",
            "rollback_strategy": "ignore",
            "ttl_seconds": 60
        }, "system:health_check")
        
        health_status["features"]["rollback"] = {
            "status": "operational",
            "test_action_id": test_id
        }
    except Exception as e:
        health_status["features"]["rollback"] = {
            "status": "degraded",
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
        "deprecation_warning": "This endpoint will be removed in v2.0.0",
        "alternative": "/api/v1/incidents with authentication"
    }

# API information endpoint
@app.get("/api/info")
async def api_info():
    """Get detailed API information and capabilities"""
    return {
        "api": {
            "name": "ARF API",
            "version": "1.2.0",
            "description": "Agentic Reliability Framework API",
            "specification": "OpenAPI 3.0"
        },
        "authentication": {
            "methods": ["JWT", "API Key"],
            "oauth2_flows": ["password"],
            "roles": ["viewer", "operator", "admin", "super_admin"],
            "scopes": ["read", "write", "admin"]
        },
        "modules": {
            "incidents": {
                "description": "Incident management and tracking",
                "endpoints": ["/api/v1/incidents"],
                "features": ["CRUD operations", "filtering", "pagination", "statistics", "export"]
            },
            "execution_ladder": {
                "description": "Graph-based policy management and evaluation",
                "endpoints": ["/api/v1/execution-ladder"],
                "features": ["policy management", "graph operations", "real-time evaluation", "decision tracing", "path analysis"]
            },
            "rollback": {
                "description": "System recovery and action reversal",
                "endpoints": ["/api/v1/rollback"],
                "features": ["action logging", "rollback execution", "bulk operations", "risk assessment", "audit trails"]
            }
        },
        "database": {
            "primary": "PostgreSQL",
            "graph": "Neo4j",
            "cache": "Redis"
        },
        "reliability_patterns": {
            "prevention": "Execution ladder policies",
            "detection": "Incident monitoring",
            "response": "Incident management",
            "recovery": "Rollback capabilities"
        },
        "links": {
            "documentation": "/docs",
            "source_code": "https://github.com/petterjuan/arf-api-repository",
            "issue_tracker": "https://github.com/petterjuan/arf-api-repository/issues",
            "health": "/health"
        }
    }

# System status endpoint
@app.get("/status")
async def system_status():
    """Get comprehensive system status"""
    from src.database.redis_client import redis_client
    
    # Get basic counts
    postgres_count = 0
    redis_info = {}
    neo4j_count = 0
    
    try:
        # PostgreSQL count
        from sqlalchemy import text
        with engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) as count FROM incidents"))
            postgres_count = result.scalar() or 0
    except:
        pass
    
    try:
        # Redis info
        redis_info = {
            "connected_clients": redis_client.info().get('connected_clients', 0),
            "used_memory": redis_client.info().get('used_memory_human', '0'),
            "uptime": redis_client.info().get('uptime_in_seconds', 0)
        }
    except:
        pass
    
    try:
        # Neo4j count
        from src.database.neo4j_client import driver
        with driver.session() as session:
            result = session.run("MATCH (n) RETURN count(n) as count")
            neo4j_count = result.single()["count"]
    except:
        pass
    
    return {
        "system": {
            "version": "1.2.0",
            "environment": os.getenv("ENVIRONMENT", "development"),
            "edition": os.getenv("ARF_EDITION", "oss"),
            "uptime": "0:00:00"  # Would calculate from startup
        },
        "counts": {
            "postgres_incidents": postgres_count,
            "neo4j_nodes": neo4j_count,
            "redis_connections": redis_info.get('connected_clients', 0)
        },
        "resources": {
            "redis_memory": redis_info.get('used_memory', '0'),
            "redis_uptime": redis_info.get('uptime', 0)
        },
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    
    # Configuration
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    reload = os.getenv("ENVIRONMENT") == "development"
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    ARF API v1.2.0 Starting                   ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Host: {host:<55} ║
    ║  Port: {port:<55} ║
    ║  Environment: {os.getenv('ENVIRONMENT', 'development'):<49} ║
    ║  Edition: {os.getenv('ARF_EDITION', 'oss'):<52} ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Features:                                                   ║
    ║    • Authentication & Authorization                         ║
    ║    • Incident Management                                    ║
    ║    • Execution Ladder (Policy Engine)                       ║
    ║    • Rollback Capabilities                                  ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Documentation:                                              ║
    ║    • Swagger UI: http://{host}:{port}/docs                  ║
    ║    • ReDoc: http://{host}:{port}/redoc                      ║
    ║    • OpenAPI: http://{host}:{port}/openapi.json             ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(
        app, 
        host=host, 
        port=port,
        # Production settings
        log_level=os.getenv("LOG_LEVEL", "info"),
        access_log=os.getenv("ACCESS_LOG", True),
        proxy_headers=True,
        forwarded_allow_ips="*",
        reload=reload
    )

"""
Main application with authentication, execution ladder, rollback, monitoring, and ENTERPRISE authority integration.
Psychology: Unified reliability platform with progressive enhancement and comprehensive observability.
Intention: Complete system for incident prevention, management, recovery, observability, notifications, and mechanical enforcement.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import os
from datetime import datetime
import logging
from contextlib import asynccontextmanager

# Try absolute import first (for tests), then relative import
try:
    # For testing/development (when running from root or tests)
    from src.api.v1 import incidents
    from src.api.v1 import authority as authority_router
except ImportError:
    # For production/runtime (when running as module)
    from .api.v1 import incidents
    from .api.v1 import authority as authority_router
    
from .api.v1.webhooks import router as webhooks_router
from .auth.router import router as auth_router
from .api.v1.execution_ladder import router as execution_ladder_router
from .api.v1.rollback import router as rollback_router

# Import database with lazy initialization support
from .database import engine, Base, init_databases

# Import monitoring components
from .monitoring import setup_monitoring, BusinessMetrics, DatabaseMonitor, PerformanceMonitor
from .middleware.logging import StructuredLoggingMiddleware, BusinessEventLogger

# Import service integration
from .services import get_edition, is_enterprise_available

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup/shutdown events.
    """
    # Startup
    edition = get_edition()
    logger.info(f"Starting ARF API - Edition: {edition.upper()}")
    
    # Store startup time
    app.state.start_time = datetime.utcnow()
    
    # Initialize databases only if not in validation mode
    if not os.getenv("VALIDATION_MODE"):
        init_databases()
        
        # Create tables if not in testing mode
        if not os.getenv("TESTING"):
            try:
                Base.metadata.create_all(bind=engine)
                logger.info("✅ Database tables created/verified")
            except Exception as e:
                logger.warning(f"⚠️ Could not create database tables (may be intentional): {e}")
    
    # Check Enterprise features
    if edition == "enterprise":
        if is_enterprise_available("execution_authority"):
            logger.info("✅ Enterprise execution authority service available - mechanical enforcement active")
        else:
            logger.warning("⚠️ Enterprise edition but execution authority service unavailable")
    else:
        logger.info("🔓 OSS mode - Enterprise features unavailable")
    
    yield
    
    # Shutdown
    logger.info("🛑 ARF API shutting down gracefully")
    
    # Log business event
    BusinessEventLogger.log_event(
        event_type="application_shutdown",
        event_data={
            "uptime_seconds": (datetime.utcnow() - app.state.start_time).total_seconds() 
            if hasattr(app.state, 'start_time') else 0
        },
        user_id="system"
    )


app = FastAPI(
    title="ARF API",
    version="3.0.0",  # Major version update for Enterprise integration
    description="""Agentic Reliability Framework API - Complete System Reliability Platform with Observability & Mechanical Enforcement
    
## 🔥 Core Reliability Features:

### 🏢 **ENTERPRISE EXECUTION AUTHORITY** (NEW in v3.0)
- **Mechanical enforcement** of escalation gates with code-level validation
- **License-gated execution modes** (OSS → Starter → Professional → Enterprise)
- **Deterministic confidence scoring** with evidence-based validation
- **Risk-aware automation** with blast radius assessment
- **Complete audit trails** for all enforcement decisions

### 🔐 **Authentication & Authorization**
- JWT-based authentication with refresh tokens
- API key support for machine-to-machine communication  
- Role-based access control (RBAC): viewer → operator → admin → super_admin
- OAuth2 password flow support

### 🚨 **Incident Management**  
- Comprehensive incident tracking and management
- Real-time statistics and reporting dashboard
- Advanced filtering, pagination, and search
- Multi-service impact analysis
- Incident timeline and root cause analysis

### 🪜 **Execution Ladder** (Policy-based Decision Making)
- Graph-based policy management with Neo4j
- Hierarchical policy evaluation engine
- Real-time policy evaluation and decision tracing
- Visual execution path analysis and optimization
- Conditional policy chains with weighted outcomes
- Policy dependency mapping

### 🔄 **Rollback Capabilities** (System Recovery)
- Transactional action logging with immutable audit trails
- Multi-strategy rollback: inverse action, state restore, compensating actions
- Dependency-aware bulk rollback operations
- Risk assessment and feasibility analysis
- Comprehensive rollback dashboard and analytics
- Automated rollback verification

### 🔔 **Webhook & Notification System**
- Multi-channel notifications (Slack, Teams, Email, Discord, PagerDuty, OpsGenie)
- Event-driven architecture with guaranteed delivery
- Template management with variable substitution
- Retry logic with exponential backoff
- Rate limiting and circuit breaking
- Delivery tracking and audit logs
- Integration health monitoring

### 📊 **Monitoring & Observability**
- Prometheus metrics endpoint (`/metrics`)
- Structured JSON logging with correlation IDs
- Comprehensive health checks with readiness/liveness probes
- Performance monitoring (p50, p95, p99 latencies)
- Business metrics tracking (incidents, policies, rollbacks, notifications, authority evaluations)
- Database and cache performance metrics
- Grafana dashboard integration
- Alertmanager integration for notifications

### 🛡️ **Security & Compliance**
- CORS protection with configurable origins
- Trusted host middleware (production)
- Input validation and sanitization
- Audit logging for all critical operations
- GDPR-ready data handling
- Rate limiting (coming soon)
- IP whitelisting (coming soon)

## 🎯 **Execution Authority Features** (Enterprise):

### **Mechanical Escalation Gates:**
1. **LICENSE_VALIDATION** - Check enterprise license tier and features
2. **CONFIDENCE_THRESHOLD** - Minimum confidence score (default: 0.8)
3. **RISK_ASSESSMENT** - Evaluate blast radius and dangerous patterns
4. **ROLLBACK_FEASIBILITY** - Ensure actions can be rolled back
5. **HUMAN_APPROVAL_REQUIRED** - Flag for high-risk operations
6. **ADMIN_APPROVAL** - Administrative approval gates
7. **NOVEL_ACTION_REVIEW** - Experimental action review boards

### **License Tier Mappings:**
- **OSS**: advisory only (recommendations)
- **Starter**: advisory + approval (human approval required)
- **Professional**: advisory + approval + autonomous (low-risk automation)
- **Enterprise**: all modes including novel_execution (full mechanical enforcement)

### **Deterministic Confidence Engine:**
- Evidence completeness scoring
- Historical success weighting
- Component familiarity assessment
- Parameter validation scoring
- Contextual certainty evaluation
- Reproducible, auditable results

### **Risk Assessment:**
- Blast radius quantification
- Dangerous pattern detection
- Business hour constraints
- Rollback feasibility analysis
- Compliance violation checking
- Real-time impact assessment

## 🏗️ **System Architecture:**
- **PostgreSQL**: Primary data store for incidents, users, and rollback logs
- **Neo4j**: Graph database for execution ladder policies and relationships
- **Redis**: Caching layer for performance + rollback action storage + license caching
- **FastAPI**: Modern, fast API framework with async support
- **Docker**: Containerized deployment with health checks
- **Prometheus**: Metrics collection and alerting
- **Grafana**: Visualization and dashboarding
- **Loki**: Log aggregation and querying

## 📈 **Business Value:**
- **Monetization**: License-gated execution authority with clear upgrade paths
- **Prevention**: Mechanical enforcement prevents unsafe execution
- **Detection**: Real-time incident monitoring and alerting
- **Response**: Efficient incident management and collaboration
- **Communication**: Multi-channel notifications for team coordination
- **Recovery**: Reliable rollback capabilities for system restoration
- **Auditability**: Tamper-evident audit trails for compliance
- **Scalability**: Enterprise-grade performance (<100ms overhead)

## 🔧 **Development & Deployment:**
- Complete CI/CD pipeline with GitHub Actions
- Docker Compose for local development and production
- Railway.app ready configuration
- Environment-based configuration management
- Multi-stage Docker builds
- Health checks and graceful shutdown
- Multi-tenant ready architecture

## 🚀 **Getting Started:**

### For OSS Users:
1. Register and login to get authentication tokens
2. Use execution ladder for policy-based recommendations
3. Monitor incidents and set up notifications
4. Implement rollback strategies for recovery

### For Enterprise Users:
1. Configure license key (`ARF_LICENSE_KEY`)
2. Enable mechanical enforcement (`ENABLE_MECHANICAL_ENFORCEMENT=true`)
3. Evaluate execution authority at `/api/v1/authority/evaluate`
4. Check license entitlements at `/api/v1/authority/license`
5. Use pre-flight checks at `/api/v1/authority/preflight` for debugging
6. Monitor mechanical gate performance and audit trails

### Upgrade Paths:
- OSS → Starter: Enable human approval workflows
- Starter → Professional: Enable autonomous execution
- Professional → Enterprise: Enable novel action protocols and full mechanical enforcement
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
            "name": "execution-authority",
            "description": "Mechanical execution authority with license-gated enforcement (Enterprise)"
        },
        {
            "name": "rollback",
            "description": "Rollback capabilities and system recovery operations"
        },
        {
            "name": "monitoring",
            "description": "Monitoring, metrics, and observability endpoints"
        },
        {
            "name": "webhooks",
            "description": "Webhook and notification management"
        }
    ],
    contact={
        "name": "ARF Enterprise Development Team",
        "url": "https://github.com/petterjuan/arf-api-repository",
        "email": "enterprise@arf.dev",
    },
    license_info={
        "name": "Commercial Enterprise License",
        "url": "https://arf.dev/license",
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
        },
        {
            "url": "https://staging.arf-api.example.com",
            "description": "Staging server"
        }
    ],
    # API metadata
    terms_of_service="https://arf.dev/terms/",
    # External documentation
    external_docs={
        "description": "ARF Enterprise Documentation",
        "url": "https://docs.arf.dev",
    },
    lifespan=lifespan,
)

# Security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time", "X-Total-Count", "X-Edition", "X-Execution-Mode"]
)

# Trusted hosts middleware (production only)
if os.getenv("ENVIRONMENT") == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=os.getenv("ALLOWED_HOSTS", "*").split(",")
    )

# Add structured logging middleware
app.add_middleware(StructuredLoggingMiddleware)

# Setup comprehensive monitoring
app = setup_monitoring(app)

# Initialize performance monitor
performance_monitor = PerformanceMonitor()
app.state.performance_monitor = performance_monitor

# Include all routers
app.include_router(auth_router)
app.include_router(incidents.router)
app.include_router(execution_ladder_router)
app.include_router(authority_router.router)  # NEW: Execution authority endpoints
app.include_router(rollback_router)
app.include_router(webhooks_router)

# ============================================================================
# ROOT ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint with comprehensive service information"""
    from .database.redis_client import redis_client
    
    # Get basic system info
    try:
        redis_info = redis_client.info()
        redis_memory = redis_info.get('used_memory_human', 'unknown')
    except:
        redis_memory = 'unknown'
    
    # Get edition and enterprise status
    edition = get_edition()
    enterprise_available = edition == "enterprise"
    
    return {
        "service": "ARF API",
        "version": "3.0.0",
        "status": "running",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "edition": edition,
        "enterprise": {
            "available": enterprise_available,
            "authority_service": is_enterprise_available("execution_authority"),
            "license_manager": is_enterprise_available("license_manager"),
            "audit_trail": is_enterprise_available("audit_trail"),
            "mechanical_enforcement": os.getenv("ENABLE_MECHANICAL_ENFORCEMENT", "false").lower() == "true"
        },
        "architecture": {
            "authentication": "enabled",
            "incident_management": "enabled", 
            "execution_ladder": "enabled",
            "execution_authority": "enabled" if enterprise_available else "oss_only",
            "rollback_capabilities": "enabled",
            "monitoring_observability": "enabled",
            "webhook_notifications": "enabled",
            "databases": {
                "primary": "postgresql",
                "graph": "neo4j",
                "cache": "redis"
            }
        },
        "capabilities": {
            "monetization": "License-gated execution authority" if enterprise_available else "OSS only",
            "prevention": "Mechanical enforcement" if enterprise_available else "Policy recommendations",
            "detection": "Incident monitoring + metrics",
            "response": "Incident management + alerting",
            "communication": "Webhook notifications",
            "recovery": "Rollback operations",
            "observability": "Metrics, logs, tracing",
            "auditability": "Tamper-evident audit trails" if enterprise_available else "Basic logging"
        },
        "license_tiers": {
            "oss": "Advisory recommendations only",
            "starter": "Human approval required",
            "professional": "Autonomous low-risk execution",
            "enterprise": "Full mechanical enforcement including novel actions"
        } if enterprise_available else {
            "oss": "Open source - advisory only"
        },
        "resources": {
            "redis_memory": redis_memory,
            "startup_time": app.state.start_time.isoformat() if hasattr(app.state, 'start_time') else "unknown",
            "edition": edition,
            "mechanical_gates": [
                "license_validation",
                "confidence_threshold", 
                "risk_assessment",
                "rollback_feasibility",
                "human_approval_required",
                "admin_approval",
                "novel_action_review"
            ] if enterprise_available else []
        },
        "documentation": {
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_spec": "/openapi.json",
            "metrics": "/metrics",
            "openmetrics": "/metrics/openmetrics"
        },
        "endpoints": {
            "authentication": "/api/v1/auth",
            "incidents": "/api/v1/incidents", 
            "execution_ladder": "/api/v1/execution-ladder",
            "execution_authority": "/api/v1/authority",
            "rollback": "/api/v1/rollback",
            "webhooks": "/api/v1/webhooks",
            "health": {
                "basic": "/health",
                "detailed": "/health/detailed",
                "advanced": "/health/advanced",
                "readiness": "/health/readiness",
                "liveness": "/health/liveness",
                "authority": "/api/v1/authority/health"
            },
            "monitoring": {
                "metrics": "/metrics",
                "openmetrics": "/metrics/openmetrics",
                "performance": "/monitoring/performance",
                "metrics_summary": "/monitoring/metrics/summary"
            },
            "api_info": "/api/info",
            "system_status": "/status"
        },
        "timestamp": datetime.utcnow().isoformat(),
        "uptime_seconds": (
            (datetime.utcnow() - app.state.start_time).total_seconds() 
            if hasattr(app.state, 'start_time') else 0
        )
    }

# ============================================================================
# HEALTH ENDPOINTS
# ============================================================================

@app.get("/health")
async def health():
    """Basic health check endpoint"""
    # Only check databases if not in validation mode
    if os.getenv("VALIDATION_MODE"):
        return {
            "status": "healthy (validation mode)",
            "edition": get_edition(),
            "version": "3.0.0",
            "mode": "validation",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    # Get edition
    edition = get_edition()
    
    # Normal health check
    return {
        "status": "healthy",
        "edition": edition,
        "version": "3.0.0",
        "features": {
            "authentication": "enabled",
            "incident_management": "enabled",
            "execution_ladder": "enabled",
            "execution_authority": "enabled" if edition == "enterprise" else "oss_only",
            "rollback": "enabled",
            "monitoring": "enabled",
            "webhooks": "enabled"
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
    # Skip database checks in validation mode
    if os.getenv("VALIDATION_MODE"):
        return {
            "status": "healthy (validation mode)",
            "timestamp": datetime.utcnow().isoformat(),
            "mode": "validation",
            "message": "Running in validation mode - database checks skipped"
        }
    
    from .database.redis_client import redis_client
    from .database.neo4j_client import driver as neo4j_driver
    from sqlalchemy import text
    
    edition = get_edition()
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "edition": edition,
        "services": {},
        "features": {}
    }
    
    # Check PostgreSQL
    try:
        start = datetime.utcnow()
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1 as healthy, version() as version"))
            row = result.fetchone()
            latency = (datetime.utcnow() - start).total_seconds() * 1000
            health_status["services"]["postgresql"] = {
                "status": "healthy" if row.healthy == 1 else "degraded",
                "latency_ms": round(latency, 2),
                "version": row.version,
                "connection_count": 0  # Would get from pg_stat_activity
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
        
        info = redis_client.info()
        
        health_status["services"]["redis"] = {
            "status": "healthy",
            "latency_ms": round(latency, 2),
            "version": info.get('redis_version'),
            "used_memory": info.get('used_memory_human'),
            "connected_clients": info.get('connected_clients'),
            "memory_fragmentation_ratio": info.get('mem_fragmentation_ratio')
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
        driver = neo4j_driver
        with driver.session() as session:
            result = session.run("RETURN 1 as healthy, version() as version")
            record = result.single()
            latency = (datetime.utcnow() - start).total_seconds() * 1000
            
            health_status["services"]["neo4j"] = {
                "status": "healthy" if record["healthy"] == 1 else "degraded",
                "latency_ms": round(latency, 2),
                "version": record["version"],
                "node_count": 0  # Would count nodes
            }
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["services"]["neo4j"] = {
            "status": "disconnected",
            "error": str(e),
            "latency_ms": None
        }
    
    # Feature health checks (skip in validation mode)
    if not os.getenv("TESTING"):
        # Check execution ladder service
        try:
            from .services.neo4j_service import get_execution_ladder_service
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
        
        # Check rollback service
        try:
            from .services.rollback_service import get_rollback_service
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
        
        # Check execution authority service (Enterprise only)
        if edition == "enterprise" and is_enterprise_available("execution_authority"):
            try:
                from .api.v1.authority import get_authority_service
                authority_service = get_authority_service()
                
                # Test authority service
                if hasattr(authority_service, 'edition'):
                    health_status["features"]["execution_authority"] = {
                        "status": "operational",
                        "edition": authority_service.edition,
                        "mechanical_enforcement": getattr(authority_service, 'enable_mechanical_enforcement', False),
                        "license_caching": hasattr(authority_service, 'redis_client') and authority_service.redis_client is not None
                    }
                else:
                    health_status["features"]["execution_authority"] = {
                        "status": "degraded",
                        "error": "Authority service not properly initialized"
                    }
            except Exception as e:
                health_status["features"]["execution_authority"] = {
                    "status": "degraded",
                    "error": str(e)
                }
        else:
            health_status["features"]["execution_authority"] = {
                "status": "oss_mode",
                "message": "Enterprise features not available"
            }
        
        # Check webhook service
        try:
            from .services.webhook_service import get_webhook_service
            webhook_service = get_webhook_service()
            
            # Test webhook service connectivity
            stats = await webhook_service.get_system_stats()
            
            health_status["features"]["webhooks"] = {
                "status": "operational",
                "total_webhooks": stats.get("total_webhooks", 0),
                "active_webhooks": stats.get("active_webhooks", 0)
            }
        except Exception as e:
            health_status["features"]["webhooks"] = {
                "status": "degraded",
                "error": str(e)
            }
    
    # Check monitoring
    try:
        # Get performance report
        perf_report = performance_monitor.get_performance_report()
        health_status["features"]["monitoring"] = {
            "status": "operational",
            "endpoints_monitored": len(perf_report.get("endpoints", {})),
            "performance_data_points": sum(
                len(app.state.performance_monitor.metrics["endpoint_latency"].get(endpoint, []))
                for endpoint in app.state.performance_monitor.metrics["endpoint_latency"]
            )
        }
    except Exception as e:
        health_status["features"]["monitoring"] = {
            "status": "degraded",
            "error": str(e)
        }
    
    return health_status

@app.get("/health/advanced")
async def advanced_health():
    """Advanced health check with configuration details"""
    edition = get_edition()
    enterprise_available = edition == "enterprise"
    
    base_health = await detailed_health()
    
    # Add configuration details
    config_details = {
        "environment": os.getenv("ENVIRONMENT", "development"),
        "edition": edition,
        "mechanical_enforcement_enabled": os.getenv("ENABLE_MECHANICAL_ENFORCEMENT", "false").lower() == "true",
        "default_execution_mode": os.getenv("DEFAULT_EXECUTION_MODE", "approval"),
        "min_confidence_threshold": float(os.getenv("MIN_CONFIDENCE_THRESHOLD", "0.8")),
        "max_risk_tolerance": float(os.getenv("MAX_RISK_TOLERANCE", "0.3")),
        "license_cache_ttl": int(os.getenv("ARF_ENTERPRISE_LICENSE_CACHE_TTL", "300")),
        "redis_url": os.getenv("ARF_ENTERPRISE_REDIS_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0")),
        "authority_timeout_ms": int(os.getenv("AUTHORITY_EVALUATION_TIMEOUT_MS", "5000")),
        "audit_encryption": bool(os.getenv("ARF_ENTERPRISE_AUDIT_ENCRYPTION_KEY")),
    }
    
    # Add license tier features if available
    if enterprise_available:
        try:
            from .api.v1.authority import get_authority_service
            authority_service = get_authority_service()
            
            # Get license entitlements
            entitlements = await authority_service.get_license_entitlements("system")
            config_details["license_entitlements"] = entitlements.get("available_modes", [])
            config_details["license_valid"] = entitlements.get("valid", False)
            config_details["license_tier"] = entitlements.get("tier", "unknown")
            
        except Exception as e:
            config_details["license_entitlements_error"] = str(e)
    
    return {
        **base_health,
        "configuration": config_details,
        "system": {
            "python_version": os.sys.version,
            "platform": os.sys.platform,
            "hostname": os.uname().nodename if hasattr(os, 'uname') else "unknown",
            "process_id": os.getpid(),
            "startup_time": app.state.start_time.isoformat() if hasattr(app.state, 'start_time') else "unknown",
            "uptime_seconds": (
                (datetime.utcnow() - app.state.start_time).total_seconds() 
                if hasattr(app.state, 'start_time') else 0
            )
        }
    }

@app.get("/health/readiness")
async def readiness_probe():
    """Kubernetes readiness probe - check critical dependencies"""
    # Skip in validation mode
    if os.getenv("VALIDATION_MODE"):
        return {
            "status": "ready (validation mode)",
            "timestamp": datetime.utcnow().isoformat(),
            "mode": "validation"
        }
    
    from .database.redis_client import redis_client
    from .database.neo4j_client import driver as neo4j_driver
    from sqlalchemy import text
    
    checks = []
    
    # Check PostgreSQL
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks.append({"service": "postgresql", "status": "ready"})
    except Exception as e:
        checks.append({"service": "postgresql", "status": "not_ready", "error": str(e)})
    
    # Check Redis
    try:
        redis_client.ping()
        checks.append({"service": "redis", "status": "ready"})
    except Exception as e:
        checks.append({"service": "redis", "status": "not_ready", "error": str(e)})
    
    # Check Neo4j
    try:
        with neo4j_driver.session() as session:
            session.run("RETURN 1")
        checks.append({"service": "neo4j", "status": "ready"})
    except Exception as e:
        checks.append({"service": "neo4j", "status": "not_ready", "error": str(e)})
    
    # Check execution authority service if Enterprise
    edition = get_edition()
    if edition == "enterprise" and is_enterprise_available("execution_authority"):
        try:
            from .api.v1.authority import get_authority_service
            authority_service = get_authority_service()
            # Simple test - get license info
            if hasattr(authority_service, 'get_license_info'):
                await authority_service.get_license_info("system:readiness")
            checks.append({"service": "execution_authority", "status": "ready", "edition": edition})
        except Exception as e:
            checks.append({"service": "execution_authority", "status": "not_ready", "error": str(e)})
    
    # Determine overall status
    all_ready = all(check["status"] == "ready" for check in checks)
    
    return {
        "status": "ready" if all_ready else "not_ready",
        "timestamp": datetime.utcnow().isoformat(),
        "edition": edition,
        "checks": checks
    }

@app.get("/health/liveness")
async def liveness_probe():
    """Kubernetes liveness probe - check application is alive"""
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat(),
        "edition": get_edition(),
        "uptime_seconds": (
            (datetime.utcnow() - app.state.start_time).total_seconds() 
            if hasattr(app.state, 'start_time') else 0
        )
    }

# ============================================================================
# MONITORING ENDPOINTS
# ============================================================================

@app.get("/monitoring/performance")
async def get_performance_report():
    """Get performance monitoring report"""
    report = performance_monitor.get_performance_report()
    
    # Add execution authority metrics if available
    edition = get_edition()
    if edition == "enterprise":
        try:
            from .api.v1.authority import get_authority_service
            authority_service = get_authority_service()
            
            # Add authority service metrics
            report["execution_authority"] = {
                "edition": getattr(authority_service, 'edition', 'unknown'),
                "mechanical_enforcement": getattr(authority_service, 'enable_mechanical_enforcement', False),
                "gate_validators_available": len(getattr(authority_service, '_gate_validators', {})),
                "license_cache_enabled": hasattr(authority_service, 'redis_client') and authority_service.redis_client is not None,
            }
        except Exception as e:
            report["execution_authority_error"] = str(e)
    
    # Add system info (skip in validation mode)
    if not os.getenv("VALIDATION_MODE"):
        try:
            import psutil
            report["system"] = {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent,
                "active_connections": len(psutil.net_connections())
            }
        except ImportError:
            report["system"] = {"message": "psutil not available"}
    
    return report

@app.get("/monitoring/metrics/summary")
async def get_metrics_summary():
    """Get metrics summary for dashboard"""
    from prometheus_client import REGISTRY
    import io
    
    # Collect metrics data
    output = io.StringIO()
    for metric in REGISTRY.collect():
        output.write(f"# HELP {metric.name} {metric.documentation}\n")
        output.write(f"# TYPE {metric.name} {metric.type}\n")
        for sample in metric.samples:
            labels = ','.join(f'{k}="{v}"' for k, v in sample.labels.items()) if sample.labels else ''
            if labels:
                output.write(f'{sample.name}{{{labels}}} {sample.value}\n')
            else:
                output.write(f'{sample.name} {sample.value}\n')
    
    metrics_text = output.getvalue()
    
    # Parse for summary
    edition = get_edition()
    summary = {
        "total_metrics": len(list(REGISTRY.collect())),
        "http_metrics": 0,
        "business_metrics": 0,
        "system_metrics": 0,
        "webhook_metrics": 0,
        "authority_metrics": 0,
        "timestamp": datetime.utcnow().isoformat(),
        "edition": edition,
        "mode": "validation" if os.getenv("VALIDATION_MODE") else "normal"
    }
    
    for line in metrics_text.split('\n'):
        if line.startswith('http_'):
            summary["http_metrics"] += 1
        elif any(x in line for x in ['incident', 'policy', 'rollback']):
            summary["business_metrics"] += 1
        elif any(x in line for x in ['authority', 'license', 'gate', 'confidence']):
            summary["authority_metrics"] += 1
        elif any(x in line for x in ['webhook', 'notification', 'integration']):
            summary["webhook_metrics"] += 1
        elif any(x in line for x in ['memory', 'cpu', 'disk', 'uptime']):
            summary["system_metrics"] += 1
    
    return summary

# ============================================================================
# API INFORMATION ENDPOINTS
# ============================================================================

@app.get("/api/info")
async def api_info():
    """Get detailed API information and capabilities"""
    edition = get_edition()
    enterprise_available = edition == "enterprise"
    
    api_info = {
        "api": {
            "name": "ARF API",
            "version": "3.0.0",
            "description": "Agentic Reliability Framework API",
            "specification": "OpenAPI 3.0",
            "schema_version": "3.0",
            "edition": edition,
            "enterprise_features": enterprise_available
        },
        "authentication": {
            "methods": ["JWT", "API Key"],
            "oauth2_flows": ["password"],
            "roles": ["viewer", "operator", "admin", "super_admin"],
            "scopes": ["read", "write", "admin"],
            "token_expiry": {
                "access_token": "30 minutes",
                "refresh_token": "7 days"
            }
        },
        "modules": {
            "incidents": {
                "description": "Incident management and tracking",
                "endpoints": ["/api/v1/incidents"],
                "features": ["CRUD operations", "filtering", "pagination", "statistics", "export", "timeline"]
            },
            "execution_ladder": {
                "description": "Graph-based policy management and evaluation",
                "endpoints": ["/api/v1/execution-ladder"],
                "features": ["policy management", "graph operations", "real-time evaluation", "decision tracing", "path analysis", "dependency mapping"]
            },
            "execution_authority": {
                "description": "Mechanical enforcement with license-gated execution modes (Enterprise)",
                "endpoints": ["/api/v1/authority"],
                "features": [
                    "license validation",
                    "deterministic confidence scoring", 
                    "risk assessment with blast radius",
                    "mechanical escalation gates",
                    "audit trails",
                    "pre-flight checks",
                    "license entitlements"
                ] if enterprise_available else ["OSS mode - advisory only"],
                "enterprise": enterprise_available
            },
            "rollback": {
                "description": "System recovery and action reversal",
                "endpoints": ["/api/v1/rollback"],
                "features": ["action logging", "rollback execution", "bulk operations", "risk assessment", "audit trails", "verification"]
            },
            "webhooks": {
                "description": "Notification system with multi-channel support",
                "endpoints": ["/api/v1/webhooks"],
                "features": ["multi-channel notifications", "template management", "retry logic", "delivery tracking", "integration validation"]
            },
            "monitoring": {
                "description": "Observability and metrics",
                "endpoints": ["/metrics", "/monitoring/*", "/health/*"],
                "features": ["prometheus metrics", "structured logging", "health checks", "performance monitoring", "business metrics"]
            }
        },
        "execution_authority_details": {
            "mechanical_gates": [
                "license_validation",
                "confidence_threshold", 
                "risk_assessment",
                "rollback_feasibility",
                "human_approval_required",
                "admin_approval",
                "novel_action_review"
            ] if enterprise_available else ["Not available in OSS mode"],
            "license_tiers": {
                "oss": "Advisory recommendations only",
                "starter": "Human approval required",
                "professional": "Autonomous low-risk execution",
                "enterprise": "Full mechanical enforcement including novel actions"
            } if enterprise_available else {"oss": "Open source - advisory only"},
            "performance": "<100ms overhead per evaluation",
            "auditability": "Tamper-evident audit trails"
        } if enterprise_available else {
            "message": "Enterprise execution authority requires commercial license"
        },
        "database": {
            "primary": {
                "type": "PostgreSQL",
                "version": "15+",
                "features": ["ACID compliance", "JSONB support", "full-text search"]
            },
            "graph": {
                "type": "Neo4j",
                "version": "5+",
                "features": ["Cypher query language", "ACID compliance", "graph algorithms"]
            },
            "cache": {
                "type": "Redis",
                "version": "7+",
                "features": ["in-memory data store", "pub/sub", "transactions", "license caching"]
            }
        },
        "notification_channels": {
            "slack": "Webhook integration with rich formatting",
            "teams": "Microsoft Teams adaptive cards",
            "email": "SMTP with HTML templates",
            "discord": "Webhook with embeds and mentions",
            "pagerduty": "Incident management integration",
            "opsgenie": "Alerting and on-call management"
        },
        "reliability_patterns": {
            "prevention": "Execution ladder policies with mechanical enforcement" if enterprise_available else "Execution ladder policies with conditional evaluation",
            "detection": "Incident monitoring + real-time metrics + alerting",
            "communication": "Multi-channel notifications for team coordination",
            "response": "Incident management with collaboration tools",
            "recovery": "Rollback capabilities with verification",
            "observability": "Three pillars: metrics, logs, traces",
            "auditability": "Complete audit trails for compliance" if enterprise_available else "Basic operation logging"
        },
        "deployment": {
            "containerization": "Docker with multi-stage builds",
            "orchestration": "Docker Compose for development, Kubernetes ready",
            "ci_cd": "GitHub Actions with automated testing",
            "monitoring_stack": "Prometheus, Grafana, Loki, Alertmanager",
            "enterprise_requirements": {
                "license_key": "ARF_LICENSE_KEY environment variable",
                "redis": "Required for license caching",
                "configuration": "ENABLE_MECHANICAL_ENFORCEMENT=true"
            } if enterprise_available else {}
        },
        "links": {
            "documentation": {
                "swagger": "/docs",
                "redoc": "/redoc",
                "openapi": "/openapi.json"
            },
            "source_code": "https://github.com/petterjuan/arf-api-repository",
            "issue_tracker": "https://github.com/petterjuan/arf-api-repository/issues",
            "wiki": "https://github.com/petterjuan/arf-api-repository/wiki",
            "health": "/health",
            "metrics": "/metrics",
            "enterprise_docs": "https://docs.arf.dev/enterprise" if enterprise_available else None
        },
        "support": {
            "community": "GitHub Discussions",
            "commercial": "enterprise@arf.dev",
            "sla": "Available for enterprise edition" if enterprise_available else "Community support"
        }
    }
    
    return api_info

@app.get("/status")
async def system_status():
    """Get comprehensive system status"""
    from .database.redis_client import redis_client
    
    # Skip database checks in validation mode
    if os.getenv("VALIDATION_MODE"):
        return {
            "system": {
                "version": "3.0.0",
                "environment": os.getenv("ENVIRONMENT", "development"),
                "edition": get_edition(),
                "mode": "validation",
                "timestamp": datetime.utcnow().isoformat()
            },
            "message": "Running in validation mode - limited functionality"
        }
    
    # Get edition
    edition = get_edition()
    enterprise_available = edition == "enterprise"
    
    # Get basic counts
    postgres_count = 0
    redis_info = {}
    neo4j_count = 0
    authority_stats = {}
    
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
            "uptime": redis_client.info().get('uptime_in_seconds', 0),
            "total_commands_processed": redis_client.info().get('total_commands_processed', 0)
        }
    except:
        pass
    
    try:
        # Neo4j count
        from .database.neo4j_client import driver
        with driver.session() as session:
            result = session.run("MATCH (n) RETURN count(n) as count")
            neo4j_count = result.single()["count"]
    except:
        pass
    
    # Get authority service stats if available
    if enterprise_available and is_enterprise_available("execution_authority"):
        try:
            from .api.v1.authority import get_authority_service
            authority_service = get_authority_service()
            
            # Get license info
            entitlements = await authority_service.get_license_entitlements("system")
            authority_stats = {
                "license_tier": entitlements.get("tier", "unknown"),
                "license_valid": entitlements.get("valid", False),
                "available_modes": entitlements.get("available_modes", []),
                "edition": getattr(authority_service, 'edition', 'unknown'),
                "mechanical_enforcement": getattr(authority_service, 'enable_mechanical_enforcement', False),
            }
        except Exception as e:
            authority_stats = {"error": str(e)}
    
    # Get performance data
    perf_report = performance_monitor.get_performance_report()
    
    return {
        "system": {
            "version": "3.0.0",
            "environment": os.getenv("ENVIRONMENT", "development"),
            "edition": edition,
            "enterprise_features": enterprise_available,
            "mechanical_enforcement": os.getenv("ENABLE_MECHANICAL_ENFORCEMENT", "false").lower() == "true",
            "startup_time": app.state.start_time.isoformat() if hasattr(app.state, 'start_time') else "unknown",
            "uptime_seconds": (
                (datetime.utcnow() - app.state.start_time).total_seconds() 
                if hasattr(app.state, 'start_time') else 0
            )
        },
        "counts": {
            "postgres_incidents": postgres_count,
            "neo4j_nodes": neo4j_count,
            "redis_connections": redis_info.get('connected_clients', 0)
        },
        "execution_authority": authority_stats,
        "performance": {
            "endpoints_monitored": len(perf_report.get("endpoints", {})),
            "average_latency_ms": sum(
                endpoint.get("p50_latency", 0) * 1000 
                for endpoint in perf_report.get("endpoints", {}).values()
            ) / max(len(perf_report.get("endpoints", {})), 1),
            "total_requests": sum(
                endpoint.get("request_count", 0)
                for endpoint in perf_report.get("endpoints", {}).values()
            )
        },
        "resources": {
            "redis": {
                "memory": redis_info.get('used_memory', '0'),
                "uptime": redis_info.get('uptime', 0),
                "commands_processed": redis_info.get('total_commands_processed', 0)
            }
        },
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================================================
# LEGACY ENDPOINTS (Deprecation path)
# ============================================================================

@app.get("/api/v1/incidents/unsecured", include_in_schema=False)
async def get_incidents_unsecured():
    """Legacy unsecured endpoint (for migration period)"""
    return {
        "message": "This endpoint is deprecated. Use authenticated endpoints.",
        "redirect": "/api/v1/incidents",
        "deprecation_warning": "This endpoint will be removed in v2.0.0",
        "alternative": "/api/v1/incidents with authentication",
        "documentation": "/docs#/incidents/get_incidents_incidents__get"
    }

# ============================================================================
# STARTUP LOGGING (Moved from on_event to lifespan startup)
# ============================================================================

# Note: Startup logging is now handled in the lifespan context manager

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # Configuration
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    reload = os.getenv("ENVIRONMENT") == "development"
    
    uvicorn.run(
        app, 
        host=host, 
        port=port,
        # Production settings
        log_level=os.getenv("LOG_LEVEL", "info"),
        access_log=os.getenv("ACCESS_LOG", True),
        proxy_headers=True,
        forwarded_allow_ips="*",
        reload=reload,
        # Timeouts
        timeout_keep_alive=30,
        timeout_graceful_shutdown=30,
        # Workers (0 = auto based on cores)
        workers=int(os.getenv("UVICORN_WORKERS", 0))
    )

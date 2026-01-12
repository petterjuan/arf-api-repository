"""
Main application with authentication, execution ladder, rollback, and monitoring integrated.
Psychology: Unified reliability platform with progressive enhancement and comprehensive observability.
Intention: Complete system for incident prevention, management, recovery, observability, and notifications.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import os
from datetime import datetime
import logging

try:
    from .api.v1 import incidents
except ImportError:
    # Fallback for when running tests or other cases
    from src.api.v1 import incidents
from .api.v1.webhooks import router as webhooks_router
from .auth.router import router as auth_router
from .api.v1.execution_ladder import router as execution_ladder_router
from .api.v1.rollback import router as rollback_router

# Import database with lazy initialization support
from .database import engine, Base, init_databases

# Import monitoring components
from .monitoring import setup_monitoring, BusinessMetrics, DatabaseMonitor, PerformanceMonitor
from .middleware.logging import StructuredLoggingMiddleware, BusinessEventLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Only create tables if we're not in validation mode and not testing
if not os.getenv("VALIDATION_MODE") and not os.getenv("TESTING"):
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Database tables created/verified")
    except Exception as e:
        logger.warning(f"⚠️ Could not create database tables (may be intentional): {e}")

app = FastAPI(
    title="ARF API",
    version="1.4.0",  # Updated version for webhook feature
    description="""Agentic Reliability Framework API - Complete System Reliability Platform with Observability
    
## 🔥 Core Reliability Features:

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

### 🔔 **Webhook & Notification System** (NEW)
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
- Business metrics tracking (incidents, policies, rollbacks, notifications)
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

## 🏗️ **System Architecture:**
- **PostgreSQL**: Primary data store for incidents, users, and rollback logs
- **Neo4j**: Graph database for execution ladder policies and relationships
- **Redis**: Caching layer for performance + rollback action storage
- **FastAPI**: Modern, fast API framework with async support
- **Docker**: Containerized deployment with health checks
- **Prometheus**: Metrics collection and alerting
- **Grafana**: Visualization and dashboarding
- **Loki**: Log aggregation and querying

## 📈 **Business Value:**
- **Prevention**: Proactive policy enforcement via execution ladder
- **Detection**: Real-time incident monitoring and alerting
- **Response**: Efficient incident management and collaboration
- **Communication**: Multi-channel notifications for team coordination
- **Recovery**: Reliable rollback capabilities for system restoration
- **Improvement**: Data-driven insights from comprehensive metrics

## 🔧 **Development & Deployment:**
- Complete CI/CD pipeline with GitHub Actions
- Docker Compose for local development and production
- Railway.app ready configuration
- Environment-based configuration management
- Multi-stage Docker builds
- Health checks and graceful shutdown
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
        },
        {
            "url": "https://staging.arf-api.example.com",
            "description": "Staging server"
        }
    ],
    # API metadata
    terms_of_service="https://arf.example.com/terms/",
    # External documentation
    external_docs={
        "description": "ARF API Documentation",
        "url": "https://docs.arf.example.com",
    }
)

# Security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time", "X-Total-Count"]
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
    
    return {
        "service": "ARF API",
        "version": "1.4.0",
        "status": "running",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "edition": os.getenv("ARF_EDITION", "oss"),
        "architecture": {
            "authentication": "enabled",
            "incident_management": "enabled", 
            "execution_ladder": "enabled",
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
            "prevention": "Execution ladder policies",
            "detection": "Incident monitoring + metrics",
            "response": "Incident management + alerting",
            "communication": "Webhook notifications",
            "recovery": "Rollback operations",
            "observability": "Metrics, logs, tracing"
        },
        "resources": {
            "redis_memory": redis_memory,
            "startup_time": app.state.start_time.isoformat() if hasattr(app.state, 'start_time') else "unknown"
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
            "rollback": "/api/v1/rollback",
            "webhooks": "/api/v1/webhooks",
            "health": {
                "basic": "/health",
                "detailed": "/health/detailed",
                "advanced": "/health/advanced",
                "readiness": "/health/readiness",
                "liveness": "/health/liveness"
            },
            "monitoring": {
                "metrics": "/metrics",
                "openmetrics": "/metrics/openmetrics",
                "performance": "/monitoring/performance"
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
            "edition": os.getenv("ARF_EDITION", "oss"),
            "version": "1.4.0",
            "mode": "validation",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    # Normal health check
    return {
        "status": "healthy",
        "edition": os.getenv("ARF_EDITION", "oss"),
        "version": "1.4.0",
        "features": {
            "authentication": "enabled",
            "incident_management": "enabled",
            "execution_ladder": "enabled",
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
        try:
            # Check execution ladder service
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
        
        try:
            # Check rollback service
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
    
    # Determine overall status
    all_ready = all(check["status"] == "ready" for check in checks)
    
    return {
        "status": "ready" if all_ready else "not_ready",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks
    }

@app.get("/health/liveness")
async def liveness_probe():
    """Kubernetes liveness probe - check application is alive"""
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat(),
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
    
    # Parse for summary (simplified)
    summary = {
        "total_metrics": len(list(REGISTRY.collect())),
        "http_metrics": 0,
        "business_metrics": 0,
        "system_metrics": 0,
        "webhook_metrics": 0,
        "timestamp": datetime.utcnow().isoformat(),
        "mode": "validation" if os.getenv("VALIDATION_MODE") else "normal"
    }
    
    for line in metrics_text.split('\n'):
        if line.startswith('http_'):
            summary["http_metrics"] += 1
        elif any(x in line for x in ['incident', 'policy', 'rollback']):
            summary["business_metrics"] += 1
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
    return {
        "api": {
            "name": "ARF API",
            "version": "1.4.0",
            "description": "Agentic Reliability Framework API",
            "specification": "OpenAPI 3.0",
            "schema_version": "1.0"
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
                "features": ["in-memory data store", "pub/sub", "transactions"]
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
            "prevention": "Execution ladder policies with conditional evaluation",
            "detection": "Incident monitoring + real-time metrics + alerting",
            "communication": "Multi-channel notifications for team coordination",
            "response": "Incident management with collaboration tools",
            "recovery": "Rollback capabilities with verification",
            "observability": "Three pillars: metrics, logs, traces"
        },
        "deployment": {
            "containerization": "Docker with multi-stage builds",
            "orchestration": "Docker Compose for development, Kubernetes ready",
            "ci_cd": "GitHub Actions with automated testing",
            "monitoring_stack": "Prometheus, Grafana, Loki, Alertmanager"
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
            "metrics": "/metrics"
        },
        "support": {
            "community": "GitHub Discussions",
            "commercial": "contact@arf.example.com",
            "sla": "Available for enterprise edition"
        }
    }

@app.get("/status")
async def system_status():
    """Get comprehensive system status"""
    from .database.redis_client import redis_client
    
    # Skip database checks in validation mode
    if os.getenv("VALIDATION_MODE"):
        return {
            "system": {
                "version": "1.4.0",
                "environment": os.getenv("ENVIRONMENT", "development"),
                "edition": os.getenv("ARF_EDITION", "oss"),
                "mode": "validation",
                "timestamp": datetime.utcnow().isoformat()
            },
            "message": "Running in validation mode - limited functionality"
        }
    
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
    
    # Get performance data
    perf_report = performance_monitor.get_performance_report()
    
    return {
        "system": {
            "version": "1.4.0",
            "environment": os.getenv("ENVIRONMENT", "development"),
            "edition": os.getenv("ARF_EDITION", "oss"),
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
# APPLICATION LIFECYCLE EVENTS
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Application startup event"""
    # Initialize databases only if not in validation mode
    if not os.getenv("VALIDATION_MODE"):
        init_databases()
    
    logger.info(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    ARF API v1.4.0 Starting                   ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Environment: {os.getenv('ENVIRONMENT', 'development'):<49} ║
    ║  Edition: {os.getenv('ARF_EDITION', 'oss'):<52} ║
    ║  Mode: {os.getenv('VALIDATION_MODE', 'normal'):<54} ║
    ║  Host: {os.getenv('HOST', '0.0.0.0'):<55} ║
    ║  Port: {os.getenv('PORT', '8000'):<55} ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Core Features:                                              ║
    ║    • 🔐 Authentication & Authorization                       ║
    ║    • 🚨 Incident Management                                  ║
    ║    • 🪜 Execution Ladder (Policy Engine)                     ║
    ║    • 🔄 Rollback Capabilities                                ║
    ║    • 📊 Monitoring & Observability                           ║
    ║    • 🔔 Webhook Notifications                                ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Documentation:                                              ║
    ║    • Swagger UI: http://{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}/docs ║
    ║    • ReDoc: http://{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}/redoc ║
    ║    • OpenAPI: http://{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}/openapi.json ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Monitoring Endpoints:                                       ║
    ║    • Prometheus: http://{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}/metrics ║
    ║    • OpenMetrics: http://{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}/metrics/openmetrics ║
    ║    • Health: http://{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}/health/advanced ║
    ║    • Readiness: http://{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}/health/readiness ║
    ║    • Liveness: http://{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}/health/liveness ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Log business event
    BusinessEventLogger.log_event(
        event_type="application_startup",
        event_data={
            "version": "1.4.0",
            "environment": os.getenv("ENVIRONMENT", "development"),
            "edition": os.getenv("ARF_EDITION", "oss"),
            "mode": os.getenv("VALIDATION_MODE", "normal")
        },
        user_id="system"
    )

@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown event"""
    logger.info("ARF API shutting down gracefully")
    
    # Log business event
    BusinessEventLogger.log_event(
        event_type="application_shutdown",
        event_data={
            "uptime_seconds": (datetime.utcnow() - app.state.start_time).total_seconds() 
            if hasattr(app.state, 'start_time') else 0
        },
        user_id="system"
    )

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # Configuration
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    reload = os.getenv("ENVIRONMENT") == "development"
    
    # Store startup time
    app.state.start_time = datetime.utcnow()
    
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

"""
Monitoring and metrics for ARF API.
Psychology: Proactive observability with actionable metrics.
Intention: Comprehensive monitoring for production reliability.
"""
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import time
from contextlib import asynccontextmanager
import logging
from functools import wraps

from fastapi import FastAPI, Request, Response
from fastapi.routing import APIRoute
from prometheus_client import Counter, Histogram, Gauge, Summary, generate_latest, REGISTRY
from prometheus_client.openmetrics.exposition import generate_latest as generate_latest_openmetrics
import redis
from sqlalchemy import text

from .database import engine
from .database.redis_client import get_redis
from .database.neo4j_client import get_neo4j

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================================================
# PROMETHEUS METRICS
# ============================================================================

# HTTP Metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP request latency in seconds',
    ['method', 'endpoint'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
)

REQUEST_IN_PROGRESS = Gauge(
    'http_requests_in_progress',
    'Number of HTTP requests in progress',
    ['method', 'endpoint']
)

# Business Metrics
INCIDENTS_CREATED = Counter(
    'incidents_created_total',
    'Total incidents created',
    ['severity', 'type']
)

INCIDENTS_RESOLVED = Counter(
    'incidents_resolved_total',
    'Total incidents resolved',
    ['severity', 'type']
)

POLICY_EVALUATIONS = Counter(
    'policy_evaluations_total',
    'Total policy evaluations',
    ['policy_type', 'result']
)

ROLLBACK_EXECUTIONS = Counter(
    'rollback_executions_total',
    'Total rollback executions',
    ['action_type', 'status']
)

# Database Metrics
DATABASE_QUERIES = Counter(
    'database_queries_total',
    'Total database queries',
    ['database', 'operation']
)

DATABASE_LATENCY = Histogram(
    'database_query_duration_seconds',
    'Database query latency in seconds',
    ['database', 'operation'],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
)

# Cache Metrics
CACHE_HITS = Counter(
    'cache_hits_total',
    'Total cache hits',
    ['cache', 'key_pattern']
)

CACHE_MISSES = Counter(
    'cache_misses_total',
    'Total cache misses',
    ['cache', 'key_pattern']
)

CACHE_SIZE = Gauge(
    'cache_size_bytes',
    'Cache size in bytes',
    ['cache']
)

# System Metrics
SYSTEM_UPTIME = Gauge(
    'system_uptime_seconds',
    'System uptime in seconds'
)

ACTIVE_SESSIONS = Gauge(
    'active_sessions_total',
    'Number of active user sessions'
)

MEMORY_USAGE = Gauge(
    'memory_usage_bytes',
    'Memory usage in bytes'
)

# Error Metrics
ERROR_COUNT = Counter(
    'errors_total',
    'Total errors',
    ['error_type', 'endpoint', 'severity']
)

# ============================================================================
# MONITORING MIDDLEWARE
# ============================================================================

class MonitoringMiddleware:
    """Middleware for comprehensive request monitoring"""
    
    def __init__(self, app: FastAPI):
        self.app = app
        self.start_time = datetime.utcnow()
    
    async def __call__(self, request: Request, call_next):
        # Track request start
        method = request.method
        endpoint = request.url.path
        
        # Skip metrics for monitoring endpoints
        if endpoint in ['/metrics', '/health', '/health/detailed']:
            return await call_next(request)
        
        # Increment in-progress gauge
        REQUEST_IN_PROGRESS.labels(method=method, endpoint=endpoint).inc()
        
        # Measure latency
        start_time = time.time()
        
        try:
            response = await call_next(request)
            status_code = response.status_code
            
            # Record success
            REQUEST_COUNT.labels(
                method=method,
                endpoint=endpoint,
                status_code=status_code
            ).inc()
            
            # Record latency
            latency = time.time() - start_time
            REQUEST_LATENCY.labels(
                method=method,
                endpoint=endpoint
            ).observe(latency)
            
            # Add monitoring headers
            response.headers["X-Request-ID"] = request.headers.get("X-Request-ID", "")
            response.headers["X-Response-Time"] = f"{latency:.3f}s"
            
            return response
            
        except Exception as e:
            # Record error
            ERROR_COUNT.labels(
                error_type=type(e).__name__,
                endpoint=endpoint,
                severity="error"
            ).inc()
            
            # Re-raise the exception
            raise
            
        finally:
            # Decrement in-progress gauge
            REQUEST_IN_PROGRESS.labels(method=method, endpoint=endpoint).dec()

# ============================================================================
# DATABASE MONITORING
# ============================================================================

class DatabaseMonitor:
    """Monitor database operations"""
    
    @staticmethod
    def track_query(database: str, operation: str):
        """Decorator to track database queries"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                start_time = time.time()
                
                try:
                    result = await func(*args, **kwargs)
                    
                    # Record successful query
                    DATABASE_QUERIES.labels(
                        database=database,
                        operation=operation
                    ).inc()
                    
                    # Record latency
                    latency = time.time() - start_time
                    DATABASE_LATENCY.labels(
                        database=database,
                        operation=operation
                    ).observe(latency)
                    
                    return result
                    
                except Exception as e:
                    # Record error
                    ERROR_COUNT.labels(
                        error_type=type(e).__name__,
                        endpoint=f"db:{database}.{operation}",
                        severity="error"
                    ).inc()
                    raise
                    
            return wrapper
        return decorator
    
    @staticmethod
    async def check_database_health() -> Dict[str, Any]:
        """Check health of all databases"""
        health_status = {
            "timestamp": datetime.utcnow().isoformat(),
            "databases": {}
        }
        
        # Check PostgreSQL
        try:
            start = time.time()
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1 as healthy, version() as version"))
                row = result.fetchone()
                latency = time.time() - start
                
                health_status["databases"]["postgresql"] = {
                    "status": "healthy" if row.healthy == 1 else "degraded",
                    "latency_ms": round(latency * 1000, 2),
                    "version": row.version,
                    "connection_count": 0  # Would get from pg_stat_activity
                }
        except Exception as e:
            health_status["databases"]["postgresql"] = {
                "status": "unhealthy",
                "error": str(e),
                "latency_ms": None
            }
        
        # Check Redis
        try:
            start = time.time()
            redis_client = get_redis()
            redis_client.ping()
            latency = time.time() - start
            
            info = redis_client.info()
            
            health_status["databases"]["redis"] = {
                "status": "healthy",
                "latency_ms": round(latency * 1000, 2),
                "version": info.get('redis_version'),
                "used_memory": info.get('used_memory_human'),
                "connected_clients": info.get('connected_clients')
            }
        except Exception as e:
            health_status["databases"]["redis"] = {
                "status": "unhealthy",
                "error": str(e),
                "latency_ms": None
            }
        
        # Check Neo4j
        try:
            start = time.time()
            driver = get_neo4j()
            with driver.session() as session:
                result = session.run("RETURN 1 as healthy, version() as version")
                record = result.single()
                latency = time.time() - start
                
                health_status["databases"]["neo4j"] = {
                    "status": "healthy" if record["healthy"] == 1 else "degraded",
                    "latency_ms": round(latency * 1000, 2),
                    "version": record["version"],
                    "node_count": 0  # Would count nodes
                }
        except Exception as e:
            health_status["databases"]["neo4j"] = {
                "status": "unhealthy",
                "error": str(e),
                "latency_ms": None
            }
        
        return health_status

# ============================================================================
# CACHE MONITORING
# ============================================================================

class CacheMonitor:
    """Monitor cache operations"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client or get_redis()
    
    def track_cache(self, cache_name: str, key_pattern: str = "*"):
        """Decorator to track cache operations"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                try:
                    result = await func(*args, **kwargs)
                    
                    # Check if result came from cache
                    # This is simplified - in production would track cache hits/misses
                    CACHE_HITS.labels(
                        cache=cache_name,
                        key_pattern=key_pattern
                    ).inc()
                    
                    return result
                    
                except Exception as e:
                    # Record cache error
                    ERROR_COUNT.labels(
                        error_type=type(e).__name__,
                        endpoint=f"cache:{cache_name}",
                        severity="warning"
                    ).inc()
                    raise
                    
            return wrapper
        return decorator
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            info = self.redis.info()
            
            # Scan for cache keys
            cache_patterns = [
                "api:incidents:*",
                "api:execution-ladder:*", 
                "rollback:cache:*"
            ]
            
            key_counts = {}
            for pattern in cache_patterns:
                count = 0
                for _ in self.redis.scan_iter(match=pattern):
                    count += 1
                key_counts[pattern] = count
            
            # Estimate memory usage
            total_memory = 0
            for pattern, count in key_counts.items():
                if count > 0:
                    # Rough estimate: 100 bytes per key + value size
                    total_memory += count * 500  # Conservative estimate
            
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "redis_info": {
                    "used_memory": info.get('used_memory_human'),
                    "total_keys": info.get('keyspace', {}).get('db0', {}).get('keys', 0),
                    "hit_rate": info.get('keyspace_hit_ratio', 0)
                },
                "cache_patterns": key_counts,
                "estimated_cache_size_bytes": total_memory
            }
            
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }

# ============================================================================
# BUSINESS METRICS COLLECTION
# ============================================================================

class BusinessMetrics:
    """Collect business-specific metrics"""
    
    @staticmethod
    def track_incident(severity: str, incident_type: str, created: bool = True):
        """Track incident creation/resolution"""
        if created:
            INCIDENTS_CREATED.labels(
                severity=severity,
                type=incident_type
            ).inc()
        else:
            INCIDENTS_RESOLVED.labels(
                severity=severity,
                type=incident_type
            ).inc()
    
    @staticmethod
    def track_policy_evaluation(policy_type: str, result: str):
        """Track policy evaluation"""
        POLICY_EVALUATIONS.labels(
            policy_type=policy_type,
            result=result
        ).inc()
    
    @staticmethod
    def track_rollback(action_type: str, status: str):
        """Track rollback execution"""
        ROLLBACK_EXECUTIONS.labels(
            action_type=action_type,
            status=status
        ).inc()
    
    @staticmethod
    def track_error(error_type: str, endpoint: str, severity: str = "error"):
        """Track error occurrence"""
        ERROR_COUNT.labels(
            error_type=error_type,
            endpoint=endpoint,
            severity=severity
        ).inc()

# ============================================================================
# METRICS ENDPOINT
# ============================================================================

def setup_metrics_endpoint(app: FastAPI):
    """Setup metrics endpoint for Prometheus scraping"""
    
    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint():
        """Prometheus metrics endpoint"""
        # Update system metrics
        SYSTEM_UPTIME.set((datetime.utcnow() - app.state.start_time).total_seconds())
        
        # Generate metrics response
        return Response(
            content=generate_latest(REGISTRY),
            media_type="text/plain"
        )
    
    @app.get("/metrics/openmetrics", include_in_schema=False)
    async def openmetrics_endpoint():
        """OpenMetrics format endpoint"""
        return Response(
            content=generate_latest_openmetrics(REGISTRY),
            media_type="application/openmetrics-text"
        )

# ============================================================================
# HEALTH CHECKS WITH METRICS
# ============================================================================

def setup_advanced_health_checks(app: FastAPI):
    """Setup advanced health checks with metrics"""
    
    db_monitor = DatabaseMonitor()
    cache_monitor = CacheMonitor()
    
    @app.get("/health/advanced")
    async def advanced_health():
        """Advanced health check with metrics"""
        # Check all systems
        db_health = await db_monitor.check_database_health()
        cache_stats = await cache_monitor.get_cache_stats()
        
        # Calculate overall status
        all_healthy = all(
            db["status"] == "healthy" 
            for db in db_health["databases"].values()
        )
        
        return {
            "status": "healthy" if all_healthy else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "systems": {
                "databases": db_health,
                "cache": cache_stats
            },
            "metrics": {
                "request_rate": "N/A",  # Would calculate
                "error_rate": "N/A",    # Would calculate
                "latency_p95": "N/A"    # Would calculate
            }
        }
    
    @app.get("/health/readiness")
    async def readiness_probe():
        """Kubernetes readiness probe"""
        try:
            # Check critical dependencies
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            get_redis().ping()
            
            driver = get_neo4j()
            with driver.session() as session:
                session.run("RETURN 1")
            
            return {"status": "ready"}
            
        except Exception as e:
            return {"status": "not_ready", "error": str(e)}
    
    @app.get("/health/liveness")
    async def liveness_probe():
        """Kubernetes liveness probe"""
        return {"status": "alive"}

# ============================================================================
# PERFORMANCE MONITORING
# ============================================================================

class PerformanceMonitor:
    """Monitor application performance"""
    
    def __init__(self):
        self.metrics = {
            "endpoint_latency": {},
            "error_rates": {},
            "throughput": {}
        }
        self.window_size = 300  # 5 minutes in seconds
    
    def record_endpoint_performance(self, endpoint: str, latency: float, status_code: int):
        """Record endpoint performance metrics"""
        if endpoint not in self.metrics["endpoint_latency"]:
            self.metrics["endpoint_latency"][endpoint] = []
        
        self.metrics["endpoint_latency"][endpoint].append({
            "timestamp": datetime.utcnow(),
            "latency": latency,
            "status_code": status_code
        })
        
        # Keep only recent data
        cutoff = datetime.utcnow() - timedelta(seconds=self.window_size)
        self.metrics["endpoint_latency"][endpoint] = [
            m for m in self.metrics["endpoint_latency"][endpoint]
            if m["timestamp"] > cutoff
        ]
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate performance report"""
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "window_seconds": self.window_size,
            "endpoints": {}
        }
        
        for endpoint, metrics in self.metrics["endpoint_latency"].items():
            if metrics:
                latencies = [m["latency"] for m in metrics]
                status_codes = [m["status_code"] for m in metrics]
                
                successful = sum(1 for sc in status_codes if 200 <= sc < 300)
                error_rate = 1 - (successful / len(status_codes)) if status_codes else 0
                
                report["endpoints"][endpoint] = {
                    "request_count": len(metrics),
                    "p50_latency": sorted(latencies)[len(latencies) // 2] if latencies else 0,
                    "p95_latency": sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0,
                    "p99_latency": sorted(latencies)[int(len(latencies) * 0.99)] if latencies else 0,
                    "error_rate": error_rate,
                    "success_rate": 1 - error_rate
                }
        
        return report

# ============================================================================
# INITIALIZATION
# ============================================================================

def setup_monitoring(app: FastAPI):
    """Setup comprehensive monitoring for the application"""
    
    # Store start time
    app.state.start_time = datetime.utcnow()
    
    # Add monitoring middleware
    app.add_middleware(MonitoringMiddleware)
    
    # Setup metrics endpoint
    setup_metrics_endpoint(app)
    
    # Setup advanced health checks
    setup_advanced_health_checks(app)
    
    # Initialize performance monitor
    app.state.performance_monitor = PerformanceMonitor()
    
    # Add startup event
    @app.on_event("startup")
    async def startup_event():
        logger.info(f"ARF API v{app.version} starting with monitoring enabled")
        logger.info("Monitoring endpoints available:")
        logger.info("  - /metrics (Prometheus)")
        logger.info("  - /metrics/openmetrics (OpenMetrics)")
        logger.info("  - /health/advanced (Comprehensive health)")
        logger.info("  - /health/readiness (Kubernetes readiness)")
        logger.info("  - /health/liveness (Kubernetes liveness)")
    
    # Add shutdown event
    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info("ARF API shutting down")
    
    return app

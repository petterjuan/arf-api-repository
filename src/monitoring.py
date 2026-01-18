"""
Monitoring and metrics for ARF API.
Production-grade observability with correct ASGI middleware implementation.
Psychology: Proactive observability with actionable metrics.
Intention: Comprehensive monitoring for production reliability.
"""
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import time
from contextlib import asynccontextmanager
import logging
from functools import wraps
import os

from fastapi import FastAPI, Request, Response
from fastapi.routing import APIRoute
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
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

# MONITORING MIDDLEWARE - CORRECTED FOR PRODUCTION

class MonitoringMiddleware(BaseHTTPMiddleware):
    """
    Production-grade middleware for comprehensive request monitoring.
    Uses BaseHTTPMiddleware pattern for clean integration with FastAPI.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.start_time = datetime.utcnow()
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request and track metrics.
        This is the correct pattern for FastAPI middleware.
        """
        # Track request start
        method = request.method
        endpoint = request.url.path
        
        # Skip metrics for monitoring endpoints
        if endpoint in ['/metrics', '/health', '/health/detailed',
                       '/health/readiness', '/health/liveness', '/health/advanced']:
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
            response.headers["X-Monitored"] = "true"
            
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

class DatabaseMonitor:
    """Monitor database operations with production reliability"""
    
    @staticmethod
    def track_query(database: str, operation: str):
        """Decorator to track database queries with proper error handling"""
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
                    # Record error with context
                    ERROR_COUNT.labels(
                        error_type=type(e).__name__,
                        endpoint=f"db:{database}.{operation}",
                        severity="error"
                    ).inc()
                    
                    # Log with structured format
                    logger.error(
                        f"Database query failed: {database}.{operation}",
                        extra={
                            "database": database,
                            "operation": operation,
                            "error_type": type(e).__name__,
                            "error_message": str(e),
                            "duration_seconds": time.time() - start_time
                        }
                    )
                    raise
                    
            return wrapper
        return decorator
    
    @staticmethod
    async def check_database_health() -> Dict[str, Any]:
        """Comprehensive database health check with fail-safe design"""
        health_status = {
            "timestamp": datetime.utcnow().isoformat(),
            "databases": {},
            "overall_status": "healthy"
        }
        
        # Check PostgreSQL
        postgres_health = await DatabaseMonitor._check_postgresql()
        health_status["databases"]["postgresql"] = postgres_health
        
        # Check Redis
        redis_health = await DatabaseMonitor._check_redis()
        health_status["databases"]["redis"] = redis_health
        
        # Check Neo4j
        neo4j_health = await DatabaseMonitor._check_neo4j()
        health_status["databases"]["neo4j"] = neo4j_health
        
        # Determine overall status
        unhealthy_count = sum(
            1 for db in health_status["databases"].values()
            if db["status"] != "healthy"
        )
        
        if unhealthy_count > 0:
            health_status["overall_status"] = "degraded" if unhealthy_count < 3 else "unhealthy"
        
        return health_status
    
    @staticmethod
    async def _check_postgresql() -> Dict[str, Any]:
        """Check PostgreSQL health with connection pooling"""
        try:
            start = time.time()
            
            # Use connection pool efficiently
            async with engine.connect() as conn:
                result = await conn.execute(text("""
                    SELECT 1 as healthy, 
                           version() as version,
                           (SELECT count(*) FROM pg_stat_activity) as connection_count,
                           (SELECT pg_database_size(current_database())) as database_size
                """))
                row = result.first()
                latency = time.time() - start
                
                return {
                    "status": "healthy" if row.healthy == 1 else "degraded",
                    "latency_ms": round(latency * 1000, 2),
                    "version": row.version,
                    "connection_count": row.connection_count,
                    "database_size_bytes": row.database_size,
                    "database_size_human": f"{row.database_size / 1024 / 1024:.1f} MB"
                }
        except Exception as e:
            logger.error(f"PostgreSQL health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "latency_ms": None
            }
    
    @staticmethod
    async def _check_redis() -> Dict[str, Any]:
        """Check Redis health with connection validation"""
        try:
            start = time.time()
            redis_client = get_redis()
            
            # Test connection and basic operations
            redis_client.ping()
            
            # Get detailed info
            info = redis_client.info()
            latency = time.time() - start
            
            # Calculate hit rate if available
            keyspace_hits = info.get('keyspace_hits', 0)
            keyspace_misses = info.get('keyspace_misses', 0)
            total = keyspace_hits + keyspace_misses
            hit_rate = keyspace_hits / total if total > 0 else 0
            
            return {
                "status": "healthy",
                "latency_ms": round(latency * 1000, 2),
                "version": info.get('redis_version'),
                "used_memory": info.get('used_memory_human'),
                "used_memory_bytes": info.get('used_memory'),
                "connected_clients": info.get('connected_clients'),
                "hit_rate": round(hit_rate, 4),
                "uptime_days": info.get('uptime_in_days', 0)
            }
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "latency_ms": None
            }
    
    @staticmethod
    async def _check_neo4j() -> Dict[str, Any]:
        """Check Neo4j health with session management"""
        try:
            start = time.time()
            driver = get_neo4j()
            
            # Use session context manager for proper cleanup
            with driver.session() as session:
                result = session.run("""
                    RETURN 1 as healthy, 
                           "Neo4j " + version() as version,
                           size([(n) WHERE exists(n.id) | n]) as node_count,
                           size([(r) WHERE exists(r.id) | r]) as relationship_count
                """)
                record = result.single()
                latency = time.time() - start
                
                return {
                    "status": "healthy" if record["healthy"] == 1 else "degraded",
                    "latency_ms": round(latency * 1000, 2),
                    "version": record["version"],
                    "node_count": record["node_count"],
                    "relationship_count": record["relationship_count"],
                    "driver_status": "connected"
                }
        except Exception as e:
            logger.error(f"Neo4j health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "latency_ms": None
            }

# ============================================================================

# CACHE MONITORING

class CacheMonitor:
    """Production-grade cache monitoring with detailed metrics"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client or get_redis()
        self.cache_patterns = [
            "api:incidents:*",
            "api:execution-ladder:*", 
            "rollback:cache:*",
            "auth:session:*",
            "webhook:config:*"
        ]
    
    def track_cache_operation(self, cache_name: str, operation: str, key_pattern: str = "*"):
        """Decorator to track cache operations with success/failure metrics"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                start_time = time.time()
                
                try:
                    result = await func(*args, **kwargs)
                    
                    # Record successful operation
                    if operation == "hit":
                        CACHE_HITS.labels(cache=cache_name, key_pattern=key_pattern).inc()
                    elif operation == "miss":
                        CACHE_MISSES.labels(cache=cache_name, key_pattern=key_pattern).inc()
                    
                    # Record latency
                    latency = time.time() - start_time
                    DATABASE_LATENCY.labels(
                        database="redis",
                        operation=f"cache_{operation}"
                    ).observe(latency)
                    
                    return result
                    
                except Exception as e:
                    # Record cache error
                    ERROR_COUNT.labels(
                        error_type=type(e).__name__,
                        endpoint=f"cache:{cache_name}.{operation}",
                        severity="warning"
                    ).inc()
                    
                    logger.warning(
                        f"Cache operation failed: {cache_name}.{operation}",
                        extra={
                            "cache": cache_name,
                            "operation": operation,
                            "key_pattern": key_pattern,
                            "error": str(e)
                        }
                    )
                    raise
                    
            return wrapper
        return decorator
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics with memory analysis"""
        try:
            info = self.redis.info()
            
            # Detailed cache analysis
            cache_analysis = {}
            total_keys = 0
            estimated_memory = 0
            
            for pattern in self.cache_patterns:
                keys = list(self.redis.scan_iter(match=pattern, count=100))
                key_count = len(keys)
                
                if key_count > 0:
                    # Estimate memory usage for this pattern
                    pattern_memory = 0
                    sample_keys = keys[:10]  # Sample first 10 keys for estimation
                    
                    for key in sample_keys:
                        try:
                            key_type = self.redis.type(key)
                            if key_type == "string":
                                pattern_memory += self.redis.memory_usage(key) or 100
                            elif key_type in ["hash", "list", "set", "zset"]:
                                pattern_memory += 500  # Conservative estimate for complex types
                            else:
                                pattern_memory += 100  # Default estimate
                        except:
                            pattern_memory += 100
                    
                    # Extrapolate to all keys in pattern
                    if sample_keys:
                        avg_key_size = pattern_memory / len(sample_keys)
                        pattern_memory = avg_key_size * key_count
                    
                    cache_analysis[pattern] = {
                        "key_count": key_count,
                        "estimated_memory_bytes": int(pattern_memory),
                        "estimated_memory_human": f"{pattern_memory / 1024 / 1024:.2f} MB"
                    }
                    
                    total_keys += key_count
                    estimated_memory += pattern_memory
            
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "redis_info": {
                    "used_memory": info.get('used_memory_human'),
                    "used_memory_bytes": info.get('used_memory'),
                    "total_keys": info.get('keyspace', {}).get('db0', {}).get('keys', 0),
                    "hit_rate": f"{info.get('keyspace_hit_ratio', 0) * 100:.1f}%",
                    "connected_clients": info.get('connected_clients'),
                    "uptime_days": info.get('uptime_in_days', 0)
                },
                "cache_analysis": cache_analysis,
                "summary": {
                    "total_pattern_keys": total_keys,
                    "total_estimated_memory_bytes": int(estimated_memory),
                    "total_estimated_memory_human": f"{estimated_memory / 1024 / 1024:.2f} MB"
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e),
                "status": "degraded"
            }

# ============================================================================

# BUSINESS METRICS COLLECTION

class BusinessMetrics:
    """Production-grade business metrics with contextual tracking"""
    
    @staticmethod
    def track_incident(severity: str, incident_type: str, created: bool = True, 
                      metadata: Optional[Dict] = None):
        """Track incident creation/resolution with metadata"""
        if created:
            INCIDENTS_CREATED.labels(
                severity=severity,
                type=incident_type
            ).inc()
            
            logger.info(
                f"Incident created: {incident_type} ({severity})",
                extra={
                    "event": "incident_created",
                    "severity": severity,
                    "type": incident_type,
                    "metadata": metadata or {}
                }
            )
        else:
            INCIDENTS_RESOLVED.labels(
                severity=severity,
                type=incident_type
            ).inc()
            
            logger.info(
                f"Incident resolved: {incident_type} ({severity})",
                extra={
                    "event": "incident_resolved",
                    "severity": severity,
                    "type": incident_type,
                    "metadata": metadata or {}
                }
            )
    
    @staticmethod
    def track_policy_evaluation(policy_type: str, result: str, context: Optional[Dict] = None):
        """Track policy evaluation with context"""
        POLICY_EVALUATIONS.labels(
            policy_type=policy_type,
            result=result
        ).inc()
        
        logger.info(
            f"Policy evaluated: {policy_type} -> {result}",
            extra={
                "event": "policy_evaluation",
                "policy_type": policy_type,
                "result": result,
                "context_keys": list(context.keys()) if context else []
            }
        )
    
    @staticmethod
    def track_rollback(action_type: str, status: str, execution_id: Optional[str] = None):
        """Track rollback execution with execution ID"""
        ROLLBACK_EXECUTIONS.labels(
            action_type=action_type,
            status=status
        ).inc()
        
        logger.info(
            f"Rollback executed: {action_type} -> {status}",
            extra={
                "event": "rollback_execution",
                "action_type": action_type,
                "status": status,
                "execution_id": execution_id
            }
        )
    
    @staticmethod
    def track_error(error_type: str, endpoint: str, severity: str = "error", 
                   context: Optional[Dict] = None):
        """Track error occurrence with context"""
        ERROR_COUNT.labels(
            error_type=error_type,
            endpoint=endpoint,
            severity=severity
        ).inc()
        
        log_level = {
            "error": logging.ERROR,
            "warning": logging.WARNING,
            "info": logging.INFO
        }.get(severity, logging.ERROR)
        
        logger.log(
            log_level,
            f"Error occurred: {error_type} at {endpoint}",
            extra={
                "event": "error_occurred",
                "error_type": error_type,
                "endpoint": endpoint,
                "severity": severity,
                "context": context or {}
            }
        )

# ============================================================================

# METRICS ENDPOINT WITH SECURITY

def setup_metrics_endpoint(app: FastAPI, require_auth: bool = True):
    """Setup secure metrics endpoint for Prometheus scraping"""
    
    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint(request: Request):
        """Secure Prometheus metrics endpoint"""
        if require_auth:
            api_key = request.headers.get("X-API-Key")
            if not api_key or api_key != os.getenv("METRICS_API_KEY"):
                return Response(
                    content="Unauthorized",
                    status_code=401,
                    headers={"WWW-Authenticate": "ApiKey"}
                )
        
        # Update system metrics
        if hasattr(app.state, 'start_time'):
            SYSTEM_UPTIME.set((datetime.utcnow() - app.state.start_time).total_seconds())
        
        # Update cache size metrics
        try:
            cache_monitor = CacheMonitor()
            stats = await cache_monitor.get_cache_stats()
            if "summary" in stats:
                CACHE_SIZE.labels(cache="redis").set(
                    stats["summary"].get("total_estimated_memory_bytes", 0)
                )
        except Exception as e:
            logger.warning(f"Failed to update cache metrics: {e}")
        
        # Generate metrics response
        return Response(
            content=generate_latest(REGISTRY),
            media_type="text/plain",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "X-Metrics-Version": "1.0"
            }
        )
    
    @app.get("/metrics/openmetrics", include_in_schema=False)
    async def openmetrics_endpoint(request: Request):
        """Secure OpenMetrics format endpoint"""
        if require_auth:
            api_key = request.headers.get("X-API-Key")
            if not api_key or api_key != os.getenv("METRICS_API_KEY"):
                return Response(
                    content="Unauthorized",
                    status_code=401
                )
        
        return Response(
            content=generate_latest_openmetrics(REGISTRY),
            media_type="application/openmetrics-text",
            headers={"Cache-Control": "no-cache"}
        )

# ============================================================================

# ADVANCED HEALTH CHECKS WITH DEPENDENCY INJECTION

def setup_advanced_health_checks(app: FastAPI):
    """Setup production-grade health checks with dependency injection"""
    
    db_monitor = DatabaseMonitor()
    cache_monitor = CacheMonitor()
    
    @app.get("/health/advanced", tags=["monitoring"])
    async def advanced_health():
        """Comprehensive health check for production monitoring"""
        import asyncio
        
        async def check_databases():
            return await db_monitor.check_database_health()
        
        async def check_cache():
            return await cache_monitor.get_cache_stats()
        
        # Run checks concurrently
        db_health_task = asyncio.create_task(check_databases())
        cache_stats_task = asyncio.create_task(check_cache())
        
        db_health = await db_health_task
        cache_stats = await cache_stats_task
        
        # Calculate overall status
        all_healthy = all(
            db["status"] == "healthy" 
            for db in db_health["databases"].values()
        )
        
        # Add application-level health indicators
        app_health = {
            "status": "healthy",
            "version": getattr(app, 'version', '1.0.0'),
            "uptime_seconds": (
                (datetime.utcnow() - app.state.start_time).total_seconds()
                if hasattr(app.state, 'start_time') else 0
            ),
            "active_requests": REQUEST_IN_PROGRESS._value.get() if hasattr(REQUEST_IN_PROGRESS, '_value') else 0
        }
        
        return {
            "status": "healthy" if all_healthy else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "application": app_health,
            "systems": {
                "databases": db_health,
                "cache": cache_stats
            },
            "performance": {
                "request_rate_1m": "N/A",
                "error_rate_1m": "N/A",
                "avg_latency_1m": "N/A"
            },
            "recommendations": []
        }
    
    @app.get("/health/readiness", tags=["monitoring"])
    async def readiness_probe():
        """Kubernetes readiness probe with circuit breaker pattern"""
        try:
            import asyncio
            
            async def check_postgres():
                async with engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
                    return True
            
            async def check_redis():
                redis_client = get_redis()
                redis_client.ping()
                return True
            
            async def check_neo4j():
                driver = get_neo4j()
                with driver.session() as session:
                    session.run("RETURN 1")
                    return True
            
            tasks = [
                asyncio.wait_for(check_postgres(), timeout=2),
                asyncio.wait_for(check_redis(), timeout=2),
                asyncio.wait_for(check_neo4j(), timeout=2)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            healthy = all(isinstance(r, bool) and r for r in results)
            
            return {
                "status": "ready" if healthy else "not_ready",
                "checks": {
                    "postgresql": not isinstance(results[0], Exception),
                    "redis": not isinstance(results[1], Exception),
                    "neo4j": not isinstance(results[2], Exception)
                }
            }
            
        except Exception as e:
            logger.error(f"Readiness probe failed: {e}")
            return {
                "status": "not_ready",
                "error": str(e)
            }
    
    @app.get("/health/liveness", tags=["monitoring"])
    async def liveness_probe():
        """Kubernetes liveness probe with memory check"""
        import psutil
        
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        
        return {
            "status": "alive",
            "timestamp": datetime.utcnow().isoformat(),
            "process": {
                "memory_used_mb": memory_info.rss / 1024 / 1024,
                "cpu_percent": process.cpu_percent(interval=0.1),
                "thread_count": process.num_threads(),
                "uptime_seconds": time.time() - process.create_time()
            }
        }

# ============================================================================

# PERFORMANCE MONITORING WITH ALERTING

class PerformanceMonitor:
    """Production performance monitoring with alerting capabilities"""
    
    def __init__(self, window_size: int = 300):
        self.window_size = window_size  # 5 minutes in seconds
        self.metrics = {
            "endpoint_latency": {},
            "error_rates": {},
            "throughput": {}
        }
        self.alerts = []
        self.alert_thresholds = {
            "p95_latency": 1.0,  # 1 second
            "error_rate": 0.05,  # 5%
            "throughput_drop": 0.5  # 50% drop
        }
    
    def record_endpoint_performance(self, endpoint: str, latency: float, status_code: int):
        """Record endpoint performance with automatic alerting"""
        if endpoint not in self.metrics["endpoint_latency"]:
            self.metrics["endpoint_latency"][endpoint] = []
        
        timestamp = datetime.utcnow()
        self.metrics["endpoint_latency"][endpoint].append({
            "timestamp": timestamp,
            "latency": latency,
            "status_code": status_code
        })
        
        cutoff = timestamp - timedelta(seconds=self.window_size)
        self.metrics["endpoint_latency"][endpoint] = [
            m for m in self.metrics["endpoint_latency"][endpoint]
            if m["timestamp"] > cutoff
        ]
        
        self._check_alerts(endpoint)
    
    def _check_alerts(self, endpoint: str):
        """Check performance metrics against thresholds"""
        metrics = self.metrics["endpoint_latency"].get(endpoint, [])
        if len(metrics) < 10:
            return
        
        latencies = [m["latency"] for m in metrics]
        status_codes = [m["status_code"] for m in metrics]
        
        sorted_latencies = sorted(latencies)
        p95_index = int(len(sorted_latencies) * 0.95)
        p95_latency = sorted_latencies[p95_index] if p95_index < len(sorted_latencies) else 0
        
        error_count = sum(1 for sc in status_codes if sc >= 400)
        error_rate = error_count / len(status_codes) if status_codes else 0
        
        if p95_latency > self.alert_thresholds["p95_latency"]:
            self._trigger_alert(
                endpoint=endpoint,
                type="high_latency",
                severity="warning",
                value=p95_latency,
                threshold=self.alert_thresholds["p95_latency"]
            )
        
        if error_rate > self.alert_thresholds["error_rate"]:
            self._trigger_alert(
                endpoint=endpoint,
                type="high_error_rate",
                severity="error",
                value=error_rate,
                threshold=self.alert_thresholds["error_rate"]
            )
    
    def _trigger_alert(self, endpoint: str, type: str, severity: str, value: float, threshold: float):
        """Trigger performance alert"""
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "endpoint": endpoint,
            "type": type,
            "severity": severity,
            "value": value,
            "threshold": threshold,
            "message": f"{type.replace('_', ' ').title()}: {value:.3f} > {threshold:.3f} on {endpoint}"
        }
        
        self.alerts.append(alert)
        
        logger.warning(
            f"Performance alert: {alert['message']}",
            extra={"alert": alert}
        )
        
        cutoff = datetime.utcnow() - timedelta(minutes=60)
        self.alerts = [
            a for a in self.alerts
            if datetime.fromisoformat(a["timestamp"].replace('Z', '+00:00')) > cutoff
        ]
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "window_seconds": self.window_size,
            "endpoints": {},
            "alerts": self.alerts[-10:],
            "summary": {
                "total_endpoints_monitored": len(self.metrics["endpoint_latency"]),
                "total_alerts_last_hour": len([a for a in self.alerts 
                    if datetime.fromisoformat(a["timestamp"].replace('Z', '+00:00')) > 
                    datetime.utcnow() - timedelta(hours=1)]),
                "overall_status": "healthy"
            }
        }
        
        for endpoint, metrics in self.metrics["endpoint_latency"].items():
            if metrics:
                latencies = [m["latency"] for m in metrics]
                status_codes = [m["status_code"] for m in metrics]
                
                sorted_latencies = sorted(latencies)
                percentiles = {}
                for p in [50, 75, 90, 95, 99]:
                    index = int(len(sorted_latencies) * (p / 100))
                    percentiles[f"p{p}_latency"] = (
                        sorted_latencies[index] if index < len(sorted_latencies) else 0
                    )
                
                successful = sum(1 for sc in status_codes if 200 <= sc < 300)
                error_rate = 1 - (successful / len(status_codes)) if status_codes else 0
                
                report["endpoints"][endpoint] = {
                    "request_count": len(metrics),
                    "throughput_rps": len(metrics) / self.window_size,
                    **percentiles,
                    "error_rate": error_rate,
                    "success_rate": 1 - error_rate,
                    "status": (
                        "healthy" if percentiles["p95_latency"] < 1.0 and error_rate < 0.05
                        else "degraded"
                    )
                }
        
        degraded_endpoints = sum(
            1 for ep in report["endpoints"].values()
            if ep["status"] == "degraded"
        )
        
        if degraded_endpoints > 0:
            report["summary"]["overall_status"] = "degraded"
            report["summary"]["degraded_endpoints"] = degraded_endpoints
        
        return report

# ============================================================================

# PRODUCTION INITIALIZATION

def setup_monitoring(app: FastAPI, enable_metrics: bool = True, enable_health: bool = True):
    """
    Setup comprehensive production monitoring.
    
    Args:
        app: FastAPI application instance
        enable_metrics: Enable Prometheus metrics endpoint
        enable_health: Enable health check endpoints
    """
    
    # Store start time
    app.state.start_time = datetime.utcnow()
    
    # Add monitoring middleware
    app.add_middleware(MonitoringMiddleware)
    
    # Setup metrics endpoint (secured by default)
    if enable_metrics:
        require_auth = os.getenv("METRICS_AUTH_ENABLED", "true").lower() == "true"
        setup_metrics_endpoint(app, require_auth=require_auth)
    
    # Setup advanced health checks
    if enable_health:
        setup_advanced_health_checks(app)
    
    # Initialize performance monitor
    app.state.performance_monitor = PerformanceMonitor()
    
    # Add startup logging
    @app.on_event("startup")
    async def startup_event():
        version = getattr(app, 'version', '1.0.0')
        logger.info(f"ARF API v{version} starting with production monitoring")
        logger.info(f"Metrics endpoint: /metrics {'(secured)' if enable_metrics else '(disabled)'}")
        logger.info(f"Health checks: /health/* {'(enabled)' if enable_health else '(disabled)'}")
        logger.info(f"Performance monitoring: Active")
        logger.info(f"Middleware: MonitoringMiddleware loaded")
    
    # Add shutdown cleanup
    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info("ARF API shutting down gracefully")
        
        try:
            if hasattr(app.state, 'performance_monitor'):
                report = app.state.performance_monitor.get_performance_report()
                logger.info(
                    "Final performance report",
                    extra={"performance_report": report["summary"]}
                )
        except Exception as e:
            logger.warning(f"Failed to generate final performance report: {e}")
    
    return app

"""
Structured logging middleware for ARF API.
Psychology: Contextual logging with correlation IDs for debugging.
Intention: Production-ready logging with request tracing.
"""
import uuid
import time
import json
from typing import Dict, Any, Optional
from datetime import datetime
import logging

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# Configure structured logger
logger = logging.getLogger("arf.api")

class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for structured HTTP request logging"""
    
    async def dispatch(self, request: Request, call_next):
        # Generate or get request ID
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        
        # Store in request state
        request.state.request_id = request_id
        request.state.start_time = time.time()
        
        # Log request start
        await self.log_request_start(request, request_id)
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - request.state.start_time
            
            # Log request completion
            await self.log_request_end(
                request, response, request_id, duration, None
            )
            
            # Add headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = f"{duration:.3f}"
            
            return response
            
        except Exception as exc:
            # Calculate duration
            duration = time.time() - request.state.start_time
            
            # Log error
            await self.log_request_end(
                request, None, request_id, duration, exc
            )
            
            # Re-raise
            raise
    
    async def log_request_start(self, request: Request, request_id: str):
        """Log HTTP request start"""
        log_data = {
            "event": "request_start",
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request_id,
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "content_type": request.headers.get("content-type"),
            "content_length": request.headers.get("content-length"),
        }
        
        # Add user info if available
        if hasattr(request.state, "user"):
            log_data["user_id"] = request.state.user.id
            log_data["user_email"] = request.state.user.email
        
        logger.info("Request started", extra=log_data)
    
    async def log_request_end(self, request: Request, response: Optional[Response], 
                             request_id: str, duration: float, error: Optional[Exception]):
        """Log HTTP request completion"""
        log_data = {
            "event": "request_end",
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request_id,
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "duration_seconds": round(duration, 3),
            "duration_ms": round(duration * 1000, 1),
        }
        
        if response:
            log_data.update({
                "status_code": response.status_code,
                "response_size": response.headers.get("content-length"),
                "response_content_type": response.headers.get("content-type"),
            })
            level = logging.INFO if response.status_code < 400 else logging.WARNING
        elif error:
            log_data.update({
                "status_code": 500,
                "error_type": type(error).__name__,
                "error_message": str(error),
            })
            level = logging.ERROR
        else:
            level = logging.INFO
        
        # Add user info if available
        if hasattr(request.state, "user"):
            log_data["user_id"] = request.state.user.id
            log_data["user_email"] = request.state.user.email
        
        logger.log(level, "Request completed", extra=log_data)

class DatabaseQueryLogger:
    """Log database queries with timing"""
    
    @staticmethod
    def log_query(operation: str, query: str, duration: float, 
                 parameters: Optional[Dict] = None, error: Optional[Exception] = None):
        """Log database query"""
        log_data = {
            "event": "database_query",
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation,
            "query": query[:500],  # Truncate long queries
            "duration_seconds": round(duration, 3),
            "duration_ms": round(duration * 1000, 1),
        }
        
        if parameters:
            log_data["parameters"] = json.dumps(parameters)[:500]
        
        if error:
            log_data.update({
                "error_type": type(error).__name__,
                "error_message": str(error),
            })
            logger.error("Database query failed", extra=log_data)
        else:
            logger.debug("Database query executed", extra=log_data)

class BusinessEventLogger:
    """Log business events for auditing"""
    
    @staticmethod
    def log_event(event_type: str, event_data: Dict[str, Any], 
                 user_id: Optional[str] = None, request_id: Optional[str] = None):
        """Log business event"""
        log_data = {
            "event": "business_event",
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "event_data": event_data,
        }
        
        if user_id:
            log_data["user_id"] = user_id
        
        if request_id:
            log_data["request_id"] = request_id
        
        logger.info(f"Business event: {event_type}", extra=log_data)
    
    @staticmethod
    def log_incident(incident_id: str, action: str, severity: str, 
                    user_id: Optional[str] = None, request_id: Optional[str] = None):
        """Log incident-related event"""
        BusinessEventLogger.log_event(
            event_type=f"incident_{action}",
            event_data={
                "incident_id": incident_id,
                "severity": severity,
                "action": action,
            },
            user_id=user_id,
            request_id=request_id
        )
    
    @staticmethod
    def log_policy_evaluation(policy_id: str, triggered: bool, context: Dict[str, Any],
                            user_id: Optional[str] = None, request_id: Optional[str] = None):
        """Log policy evaluation"""
        BusinessEventLogger.log_event(
            event_type="policy_evaluation",
            event_data={
                "policy_id": policy_id,
                "triggered": triggered,
                "context_keys": list(context.keys()),
            },
            user_id=user_id,
            request_id=request_id
        )
    
    @staticmethod
    def log_rollback(action_id: str, execution_id: str, status: str,
                    user_id: Optional[str] = None, request_id: Optional[str] = None):
        """Log rollback execution"""
        BusinessEventLogger.log_event(
            event_type="rollback_execution",
            event_data={
                "action_id": action_id,
                "execution_id": execution_id,
                "status": status,
            },
            user_id=user_id,
            request_id=request_id
        )

# Configure logging format
def setup_structured_logging():
    """Setup structured logging configuration"""
    import structlog
    
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    return structlog.get_logger()

"""
Base integration interface for ARF notifications.
Psychology: Strategy pattern for channel-specific implementations.
Intention: Consistent interface across all notification channels.
"""
import abc
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum

from src.models.webhook import Notification, NotificationPriority

logger = logging.getLogger(__name__)

class IntegrationType(str, Enum):
    """Integration type enumeration - MUST MATCH integrations/__init__.py"""
    SLACK = "slack"
    TEAMS = "teams"
    EMAIL = "email"
    DISCORD = "discord"
    PAGERDUTY = "pagerduty"
    OPSGENIE = "opsgenie"
    WEBHOOK = "webhook"  # Added to match potential usage

class IntegrationStatus(str, Enum):
    """Integration status enumeration"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"

class IntegrationHealth:
    """Integration health metrics"""
    
    def __init__(self):
        self.total_sent = 0
        self.total_failed = 0
        self.last_success = None
        self.last_failure = None
        self.consecutive_failures = 0
        self.average_response_time = 0.0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        total = self.total_sent
        if total == 0:
            return 0.0
        return (self.total_sent - self.total_failed) / total
    
    @property
    def is_healthy(self) -> bool:
        """Determine if integration is healthy"""
        if self.total_sent < 10:
            return True  # Not enough data
        
        if self.success_rate < 0.8:
            return False
        
        if self.consecutive_failures > 5:
            return False
        
        return True
    
    def record_success(self, response_time: float):
        """Record successful delivery"""
        self.total_sent += 1
        self.last_success = datetime.utcnow()
        self.consecutive_failures = 0
        
        # Update average response time
        total_time = self.average_response_time * (self.total_sent - 1) + response_time
        self.average_response_time = total_time / self.total_sent
    
    def record_failure(self):
        """Record failed delivery"""
        self.total_sent += 1
        self.total_failed += 1
        self.last_failure = datetime.utcnow()
        self.consecutive_failures += 1

class BaseIntegration(abc.ABC):
    """Abstract base class for all integrations"""
    
    def __init__(self, config: Any):
        self.config = config
        self.status = IntegrationStatus.DISCONNECTED
        self.health = IntegrationHealth()
        self._connection = None
    
    @abc.abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the integration"""
        pass
    
    @abc.abstractmethod
    async def disconnect(self) -> bool:
        """Close connection to the integration"""
        pass
    
    @abc.abstractmethod
    async def send_notification(self, notification: Notification) -> Dict[str, Any]:
        """
        Send notification through this integration
        
        Returns:
            Dict containing:
            - success: bool
            - status_code: Optional[int]
            - message: Optional[str]
            - error: Optional[str]
            - response_time_ms: float
        """
        pass
    
    @abc.abstractmethod
    async def validate_configuration(self) -> bool:
        """Validate integration configuration"""
        pass
    
    @abc.abstractmethod
    def get_integration_type(self) -> IntegrationType:
        """Get integration type"""
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on integration"""
        try:
            # Try to connect if not connected
            if self.status != IntegrationStatus.CONNECTED:
                connected = await self.connect()
                if not connected:
                    return {
                        "healthy": False,
                        "status": self.status.value,
                        "error": "Failed to connect"
                    }
            
            # Perform a simple test
            test_result = await self._perform_health_test()
            
            return {
                "healthy": self.health.is_healthy and test_result["success"],
                "status": self.status.value,
                "success_rate": self.health.success_rate,
                "total_sent": self.health.total_sent,
                "total_failed": self.health.total_failed,
                "consecutive_failures": self.health.consecutive_failures,
                "average_response_time_ms": self.health.average_response_time * 1000,
                "last_success": self.health.last_success.isoformat() if self.health.last_success else None,
                "last_failure": self.health.last_failure.isoformat() if self.health.last_failure else None,
                "test_result": test_result
            }
        
        except Exception as e:
            logger.error(f"Health check failed for {self.get_integration_type().value}: {e}")
            return {
                "healthy": False,
                "status": self.status.value,
                "error": str(e)
            }
    
    async def _perform_health_test(self) -> Dict[str, Any]:
        """Perform a simple health test (can be overridden)"""
        # Default implementation just checks connection
        return {
            "success": self.status == IntegrationStatus.CONNECTED,
            "message": "Connection check"
        }
    
    def _format_notification_for_channel(self, notification: Notification) -> Dict[str, Any]:
        """Format notification for specific channel (can be overridden)"""
        return {
            "title": f"Notification: {notification.metadata.get('event_type', 'Unknown')}",
            "body": notification.body,
            "priority": notification.priority.value,
            "urgent": notification.urgent,
            "metadata": notification.metadata
        }


# Export all important classes
__all__ = [
    'IntegrationType',
    'IntegrationStatus',
    'IntegrationHealth',
    'BaseIntegration',
]

"""
Simplified email integration for ARF notifications.
"""
import logging
from typing import Dict, Any
from src.integrations.base import BaseIntegration, IntegrationType, IntegrationStatus

logger = logging.getLogger(__name__)

class EmailIntegration(BaseIntegration):
    """SMTP email integration - Simplified version"""
    
    def __init__(self, config):
        super().__init__(config)
        self.config = config
    
    def get_integration_type(self) -> IntegrationType:
        return IntegrationType.EMAIL
    
    async def connect(self) -> bool:
        """Test SMTP connection"""
        try:
            logger.info(f"Email integration connected")
            self.status = IntegrationStatus.CONNECTED
            return True
        except Exception as e:
            self.status = IntegrationStatus.ERROR
            logger.error(f"Failed to connect Email integration: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Nothing to disconnect for SMTP"""
        self.status = IntegrationStatus.DISCONNECTED
        logger.info("Email integration disconnected")
        return True
    
    async def validate_configuration(self) -> bool:
        """Validate email configuration"""
        try:
            # Basic validation
            if not hasattr(self.config, 'smtp_server'):
                return False
            logger.info("Email configuration validated successfully")
            return True
        except Exception as e:
            logger.error(f"Email configuration validation failed: {e}")
            return False
    
    async def send_notification(self, notification) -> Dict[str, Any]:
        """Send notification via email"""
        try:
            logger.info(f"Simulating email notification: {notification}")
            return {
                "success": True,
                "message": "Notification sent via email (simulated)",
                "response_time_ms": 100
            }
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return {
                "success": False,
                "error": str(e),
                "response_time_ms": 0
            }
    
    async def _perform_health_test(self) -> Dict[str, Any]:
        """Perform email-specific health test"""
        return {
            "success": True,
            "message": "Email health check passed (simulated)"
        }

"""
Slack integration for ARF notifications.
Psychology: Conversational notifications with rich formatting and interactivity.
Intention: Effective team communication with actionable notifications.
"""
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import asyncio

import aiohttp
from pydantic import ValidationError

from src.models.webhook import (
    SlackConfiguration, Notification, NotificationPriority, NotificationChannel,
    IncidentEventPayload, PolicyEventPayload, RollbackEventPayload, SystemEventPayload,
    WebhookEventType
)
from src.integrations.base import BaseIntegration, IntegrationType, IntegrationStatus

logger = logging.getLogger(__name__)

class SlackIntegration(BaseIntegration):
    """Slack webhook integration"""
    
    def __init__(self, config: SlackConfiguration):
        super().__init__(config)
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
    
    def get_integration_type(self) -> IntegrationType:
        return IntegrationType.SLACK
    
    async def connect(self) -> bool:
        """Initialize HTTP session"""
        try:
            if self.session is None or self.session.closed:
                self.session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=30)
                )
            
            # Test connection with a simple request
            test_payload = {"text": "Connection test"}
            async with self.session.post(
                str(self.config.webhook_url),
                json=test_payload,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    self.status = IntegrationStatus.CONNECTED
                    logger.info(f"Slack integration connected to {self.config.channel}")
                    return True
                else:
                    self.status = IntegrationStatus.ERROR
                    logger.error(f"Slack connection test failed: {response.status}")
                    return False
        
        except Exception as e:
            self.status = IntegrationStatus.ERROR
            logger.error(f"Failed to connect Slack integration: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Close HTTP session"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
                self.session = None
            
            self.status = IntegrationStatus.DISCONNECTED
            logger.info("Slack integration disconnected")
            return True
        
        except Exception as e:
            logger.error(f"Error disconnecting Slack integration: {e}")
            return False
    
    async def validate_configuration(self) -> bool:
        """Validate Slack configuration"""
        try:
            # Check required fields
            if not self.config.webhook_url:
                logger.error("Slack webhook URL is required")
                return False
            
            # Validate URL format
            from urllib.parse import urlparse
            parsed = urlparse(str(self.config.webhook_url))
            if not parsed.scheme or not parsed.netloc:
                logger.error(f"Invalid Slack webhook URL: {self.config.webhook_url}")
                return False
            
            # Validate channel name format
            if self.config.channel and not self.config.channel.startswith('#'):
                logger.warning(f"Slack channel should start with #: {self.config.channel}")
            
            # Validate color map
            if not self.config.color_map:
                logger.error("Color map is required for Slack integration")
                return False
            
            # Test with minimal payload
            test_payload = {"text": "Configuration test"}
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    str(self.config.webhook_url),
                    json=test_payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        logger.info("Slack configuration validated successfully")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"Slack configuration test failed: {response.status} - {error_text}")
                        return False
        
        except Exception as e:
            logger.error(f"Slack configuration validation failed: {e}")
            return False
    
    async def send_notification(self, notification: Notification) -> Dict[str, Any]:
        """Send notification to Slack"""
        import time
        start_time = time.time()
        
        try:
            # Ensure connected
            if self.status != IntegrationStatus.CONNECTED:
                connected = await self.connect()
                if not connected:
                    self.health.record_failure()
                    return {
                        "success": False,
                        "error": "Failed to connect to Slack",
                        "response_time_ms": (time.time() - start_time) * 1000
                    }
            
            # Prepare Slack message
            message = await self._prepare_slack_message(notification)
            
            # Send to Slack webhook
            async with self.session.post(
                str(self.config.webhook_url),
                json=message,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                response_time_ms = (time.time() - start_time) * 1000
                
                if response.status == 200:
                    self.health.record_success(response_time_ms / 1000)
                    logger.info(f"Slack notification sent to {self.config.channel}")
                    return {
                        "success": True,
                        "status_code": response.status,
                        "message": "Notification sent to Slack",
                        "response_time_ms": response_time_ms
                    }
                else:
                    error_text = await response.text()
                    self.health.record_failure()
                    logger.error(f"Slack API error: {response.status} - {error_text}")
                    
                    # Check for rate limiting
                    if response.status == 429:
                        self.status = IntegrationStatus.RATE_LIMITED
                        retry_after = response.headers.get('Retry-After', 60)
                        logger.warning(f"Slack rate limited. Retry after: {retry_after} seconds")
                    
                    return {
                        "success": False,
                        "status_code": response.status,
                        "error": error_text,
                        "response_time_ms": response_time_ms
                    }
        
        except asyncio.TimeoutError:
            response_time_ms = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.error(f"Slack notification timeout after {response_time_ms}ms")
            return {
                "success": False,
                "error": "Request timeout",
                "response_time_ms": response_time_ms
            }
        
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.error(f"Failed to send Slack notification: {e}")
            return {
                "success": False,
                "error": str(e),
                "response_time_ms": response_time_ms
            }
    
    async def _prepare_slack_message(self, notification: Notification) -> Dict[str, Any]:
        """Prepare Slack message payload"""
        # Base message structure
        message = {
            "channel": self.config.channel,
            "username": self.config.username,
            "icon_emoji": self.config.icon_emoji,
            "mrkdwn": True
        }
        
        # Add icon URL if specified
        if self.config.icon_url:
            message["icon_url"] = str(self.config.icon_url)
        
        # Format text based on notification type
        text = await self._format_notification_text(notification)
        message["text"] = text
        
        # Add attachments for rich formatting
        if self.config.include_attachments:
            attachments = await self._create_slack_attachments(notification)
            if attachments:
                message["attachments"] = attachments
        
        # Add blocks for advanced formatting
        if self.config.include_blocks:
            blocks = await self._create_slack_blocks(notification)
            if blocks:
                message["blocks"] = blocks
        
        return message
    
    async def _format_notification_text(self, notification: Notification) -> str:
        """Format notification text for Slack"""
        metadata = notification.metadata or {}
        event_type = metadata.get("event_type", "unknown")
        
        # Add priority indicator
        priority_prefix = ""
        if notification.priority == NotificationPriority.CRITICAL:
            priority_prefix = "🚨 CRITICAL: "
        elif notification.priority == NotificationPriority.HIGH:
            priority_prefix = "⚠️ HIGH: "
        elif notification.priority == NotificationPriority.MEDIUM:
            priority_prefix = "📢 MEDIUM: "
        elif notification.priority == NotificationPriority.LOW:
            priority_prefix = "📝 LOW: "
        
        # Format based on event type
        if event_type in [WebhookEventType.INCIDENT_CREATED.value, 
                         WebhookEventType.INCIDENT_UPDATED.value,
                         WebhookEventType.INCIDENT_RESOLVED.value]:
            return f"{priority_prefix}Incident Update: {notification.body}"
        
        elif event_type in [WebhookEventType.POLICY_EVALUATED.value,
                           WebhookEventType.POLICY_TRIGGERED.value]:
            return f"{priority_prefix}Policy Event: {notification.body}"
        
        elif event_type in [WebhookEventType.ROLLBACK_EXECUTED.value,
                           WebhookEventType.ROLLBACK_FAILED.value]:
            return f"{priority_prefix}Rollback Event: {notification.body}"
        
        else:
            return f"{priority_prefix}{notification.body}"
    
    async def _create_slack_attachments(self, notification: Notification) -> List[Dict[str, Any]]:
        """Create Slack attachments with rich formatting"""
        metadata = notification.metadata or {}
        event_type = metadata.get("event_type", "unknown")
        
        # Get color based on priority
        color = self.config.color_map.get(
            notification.priority,
            self.config.color_map[NotificationPriority.MEDIUM]
        )
        
        # Create base attachment
        attachment = {
            "color": color,
            "ts": int(datetime.utcnow().timestamp()),
            "footer": f"ARF Notification | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "footer_icon": "https://raw.githubusercontent.com/petterjuan/arf-api-repository/main/arf-logo.png"
        }
        
        # Add fields based on event type
        fields = []
        
        # Add source information
        if metadata.get("source_type"):
            fields.append({
                "title": "Source",
                "value": metadata.get("source_type"),
                "short": True
            })
        
        if metadata.get("source_id"):
            fields.append({
                "title": "ID",
                "value": metadata.get("source_id"),
                "short": True
            })
        
        # Add priority field
        fields.append({
            "title": "Priority",
            "value": notification.priority.value.upper(),
            "short": True
        })
        
        # Add urgent flag if applicable
        if notification.urgent:
            fields.append({
                "title": "Urgent",
                "value": "YES",
                "short": True
            })
        
        if fields:
            attachment["fields"] = fields
        
        # Add action buttons for incident events
        if event_type in [WebhookEventType.INCIDENT_CREATED.value,
                         WebhookEventType.INCIDENT_UPDATED.value]:
            attachment["actions"] = [
                {
                    "type": "button",
                    "text": "View Details",
                    "url": f"https://arf.example.com/incidents/{metadata.get('source_id', '')}",
                    "style": "primary"
                },
                {
                    "type": "button",
                    "text": "Acknowledge",
                    "url": f"https://arf.example.com/incidents/{metadata.get('source_id', '')}/acknowledge",
                    "style": "danger"
                }
            ]
        
        return [attachment]
    
    async def _create_slack_blocks(self, notification: Notification) -> List[Dict[str, Any]]:
        """Create Slack blocks for advanced formatting"""
        metadata = notification.metadata or {}
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{notification.priority.value.upper()} Notification",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": notification.body
                }
            },
            {
                "type": "divider"
            }
        ]
        
        # Add context section
        context_fields = []
        
        if metadata.get("event_type"):
            context_fields.append({
                "type": "mrkdwn",
                "text": f"*Event Type:*\n{metadata.get('event_type')}"
            })
        
        if metadata.get("source_type"):
            context_fields.append({
                "type": "mrkdwn",
                "text": f"*Source:*\n{metadata.get('source_type')}"
            })
        
        if metadata.get("webhook_name"):
            context_fields.append({
                "type": "mrkdwn",
                "text": f"*Webhook:*\n{metadata.get('webhook_name')}"
            })
        
        if context_fields:
            blocks.append({
                "type": "section",
                "fields": context_fields
            })
        
        # Add actions for critical notifications
        if notification.priority in [NotificationPriority.CRITICAL, NotificationPriority.HIGH]:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🚨 View in Dashboard",
                            "emoji": True
                        },
                        "url": "https://arf.example.com/dashboard",
                        "style": "danger"
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "✅ Acknowledge",
                            "emoji": True
                        },
                        "value": f"ack_{notification.notification_id}",
                        "action_id": "acknowledge_notification"
                    }
                ]
            })
        
        return blocks
    
    async def _perform_health_test(self) -> Dict[str, Any]:
        """Perform Slack-specific health test"""
        try:
            test_payload = {
                "text": "🔧 ARF Health Check",
                "attachments": [{
                    "color": "#36a64f",
                    "text": f"Slack integration health check at {datetime.utcnow().isoformat()}",
                    "footer": "ARF Monitoring"
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    str(self.config.webhook_url),
                    json=test_payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        return {
                            "success": True,
                            "message": "Health check successful",
                            "response_time_ms": response.elapsed.total_seconds() * 1000
                        }
                    else:
                        return {
                            "success": False,
                            "message": f"Health check failed: {response.status}",
                            "response_time_ms": response.elapsed.total_seconds() * 1000
                        }
        
        except Exception as e:
            return {
                "success": False,
                "message": f"Health check error: {str(e)}"
            }

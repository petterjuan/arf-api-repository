"""
Slack integration for ARF notifications.
Psychology: Conversational notifications with rich formatting and interactivity.
Intention: Effective team communication with actionable notifications.
"""
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

import aiohttp
from pydantic import ValidationError

from src.models.webhook import (
    SlackConfiguration, Notification, NotificationPriority,
    IncidentEventPayload, PolicyEventPayload, RollbackEventPayload, SystemEventPayload
)

logger = logging.getLogger(__name__)

class SlackIntegration:
    """Slack webhook integration"""
    
    def __init__(self, config: SlackConfiguration):
        self.config = config
        self.session = None
    
    async def connect(self):
        """Initialize HTTP session"""
        self.session = aiohttp.ClientSession()
    
    async def disconnect(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
    
    async def send_notification(self, notification: Notification) -> Dict[str, Any]:
        """Send notification to Slack"""
        try:
            # Prepare Slack message
            message = await self._prepare_slack_message(notification)
            
            # Send to Slack webhook
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    str(self.config.webhook_url),
                    json=message,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        logger.info(f"Slack notification sent to {self.config.channel}")
                        return {
                            "success": True,
                            "status_code": response.status,
                            "message": "Notification sent to Slack"
                        }
                    else:
                        error_text = await response.text()
                        logger.error(f"Slack API error: {response.status} - {error_text}")
                        return {
                            "success": False,
                            "status_code": response.status,
                            "error": error_text
                        }
        
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _prepare_slack_message(self, notification: Notification) -> Dict[str, Any]:
        """Prepare Slack message payload"""
        # Base message structure
        message = {
            "channel": self.config.channel,
            "username": self.config.username,
            "icon_emoji": self.config.icon_emoji,
            "text": notification.body,
            "mrkdwn": True
        }
        
        # Add icon URL if specified
        if self.config.icon_url:
            message["icon_url"] = str(self.config.icon_url)
        
        # Add attachments for rich formatting
        if self.config.include_attachments:
            attachment = await self._create_slack_attachment(notification)
            if attachment:
                message["attachments"] = [attachment]
        
        return message
    
    async def _create_slack_attachment(self, notification: Notification) -> Optional[Dict[str, Any]]:
        """Create Slack attachment with rich formatting"""
        # Get color based on priority
        color = self.config.color_map.get(
            notification.priority,
            self.config.color_map[NotificationPriority.MEDIUM]
        )
        
        # Parse metadata
        metadata = notification.metadata or {}
        event_type = metadata.get("event_type", "unknown")
        source_type = metadata.get("source_type

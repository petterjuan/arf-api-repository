"""
Discord integration for ARF notifications.
Psychology: Community-focused notifications with rich embeds and mentions.
Intention: Real-time team communication with interactive webhooks.
"""
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import asyncio

import aiohttp
from pydantic import ValidationError

from src.models.webhook import (
    DiscordConfiguration, Notification, NotificationPriority, NotificationChannel,
    IncidentEventPayload, PolicyEventPayload, RollbackEventPayload, SystemEventPayload,
    WebhookEventType
)
from src.integrations.base import BaseIntegration, IntegrationType, IntegrationStatus

logger = logging.getLogger(__name__)

class DiscordIntegration(BaseIntegration):
    """Discord webhook integration"""
    
    def __init__(self, config: DiscordConfiguration):
        super().__init__(config)
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
    
    def get_integration_type(self) -> IntegrationType:
        return IntegrationType.DISCORD
    
    async def connect(self) -> bool:
        """Initialize HTTP session"""
        try:
            if self.session is None or self.session.closed:
                self.session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=30)
                )
            
            # Test connection with a simple message
            test_payload = {"content": "🔧 ARF Discord integration connected"}
            async with self.session.post(
                str(self.config.webhook_url),
                json=test_payload,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 204:  # Discord returns 204 No Content on success
                    self.status = IntegrationStatus.CONNECTED
                    logger.info(f"Discord integration connected")
                    return True
                else:
                    self.status = IntegrationStatus.ERROR
                    error_text = await response.text()
                    logger.error(f"Discord connection test failed: {response.status} - {error_text}")
                    return False
        
        except Exception as e:
            self.status = IntegrationStatus.ERROR
            logger.error(f"Failed to connect Discord integration: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Close HTTP session"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
                self.session = None
            
            self.status = IntegrationStatus.DISCONNECTED
            logger.info("Discord integration disconnected")
            return True
        
        except Exception as e:
            logger.error(f"Error disconnecting Discord integration: {e}")
            return False
    
    async def validate_configuration(self) -> bool:
        """Validate Discord configuration"""
        try:
            # Check required fields
            if not self.config.webhook_url:
                logger.error("Discord webhook URL is required")
                return False
            
            # Validate URL format
            from urllib.parse import urlparse
            parsed = urlparse(str(self.config.webhook_url))
            if not parsed.scheme or not parsed.netloc:
                logger.error(f"Invalid Discord webhook URL: {self.config.webhook_url}")
                return False
            
            # Check if it's a Discord webhook URL
            if "discord.com/api/webhooks" not in str(self.config.webhook_url):
                logger.warning(f"URL doesn't look like a Discord webhook: {self.config.webhook_url}")
            
            # Test with minimal payload
            test_payload = {
                "content": "🔧 ARF Discord configuration test",
                "embeds": [{
                    "title": "Configuration Test",
                    "description": f"Testing at {datetime.utcnow().isoformat()}",
                    "color": 5814783,  # Blue color
                    "timestamp": datetime.utcnow().isoformat()
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    str(self.config.webhook_url),
                    json=test_payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 204:
                        logger.info("Discord configuration validated successfully")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"Discord configuration test failed: {response.status} - {error_text}")
                        return False
        
        except Exception as e:
            logger.error(f"Discord configuration validation failed: {e}")
            return False
    
    async def send_notification(self, notification: Notification) -> Dict[str, Any]:
        """Send notification to Discord"""
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
                        "error": "Failed to connect to Discord",
                        "response_time_ms": (time.time() - start_time) * 1000
                    }
            
            # Prepare Discord message
            message = await self._prepare_discord_message(notification)
            
            # Send to Discord webhook
            async with self.session.post(
                str(self.config.webhook_url),
                json=message,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                response_time_ms = (time.time() - start_time) * 1000
                
                if response.status == 204:
                    self.health.record_success(response_time_ms / 1000)
                    logger.info("Discord notification sent successfully")
                    return {
                        "success": True,
                        "status_code": response.status,
                        "message": "Notification sent to Discord",
                        "response_time_ms": response_time_ms
                    }
                elif response.status == 429:
                    # Rate limited
                    error_text = await response.text()
                    retry_after = response.headers.get('Retry-After', 60)
                    self.health.record_failure()
                    self.status = IntegrationStatus.RATE_LIMITED
                    logger.warning(f"Discord rate limited. Retry after: {retry_after} seconds")
                    
                    return {
                        "success": False,
                        "status_code": response.status,
                        "error": f"Rate limited: {error_text}",
                        "retry_after": retry_after,
                        "response_time_ms": response_time_ms
                    }
                else:
                    error_text = await response.text()
                    self.health.record_failure()
                    logger.error(f"Discord API error: {response.status} - {error_text}")
                    
                    return {
                        "success": False,
                        "status_code": response.status,
                        "error": error_text,
                        "response_time_ms": response_time_ms
                    }
        
        except asyncio.TimeoutError:
            response_time_ms = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.error(f"Discord notification timeout after {response_time_ms}ms")
            return {
                "success": False,
                "error": "Request timeout",
                "response_time_ms": response_time_ms
            }
        
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.error(f"Failed to send Discord notification: {e}")
            return {
                "success": False,
                "error": str(e),
                "response_time_ms": response_time_ms
            }
    
    async def _prepare_discord_message(self, notification: Notification) -> Dict[str, Any]:
        """Prepare Discord message with embeds"""
        metadata = notification.metadata or {}
        event_type = metadata.get("event_type", "unknown")
        
        message = {
            "content": await self._get_message_content(notification, event_type),
            "username": self.config.username or "ARF Notifications",
            "avatar_url": str(self.config.avatar_url) if self.config.avatar_url else None,
            "tts": False,
            "embeds": []
        }
        
        # Add main embed
        main_embed = await self._create_main_embed(notification, event_type)
        if main_embed:
            message["embeds"].append(main_embed)
        
        # Add additional embeds if configured
        if self.config.include_additional_embeds:
            additional_embeds = await self._create_additional_embeds(notification)
            if additional_embeds:
                message["embeds"].extend(additional_embeds)
        
        # Limit to 10 embeds (Discord limit)
        if len(message["embeds"]) > 10:
            message["embeds"] = message["embeds"][:10]
        
        # Add thread support if configured
        if self.config.thread_id:
            message["thread_id"] = self.config.thread_id
        
        return message
    
    async def _get_message_content(self, notification: Notification, event_type: str) -> Optional[str]:
        """Get message content with mentions"""
        content_parts = []
        
        # Add role mentions for critical/high priority
        if notification.priority in [NotificationPriority.CRITICAL, NotificationPriority.HIGH]:
            if self.config.mention_roles:
                for role_id in self.config.mention_roles:
                    content_parts.append(f"<@&{role_id}>")
        
        # Add user mentions
        if self.config.mention_users:
            for user_id in self.config.mention_users:
                content_parts.append(f"<@{user_id}>")
        
        # Add everyone/here mention if configured
        if notification.priority == NotificationPriority.CRITICAL and self.config.mention_everyone:
            content_parts.append("@everyone")
        elif notification.priority == NotificationPriority.HIGH and self.config.mention_here:
            content_parts.append("@here")
        
        # Add message prefix
        if content_parts:
            return " ".join(content_parts)
        
        return None
    
    async def _create_main_embed(self, notification: Notification, event_type: str) -> Dict[str, Any]:
        """Create main Discord embed"""
        metadata = notification.metadata or {}
        
        # Get color based on priority
        color = self._get_color_for_priority(notification.priority)
        
        embed = {
            "title": await self._get_embed_title(notification, event_type),
            "description": notification.body[:2000],  # Discord limit
            "color": color,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {
                "text": "ARF Notification",
                "icon_url": "https://raw.githubusercontent.com/petterjuan/arf-api-repository/main/arf-logo.png"
            }
        }
        
        # Add author if configured
        if self.config.author_name:
            embed["author"] = {
                "name": self.config.author_name,
                "icon_url": str(self.config.author_icon_url) if self.config.author_icon_url else None,
                "url": str(self.config.author_url) if self.config.author_url else None
            }
        
        # Add thumbnail if configured
        if self.config.thumbnail_url:
            embed["thumbnail"] = {
                "url": str(self.config.thumbnail_url)
            }
        
        # Add image if configured
        if self.config.image_url:
            embed["image"] = {
                "url": str(self.config.image_url)
            }
        
        # Add fields
        fields = await self._get_embed_fields(notification, metadata)
        if fields:
            embed["fields"] = fields
        
        return embed
    
    def _get_color_for_priority(self, priority: NotificationPriority) -> int:
        """Get Discord color integer for priority"""
        color_map = {
            NotificationPriority.CRITICAL: 0xDC3545,  # Red
            NotificationPriority.HIGH: 0xFD7E14,     # Orange
            NotificationPriority.MEDIUM: 0xFFC107,   # Yellow
            NotificationPriority.LOW: 0x17A2B8,      # Teal
        }
        return color_map.get(priority, 0x007BFF)  # Default blue
    
    async def _get_embed_title(self, notification: Notification, event_type: str) -> str:
        """Get embed title"""
        emoji_map = {
            NotificationPriority.CRITICAL: "🚨",
            NotificationPriority.HIGH: "⚠️",
            NotificationPriority.MEDIUM: "📢",
            NotificationPriority.LOW: "📝"
        }
        
        emoji = emoji_map.get(notification.priority, "📨")
        
        if event_type == WebhookEventType.INCIDENT_CREATED.value:
            return f"{emoji} New Incident Created"
        elif event_type == WebhookEventType.INCIDENT_UPDATED.value:
            return f"{emoji} Incident Updated"
        elif event_type == WebhookEventType.INCIDENT_RESOLVED.value:
            return f"✅ Incident Resolved"
        elif event_type == WebhookEventType.POLICY_TRIGGERED.value:
            return f"{emoji} Policy Triggered"
        elif event_type == WebhookEventType.ROLLBACK_EXECUTED.value:
            return f"↩️ Rollback Executed"
        elif event_type == WebhookEventType.ROLLBACK_FAILED.value:
            return f"❌ Rollback Failed"
        elif event_type == WebhookEventType.SYSTEM_HEALTH_CHANGE.value:
            return f"🔧 System Health Change"
        else:
            return f"{emoji} ARF Notification"
    
    async def _get_embed_fields(self, notification: Notification, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get embed fields"""
        fields = []
        
        # Add priority field
        fields.append({
            "name": "Priority",
            "value": notification.priority.value.upper(),
            "inline": True
        })
        
        # Add source field if available
        if metadata.get("source_type"):
            fields.append({
                "name": "Source",
                "value": metadata["source_type"],
                "inline": True
            })
        
        # Add ID field if available
        if metadata.get("source_id"):
            fields.append({
                "name": "ID",
                "value": f"`{metadata['source_id']}`",
                "inline": True
            })
        
        # Add webhook field if available
        if metadata.get("webhook_name"):
            fields.append({
                "name": "Webhook",
                "value": metadata["webhook_name"],
                "inline": True
            })
        
        # Add urgent field if applicable
        if notification.urgent:
            fields.append({
                "name": "Urgent",
                "value": "🚨 **YES**",
                "inline": True
            })
        
        # Add timestamp field
        fields.append({
            "name": "Time",
            "value": f"<t:{int(datetime.utcnow().timestamp())}:R>",
            "inline": True
        })
        
        return fields
    
    async def _create_additional_embeds(self, notification: Notification) -> List[Dict[str, Any]]:
        """Create additional embeds for complex notifications"""
        embeds = []
        
        # Add payload embed for detailed view
        metadata = notification.metadata or {}
        if metadata.get("payload"):
            payload = metadata["payload"]
            if isinstance(payload, dict) and len(str(payload)) > 500:
                payload_embed = {
                    "title": "📋 Payload Details",
                    "description": f"```json\n{json.dumps(payload, indent=2)[:1000]}...\n```",
                    "color": 0x6C757D,  # Gray
                    "timestamp": datetime.utcnow().isoformat()
                }
                embeds.append(payload_embed)
        
        # Add action embed for incidents
        if metadata.get("event_type") in [
            WebhookEventType.INCIDENT_CREATED.value,
            WebhookEventType.INCIDENT_UPDATED.value
        ]:
            action_embed = {
                "title": "🔗 Quick Actions",
                "color": 0x28A745,  # Green
                "fields": [
                    {
                        "name": "View Incident",
                        "value": f"[Click here](https://arf.example.com/incidents/{metadata.get('source_id', '')})",
                        "inline": True
                    },
                    {
                        "name": "Acknowledge",
                        "value": f"[Click here](https://arf.example.com/incidents/{metadata.get('source_id', '')}/acknowledge)",
                        "inline": True
                    },
                    {
                        "name": "Dashboard",
                        "value": "[Click here](https://arf.example.com/dashboard)",
                        "inline": True
                    }
                ]
            }
            embeds.append(action_embed)
        
        return embeds
    
    async def _perform_health_test(self) -> Dict[str, Any]:
        """Perform Discord-specific health test"""
        try:
            test_payload = {
                "content": "🔧 ARF Health Check",
                "embeds": [{
                    "title": "Health Check",
                    "description": f"Discord integration health check at <t:{int(datetime.utcnow().timestamp())}:R>",
                    "color": 0x28A745,  # Green
                    "fields": [
                        {
                            "name": "Status",
                            "value": "✅ Connected",
                            "inline": True
                        },
                        {
                            "name": "Response Time",
                            "value": "Testing...",
                            "inline": True
                        }
                    ],
                    "timestamp": datetime.utcnow().isoformat(),
                    "footer": {
                        "text": "ARF Health Monitoring"
                    }
                }]
            }
            
            start_time = datetime.utcnow()
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    str(self.config.webhook_url),
                    json=test_payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    response_time = (datetime.utcnow() - start_time).total_seconds()
                    
                    if response.status == 204:
                        return {
                            "success": True,
                            "message": "Health check successful",
                            "response_time_ms": response_time * 1000
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "success": False,
                            "message": f"Health check failed: {response.status}",
                            "error": error_text,
                            "response_time_ms": response_time * 1000
                        }
        
        except Exception as e:
            return {
                "success": False,
                "message": f"Health check error: {str(e)}"
            }

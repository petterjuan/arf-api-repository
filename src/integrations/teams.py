"""
Microsoft Teams integration for ARF notifications.
Psychology: Structured notifications with action cards for enterprise workflows.
Intention: Professional communication with interactive message cards.
"""
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import asyncio

import aiohttp
from pydantic import ValidationError

from src.models.webhook import (
    TeamsConfiguration, Notification, NotificationPriority, NotificationChannel,
    IncidentEventPayload, PolicyEventPayload, RollbackEventPayload, SystemEventPayload,
    WebhookEventType
)
from src.integrations.base import BaseIntegration, IntegrationType, IntegrationStatus

logger = logging.getLogger(__name__)

class TeamsIntegration(BaseIntegration):
    """Microsoft Teams integration"""
    
    def __init__(self, config: TeamsConfiguration):
        super().__init__(config)
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
    
    def get_integration_type(self) -> IntegrationType:
        return IntegrationType.TEAMS
    
    async def connect(self) -> bool:
        """Initialize HTTP session"""
        try:
            if self.session is None or self.session.closed:
                self.session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=30)
                )
            
            # Test connection with a simple adaptive card
            test_card = self._create_test_adaptive_card()
            async with self.session.post(
                str(self.config.webhook_url),
                json=test_card,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    self.status = IntegrationStatus.CONNECTED
                    logger.info(f"Teams integration connected")
                    return True
                else:
                    self.status = IntegrationStatus.ERROR
                    error_text = await response.text()
                    logger.error(f"Teams connection test failed: {response.status} - {error_text}")
                    return False
        
        except Exception as e:
            self.status = IntegrationStatus.ERROR
            logger.error(f"Failed to connect Teams integration: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Close HTTP session"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
                self.session = None
            
            self.status = IntegrationStatus.DISCONNECTED
            logger.info("Teams integration disconnected")
            return True
        
        except Exception as e:
            logger.error(f"Error disconnecting Teams integration: {e}")
            return False
    
    async def validate_configuration(self) -> bool:
        """Validate Teams configuration"""
        try:
            # Check required fields
            if not self.config.webhook_url:
                logger.error("Teams webhook URL is required")
                return False
            
            # Validate URL format
            from urllib.parse import urlparse
            parsed = urlparse(str(self.config.webhook_url))
            if not parsed.scheme or not parsed.netloc:
                logger.error(f"Invalid Teams webhook URL: {self.config.webhook_url}")
                return False
            
            # Test with minimal adaptive card
            test_card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": "Configuration test",
                "sections": [{
                    "activityTitle": "ARF Configuration Test",
                    "activitySubtitle": "Validating Teams integration",
                    "activityText": f"Test at {datetime.utcnow().isoformat()}"
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    str(self.config.webhook_url),
                    json=test_card,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        logger.info("Teams configuration validated successfully")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"Teams configuration test failed: {response.status} - {error_text}")
                        return False
        
        except Exception as e:
            logger.error(f"Teams configuration validation failed: {e}")
            return False
    
    async def send_notification(self, notification: Notification) -> Dict[str, Any]:
        """Send notification to Microsoft Teams"""
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
                        "error": "Failed to connect to Teams",
                        "response_time_ms": (time.time() - start_time) * 1000
                    }
            
            # Prepare Teams adaptive card
            adaptive_card = await self._prepare_adaptive_card(notification)
            
            # Send to Teams webhook
            async with self.session.post(
                str(self.config.webhook_url),
                json=adaptive_card,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                response_time_ms = (time.time() - start_time) * 1000
                
                if response.status == 200:
                    self.health.record_success(response_time_ms / 1000)
                    logger.info("Teams notification sent successfully")
                    return {
                        "success": True,
                        "status_code": response.status,
                        "message": "Notification sent to Teams",
                        "response_time_ms": response_time_ms
                    }
                else:
                    error_text = await response.text()
                    self.health.record_failure()
                    logger.error(f"Teams API error: {response.status} - {error_text}")
                    
                    # Check for rate limiting
                    if response.status == 429:
                        self.status = IntegrationStatus.RATE_LIMITED
                        retry_after = response.headers.get('Retry-After', 60)
                        logger.warning(f"Teams rate limited. Retry after: {retry_after} seconds")
                    
                    return {
                        "success": False,
                        "status_code": response.status,
                        "error": error_text,
                        "response_time_ms": response_time_ms
                    }
        
        except asyncio.TimeoutError:
            response_time_ms = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.error(f"Teams notification timeout after {response_time_ms}ms")
            return {
                "success": False,
                "error": "Request timeout",
                "response_time_ms": response_time_ms
            }
        
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.error(f"Failed to send Teams notification: {e}")
            return {
                "success": False,
                "error": str(e),
                "response_time_ms": response_time_ms
            }
    
    async def _prepare_adaptive_card(self, notification: Notification) -> Dict[str, Any]:
        """Prepare Microsoft Teams adaptive card"""
        metadata = notification.metadata or {}
        event_type = metadata.get("event_type", "unknown")
        
        # Create base adaptive card
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": notification.body[:100],  # Short summary for notifications
            "themeColor": self._get_theme_color(notification.priority),
            "title": await self._get_card_title(notification, event_type),
            "sections": []
        }
        
        # Add main text section
        main_section = {
            "activityTitle": await self._get_activity_title(notification, event_type),
            "activitySubtitle": await self._get_activity_subtitle(notification, event_type),
            "activityText": notification.body,
            "activityImage": self.config.activity_image_url if self.config.activity_image_url else None,
            "markdown": True
        }
        
        card["sections"].append(main_section)
        
        # Add facts section
        facts_section = {
            "title": "Details",
            "facts": await self._get_facts(notification, metadata)
        }
        
        card["sections"].append(facts_section)
        
        # Add potential actions section
        actions = await self._get_actions(notification, metadata)
        if actions:
            card["potentialAction"] = actions
        
        # Add target URLs if configured
        if self.config.target_url:
            card["@context"] = "http://schema.org/extensions"
        
        return card
    
    def _get_theme_color(self, priority: NotificationPriority) -> str:
        """Get theme color based on priority"""
        color_map = {
            NotificationPriority.CRITICAL: "#DC3545",  # Red
            NotificationPriority.HIGH: "#FD7E14",     # Orange
            NotificationPriority.MEDIUM: "#FFC107",   # Yellow
            NotificationPriority.LOW: "#17A2B8",      # Teal
        }
        return color_map.get(priority, "#007BFF")  # Default blue
    
    async def _get_card_title(self, notification: Notification, event_type: str) -> str:
        """Get card title"""
        priority_prefix = ""
        if notification.priority == NotificationPriority.CRITICAL:
            priority_prefix = "🚨 "
        elif notification.priority == NotificationPriority.HIGH:
            priority_prefix = "⚠️ "
        
        if event_type == WebhookEventType.INCIDENT_CREATED.value:
            return f"{priority_prefix}New Incident Created"
        elif event_type == WebhookEventType.INCIDENT_UPDATED.value:
            return f"{priority_prefix}Incident Updated"
        elif event_type == WebhookEventType.INCIDENT_RESOLVED.value:
            return f"✅ Incident Resolved"
        elif event_type == WebhookEventType.POLICY_EVALUATED.value:
            return f"📋 Policy Evaluated"
        elif event_type == WebhookEventType.POLICY_TRIGGERED.value:
            return f"🚨 Policy Triggered"
        elif event_type == WebhookEventType.ROLLBACK_EXECUTED.value:
            return f"↩️ Rollback Executed"
        elif event_type == WebhookEventType.ROLLBACK_FAILED.value:
            return f"❌ Rollback Failed"
        else:
            return f"{priority_prefix}ARF Notification"
    
    async def _get_activity_title(self, notification: Notification, event_type: str) -> str:
        """Get activity title"""
        metadata = notification.metadata or {}
        source_type = metadata.get("source_type", "")
        
        if source_type:
            return f"{source_type.replace('_', ' ').title()}"
        
        return "ARF System Notification"
    
    async def _get_activity_subtitle(self, notification: Notification, event_type: str) -> str:
        """Get activity subtitle"""
        metadata = notification.metadata or {}
        
        if metadata.get("webhook_name"):
            return f"via {metadata['webhook_name']}"
        
        return f"Event: {event_type.replace('_', ' ').title()}"
    
    async def _get_facts(self, notification: Notification, metadata: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get facts for the adaptive card"""
        facts = []
        
        # Add priority fact
        facts.append({
            "name": "Priority",
            "value": notification.priority.value.upper()
        })
        
        # Add source fact if available
        if metadata.get("source_type"):
            facts.append({
                "name": "Source",
                "value": metadata["source_type"]
            })
        
        # Add ID fact if available
        if metadata.get("source_id"):
            facts.append({
                "name": "ID",
                "value": metadata["source_id"]
            })
        
        # Add timestamp
        facts.append({
            "name": "Time",
            "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        })
        
        # Add urgent flag if applicable
        if notification.urgent:
            facts.append({
                "name": "Urgent",
                "value": "YES"
            })
        
        return facts
    
    async def _get_actions(self, notification: Notification, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get actions for the adaptive card"""
        actions = []
        
        # Add View Details action for incidents
        if metadata.get("event_type") in [
            WebhookEventType.INCIDENT_CREATED.value,
            WebhookEventType.INCIDENT_UPDATED.value,
            WebhookEventType.INCIDENT_RESOLVED.value
        ] and metadata.get("source_id"):
            actions.append({
                "@type": "OpenUri",
                "name": "View Incident",
                "targets": [{
                    "os": "default",
                    "uri": f"https://arf.example.com/incidents/{metadata['source_id']}"
                }]
            })
        
        # Add Acknowledge action for critical/high priority
        if notification.priority in [NotificationPriority.CRITICAL, NotificationPriority.HIGH]:
            actions.append({
                "@type": "HttpPOST",
                "name": "Acknowledge",
                "target": f"https://arf.example.com/api/v1/notifications/{notification.notification_id}/acknowledge",
                "headers": [{
                    "name": "Content-Type",
                    "value": "application/json"
                }],
                "body": json.dumps({
                    "acknowledged": True,
                    "timestamp": datetime.utcnow().isoformat()
                }),
                "bodyContentType": "application/json"
            })
        
        # Add generic dashboard action
        actions.append({
            "@type": "OpenUri",
            "name": "Open Dashboard",
            "targets": [{
                "os": "default",
                "uri": "https://arf.example.com/dashboard"
            }]
        })
        
        return actions
    
    def _create_test_adaptive_card(self) -> Dict[str, Any]:
        """Create test adaptive card for connection testing"""
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "ARF Connection Test",
            "themeColor": "#007BFF",
            "title": "🔧 ARF Connection Test",
            "sections": [{
                "activityTitle": "Teams Integration",
                "activitySubtitle": "Connection validation",
                "activityText": f"Testing connection at {datetime.utcnow().isoformat()}",
                "facts": [{
                    "name": "Status",
                    "value": "Testing..."
                }, {
                    "name": "Time",
                    "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                }],
                "markdown": True
            }]
        }
    
    async def _perform_health_test(self) -> Dict[str, Any]:
        """Perform Teams-specific health test"""
        try:
            test_card = self._create_test_adaptive_card()
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    str(self.config.webhook_url),
                    json=test_card,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        return {
                            "success": True,
                            "message": "Health check successful",
                            "response_time_ms": response.elapsed.total_seconds() * 1000
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "success": False,
                            "message": f"Health check failed: {response.status} - {error_text}",
                            "response_time_ms": response.elapsed.total_seconds() * 1000
                        }
        
        except Exception as e:
            return {
                "success": False,
                "message": f"Health check error: {str(e)}"
            }

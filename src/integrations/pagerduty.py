"""
PagerDuty integration for ARF notifications.
Psychology: Emergency response with structured incident management.
Intention: Reliable alerting for on-call teams with escalation policies.
"""
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import asyncio

import aiohttp
from pydantic import ValidationError

from src.models.webhook import (
    PagerDutyConfiguration, Notification, NotificationPriority, NotificationChannel,
    IncidentEventPayload, PolicyEventPayload, RollbackEventPayload, SystemEventPayload,
    WebhookEventType
)
from src.integrations.base import BaseIntegration, IntegrationType, IntegrationStatus

logger = logging.getLogger(__name__)

class PagerDutyIntegration(BaseIntegration):
    """PagerDuty integration"""
    
    def __init__(self, config: PagerDutyConfiguration):
        super().__init__(config)
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.base_url = "https://api.pagerduty.com"
    
    def get_integration_type(self) -> IntegrationType:
        return IntegrationType.PAGERDUTY
    
    async def connect(self) -> bool:
        """Initialize HTTP session with API key"""
        try:
            if self.session is None or self.session.closed:
                headers = {
                    "Authorization": f"Token token={self.config.api_key}",
                    "Accept": "application/vnd.pagerduty+json;version=2",
                    "Content-Type": "application/json"
                }
                
                self.session = aiohttp.ClientSession(
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                )
            
            # Test connection by fetching current user
            async with self.session.get(
                f"{self.base_url}/users/me",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    self.status = IntegrationStatus.CONNECTED
                    data = await response.json()
                    user_email = data.get("user", {}).get("email", "unknown")
                    logger.info(f"PagerDuty integration connected as {user_email}")
                    return True
                else:
                    self.status = IntegrationStatus.ERROR
                    error_text = await response.text()
                    logger.error(f"PagerDuty connection test failed: {response.status} - {error_text}")
                    return False
        
        except Exception as e:
            self.status = IntegrationStatus.ERROR
            logger.error(f"Failed to connect PagerDuty integration: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Close HTTP session"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
                self.session = None
            
            self.status = IntegrationStatus.DISCONNECTED
            logger.info("PagerDuty integration disconnected")
            return True
        
        except Exception as e:
            logger.error(f"Error disconnecting PagerDuty integration: {e}")
            return False
    
    async def validate_configuration(self) -> bool:
        """Validate PagerDuty configuration"""
        try:
            # Check required fields
            if not self.config.api_key:
                logger.error("PagerDuty API key is required")
                return False
            
            if not self.config.service_id:
                logger.error("PagerDuty service ID is required")
                return False
            
            # Validate API key format
            if len(self.config.api_key) < 20:
                logger.error("PagerDuty API key appears invalid")
                return False
            
            # Test API connection
            headers = {
                "Authorization": f"Token token={self.config.api_key}",
                "Accept": "application/vnd.pagerduty+json;version=2"
            }
            
            async with aiohttp.ClientSession(headers=headers) as session:
                # Test service access
                async with session.get(
                    f"{self.base_url}/services/{self.config.service_id}",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        logger.info("PagerDuty configuration validated successfully")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"PagerDuty configuration test failed: {response.status} - {error_text}")
                        return False
        
        except Exception as e:
            logger.error(f"PagerDuty configuration validation failed: {e}")
            return False
    
    async def send_notification(self, notification: Notification) -> Dict[str, Any]:
        """Send notification to PagerDuty"""
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
                        "error": "Failed to connect to PagerDuty",
                        "response_time_ms": (time.time() - start_time) * 1000
                    }
            
            # Determine PagerDuty event action
            action = await self._determine_pagerduty_action(notification)
            
            # Prepare PagerDuty event
            event = await self._prepare_pagerduty_event(notification, action)
            
            # Send to PagerDuty Events API v2
            async with self.session.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=event,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                response_time_ms = (time.time() - start_time) * 1000
                response_data = await response.json()
                
                if response.status == 202:
                    self.health.record_success(response_time_ms / 1000)
                    
                    # Log PagerDuty dedup key
                    dedup_key = response_data.get("dedup_key")
                    logger.info(f"PagerDuty notification sent. Dedup key: {dedup_key}")
                    
                    return {
                        "success": True,
                        "status_code": response.status,
                        "message": "Notification sent to PagerDuty",
                        "dedup_key": dedup_key,
                        "response_time_ms": response_time_ms
                    }
                else:
                    self.health.record_failure()
                    logger.error(f"PagerDuty API error: {response.status} - {response_data}")
                    
                    # Check for rate limiting
                    if response.status == 429:
                        self.status = IntegrationStatus.RATE_LIMITED
                        retry_after = response.headers.get('Retry-After', 60)
                        logger.warning(f"PagerDuty rate limited. Retry after: {retry_after} seconds")
                    
                    return {
                        "success": False,
                        "status_code": response.status,
                        "error": json.dumps(response_data),
                        "response_time_ms": response_time_ms
                    }
        
        except asyncio.TimeoutError:
            response_time_ms = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.error(f"PagerDuty notification timeout after {response_time_ms}ms")
            return {
                "success": False,
                "error": "Request timeout",
                "response_time_ms": response_time_ms
            }
        
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.error(f"Failed to send PagerDuty notification: {e}")
            return {
                "success": False,
                "error": str(e),
                "response_time_ms": response_time_ms
            }
    
    async def _determine_pagerduty_action(self, notification: Notification) -> str:
        """Determine PagerDuty event action"""
        metadata = notification.metadata or {}
        event_type = metadata.get("event_type", "")
        
        # Map ARF events to PagerDuty actions
        if notification.priority in [NotificationPriority.CRITICAL, NotificationPriority.HIGH]:
            if event_type == WebhookEventType.INCIDENT_RESOLVED.value:
                return "resolve"
            elif event_type in [WebhookEventType.ROLLBACK_EXECUTED.value,
                              WebhookEventType.SYSTEM_HEALTH_CHANGE.value]:
                # Check if this should trigger or resolve
                if metadata.get("payload", {}).get("status") == "healthy":
                    return "resolve"
                else:
                    return "trigger"
            else:
                return "trigger"
        else:
            # Low/medium priority notifications as low urgency triggers
            return "trigger"
    
    async def _prepare_pagerduty_event(self, notification: Notification, action: str) -> Dict[str, Any]:
        """Prepare PagerDuty v2 event"""
        metadata = notification.metadata or {}
        event_type = metadata.get("event_type", "unknown")
        source_id = metadata.get("source_id", notification.notification_id)
        
        # Generate dedup key (unique identifier for deduplication)
        dedup_key = f"arf-{source_id}-{event_type}"
        
        # Determine severity
        severity = await self._get_pagerduty_severity(notification.priority)
        
        # Prepare event payload
        event = {
            "routing_key": self.config.routing_key or self.config.service_id,
            "event_action": action,
            "dedup_key": dedup_key,
            "payload": {
                "summary": await self._get_pagerduty_summary(notification, event_type),
                "source": metadata.get("source_type", "ARF System"),
                "severity": severity,
                "timestamp": datetime.utcnow().isoformat(),
                "component": metadata.get("component", "ARF"),
                "group": metadata.get("group", self.config.default_group),
                "class": self._get_pagerduty_class(event_type),
                "custom_details": await self._get_custom_details(notification, metadata)
            }
        }
        
        # Add links if available
        links = await self._get_pagerduty_links(notification, metadata)
        if links:
            event["links"] = links
        
        # Add images if available
        images = await self._get_pagerduty_images()
        if images:
            event["images"] = images
        
        return event
    
    async def _get_pagerduty_severity(self, priority: NotificationPriority) -> str:
        """Map ARF priority to PagerDuty severity"""
        severity_map = {
            NotificationPriority.CRITICAL: "critical",
            NotificationPriority.HIGH: "error",
            NotificationPriority.MEDIUM: "warning",
            NotificationPriority.LOW: "info"
        }
        return severity_map.get(priority, "error")
    
    async def _get_pagerduty_summary(self, notification: Notification, event_type: str) -> str:
        """Get PagerDuty event summary"""
        metadata = notification.metadata or {}
        
        if event_type == WebhookEventType.INCIDENT_CREATED.value:
            return f"Incident Created: {metadata.get('source_id', 'Unknown')} - {notification.body[:100]}"
        elif event_type == WebhookEventType.INCIDENT_UPDATED.value:
            return f"Incident Updated: {metadata.get('source_id', 'Unknown')} - {notification.body[:100]}"
        elif event_type == WebhookEventType.INCIDENT_RESOLVED.value:
            return f"Incident Resolved: {metadata.get('source_id', 'Unknown')}"
        elif event_type == WebhookEventType.POLICY_TRIGGERED.value:
            return f"Policy Triggered: {notification.body[:100]}"
        elif event_type == WebhookEventType.ROLLBACK_EXECUTED.value:
            return f"Rollback Executed: {notification.body[:100]}"
        elif event_type == WebhookEventType.ROLLBACK_FAILED.value:
            return f"Rollback Failed: {notification.body[:100]}"
        else:
            return f"ARF Notification: {notification.body[:150]}"
    
    def _get_pagerduty_class(self, event_type: str) -> str:
        """Get PagerDuty event class"""
        class_map = {
            WebhookEventType.INCIDENT_CREATED.value: "incident",
            WebhookEventType.INCIDENT_UPDATED.value: "incident_update",
            WebhookEventType.INCIDENT_RESOLVED.value: "incident_resolution",
            WebhookEventType.POLICY_TRIGGERED.value: "policy_violation",
            WebhookEventType.POLICY_EVALUATED.value: "policy_evaluation",
            WebhookEventType.ROLLBACK_EXECUTED.value: "rollback",
            WebhookEventType.ROLLBACK_FAILED.value: "rollback_failure",
            WebhookEventType.SYSTEM_HEALTH_CHANGE.value: "health_check"
        }
        return class_map.get(event_type, "custom_event")
    
    async def _get_custom_details(self, notification: Notification, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Get custom details for PagerDuty"""
        details = {
            "notification_id": notification.notification_id,
            "priority": notification.priority.value,
            "urgent": notification.urgent,
            "event_type": metadata.get("event_type", "unknown"),
            "source_id": metadata.get("source_id", "unknown"),
            "source_type": metadata.get("source_type", "unknown"),
            "webhook_name": metadata.get("webhook_name", "unknown"),
            "full_message": notification.body,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add payload data if available
        if metadata.get("payload"):
            details["payload"] = metadata["payload"]
        
        # Add context if available
        if metadata.get("context"):
            details["context"] = metadata["context"]
        
        return details
    
    async def _get_pagerduty_links(self, notification: Notification, metadata: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get PagerDuty links"""
        links = []
        
        # Add ARF dashboard link
        links.append({
            "href": "https://arf.example.com/dashboard",
            "text": "ARF Dashboard"
        })
        
        # Add incident link if available
        if metadata.get("source_id") and metadata.get("event_type", "").startswith("incident_"):
            links.append({
                "href": f"https://arf.example.com/incidents/{metadata['source_id']}",
                "text": "View Incident"
            })
        
        # Add policy link if available
        if metadata.get("event_type", "").startswith("policy_"):
            links.append({
                "href": "https://arf.example.com/policies",
                "text": "View Policies"
            })
        
        return links
    
    async def _get_pagerduty_images(self) -> List[Dict[str, str]]:
        """Get PagerDuty images"""
        if self.config.logo_url:
            return [{
                "src": str(self.config.logo_url),
                "href": "https://arf.example.com",
                "alt": "ARF Logo"
            }]
        return []
    
    async def acknowledge_incident(self, dedup_key: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Acknowledge a PagerDuty incident"""
        try:
            payload = {
                "incident": {
                    "type": "incident_reference",
                    "status": "acknowledged"
                }
            }
            
            if user_id:
                payload["requester_id"] = user_id
            
            async with self.session.put(
                f"{self.base_url}/incidents/{dedup_key}",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    logger.info(f"PagerDuty incident {dedup_key} acknowledged")
                    return {"success": True, "message": "Incident acknowledged"}
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to acknowledge PagerDuty incident: {response.status} - {error_text}")
                    return {"success": False, "error": error_text}
        
        except Exception as e:
            logger.error(f"Error acknowledging PagerDuty incident: {e}")
            return {"success": False, "error": str(e)}
    
    async def resolve_incident(self, dedup_key: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Resolve a PagerDuty incident"""
        try:
            payload = {
                "incident": {
                    "type": "incident_reference",
                    "status": "resolved"
                }
            }
            
            if user_id:
                payload["requester_id"] = user_id
            
            async with self.session.put(
                f"{self.base_url}/incidents/{dedup_key}",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    logger.info(f"PagerDuty incident {dedup_key} resolved")
                    return {"success": True, "message": "Incident resolved"}
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to resolve PagerDuty incident: {response.status} - {error_text}")
                    return {"success": False, "error": error_text}
        
        except Exception as e:
            logger.error(f"Error resolving PagerDuty incident: {e}")
            return {"success": False, "error": str(e)}
    
    async def _perform_health_test(self) -> Dict[str, Any]:
        """Perform PagerDuty-specific health test"""
        try:
            # Test API connection
            async with self.session.get(
                f"{self.base_url}/services/{self.config.service_id}",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    service_name = data.get("service", {}).get("name", "Unknown")
                    
                    return {
                        "success": True,
                        "message": "PagerDuty API connected",
                        "service_name": service_name,
                        "service_id": self.config.service_id,
                        "response_time_ms": response.elapsed.total_seconds() * 1000
                    }
                else:
                    error_text = await response.text()
                    return {
                        "success": False,
                        "message": f"API test failed: {response.status}",
                        "error": error_text,
                        "response_time_ms": response.elapsed.total_seconds() * 1000
                    }
        
        except Exception as e:
            return {
                "success": False,
                "message": f"Health check error: {str(e)}"
            }

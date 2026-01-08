"""
OpsGenie integration for ARF notifications.
Psychology: Cross-platform alerting with rich escalation and scheduling.
Intention: Comprehensive incident response with team coordination.
"""
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import asyncio
import base64

import aiohttp
from pydantic import ValidationError

from src.models.webhook import (
    OpsGenieConfiguration, Notification, NotificationPriority, NotificationChannel,
    IncidentEventPayload, PolicyEventPayload, RollbackEventPayload, SystemEventPayload,
    WebhookEventType
)
from src.integrations.base import BaseIntegration, IntegrationType, IntegrationStatus

logger = logging.getLogger(__name__)

class OpsGenieIntegration(BaseIntegration):
    """OpsGenie integration"""
    
    def __init__(self, config: OpsGenieConfiguration):
        super().__init__(config)
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.base_url = "https://api.opsgenie.com/v2"
    
    def get_integration_type(self) -> IntegrationType:
        return IntegrationType.OPSGENIE
    
    async def connect(self) -> bool:
        """Initialize HTTP session with API key"""
        try:
            if self.session is None or self.session.closed:
                # Prepare authentication
                auth_header = self._get_auth_header()
                
                headers = {
                    "Authorization": auth_header,
                    "Content-Type": "application/json"
                }
                
                self.session = aiohttp.ClientSession(
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                )
            
            # Test connection by checking account info
            async with self.session.get(
                f"{self.base_url}/account",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    self.status = IntegrationStatus.CONNECTED
                    data = await response.json()
                    account_name = data.get("data", {}).get("name", "unknown")
                    logger.info(f"OpsGenie integration connected to {account_name}")
                    return True
                else:
                    self.status = IntegrationStatus.ERROR
                    error_text = await response.text()
                    logger.error(f"OpsGenie connection test failed: {response.status} - {error_text}")
                    return False
        
        except Exception as e:
            self.status = IntegrationStatus.ERROR
            logger.error(f"Failed to connect OpsGenie integration: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Close HTTP session"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
                self.session = None
            
            self.status = IntegrationStatus.DISCONNECTED
            logger.info("OpsGenie integration disconnected")
            return True
        
        except Exception as e:
            logger.error(f"Error disconnecting OpsGenie integration: {e}")
            return False
    
    def _get_auth_header(self) -> str:
        """Get OpsGenie authentication header"""
        if self.config.api_key:
            return f"GenieKey {self.config.api_key}"
        elif self.config.api_token:
            return f"Bearer {self.config.api_token}"
        else:
            raise ValueError("No API key or token configured for OpsGenie")
    
    async def validate_configuration(self) -> bool:
        """Validate OpsGenie configuration"""
        try:
            # Check required fields
            if not self.config.api_key and not self.config.api_token:
                logger.error("OpsGenie API key or token is required")
                return False
            
            if not self.config.team_name and not self.config.team_id:
                logger.error("OpsGenie team name or ID is required")
                return False
            
            # Test API connection
            auth_header = self._get_auth_header()
            headers = {"Authorization": auth_header}
            
            async with aiohttp.ClientSession(headers=headers) as session:
                # Test account access
                async with session.get(
                    f"{self.base_url}/account",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        logger.info("OpsGenie configuration validated successfully")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"OpsGenie configuration test failed: {response.status} - {error_text}")
                        return False
        
        except Exception as e:
            logger.error(f"OpsGenie configuration validation failed: {e}")
            return False
    
    async def send_notification(self, notification: Notification) -> Dict[str, Any]:
        """Send notification to OpsGenie"""
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
                        "error": "Failed to connect to OpsGenie",
                        "response_time_ms": (time.time() - start_time) * 1000
                    }
            
            # Determine OpsGenie alert action
            action = await self._determine_opsgenie_action(notification)
            
            if action == "create":
                return await self._create_alert(notification, start_time)
            elif action == "close":
                return await self._close_alert(notification, start_time)
            elif action == "acknowledge":
                return await self._acknowledge_alert(notification, start_time)
            else:
                return await self._add_note(notification, start_time)
        
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.error(f"Failed to send OpsGenie notification: {e}")
            return {
                "success": False,
                "error": str(e),
                "response_time_ms": response_time_ms
            }
    
    async def _determine_opsgenie_action(self, notification: Notification) -> str:
        """Determine OpsGenie alert action"""
        metadata = notification.metadata or {}
        event_type = metadata.get("event_type", "")
        
        if event_type == WebhookEventType.INCIDENT_RESOLVED.value:
            return "close"
        elif event_type == WebhookEventType.INCIDENT_UPDATED.value:
            # Check if incident was acknowledged
            if metadata.get("payload", {}).get("status") == "acknowledged":
                return "acknowledge"
            else:
                return "add_note"
        elif notification.priority in [NotificationPriority.CRITICAL, NotificationPriority.HIGH]:
            return "create"
        else:
            return "add_note"
    
    async def _create_alert(self, notification: Notification, start_time: float) -> Dict[str, Any]:
        """Create a new OpsGenie alert"""
        metadata = notification.metadata or {}
        
        # Prepare alert payload
        alert = await self._prepare_opsgenie_alert(notification)
        
        # Send to OpsGenie
        async with self.session.post(
            f"{self.base_url}/alerts",
            json=alert,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            response_time_ms = (time.time() - start_time) * 1000
            response_data = await response.json()
            
            if response.status == 202:
                self.health.record_success(response_time_ms / 1000)
                
                alert_id = response_data.get("requestId")
                alert_alias = response_data.get("data", {}).get("alias")
                
                logger.info(f"OpsGenie alert created. ID: {alert_id}, Alias: {alert_alias}")
                
                return {
                    "success": True,
                    "status_code": response.status,
                    "message": "Alert created in OpsGenie",
                    "alert_id": alert_id,
                    "alert_alias": alert_alias,
                    "response_time_ms": response_time_ms
                }
            else:
                self.health.record_failure()
                logger.error(f"OpsGenie API error: {response.status} - {response_data}")
                
                # Check for rate limiting
                if response.status == 429:
                    self.status = IntegrationStatus.RATE_LIMITED
                    retry_after = response.headers.get('Retry-After', 60)
                    logger.warning(f"OpsGenie rate limited. Retry after: {retry_after} seconds")
                
                return {
                    "success": False,
                    "status_code": response.status,
                    "error": json.dumps(response_data),
                    "response_time_ms": response_time_ms
                }
    
    async def _close_alert(self, notification: Notification, start_time: float) -> Dict[str, Any]:
        """Close an existing OpsGenie alert"""
        metadata = notification.metadata or {}
        source_id = metadata.get("source_id", "")
        
        if not source_id:
            return {
                "success": False,
                "error": "No source ID provided for closing alert",
                "response_time_ms": (time.time() - start_time) * 1000
            }
        
        # Use source ID as alert alias
        alert_alias = f"arf-{source_id}"
        
        close_payload = {
            "user": self.config.default_user or "ARF System",
            "source": "ARF",
            "note": f"Incident resolved: {notification.body[:500]}"
        }
        
        async with self.session.post(
            f"{self.base_url}/alerts/{alert_alias}/close",
            json=close_payload,
            params={"identifierType": "alias"},
            timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            response_time_ms = (time.time() - start_time) * 1000
            
            if response.status == 202:
                self.health.record_success(response_time_ms / 1000)
                logger.info(f"OpsGenie alert {alert_alias} closed")
                
                return {
                    "success": True,
                    "status_code": response.status,
                    "message": "Alert closed in OpsGenie",
                    "response_time_ms": response_time_ms
                }
            else:
                self.health.record_failure()
                error_text = await response.text()
                logger.error(f"Failed to close OpsGenie alert: {response.status} - {error_text}")
                
                return {
                    "success": False,
                    "status_code": response.status,
                    "error": error_text,
                    "response_time_ms": response_time_ms
                }
    
    async def _acknowledge_alert(self, notification: Notification, start_time: float) -> Dict[str, Any]:
        """Acknowledge an existing OpsGenie alert"""
        metadata = notification.metadata or {}
        source_id = metadata.get("source_id", "")
        
        if not source_id:
            return {
                "success": False,
                "error": "No source ID provided for acknowledging alert",
                "response_time_ms": (time.time() - start_time) * 1000
            }
        
        alert_alias = f"arf-{source_id}"
        
        ack_payload = {
            "user": self.config.default_user or "ARF System",
            "source": "ARF",
            "note": f"Incident acknowledged: {notification.body[:500]}"
        }
        
        async with self.session.post(
            f"{self.base_url}/alerts/{alert_alias}/acknowledge",
            json=ack_payload,
            params={"identifierType": "alias"},
            timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            response_time_ms = (time.time() - start_time) * 1000
            
            if response.status == 202:
                self.health.record_success(response_time_ms / 1000)
                logger.info(f"OpsGenie alert {alert_alias} acknowledged")
                
                return {
                    "success": True,
                    "status_code": response.status,
                    "message": "Alert acknowledged in OpsGenie",
                    "response_time_ms": response_time_ms
                }
            else:
                self.health.record_failure()
                error_text = await response.text()
                logger.error(f"Failed to acknowledge OpsGenie alert: {response.status} - {error_text}")
                
                return {
                    "success": False,
                    "status_code": response.status,
                    "error": error_text,
                    "response_time_ms": response_time_ms
                }
    
    async def _add_note(self, notification: Notification, start_time: float) -> Dict[str, Any]:
        """Add note to existing OpsGenie alert"""
        metadata = notification.metadata or {}
        source_id = metadata.get("source_id", "")
        
        if not source_id:
            # Create new alert instead
            return await self._create_alert(notification, start_time)
        
        alert_alias = f"arf-{source_id}"
        
        note_payload = {
            "user": self.config.default_user or "ARF System",
            "source": "ARF",
            "note": notification.body[:1500]
        }
        
        async with self.session.post(
            f"{self.base_url}/alerts/{alert_alias}/notes",
            json=note_payload,
            params={"identifierType": "alias"},
            timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            response_time_ms = (time.time() - start_time) * 1000
            
            if response.status == 202:
                self.health.record_success(response_time_ms / 1000)
                logger.info(f"Note added to OpsGenie alert {alert_alias}")
                
                return {
                    "success": True,
                    "status_code": response.status,
                    "message": "Note added to OpsGenie alert",
                    "response_time_ms": response_time_ms
                }
            else:
                self.health.record_failure()
                error_text = await response.text()
                logger.error(f"Failed to add note to OpsGenie alert: {response.status} - {error_text}")
                
                return {
                    "success": False,
                    "status_code": response.status,
                    "error": error_text,
                    "response_time_ms": response_time_ms
                }
    
    async def _prepare_opsgenie_alert(self, notification: Notification) -> Dict[str, Any]:
        """Prepare OpsGenie alert payload"""
        metadata = notification.metadata or {}
        event_type = metadata.get("event_type", "unknown")
        source_id = metadata.get("source_id", notification.notification_id)
        
        # Generate alert alias for deduplication
        alert_alias = f"arf-{source_id}"
        
        # Determine priority
        priority = await self._get_opsgenie_priority(notification.priority)
        
        # Determine message
        message = await self._get_opsgenie_message(notification, event_type)
        
        # Prepare alert
        alert = {
            "message": message,
            "alias": alert_alias,
            "description": notification.body[:15000],  # OpsGenie limit
            "priority": priority,
            "source": metadata.get("source_type", "ARF System"),
            "entity": metadata.get("component", "ARF"),
            "tags": await self._get_opsgenie_tags(notification, metadata),
            "details": await self._get_opsgenie_details(notification, metadata),
            "note": await self._get_opsgenie_note(notification),
            "visibleTo": await self._get_visible_to()
        }
        
        # Add responders if configured
        responders = await self._get_responders()
        if responders:
            alert["responders"] = responders
        
        # Add actions if configured
        actions = await self._get_actions(notification)
        if actions:
            alert["actions"] = actions
        
        # Add custom properties
        if self.config.custom_properties:
            alert.update(self.config.custom_properties)
        
        return alert
    
    async def _get_opsgenie_priority(self, priority: NotificationPriority) -> str:
        """Map ARF priority to OpsGenie priority"""
        priority_map = {
            NotificationPriority.CRITICAL: "P1",
            NotificationPriority.HIGH: "P2",
            NotificationPriority.MEDIUM: "P3",
            NotificationPriority.LOW: "P4"
        }
        return priority_map.get(priority, "P3")
    
    async def _get_opsgenie_message(self, notification: Notification, event_type: str) -> str:
        """Get OpsGenie alert message"""
        metadata = notification.metadata or {}
        
        prefix_map = {
            NotificationPriority.CRITICAL: "🚨 CRITICAL: ",
            NotificationPriority.HIGH: "⚠️ HIGH: ",
            NotificationPriority.MEDIUM: "📢 MEDIUM: ",
            NotificationPriority.LOW: "📝 LOW: "
        }
        
        prefix = prefix_map.get(notification.priority, "")
        
        if event_type == WebhookEventType.INCIDENT_CREATED.value:
            return f"{prefix}Incident Created: {metadata.get('source_id', 'Unknown')}"
        elif event_type == WebhookEventType.INCIDENT_UPDATED.value:
            return f"{prefix}Incident Updated: {metadata.get('source_id', 'Unknown')}"
        elif event_type == WebhookEventType.INCIDENT_RESOLVED.value:
            return f"✅ Incident Resolved: {metadata.get('source_id', 'Unknown')}"
        elif event_type == WebhookEventType.POLICY_TRIGGERED.value:
            return f"{prefix}Policy Triggered"
        elif event_type == WebhookEventType.ROLLBACK_EXECUTED.value:
            return f"{prefix}Rollback Executed"
        elif event_type == WebhookEventType.ROLLBACK_FAILED.value:
            return f"{prefix}Rollback Failed"
        else:
            return f"{prefix}{notification.body[:130]}"  # OpsGenie message limit
    
    async def _get_opsgenie_tags(self, notification: Notification, metadata: Dict[str, Any]) -> List[str]:
        """Get OpsGenie alert tags"""
        tags = [
            "ARF",
            f"priority-{notification.priority.value}",
            metadata.get("event_type", "unknown").replace("_", "-")
        ]
        
        if notification.urgent:
            tags.append("urgent")
        
        if metadata.get("source_type"):
            tags.append(metadata["source_type"].replace("_", "-"))
        
        # Add custom tags from config
        if self.config.default_tags:
            tags.extend(self.config.default_tags)
        
        return tags
    
    async def _get_opsgenie_details(self, notification: Notification, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Get OpsGenie alert details"""
        details = {
            "notification_id": notification.notification_id,
            "arf_priority": notification.priority.value,
            "arf_urgent": str(notification.urgent),
            "event_type": metadata.get("event_type", "unknown"),
            "source_id": metadata.get("source_id", "unknown"),
            "source_type": metadata.get("source_type", "unknown"),
            "webhook_name": metadata.get("webhook_name", "unknown"),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add payload data if available
        if metadata.get("payload"):
            # Flatten nested payload
            self._flatten_payload(details, metadata["payload"], "payload")
        
        return details
    
    def _flatten_payload(self, target: Dict[str, Any], source: Any, prefix: str = ""):
        """Flatten nested payload for OpsGenie details"""
        if isinstance(source, dict):
            for key, value in source.items():
                new_key = f"{prefix}_{key}" if prefix else key
                self._flatten_payload(target, value, new_key)
        elif isinstance(source, list):
            target[prefix] = json.dumps(source)
        else:
            target[prefix] = str(source)
    
    async def _get_opsgenie_note(self, notification: Notification) -> str:
        """Get OpsGenie alert note"""
        metadata = notification.metadata or {}
        
        note_lines = [
            f"ARF Notification: {metadata.get('event_type', 'unknown')}",
            f"Priority: {notification.priority.value.upper()}",
            f"Urgent: {'YES' if notification.urgent else 'NO'}",
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            notification.body[:5000]  # Limit note length
        ]
        
        return "\n".join(note_lines)
    
    async def _get_visible_to(self) -> Optional[List[Dict[str, str]]]:
        """Get teams/users visible to"""
        if self.config.team_id:
            return [{"id": self.config.team_id, "type": "team"}]
        elif self.config.team_name:
            return [{"name": self.config.team_name, "type": "team"}]
        return None
    
    async def _get_responders(self) -> Optional[List[Dict[str, str]]]:
        """Get alert responders"""
        responders = []
        
        # Add team responders
        if self.config.team_id:
            responders.append({"id": self.config.team_id, "type": "team"})
        elif self.config.team_name:
            responders.append({"name": self.config.team_name, "type": "team"})
        
        # Add user responders
        if self.config.user_responders:
            for user in self.config.user_responders:
                if ":" in user:
                    responder_type, identifier = user.split(":", 1)
                    responders.append({responder_type: identifier, "type": "user"})
                else:
                    responders.append({"username": user, "type": "user"})
        
        # Add schedule responders
        if self.config.escalation_schedule:
            responders.append({"name": self.config.escalation_schedule, "type": "schedule"})
        
        return responders if responders else None
    
    async def _get_actions(self, notification: Notification) -> List[str]:
        """Get alert actions"""
        actions = []
        
        # Add view action
        actions.append("View in ARF Dashboard")
        
        # Add acknowledge action for incidents
        metadata = notification.metadata or {}
        if metadata.get("event_type", "").startswith("incident_"):
            actions.append("Acknowledge Incident")
        
        # Add custom actions from config
        if self.config.custom_actions:
            actions.extend(self.config.custom_actions)
        
        return actions
    
    async def _perform_health_test(self) -> Dict[str, Any]:
        """Perform OpsGenie-specific health test"""
        try:
            # Test account API
            async with self.session.get(
                f"{self.base_url}/account",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    account_name = data.get("data", {}).get("name", "Unknown")
                    
                    return {
                        "success": True,
                        "message": "OpsGenie API connected",
                        "account_name": account_name,
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

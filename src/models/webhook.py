"""
Webhook and notification models for ARF.
Psychology: Event-driven architecture with guaranteed delivery patterns.
Intention: Multi-channel notification system with templating and retry logic.
"""
from enum import Enum
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator, HttpUrl
import uuid

class WebhookEventType(str, Enum):
    """Types of events that can trigger webhooks"""
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    INCIDENT_RESOLVED = "incident.resolved"
    INCIDENT_ESCALATED = "incident.escalated"
    
    POLICY_EVALUATED = "policy.evaluated"
    POLICY_TRIGGERED = "policy.triggered"
    
    ROLLBACK_EXECUTED = "rollback.executed"
    ROLLBACK_FAILED = "rollback.failed"
    ROLLBACK_COMPLETED = "rollback.completed"
    
    AGENT_ACTION = "agent.action"
    AGENT_ERROR = "agent.error"
    
    SYSTEM_ALERT = "system.alert"
    SYSTEM_HEALTH = "system.health"
    
    CUSTOM_EVENT = "custom.event"

class NotificationChannel(str, Enum):
    """Supported notification channels"""
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"
    DISCORD = "discord"
    EMAIL = "email"
    SMS = "sms"
    PAGERDUTY = "pagerduty"
    OPSGENIE = "opsgenie"
    CUSTOM = "custom"

class WebhookStatus(str, Enum):
    """Webhook delivery status"""
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"
    DISABLED = "disabled"

class DeliveryMethod(str, Enum):
    """Delivery methods for notifications"""
    HTTP_POST = "http_post"
    WEBHOOK = "webhook"
    WEB_SOCKET = "web_socket"
    QUEUE = "queue"
    STREAM = "stream"

class NotificationPriority(str, Enum):
    """Notification priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class WebhookSecurity(str, Enum):
    """Webhook security methods"""
    NONE = "none"
    HMAC_SHA256 = "hmac_sha256"
    JWT = "jwt"
    API_KEY = "api_key"
    BASIC_AUTH = "basic_auth"

# ============================================================================
# BASE MODELS
# ============================================================================

class WebhookBase(BaseModel):
    """Base webhook configuration model"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    
    # Event configuration
    event_types: List[WebhookEventType] = Field(default_factory=list)
    filters: Dict[str, Any] = Field(default_factory=dict)
    
    # Delivery configuration
    url: Optional[HttpUrl] = None
    channel: NotificationChannel = NotificationChannel.WEBHOOK
    method: DeliveryMethod = DeliveryMethod.HTTP_POST
    
    # Security
    security_method: WebhookSecurity = WebhookSecurity.NONE
    security_config: Dict[str, Any]

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
    security_config: Dict[str, Any] = Field(default_factory=dict)
    
    # Retry configuration
    max_retries: int = Field(3, ge=0, le=10)
    retry_delay_seconds: int = Field(60, ge=1, le=3600)
    timeout_seconds: int = Field(30, ge=1, le=300)
    
    # Rate limiting
    rate_limit_per_minute: Optional[int] = Field(None, ge=1, le=1000)
    
    # Headers and payload
    headers: Dict[str, str] = Field(default_factory=dict)
    payload_template: Optional[str] = None
    
    # Metadata
    enabled: bool = True
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('url')
    def validate_url_for_webhook(cls, v, values):
        """Validate URL is provided for webhook channels"""
        if values.get('channel') in [NotificationChannel.WEBHOOK, NotificationChannel.CUSTOM]:
            if not v:
                raise ValueError("URL is required for webhook channels")
        return v
    
    @validator('filters')
    def validate_filters(cls, v):
        """Validate filter structure"""
        # Ensure filters are JSON serializable
        import json
        try:
            json.dumps(v)
        except TypeError as e:
            raise ValueError(f"Filters must be JSON serializable: {e}")
        return v

class NotificationTemplateBase(BaseModel):
    """Base notification template model"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    
    # Template configuration
    channel: NotificationChannel
    event_type: WebhookEventType
    
    # Content
    subject_template: Optional[str] = None
    body_template: str = Field(..., min_length=1)
    fallback_template: Optional[str] = None
    
    # Formatting
    format: str = Field("markdown", pattern="^(plaintext|markdown|html|slack|teams)$")  # FIXED: regex→pattern
    color_map: Dict[str, str] = Field(default_factory=dict)  # Severity → color
    
    # Variables
    available_variables: List[str] = Field(default_factory=list)
    variable_defaults: Dict[str, Any] = Field(default_factory=dict)
    
    # Metadata
    is_default: bool = False
    tags: List[str] = Field(default_factory=list)
    
    @validator('body_template')
    def validate_template_syntax(cls, v):
        """Validate template has valid variable syntax"""
        # Check for common template variables
        if '{{' in v and '}}' in v:
            # Basic template validation
            import re
            variables = re.findall(r'{{\s*(\w+)\s*}}', v)
            if not variables:
                raise ValueError("Template contains template syntax but no variables")
        return v

# ============================================================================
# FULL MODELS WITH RELATIONSHIPS
# ============================================================================

class Webhook(WebhookBase):
    """Full webhook model with delivery statistics"""
    webhook_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    
    # Owner and scope
    owner_id: Optional[str] = None
    owner_type: str = Field("system", pattern="^(system|user|team|organization)$")  # FIXED: regex→pattern
    scope: str = Field("global", pattern="^(global|organization|project|user)$")  # FIXED: regex→pattern
    
    # Statistics
    total_deliveries: int = 0
    successful_deliveries: int = 0
    failed_deliveries: int = 0
    last_delivery_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    
    # Health
    status: WebhookStatus = WebhookStatus.PENDING
    health_score: float = Field(1.0, ge=0.0, le=1.0)
    consecutive_failures: int = 0
    
    # Relationships
    template_id: Optional[str] = None
    
    class Config:
        from_attributes = True

class NotificationTemplate(NotificationTemplateBase):
    """Full notification template model"""
    template_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    
    # Usage statistics
    usage_count: int = 0
    last_used_at: Optional[datetime] = None
    
    # Versioning
    version: int = 1
    is_active: bool = True
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    
    class Config:
        from_attributes = True

class NotificationDelivery(BaseModel):
    """Notification delivery attempt record"""
    delivery_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    notification_id: str
    webhook_id: str
    
    # Delivery details
    status: WebhookStatus = WebhookStatus.PENDING
    attempt_number: int = 1
    max_attempts: int = 3
    
    # Timing
    scheduled_for: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    next_retry_at: Optional[datetime] = None
    
    # Results
    success: Optional[bool] = None
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    response_time_ms: Optional[float] = None
    
    # Payload
    payload_sent: Dict[str, Any] = Field(default_factory=dict)
    headers_sent: Dict[str, str] = Field(default_factory=dict)
    
    # Metadata
    retry_count: int = 0
    delivery_channel: NotificationChannel
    
    class Config:
        from_attributes = True

class NotificationEvent(BaseModel):
    """Notification event triggered by system events"""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: WebhookEventType
    
    # Source
    source_system: str = Field("arf", pattern="^(arf|external|integration)$")  # FIXED: regex→pattern
    source_id: str  # e.g., incident_id, policy_id, rollback_id
    source_type: str = Field(..., pattern="^(incident|policy|rollback|agent|system)$")  # FIXED: regex→pattern
    
    # Context
    context: Dict[str, Any] = Field(default_factory=dict)
    severity: NotificationPriority = NotificationPriority.MEDIUM
    
    # Payload
    payload: Dict[str, Any] = Field(default_factory=dict)
    raw_data: Optional[Dict[str, Any]] = None
    
    # Metadata
    triggered_at: datetime = Field(default_factory=datetime.utcnow)
    processed: bool = False
    processed_at: Optional[datetime] = None
    
    # Relationships
    notification_ids: List[str] = Field(default_factory=list)
    
    class Config:
        from_attributes = True

class Notification(BaseModel):
    """Notification created from an event"""
    notification_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str
    
    # Configuration
    channel: NotificationChannel
    priority: NotificationPriority = NotificationPriority.MEDIUM
    urgent: bool = False
    
    # Content
    subject: Optional[str] = None
    body: str
    formatted_body: Optional[str] = None
    
    # Recipients
    recipient: Optional[str] = None  # email, phone, user_id, channel_id
    recipient_type: str = Field("system", pattern="^(user|team|channel|email|phone|webhook)$")  # FIXED: regex→pattern
    
    # Delivery
    status: WebhookStatus = WebhookStatus.PENDING
    delivery_attempts: List[str] = Field(default_factory=list)  # delivery_ids
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    sent_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    
    # Metadata
    template_id: Optional[str] = None
    webhook_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        from_attributes = True

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class WebhookCreate(WebhookBase):
    """Request model for creating a webhook"""
    pass

class WebhookUpdate(BaseModel):
    """Request model for updating a webhook"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    event_types: Optional[List[WebhookEventType]] = None
    filters: Optional[Dict[str, Any]] = None
    url: Optional[HttpUrl] = None
    enabled: Optional[bool] = None
    max_retries: Optional[int] = Field(None, ge=0, le=10)
    headers: Optional[Dict[str, str]] = None
    payload_template: Optional[str] = None
    tags: Optional[List[str]] = None

class NotificationTemplateCreate(NotificationTemplateBase):
    """Request model for creating a notification template"""
    pass

class NotificationTemplateUpdate(BaseModel):
    """Request model for updating a notification template"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    body_template: Optional[str] = None
    subject_template: Optional[str] = None
    format: Optional[str] = Field(None, pattern="^(plaintext|markdown|html|slack|teams)$")  # FIXED: regex→pattern
    is_default: Optional[bool] = None
    is_active: Optional[bool] = None
    tags: Optional[List[str]] = None

class SendNotificationRequest(BaseModel):
    """Request model for sending a notification"""
    channel: NotificationChannel
    recipient: Optional[str] = None
    subject: Optional[str] = None
    body: str
    priority: NotificationPriority = NotificationPriority.MEDIUM
    urgent: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Optional event context
    event_type: Optional[WebhookEventType] = None
    source_id: Optional[str] = None
    source_type: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)

class TestWebhookRequest(BaseModel):
    """Request model for testing a webhook"""
    payload: Dict[str, Any] = Field(default_factory=dict)
    headers: Optional[Dict[str, str]] = None
    use_template: bool = False
    
    @validator('payload')
    def validate_payload(cls, v):
        """Validate payload is JSON serializable"""
        import json
        try:
            json.dumps(v)
        except TypeError as e:
            raise ValueError(f"Payload must be JSON serializable: {e}")
        return v

class WebhookTestResponse(BaseModel):
    """Response model for webhook test"""
    success: bool
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    response_time_ms: float
    error_message: Optional[str] = None
    headers_received: Optional[Dict[str, str]] = None
    
    # Validation
    payload_valid: bool = True
    security_valid: bool = True
    url_valid: bool = True
    
    class Config:
        from_attributes = True

class NotificationStats(BaseModel):
    """Notification statistics"""
    period_start: datetime
    period_end: datetime
    
    # Counts
    total_notifications: int = 0
    total_events: int = 0
    total_deliveries: int = 0
    
    # By channel
    by_channel: Dict[NotificationChannel, int] = Field(default_factory=dict)
    
    # By status
    pending: int = 0
    delivered: int = 0
    failed: int = 0
    retrying: int = 0
    
    # Success rates
    delivery_success_rate: float = Field(0.0, ge=0.0, le=1.0)
    avg_response_time_ms: Optional[float] = None
    
    # Errors
    common_errors: Dict[str, int] = Field(default_factory=dict)
    
    class Config:
        from_attributes = True

# ============================================================================
# INTEGRATION MODELS
# ============================================================================

class SlackConfiguration(BaseModel):
    """Slack integration configuration"""
    webhook_url: HttpUrl
    channel: str = Field("#general")
    username: str = Field("ARF Bot")
    icon_emoji: str = Field(":robot_face:")
    icon_url: Optional[HttpUrl] = None
    
    # Message formatting
    include_attachments: bool = True
    include_footer: bool = True
    color_map: Dict[NotificationPriority, str] = Field(default_factory=lambda: {
        NotificationPriority.LOW: "#36a64f",
        NotificationPriority.MEDIUM: "#f2c744",
        NotificationPriority.HIGH: "#ff9900",
        NotificationPriority.CRITICAL: "#cc0000"
    })

class TeamsConfiguration(BaseModel):
    """Microsoft Teams integration configuration"""
    webhook_url: HttpUrl
    theme_color: str = Field("0078D7")
    include_facts: bool = True
    include_action_buttons: bool = False

class EmailConfiguration(BaseModel):
    """Email integration configuration"""
    smtp_host: str
    smtp_port: int = Field(587, ge=1, le=65535)
    smtp_username: str
    smtp_password: str  # Should be encrypted in storage
    use_tls: bool = True
    use_ssl: bool = False
    
    # Email defaults
    from_email: str
    from_name: str = Field("ARF Notifications")
    reply_to: Optional[str] = None
    
    # Template
    html_template: Optional[str] = None
    text_template: Optional[str] = None

class PagerDutyConfiguration(BaseModel):
    """PagerDuty integration configuration"""
    integration_key: str
    service_id: Optional[str] = None
    escalation_policy_id: Optional[str] = None
    urgency_map: Dict[NotificationPriority, str] = Field(default_factory=lambda: {
        NotificationPriority.LOW: "low",
        NotificationPriority.MEDIUM: "medium",
        NotificationPriority.HIGH: "high",
        NotificationPriority.CRITICAL: "critical"
    })

# ============================================================================
# EVENT PAYLOAD MODELS
# ============================================================================

class IncidentEventPayload(BaseModel):
    """Payload for incident-related events"""
    incident_id: str
    title: str
    severity: str
    status: str
    incident_type: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # Additional context
    agent_id: Optional[str] = None
    affected_users: Optional[int] = None
    tags: List[str] = Field(default_factory=list)
    
    # Changes (for update events)
    changes: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

class PolicyEventPayload(BaseModel):
    """Payload for policy-related events"""
    policy_id: str
    policy_type: str
    triggered: bool
    confidence: float
    evaluation_time: datetime
    
    # Context
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    input_data: Optional[Dict[str, Any]] = None
    
    # Results
    matched_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_actions: List[Dict[str, Any]] = Field(default_factory=list)
    
    class Config:
        from_attributes = True

class RollbackEventPayload(BaseModel):
    """Payload for rollback-related events"""
    action_id: str
    execution_id: str
    status: str
    success: bool
    action_type: str
    
    # Context
    executed_by: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    
    # Results
    error_message: Optional[str] = None
    new_state: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

class SystemEventPayload(BaseModel):
    """Payload for system-related events"""
    event_type: str
    severity: NotificationPriority
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # System context
    component: Optional[str] = None
    resource: Optional[str] = None
    metric_name: Optional[str] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    
    # Alert details
    alert_id: Optional[str] = None
    alert_name: Optional[str] = None
    
    class Config:
        from_attributes = True

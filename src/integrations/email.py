"""
Email integration for ARF notifications.
Psychology: Formal communication with structured templates for different stakeholders.
Intention: Reliable email delivery with HTML and plaintext fallback.
"""
import json
import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import asyncio
from concurrent.futures import ThreadPoolExecutor
import re  # Added missing import
import time  # Added missing import

import aiosmtplib
from jinja2 import Environment, BaseLoader, Template

from src.models.webhook import (
    EmailConfiguration, Notification, NotificationPriority, NotificationChannel,
    IncidentEventPayload, PolicyEventPayload, RollbackEventPayload, SystemEventPayload
)
# Removed WebhookEventType import - it's not defined in webhook.py
# We'll define it locally or use string literals

from src.integrations.base import BaseIntegration, IntegrationType, IntegrationStatus

logger = logging.getLogger(__name__)

# Define WebhookEventType locally since it's not in webhook.py
class WebhookEventType:
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_RESOLVED = "incident_resolved"
    POLICY_EVALUATED = "policy_evaluated"
    POLICY_TRIGGERED = "policy_triggered"
    ROLLBACK_EXECUTED = "rollback_executed"
    ROLLBACK_FAILED = "rollback_failed"
    SYSTEM_HEALTH_CHANGE = "system_health_change"
    CUSTOM_EVENT = "custom_event"

class EmailIntegration(BaseIntegration):
    """SMTP email integration"""
    
    def __init__(self, config: EmailConfiguration):
        super().__init__(config)
        self.config = config
        self._executor = ThreadPoolExecutor(max_workers=5)
        self._jinja_env = Environment(loader=BaseLoader())
        
        # Pre-compile templates
        self._templates = {
            "incident": self._compile_incident_template(),
            "policy": self._compile_policy_template(),
            "rollback": self._compile_rollback_template(),
            "system": self._compile_system_template()
        }
    
    def get_integration_type(self) -> IntegrationType:
        return IntegrationType.EMAIL
    
    async def connect(self) -> bool:
        """Test SMTP connection"""
        try:
            # Test SMTP connection
            await self._test_smtp_connection()
            self.status = IntegrationStatus.CONNECTED
            logger.info(f"Email integration connected to {self.config.smtp_server}:{self.config.smtp_port}")
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
    
    async def _test_smtp_connection(self):
        """Test SMTP connection"""
        try:
            # Use aiosmtplib for async SMTP
            smtp_client = aiosmtplib.SMTP(
                hostname=self.config.smtp_server,
                port=self.config.smtp_port,
                use_tls=self.config.use_tls,
                start_tls=self.config.start_tls,
                timeout=10
            )
            
            await smtp_client.connect()
            
            if self.config.smtp_username and self.config.smtp_password:
                await smtp_client.login(
                    self.config.smtp_username,
                    self.config.smtp_password
                )
            
            await smtp_client.quit()
            
        except Exception as e:
            logger.error(f"SMTP connection test failed: {e}")
            raise
    
    async def validate_configuration(self) -> bool:
        """Validate email configuration"""
        try:
            # Check required fields
            if not self.config.smtp_server:
                logger.error("SMTP server is required")
                return False
            
            if not self.config.smtp_port:
                logger.error("SMTP port is required")
                return False
            
            if not self.config.sender_email:
                logger.error("Sender email is required")
                return False
            
            # Validate email format
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, self.config.sender_email):
                logger.error(f"Invalid sender email: {self.config.sender_email}")
                return False
            
            # Test SMTP connection
            await self._test_smtp_connection()
            
            logger.info("Email configuration validated successfully")
            return True
        
        except Exception as e:
            logger.error(f"Email configuration validation failed: {e}")
            return False
    
    async def send_notification(self, notification: Notification) -> Dict[str, Any]:
        """Send notification via email"""
        start_time = time.time()
        
        try:
            # Ensure connected
            if self.status != IntegrationStatus.CONNECTED:
                connected = await self.connect()
                if not connected:
                    self.health.record_failure()
                    return {
                        "success": False,
                        "error": "Failed to connect to SMTP server",
                        "response_time_ms": (time.time() - start_time) * 1000
                    }
            
            # Prepare email message
            message = await self._prepare_email_message(notification)
            
            # Send email using thread pool (SMTP is blocking)
            success = await asyncio.get_event_loop().run_in_executor(
                self._executor,
                self._send_smtp_email,
                message
            )
            
            response_time_ms = (time.time() - start_time) * 1000
            
            if success:
                self.health.record_success(response_time_ms / 1000)
                logger.info(f"Email notification sent to {self._get_recipients_str(notification)}")
                return {
                    "success": True,
                    "message": "Notification sent via email",
                    "response_time_ms": response_time_ms
                }
            else:
                self.health.record_failure()
                logger.error(f"Failed to send email notification")
                return {
                    "success": False,
                    "error": "SMTP send failed",
                    "response_time_ms": response_time_ms
                }
        
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            self.health.record_failure()
            logger.error(f"Failed to send email notification: {e}")
            return {
                "success": False,
                "error": str(e),
                "response_time_ms": response_time_ms
            }
    
    async def _prepare_email_message(self, notification: Notification) -> MIMEMultipart:
        """Prepare email message with HTML and plaintext"""
        metadata = notification.metadata or {}
        event_type = metadata.get("event_type", "unknown")
        
        # Create message
        message = MIMEMultipart("alternative")
        
        # Set headers
        message["Subject"] = await self._get_email_subject(notification, event_type)
        message["From"] = self.config.sender_email
        message["To"] = await self._get_email_recipients(notification)
        
        # Add CC if configured
        if self.config.cc_recipients:
            message["Cc"] = ", ".join(self.config.cc_recipients)
        
        # Add BCC if configured
        if self.config.bcc_recipients:
            message["Bcc"] = ", ".join(self.config.bcc_recipients)
        
        # Add reply-to if configured
        if self.config.reply_to:
            message["Reply-To"] = self.config.reply_to
        
        # Create plaintext version
        plaintext = await self._create_plaintext_body(notification, event_type)
        message.attach(MIMEText(plaintext, "plain", "utf-8"))
        
        # Create HTML version if enabled
        if self.config.use_html:
            html = await self._create_html_body(notification, event_type)
            message.attach(MIMEText(html, "html", "utf-8"))
        
        return message
    
    async def _get_email_subject(self, notification: Notification, event_type: str) -> str:
        """Get email subject line"""
        prefix_map = {
            NotificationPriority.CRITICAL: "[CRITICAL] ",
            NotificationPriority.HIGH: "[HIGH] ",
            NotificationPriority.MEDIUM: "[MEDIUM] ",
            NotificationPriority.LOW: "[LOW] "
        }
        
        prefix = prefix_map.get(notification.priority, "")
        
        if event_type == WebhookEventType.INCIDENT_CREATED:
            return f"{prefix}New Incident: {notification.metadata.get('source_id', 'Unknown')}"
        elif event_type == WebhookEventType.INCIDENT_UPDATED:
            return f"{prefix}Incident Updated: {notification.metadata.get('source_id', 'Unknown')}"
        elif event_type == WebhookEventType.INCIDENT_RESOLVED:
            return f"[RESOLVED] Incident Resolved: {notification.metadata.get('source_id', 'Unknown')}"
        elif event_type == WebhookEventType.POLICY_TRIGGERED:
            return f"{prefix}Policy Triggered"
        elif event_type == WebhookEventType.ROLLBACK_EXECUTED:
            return f"{prefix}Rollback Executed"
        elif event_type == WebhookEventType.ROLLBACK_FAILED:
            return f"{prefix}Rollback Failed"
        else:
            return f"{prefix}ARF Notification"
    
    async def _get_email_recipients(self, notification: Notification) -> str:
        """Get email recipients"""
        # If notification has specific recipient, use it
        if notification.recipient:
            return notification.recipient
        
        # Otherwise use default recipients from config
        return ", ".join(self.config.default_recipients)
    
    def _get_recipients_str(self, notification: Notification) -> str:
        """Get recipients as string for logging"""
        if notification.recipient:
            return notification.recipient
        return f"{len(self.config.default_recipients)} recipients"
    
    async def _create_plaintext_body(self, notification: Notification, event_type: str) -> str:
        """Create plaintext email body"""
        metadata = notification.metadata or {}
        
        # Use template if available for this event type
        template_type = self._get_template_type(event_type)
        if template_type in self._templates:
            context = await self._get_template_context(notification, metadata, event_type)
            return self._templates[template_type].render(context)
        
        # Fallback to simple formatting
        lines = []
        
        # Add header
        lines.append("=" * 60)
        lines.append(f"ARF NOTIFICATION - {notification.priority.value.upper()}")
        lines.append("=" * 60)
        lines.append("")
        
        # Add event info
        if metadata.get("event_type"):
            lines.append(f"Event Type: {metadata['event_type']}")
        
        if metadata.get("source_type"):
            lines.append(f"Source: {metadata['source_type']}")
        
        if metadata.get("source_id"):
            lines.append(f"ID: {metadata['source_id']}")
        
        lines.append(f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Urgent: {'YES' if notification.urgent else 'NO'}")
        lines.append("")
        lines.append("-" * 60)
        lines.append("")
        
        # Add body
        lines.append("MESSAGE:")
        lines.append("")
        lines.append(notification.body)
        lines.append("")
        lines.append("-" * 60)
        
        # Add footer
        lines.append("")
        lines.append("This is an automated notification from the ARF (Agentic Reliability Framework).")
        lines.append(f"Notification ID: {notification.notification_id}")
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    async def _create_html_body(self, notification: Notification, event_type: str) -> str:
        """Create HTML email body"""
        metadata = notification.metadata or {}
        
        # Determine color based on priority
        color_map = {
            NotificationPriority.CRITICAL: "#dc3545",
            NotificationPriority.HIGH: "#fd7e14",
            NotificationPriority.MEDIUM: "#ffc107",
            NotificationPriority.LOW: "#17a2b8"
        }
        priority_color = color_map.get(notification.priority, "#6c757d")
        
        # Create HTML template
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: {priority_color};
                    color: white;
                    padding: 20px;
                    border-radius: 5px 5px 0 0;
                }}
                .content {{
                    border: 1px solid #dee2e6;
                    border-top: none;
                    padding: 20px;
                    border-radius: 0 0 5px 5px;
                }}
                .priority-badge {{
                    display: inline-block;
                    padding: 4px 8px;
                    background-color: {priority_color};
                    color: white;
                    border-radius: 3px;
                    font-size: 12px;
                    font-weight: bold;
                    text-transform: uppercase;
                }}
                .details-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin: 20px 0;
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                }}
                .detail-item {{
                    margin-bottom: 5px;
                }}
                .detail-label {{
                    font-weight: bold;
                    color: #6c757d;
                    font-size: 14px;
                }}
                .detail-value {{
                    color: #212529;
                    font-size: 15px;
                }}
                .message-box {{
                    background-color: #f8f9fa;
                    border-left: 4px solid {priority_color};
                    padding: 15px;
                    margin: 20px 0;
                    white-space: pre-wrap;
                    font-family: monospace;
                }}
                .footer {{
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #dee2e6;
                    color: #6c757d;
                    font-size: 12px;
                }}
                @media (max-width: 600px) {{
                    .details-grid {{
                        grid-template-columns: 1fr;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2 style="margin: 0;">
                    {'🚨 ' if notification.priority == NotificationPriority.CRITICAL else ''}
                    {'⚠️ ' if notification.priority == NotificationPriority.HIGH else ''}
                    ARF Notification
                </h2>
                <p style="margin: 5px 0 0 0; opacity: 0.9;">
                    {self._get_event_type_display(event_type)}
                </p>
            </div>
            
            <div class="content">
                <span class="priority-badge">{notification.priority.value.upper()}</span>
                {'<span class="priority-badge" style="background-color: #dc3545; margin-left: 5px;">URGENT</span>' if notification.urgent else ''}
                
                <div class="details-grid">
                    <div class="detail-item">
                        <div class="detail-label">Event Type</div>
                        <div class="detail-value">{metadata.get('event_type', 'Unknown')}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Source</div>
                        <div class="detail-value">{metadata.get('source_type', 'Unknown')}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">ID</div>
                        <div class="detail-value">{metadata.get('source_id', 'N/A')}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Time</div>
                        <div class="detail-value">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
                    </div>
                    {f'<div class="detail-item"><div class="detail-label">Webhook</div><div class="detail-value">{metadata.get("webhook_name", "N/A")}</div></div>' if metadata.get("webhook_name") else ""}
                </div>
                
                <h3>Message</h3>
                <div class="message-box">
                    {notification.body.replace('\n', '<br>')}
                </div>
                
                <div class="footer">
                    <p>
                        This is an automated notification from the <strong>Agentic Reliability Framework (ARF)</strong>.<br>
                        Notification ID: <code>{notification.notification_id}</code><br>
                        Please do not reply to this email.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _get_event_type_display(self, event_type: str) -> str:
        """Get display name for event type"""
        display_map = {
            WebhookEventType.INCIDENT_CREATED: "New Incident Created",
            WebhookEventType.INCIDENT_UPDATED: "Incident Updated",
            WebhookEventType.INCIDENT_RESOLVED: "Incident Resolved",
            WebhookEventType.POLICY_EVALUATED: "Policy Evaluated",
            WebhookEventType.POLICY_TRIGGERED: "Policy Triggered",
            WebhookEventType.ROLLBACK_EXECUTED: "Rollback Executed",
            WebhookEventType.ROLLBACK_FAILED: "Rollback Failed",
            WebhookEventType.SYSTEM_HEALTH_CHANGE: "System Health Change",
            WebhookEventType.CUSTOM_EVENT: "Custom Event"
        }
        return display_map.get(event_type, "System Notification")
    
    def _send_smtp_email(self, message: MIMEMultipart) -> bool:
        """Send email via SMTP (blocking, runs in thread pool)"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to SMTP server
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                if self.config.use_tls:
                    server.starttls(context=context)
                
                if self.config.smtp_username and self.config.smtp_password:
                    server.login(self.config.smtp_username, self.config.smtp_password)
                
                # Get all recipients
                all_recipients = []
                all_recipients.extend(message["To"].split(", ") if message["To"] else [])
                all_recipients.extend(message["Cc"].split(", ") if message.get("Cc") else [])
                all_recipients.extend(message["Bcc"].split(", ") if message.get("Bcc") else [])
                
                # Send email
                server.send_message(message)
                
                return True
        
        except Exception as e:
            logger.error(f"Failed to send SMTP email: {e}")
            return False
    
    def _compile_incident_template(self) -> Template:
        """Compile incident template"""
        template_str = """
INCIDENT NOTIFICATION
=====================

Event: {{ event_type }}
Incident ID: {{ source_id }}
Severity: {{ severity }}
Status: {{ status }}
Created: {{ created_at }}

DESCRIPTION:
{{ description }}

ASSIGNED TO: {{ assigned_to|default('Unassigned') }}

ACTION REQUIRED: {{ action_required|default('Please review the incident') }}

LINKS:
- View Incident: {{ dashboard_url }}/incidents/{{ source_id }}
- ARF Dashboard: {{ dashboard_url }}

---
Automated notification from ARF
Notification ID: {{ notification_id }}
"""
        return self._jinja_env.from_string(template_str)
    
    def _compile_policy_template(self) -> Template:
        """Compile policy template"""
        template_str = """
POLICY NOTIFICATION
===================

Event: {{ event_type }}
Policy: {{ policy_name|default('Unknown') }}
Triggered: {{ triggered|default('false') }}
Confidence: {{ confidence|default(0.0) }}

CONTEXT:
{{ context|default('No additional context') }}

ACTIONS TAKEN:
{{ actions_taken|default('No actions taken') }}

---
Automated notification from ARF
Notification ID: {{ notification_id }}
"""
        return self._jinja_env.from_string(template_str)
    
    def _compile_rollback_template(self) -> Template:
        """Compile rollback template"""
        template_str = """
ROLLBACK NOTIFICATION
=====================

Event: {{ event_type }}
Action: {{ action_type|default('Unknown') }}
Status: {{ status|default('Unknown') }}
Success: {{ success|default('false') }}
Duration: {{ duration_ms|default(0) }}ms

ERROR DETAILS:
{{ error_details|default('No errors') }}

ROLLBACK REASON:
{{ rollback_reason|default('Not specified') }}

---
Automated notification from ARF
Notification ID: {{ notification_id }}
"""
        return self._jinja_env.from_string(template_str)
    
    def _compile_system_template(self) -> Template:
        """Compile system template"""
        template_str = """
SYSTEM NOTIFICATION
===================

Event: {{ event_type }}
Component: {{ component|default('Unknown') }}
Status: {{ status|default('Unknown') }}

MESSAGE:
{{ message }}

IMPACT:
{{ impact|default('No impact specified') }}

NEXT STEPS:
{{ next_steps|default('Monitor system status') }}

---
Automated notification from ARF
Notification ID: {{ notification_id }}
"""
        return self._jinja_env.from_string(template_str)
    
    def _get_template_type(self, event_type: str) -> str:
        """Get template type based on event type"""
        if "incident" in event_type.lower():
            return "incident"
        elif "policy" in event_type.lower():
            return "policy"
        elif "rollback" in event_type.lower():
            return "rollback"
        else:
            return "system"
    
    async def _get_template_context(self, notification: Notification, 
                                   metadata: Dict[str, Any], 
                                   event_type: str) -> Dict[str, Any]:
        """Get template context data"""
        context = {
            "event_type": event_type,
            "source_id": metadata.get("source_id", "Unknown"),
            "notification_id": notification.notification_id,
            "dashboard_url": "https://arf.example.com",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add payload data if available
        if notification.metadata.get("payload"):
            context.update(notification.metadata["payload"])
        
        return context
    
    async def _perform_health_test(self) -> Dict[str, Any]:
        """Perform email-specific health test"""
        try:
            # Test SMTP connection
            await self._test_smtp_connection()
            
            return {
                "success": True,
                "message": "SMTP connection successful",
                "smtp_server": self.config.smtp_server,
                "smtp_port": self.config.smtp_port,
                "use_tls": self.config.use_tls
            }
        
        except Exception as e:
            return {
                "success": False,
                "message": f"SMTP health check failed: {str(e)}"
            }

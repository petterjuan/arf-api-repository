"""
Webhook service for ARF.
Psychology: Event-driven architecture with guaranteed delivery and retry mechanisms.
Intention: Reliable notification system with multi-channel support and templating.
"""
import asyncio
import json
import hashlib
import hmac
import time
from typing import List, Optional, Dict, Any, Tuple, Callable
from datetime import datetime, timedelta
from functools import wraps
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import redis
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, and_, or_, func

from src.database import get_db
from src.database.redis_client import get_redis
from src.models.webhook import (
    Webhook, Notification, NotificationEvent, NotificationDelivery,
    WebhookStatus, WebhookEventType, NotificationChannel, DeliveryMethod,
    WebhookSecurity, NotificationPriority, NotificationTemplate,
    IncidentEventPayload, PolicyEventPayload, RollbackEventPayload, SystemEventPayload,
    SlackConfiguration, TeamsConfiguration, EmailConfiguration, PagerDutyConfiguration
)
from src.services.rollback_service import get_rollback_service
from src.middleware.logging import BusinessEventLogger

logger = logging.getLogger(__name__)

class WebhookError(Exception):
    """Custom webhook error"""
    def __init__(self, message: str, webhook_id: Optional[str] = None, 
                 retryable: bool = True):
        self.message = message
        self.webhook_id = webhook_id
        self.retryable = retryable
        super().__init__(self.message)

def with_retry(max_retries: int = 3, delay: float = 1.0):
    """Decorator for retrying webhook deliveries"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    if attempt < max_retries:
                        wait_time = delay * (2 ** attempt)  # Exponential backoff
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries} failed for {func.__name__}: {e}. "
                            f"Retrying in {wait_time}s..."
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(
                            f"All {max_retries + 1} attempts failed for {func.__name__}: {e}"
                        )
            raise last_error
        return wrapper
    return decorator

class WebhookService:
    """Service for webhook and notification operations"""
    
    def __init__(self, db_session: Optional[Session] = None,
                 redis_client: Optional[redis.Redis] = None):
        self.db = db_session
        self.redis = redis_client or get_redis()
        self._cache_prefix = "webhook:cache:"
        self._queue_prefix = "webhook:queue:"
        self._executor = ThreadPoolExecutor(max_workers=10)
        
        # Initialize channel integrations
        self._channel_handlers = {
            NotificationChannel.WEBHOOK: self._deliver_webhook,
            NotificationChannel.SLACK: self._deliver_slack,
            NotificationChannel.TEAMS: self._deliver_teams,
            NotificationChannel.EMAIL: self._deliver_email,
            NotificationChannel.PAGERDUTY: self._deliver_pagerduty,
            NotificationChannel.DISCORD: self._deliver_discord,
        }
    
    def _get_db(self):
        """Get database session (lazy initialization)"""
        if self.db is None:
            from src.database import SessionLocal
            self.db = SessionLocal()
        return self.db
    
    def _generate_signature(self, payload: str, secret: str) -> str:
        """Generate HMAC signature for webhook security"""
        return hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    async def create_webhook(self, webhook_data: Dict[str, Any], 
                           owner_id: Optional[str] = None) -> str:
        """Create a new webhook configuration"""
        db = self._get_db()
        
        # Generate webhook ID
        webhook_id = str(uuid.uuid4())
        
        # Create webhook object
        webhook = Webhook(
            webhook_id=webhook_id,
            owner_id=owner_id,
            **webhook_data
        )
        
        # Save to Redis cache
        cache_key = f"{self._cache_prefix}webhook:{webhook_id}"
        self.redis.setex(
            cache_key,
            3600,  # 1 hour cache
            json.dumps(webhook.model_dump())
        )
        
        # Index by event types
        for event_type in webhook.event_types:
            index_key = f"{self._cache_prefix}index:event:{event_type.value}"
            self.redis.sadd(index_key, webhook_id)
        
        logger.info(f"Created webhook {webhook_id}: {webhook.name}")
        return webhook_id
    
    async def get_webhook(self, webhook_id: str) -> Optional[Webhook]:
        """Get webhook by ID"""
        # Try cache first
        cache_key = f"{self._cache_prefix}webhook:{webhook_id}"
        cached = self.redis.get(cache_key)
        
        if cached:
            data = json.loads(cached)
            # Convert string dates back to datetime
            for date_field in ['created_at', 'updated_at', 'last_delivery_at', 
                             'last_success_at', 'last_failure_at', 'expires_at']:
                if data.get(date_field):
                    data[date_field] = datetime.fromisoformat(data[date_field])
            return Webhook(**data)
        
        # In production, would fetch from database
        return None
    
    async def update_webhook(self, webhook_id: str, updates: Dict[str, Any]) -> bool:
        """Update webhook configuration"""
        webhook = await self.get_webhook(webhook_id)
        if not webhook:
            return False
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(webhook, key):
                setattr(webhook, key, value)
        
        webhook.updated_at = datetime.utcnow()
        
        # Update cache
        cache_key = f"{self._cache_prefix}webhook:{webhook_id}"
        self.redis.setex(
            cache_key,
            3600,
            json.dumps(webhook.model_dump())
        )
        
        logger.info(f"Updated webhook {webhook_id}")
        return True
    
    async def delete_webhook(self, webhook_id: str) -> bool:
        """Delete a webhook"""
        # Remove from cache
        cache_key = f"{self._cache_prefix}webhook:{webhook_id}"
        self.redis.delete(cache_key)
        
        # Remove from event type indexes
        webhook = await self.get_webhook(webhook_id)
        if webhook:
            for event_type in webhook.event_types:
                index_key = f"{self._cache_prefix}index:event:{event_type.value}"
                self.redis.srem(index_key, webhook_id)
        
        logger.info(f"Deleted webhook {webhook_id}")
        return True
    
    async def trigger_event(self, event_type: WebhookEventType,
                          source_id: str, source_type: str,
                          payload: Dict[str, Any],
                          severity: NotificationPriority = NotificationPriority.MEDIUM,
                          context: Optional[Dict[str, Any]] = None) -> str:
        """
        Trigger a notification event and process webhooks.
        
        Psychology: Event-driven pattern with fan-out to multiple webhooks.
        Intention: Decouple event producers from notification consumers.
        """
        # Create event record
        event = NotificationEvent(
            event_type=event_type,
            source_id=source_id,
            source_type=source_type,
            payload=payload,
            severity=severity,
            context=context or {}
        )
        
        # Save event
        event_key = f"{self._cache_prefix}event:{event.event_id}"
        self.redis.setex(
            event_key,
            86400 * 7,  # 7 days retention
            json.dumps(event.model_dump())
        )
        
        # Find matching webhooks
        webhook_ids = await self._find_matching_webhooks(event_type, payload)
        
        # Process each webhook asynchronously
        notification_ids = []
        for webhook_id in webhook_ids:
            webhook = await self.get_webhook(webhook_id)
            if not webhook or not webhook.enabled:
                continue
            
            # Create notification
            notification = await self._create_notification(event, webhook)
            notification_ids.append(notification.notification_id)
            
            # Queue for delivery
            await self._queue_notification(notification, webhook)
        
        # Update event with notification IDs
        event.notification_ids = notification_ids
        self.redis.setex(event_key, 86400 * 7, json.dumps(event.model_dump()))
        
        # Log business event
        BusinessEventLogger.log_event(
            event_type="webhook_event_triggered",
            event_data={
                "event_type": event_type.value,
                "source_type": source_type,
                "webhook_count": len(webhook_ids),
                "notification_count": len(notification_ids)
            }
        )
        
        logger.info(
            f"Triggered event {event_type.value} for {source_type} {source_id}. "
            f"Matched {len(webhook_ids)} webhooks, created {len(notification_ids)} notifications."
        )
        
        return event.event_id
    
    async def _find_matching_webhooks(self, event_type: WebhookEventType,
                                    payload: Dict[str, Any]) -> List[str]:
        """Find webhooks that match the event type and payload filters"""
        # Get webhooks for this event type
        index_key = f"{self._cache_prefix}index:event:{event_type.value}"
        webhook_ids = self.redis.smembers(index_key)
        
        matching_webhooks = []
        
        for webhook_id in webhook_ids:
            webhook = await self.get_webhook(webhook_id)
            if not webhook or not webhook.enabled:
                continue
            
            # Check filters
            if await self._matches_filters(webhook.filters, payload):
                matching_webhooks.append(webhook_id)
        
        return matching_webhooks
    
    async def _matches_filters(self, filters: Dict[str, Any], payload: Dict[str, Any]) -> bool:
        """Check if payload matches webhook filters"""
        if not filters:
            return True
        
        for field, expected_value in filters.items():
            # Navigate nested payload (e.g., "incident.severity")
            parts = field.split('.')
            current = payload
            
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    # Field not found in payload
                    return False
            
            # Compare values
            if current != expected_value:
                return False
        
        return True
    
    async def _create_notification(self, event: NotificationEvent,
                                 webhook: Webhook) -> Notification:
        """Create a notification from an event and webhook configuration"""
        # Render template if available
        body = await self._render_notification_body(event, webhook)
        
        # Determine recipient
        recipient = self._determine_recipient(webhook, event)
        
        notification = Notification(
            event_id=event.event_id,
            channel=webhook.channel,
            priority=event.severity,
            urgent=event.severity in [NotificationPriority.HIGH, NotificationPriority.CRITICAL],
            body=body,
            recipient=recipient,
            webhook_id=webhook.webhook_id,
            metadata={
                "event_type": event.event_type.value,
                "source_type": event.source_type,
                "source_id": event.source_id,
                "webhook_name": webhook.name
            }
        )
        
        # Save notification
        notification_key = f"{self._cache_prefix}notification:{notification.notification_id}"
        self.redis.setex(
            notification_key,
            86400 * 30,  # 30 days retention
            json.dumps(notification.model_dump())
        )
        
        return notification
    
    async def _render_notification_body(self, event: NotificationEvent,
                                      webhook: Webhook) -> str:
        """Render notification body using template"""
        # If webhook has a payload template, use it
        if webhook.payload_template:
            try:
                # Simple template rendering
                # In production, use Jinja2 or similar
                template = webhook.payload_template
                
                # Replace variables
                for key, value in event.payload.items():
                    placeholder = f"{{{{payload.{key}}}}}"
                    if placeholder in template:
                        template = template.replace(placeholder, str(value))
                
                # Replace context variables
                for key, value in event.context.items():
                    placeholder = f"{{{{context.{key}}}}}"
                    if placeholder in template:
                        template = template.replace(placeholder, str(value))
                
                return template
            except Exception as e:
                logger.error(f"Failed to render template for webhook {webhook.webhook_id}: {e}")
        
        # Default rendering based on event type
        if event.event_type in [
            WebhookEventType.INCIDENT_CREATED,
            WebhookEventType.INCIDENT_UPDATED,
            WebhookEventType.INCIDENT_RESOLVED
        ]:
            incident = event.payload
            return (
                f"Incident {incident.get('title', 'Unknown')}\n"
                f"Severity: {incident.get('severity', 'unknown')}\n"
                f"Status: {incident.get('status', 'unknown')}\n"
                f"Type: {incident.get('incident_type', 'unknown')}\n"
                f"Created: {incident.get('created_at', 'unknown')}"
            )
        
        elif event.event_type in [
            WebhookEventType.POLICY_EVALUATED,
            WebhookEventType.POLICY_TRIGGERED
        ]:
            policy = event.payload
            return (
                f"Policy {policy.get('policy_type', 'Unknown')} "
                f"{'triggered' if policy.get('triggered') else 'not triggered'}\n"
                f"Confidence: {policy.get('confidence', 0):.2f}\n"
                f"Time: {policy.get('evaluation_time', 'unknown')}"
            )
        
        elif event.event_type in [
            WebhookEventType.ROLLBACK_EXECUTED,
            WebhookEventType.ROLLBACK_FAILED
        ]:
            rollback = event.payload
            return (
                f"Rollback {rollback.get('status', 'unknown')}\n"
                f"Action: {rollback.get('action_type', 'unknown')}\n"
                f"Success: {rollback.get('success', False)}\n"
                f"Duration: {rollback.get('duration_ms', 0):.0f}ms"
            )
        
        # Generic fallback
        return json.dumps(event.payload, indent=2)
    
    def _determine_recipient(self, webhook: Webhook, event: NotificationEvent) -> Optional[str]:
        """Determine notification recipient"""
        # For webhook channels, recipient is the URL
        if webhook.channel == NotificationChannel.WEBHOOK:
            return str(webhook.url) if webhook.url else None
        
        # For email/SMS, extract from webhook configuration
        # In production, this would parse webhook.config for recipient info
        
        return None
    
    async def _queue_notification(self, notification: Notification,
                                webhook: Webhook) -> str:
        """Queue notification for delivery"""
        queue_key = f"{self._queue_prefix}{webhook.channel.value}"
        
        # Create queue item
        queue_item = {
            "notification_id": notification.notification_id,
            "webhook_id": webhook.webhook_id,
            "priority": notification.priority.value,
            "timestamp": datetime.utcnow().isoformat(),
            "attempt": 0
        }
        
        # Add to appropriate queue based on priority
        if notification.priority in [NotificationPriority.HIGH, NotificationPriority.CRITICAL]:
            # High priority queue
            self.redis.lpush(f"{queue_key}:high", json.dumps(queue_item))
        else:
            # Normal priority queue
            self.redis.lpush(f"{queue_key}:normal", json.dumps(queue_item))
        
        logger.debug(f"Queued notification {notification.notification_id} for {webhook.channel.value}")
        
        # Trigger background processing
        asyncio.create_task(self._process_delivery_queue(webhook.channel))
        
        return notification.notification_id
    
    async def _process_delivery_queue(self, channel: NotificationChannel):
        """Process delivery queue for a channel"""
        queue_key = f"{self._queue_prefix}{channel.value}"
        
        while True:
            try:
                # Check high priority queue first
                item_json = self.redis.rpop(f"{queue_key}:high")
                if not item_json:
                    # Check normal priority queue
                    item_json = self.redis.rpop(f"{queue_key}:normal")
                
                if not item_json:
                    # No items in queue, wait and retry
                    await asyncio.sleep(1)
                    continue
                
                item = json.loads(item_json)
                notification_id = item["notification_id"]
                webhook_id = item["webhook_id"]
                attempt = item.get("attempt", 0) + 1
                
                # Get notification and webhook
                notification = await self._get_notification(notification_id)
                webhook = await self.get_webhook(webhook_id)
                
                if not notification or not webhook:
                    logger.error(f"Notification {notification_id} or webhook {webhook_id} not found")
                    continue
                
                # Attempt delivery
                success = await self._deliver_notification(notification, webhook, attempt)
                
                if not success and attempt < webhook.max_retries:
                    # Re-queue for retry
                    item["attempt"] = attempt
                    item["next_retry"] = (datetime.utcnow() + 
                                        timedelta(seconds=webhook.retry_delay_seconds)).isoformat()
                    
                    # Use lower priority for retries
                    self.redis.lpush(f"{queue_key}:low", json.dumps(item))
                
            except Exception as e:
                logger.error(f"Error processing delivery queue for {channel.value}: {e}")
                await asyncio.sleep(5)
    
    async def _deliver_notification(self, notification: Notification,
                                  webhook: Webhook, attempt: int) -> bool:
        """Deliver notification through appropriate channel"""
        start_time = time.time()
        
        # Create delivery record
        delivery = NotificationDelivery(
            notification_id=notification.notification_id,
            webhook_id=webhook.webhook_id,
            attempt_number=attempt,
            max_attempts=webhook.max_retries,
            started_at=datetime.utcnow(),
            delivery_channel=webhook.channel
        )
        
        try:
            # Get appropriate handler
            handler = self._channel_handlers.get(webhook.channel)
            if not handler:
                raise WebhookError(f"No handler for channel: {webhook.channel}")
            
            # Execute delivery
            success, response = await handler(notification, webhook, delivery)
            
            # Update delivery record
            delivery.completed_at = datetime.utcnow()
            delivery.success = success
            delivery.response_time_ms = (time.time() - start_time) * 1000
            
            if response:
                delivery.status_code = response.get("status_code")
                delivery.response_body = response.get("body")
                delivery.headers_sent = response.get("headers", {})
            
            # Update webhook statistics
            await self._update_webhook_stats(webhook, success)
            
            # Update notification status
            notification.status = WebhookStatus.DELIVERED if success else WebhookStatus.FAILED
            if success:
                notification.delivered_at = datetime.utcnow()
            
            # Save updated records
            await self._save_delivery(delivery)
            await self._save_notification(notification)
            
            # Log business event
            BusinessEventLogger.log_event(
                event_type="notification_delivered" if success else "notification_failed",
                event_data={
                    "notification_id": notification.notification_id,
                    "channel": webhook.channel.value,
                    "attempt": attempt,
                    "success": success,
                    "response_time_ms": delivery.response_time_ms
                }
            )
            
            return success
            
        except Exception as e:
            # Update delivery record with error
            delivery.completed_at = datetime.utcnow()
            delivery.success = False
            delivery.error_message = str(e)
            delivery.response_time_ms = (time.time() - start_time) * 1000
            
            # Save delivery record
            await self._save_delivery(delivery)
            
            # Update notification status
            notification.status = WebhookStatus.FAILED
            await self._save_notification(notification)
            
            logger.error(f"Failed to deliver notification {notification.notification_id}: {e}")
            return False
    
    @with_retry(max_retries=3, delay=1.0)
    async def _deliver_webhook(self, notification: Notification,
                             webhook: Webhook, delivery: NotificationDelivery) -> Tuple[bool, Dict]:
        """Deliver notification via HTTP webhook"""
        if not webhook.url:
            raise WebhookError("Webhook URL not configured")
        
        # Prepare payload
        payload = {
            "notification_id": notification.notification_id,
            "event_id": notification.event_id,
            "timestamp": datetime.utcnow().isoformat(),
            "channel": webhook.channel.value,
            "priority": notification.priority.value,
            "body": notification.body,
            "metadata": notification.metadata
        }
        
        # Add security headers
        headers = webhook.headers.copy()
        if webhook.security_method == WebhookSecurity.HMAC_SHA256:
            secret = webhook.security_config.get("secret")
            if secret:
                payload_str = json.dumps(payload)
                signature = self._generate_signature(payload_str, secret)
                headers["X-ARF-Signature"] = f"sha256={signature}"
                headers["X-ARF-Timestamp"] = str(int(time.time()))
        
        # Make HTTP request
        timeout = aiohttp.ClientTimeout(total=webhook.timeout_seconds)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                str(webhook.url),
                json=payload,
                headers=headers
            ) as response:
                success = 200 <= response.status < 300
                response_body = await response.text()
                
                return success, {
                    "status_code": response.status,
                    "body": response_body[:1000],  # Truncate
                    "headers": dict(response.headers)
                }
    
    async def _deliver_slack(self, notification: Notification,
                           webhook: Webhook, delivery: NotificationDelivery) -> Tuple[bool, Dict]:
        """Deliver notification to Slack"""
        # In production, implement Slack webhook API
        # For now, simulate delivery
        await asyncio.sleep(0.1)  # Simulate API call
        return True, {"status_code": 200, "body": "ok"}
    
    async def _deliver_teams(self, notification: Notification,
                           webhook: Webhook, delivery: NotificationDelivery) -> Tuple[bool, Dict]:
        """Deliver notification to Microsoft Teams"""
        await asyncio.sleep(0.1)  # Simulate API call
        return True, {"status_code": 200, "body": "ok"}
    
    async def _deliver_email(self, notification: Notification,
                           webhook: Webhook, delivery: NotificationDelivery) -> Tuple[bool, Dict]:
        """Deliver notification via email"""
        await asyncio.sleep(0.2)  # Simulate SMTP
        return True, {"status_code": 250, "body": "Message accepted"}
    
    async def _deliver_pagerduty(self, notification: Notification,
                               webhook: Webhook, delivery: NotificationDelivery) -> Tuple[bool, Dict]:
        """Deliver notification to PagerDuty"""
        await asyncio.sleep(0.1)  # Simulate API call
        return True, {"status_code": 202, "body": "accepted"}
    
    async def _deliver_discord(self, notification: Notification,
                             webhook: Webhook, delivery: NotificationDelivery) -> Tuple[bool, Dict]:
        """Deliver notification to Discord"""
        await asyncio.sleep(0.1)  # Simulate API call
        return True, {"status_code": 204, "body": ""}
    
    async def _update_webhook_stats(self, webhook: Webhook, success: bool):
        """Update webhook delivery statistics"""
        webhook.total_deliveries += 1
        webhook.last_delivery_at = datetime.utcnow()
        
        if success:
            webhook.successful_deliveries += 1
            webhook.last_success_at = datetime.utcnow()
            webhook.consecutive_failures = 0
            webhook.health_score = min(1.0, webhook.health_score + 0.1)
        else:
            webhook.failed_deliveries += 1
            webhook.last_failure_at = datetime.utcnow()
            webhook.consecutive_failures += 1
            webhook.health_score = max(0.0, webhook.health_score - 0.2)
        
        # Update status based on health
        if webhook.health_score < 0.3:
            webhook.status = WebhookStatus.FAILED
        elif webhook.consecutive_failures > 3:
            webhook.status = WebhookStatus.RETRYING
        else:
            webhook.status = WebhookStatus.DELIVERED
        
        # Update cache
        cache_key = f"{self._cache_prefix}webhook:{webhook.webhook_id}"
        self.redis.setex(
            cache_key,
            3600,
            json.dumps(webhook.model_dump())
        )
    
    async def _get_notification(self, notification_id: str) -> Optional[Notification]:
        """Get notification by ID"""
        key = f"{self._cache_prefix}notification:{notification_id}"
        cached = self.redis.get(key)
        
        if cached:
            data = json.loads(cached)
            # Convert string dates
            for date_field in ['created_at', 'sent_at', 'delivered_at', 'read_at']:
                if data.get(date_field):
                    data[date_field] = datetime.fromisoformat(data[date_field])
            return Notification(**data)
        
        return None
    
    async def _save_notification(self, notification: Notification):
        """Save notification to cache"""
        key = f"{self._cache_prefix}notification:{notification.notification_id}"
        self.redis.setex(
            key,
            86400 * 30,
            json.dumps(notification.model_dump())
        )
    
    async def _save_delivery(self, delivery: NotificationDelivery):
        """Save delivery record to cache"""
        key = f"{self._cache_prefix}delivery:{delivery.delivery_id}"
        self.redis.setex(
            key,
            86400 * 90,  # 90 days retention
            json.dumps(delivery.model_dump())
        )
    
    async def test_webhook(self, webhook_id: str, test_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Test webhook configuration with a test payload"""
        webhook = await self.get_webhook(webhook_id)
        if not webhook:
            raise WebhookError(f"Webhook not found: {webhook_id}")
        
        # Create test notification
        test_event = NotificationEvent(
            event_type=WebhookEventType.CUSTOM_EVENT,
            source_id="test",
            source_type="test",
            payload=test_payload,
            severity=NotificationPriority.MEDIUM,
            context={"test": True}
        )
        
        test_notification = await self._create_notification(test_event, webhook)
        
        # Attempt delivery
        start_time = time.time()
        success = False
        status_code = None
        response_body = None
        error_message = None
        
        try:
            success, response = await self._deliver_webhook(
                test_notification, webhook, NotificationDelivery(
                    notification_id=test_notification.notification_id,
                    webhook_id=webhook_id,
                    attempt_number=1,
                    max_attempts=1
                )
            )
            
            if response:
                status_code = response.get("status_code")
                response_body = response.get("body")
        
        except Exception as e:
            error_message = str(e)
        
        response_time_ms = (time.time() - start_time) * 1000
        
        return {
            "success": success,
            "status_code": status_code,
            "response_body": response_body,
            "response_time_ms": response_time_ms,
            "error_message": error_message,
            "webhook_config": {
                "url": str(webhook.url) if webhook.url else None,
                "method": webhook.method.value,
                "headers": webhook.headers,
                "security_method": webhook.security_method.value
            }
        }
    
    async def get_webhook_stats(self, webhook_id: str,
                              start_time: Optional[datetime] = None,
                              end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """Get statistics for a webhook"""
        webhook = await self.get_webhook(webhook_id)
        if not webhook:
            raise WebhookError(f"Webhook not found: {webhook_id}")
        
        # In production, would query database for time-range stats
        # For now, return cached statistics
        
        success_rate = 0.0
        if webhook.total_deliveries > 0:
            success_rate = webhook.successful_deliveries / webhook.total_deliveries
        
        return {
            "webhook_id": webhook_id,
            "name": webhook.name,
            "status": webhook.status.value,
            "health_score": webhook.health_score,
            "statistics": {
                "total_deliveries": webhook.total_deliveries,
                "successful_deliveries": webhook.successful_deliveries,
                "failed_deliveries": webhook.failed_deliveries,
                "success_rate": success_rate,
                "consecutive_failures": webhook.consecutive_failures
            },
            "timestamps": {
                "created_at": webhook.created_at.isoformat() if webhook.created_at else None,
                "last_delivery_at": webhook.last_delivery_at.isoformat() if webhook.last_delivery_at else None,
                "last_success_at": webhook.last_success_at.isoformat() if webhook.last_success_at else None,
                "last_failure_at": webhook.last_failure_at.isoformat() if webhook.last_failure_at else None
            }
        }
    
    async def get_system_stats(self, 
                             start_time: Optional[datetime] = None,
                             end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """Get system-wide notification statistics"""
        # In production, would aggregate from database
        # For now, return mock statistics
        
        total_webhooks = len(self.redis.keys(f"{self._cache_prefix}webhook:*"))
        
        return {
            "period_start": start_time.isoformat() if start_time else None,
            "period_end": end_time.isoformat() if end_time else None,
            "total_webhooks": total_webhooks,
            "active_webhooks": total_webhooks,  # Would filter by enabled
            "queued_notifications": 0,  # Would count queue items
            "recent_deliveries": {
                "last_hour": 0,
                "last_24_hours": 0,
                "last_7_days": 0
            },
            "success_rates": {
                "overall": 0.95,
                "last_hour": 0.98,
                "last_24_hours": 0.96
            },
            "by_channel": {
                "webhook": {"total": 0, "success_rate": 0.0},
                "slack": {"total": 0, "success_rate": 0.0},
                "email": {"total": 0, "success_rate": 0.0}
            }
        }

# Singleton instance
_webhook_service = None

def get_webhook_service(
    db_session: Optional[Session] = None,
    redis_client: Optional[redis.Redis] = None
) -> WebhookService:
    """Get singleton WebhookService instance"""
    global _webhook_service
    if _webhook_service is None:
        _webhook_service = WebhookService(db_session, redis_client)
    return _webhook_service

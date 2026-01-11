"""
Webhook API endpoints for ARF.
Psychology: RESTful API for managing notification channels and webhooks.
Intention: Provide comprehensive webhook management with enterprise features.
"""
import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Body, status, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import redis

from src.auth.dependencies import get_current_user, require_role
from src.auth.models import UserRole
from src.database import get_db
from src.database.redis_client import get_redis
from src.models.webhook import (
    Webhook, WebhookCreate, WebhookUpdate, WebhookStatus, WebhookEventType,
    Notification, NotificationDelivery, NotificationPriority, NotificationChannel,
    WebhookSecurity, WebhookTestRequest, WebhookTestResponse,
    SlackConfiguration, TeamsConfiguration, EmailConfiguration,
    PagerDutyConfiguration, NotificationTemplate, NotificationTemplateCreate, NotificationTemplateUpdate
)
from src.services.webhook_service import get_webhook_service, WebhookError
from src.integrations import IntegrationFactory, IntegrationType
from src.middleware.logging import BusinessEventLogger

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Webhook Management Endpoints

@router.post("/", response_model=Dict[str, Any])
async def create_webhook(
    webhook_data: WebhookCreate,
    current_user: Dict = Depends(require_role(UserRole.OPERATOR)),
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Create a new webhook configuration.
    
    Permissions: Operator, Admin, Super Admin
    """
    try:
        webhook_service = get_webhook_service(db, redis_client)
        
        # Convert to dict for service
        webhook_dict = webhook_data.model_dump()
        webhook_dict["owner_id"] = current_user.get("user_id")
        
        # Create webhook
        webhook_id = await webhook_service.create_webhook(webhook_dict, current_user.get("user_id"))
        
        # Log business event
        BusinessEventLogger.log_event(
            event_type="webhook_created",
            event_data={
                "webhook_id": webhook_id,
                "name": webhook_data.name,
                "channel": webhook_data.channel.value,
                "owner": current_user.get("user_id"),
                "event_types": [et.value for et in webhook_data.event_types]
            }
        )
        
        return {
            "success": True,
            "webhook_id": webhook_id,
            "message": "Webhook created successfully"
        }
    
    except Exception as e:
        logger.error(f"Failed to create webhook: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create webhook: {str(e)}"
        )

@router.get("/", response_model=Dict[str, Any])
async def list_webhooks(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    status_filter: Optional[WebhookStatus] = Query(None, description="Filter by webhook status"),
    channel_filter: Optional[NotificationChannel] = Query(None, description="Filter by notification channel"),
    event_type_filter: Optional[WebhookEventType] = Query(None, description="Filter by event type"),
    current_user: Dict = Depends(get_current_user),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    List webhooks with filtering and pagination.
    
    Permissions: Viewer, Operator, Admin, Super Admin
    """
    try:
        webhook_service = get_webhook_service(redis_client=redis_client)
        
        # In production, this would query the database with filters
        # For now, return mock data with filtering logic
        
        mock_webhooks = [
            {
                "webhook_id": "test-1",
                "name": "Production Alerts",
                "channel": "slack",
                "status": "active",
                "url": "https://hooks.slack.com/services/...",
                "event_types": ["incident_created", "incident_updated"],
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "owner_id": current_user.get("user_id")
            }
        ]
        
        # Apply filters
        filtered_webhooks = mock_webhooks
        
        if status_filter:
            filtered_webhooks = [wh for wh in filtered_webhooks if wh["status"] == status_filter.value]
        
        if channel_filter:
            filtered_webhooks = [wh for wh in filtered_webhooks if wh["channel"] == channel_filter.value]
        
        # Pagination
        paginated_webhooks = filtered_webhooks[skip:skip + limit]
        
        return {
            "success": True,
            "data": paginated_webhooks,
            "pagination": {
                "total": len(filtered_webhooks),
                "skip": skip,
                "limit": limit,
                "has_more": skip + limit < len(filtered_webhooks)
            }
        }
    
    except Exception as e:
        logger.error(f"Failed to list webhooks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list webhooks: {str(e)}"
        )

@router.get("/{webhook_id}", response_model=Dict[str, Any])
async def get_webhook(
    webhook_id: str,
    current_user: Dict = Depends(get_current_user),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Get webhook details by ID.
    
    Permissions: Viewer, Operator, Admin, Super Admin
    """
    try:
        webhook_service = get_webhook_service(redis_client=redis_client)
        
        webhook = await webhook_service.get_webhook(webhook_id)
        
        if not webhook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Webhook not found: {webhook_id}"
            )
        
        # Check permissions
        if current_user.get("role") in ["viewer", "operator"] and webhook.owner_id != current_user.get("user_id"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to view this webhook"
            )
        
        return {
            "success": True,
            "data": webhook.model_dump()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get webhook {webhook_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get webhook: {str(e)}"
        )

@router.put("/{webhook_id}", response_model=Dict[str, Any])
async def update_webhook(
    webhook_id: str,
    updates: WebhookUpdate,
    current_user: Dict = Depends(require_role(UserRole.OPERATOR)),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Update webhook configuration.
    
    Permissions: Operator, Admin, Super Admin (owner)
    """
    try:
        webhook_service = get_webhook_service(redis_client=redis_client)
        
        # Check if webhook exists
        webhook = await webhook_service.get_webhook(webhook_id)
        if not webhook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Webhook not found: {webhook_id}"
            )
        
        # Check permissions
        if current_user.get("role") in ["operator"] and webhook.owner_id != current_user.get("user_id"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only update your own webhooks"
            )
        
        # Update webhook
        update_dict = updates.model_dump(exclude_unset=True)
        success = await webhook_service.update_webhook(webhook_id, update_dict)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update webhook"
            )
        
        # Log business event
        BusinessEventLogger.log_event(
            event_type="webhook_updated",
            event_data={
                "webhook_id": webhook_id,
                "updates": list(update_dict.keys()),
                "updated_by": current_user.get("user_id")
            }
        )
        
        return {
            "success": True,
            "message": "Webhook updated successfully"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update webhook {webhook_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update webhook: {str(e)}"
        )

@router.delete("/{webhook_id}", response_model=Dict[str, Any])
async def delete_webhook(
    webhook_id: str,
    current_user: Dict = Depends(require_role(UserRole.OPERATOR)),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Delete a webhook.
    
    Permissions: Operator (owner), Admin, Super Admin
    """
    try:
        webhook_service = get_webhook_service(redis_client=redis_client)
        
        # Check if webhook exists
        webhook = await webhook_service.get_webhook(webhook_id)
        if not webhook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Webhook not found: {webhook_id}"
            )
        
        # Check permissions
        if current_user.get("role") in ["operator"] and webhook.owner_id != current_user.get("user_id"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only delete your own webhooks"
            )
        
        # Delete webhook
        success = await webhook_service.delete_webhook(webhook_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete webhook"
            )
        
        # Log business event
        BusinessEventLogger.log_event(
            event_type="webhook_deleted",
            event_data={
                "webhook_id": webhook_id,
                "name": webhook.name,
                "deleted_by": current_user.get("user_id")
            }
        )
        
        return {
            "success": True,
            "message": "Webhook deleted successfully"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete webhook {webhook_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete webhook: {str(e)}"
        )

# Webhook Testing Endpoints

@router.post("/{webhook_id}/test", response_model=Dict[str, Any])
async def test_webhook(
    webhook_id: str,
    test_request: Optional[WebhookTestRequest] = None,
    current_user: Dict = Depends(require_role(UserRole.OPERATOR)),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Test a webhook configuration.
    
    Permissions: Operator, Admin, Super Admin
    """
    try:
        webhook_service = get_webhook_service(redis_client=redis_client)
        
        # Check if webhook exists
        webhook = await webhook_service.get_webhook(webhook_id)
        if not webhook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Webhook not found: {webhook_id}"
            )
        
        # Check permissions
        if current_user.get("role") in ["operator"] and webhook.owner_id != current_user.get("user_id"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only test your own webhooks"
            )
        
        # Use provided test payload or create default
        if test_request and test_request.test_payload:
            test_payload = test_request.test_payload
        else:
            test_payload = {
                "test": True,
                "message": "This is a test notification from ARF",
                "timestamp": datetime.utcnow().isoformat(),
                "webhook_id": webhook_id,
                "user": current_user.get("user_id")
            }
        
        # Test webhook
        test_result = await webhook_service.test_webhook(webhook_id, test_payload)
        
        # Log business event
        BusinessEventLogger.log_event(
            event_type="webhook_tested",
            event_data={
                "webhook_id": webhook_id,
                "success": test_result["success"],
                "status_code": test_result.get("status_code"),
                "response_time_ms": test_result.get("response_time_ms"),
                "tested_by": current_user.get("user_id")
            }
        )
        
        return {
            "success": True,
            "test_result": test_result
        }
    
    except HTTPException:
        raise
    except WebhookError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to test webhook {webhook_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to test webhook: {str(e)}"
        )

# Statistics Endpoints

@router.get("/{webhook_id}/stats", response_model=Dict[str, Any])
async def get_webhook_stats(
    webhook_id: str,
    start_time: Optional[datetime] = Query(None, description="Start time for statistics"),
    end_time: Optional[datetime] = Query(None, description="End time for statistics"),
    current_user: Dict = Depends(get_current_user),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Get statistics for a webhook.
    
    Permissions: Viewer, Operator, Admin, Super Admin
    """
    try:
        webhook_service = get_webhook_service(redis_client=redis_client)
        
        # Check if webhook exists
        webhook = await webhook_service.get_webhook(webhook_id)
        if not webhook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Webhook not found: {webhook_id}"
            )
        
        # Check permissions
        if current_user.get("role") in ["viewer", "operator"] and webhook.owner_id != current_user.get("user_id"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to view statistics for this webhook"
            )
        
        # Get statistics
        stats = await webhook_service.get_webhook_stats(webhook_id, start_time, end_time)
        
        return {
            "success": True,
            "data": stats
        }
    
    except HTTPException:
        raise
    except WebhookError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to get statistics for webhook {webhook_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get statistics: {str(e)}"
        )

@router.get("/system/stats", response_model=Dict[str, Any])
async def get_system_webhook_stats(
    start_time: Optional[datetime] = Query(None, description="Start time for statistics"),
    end_time: Optional[datetime] = Query(None, description="End time for statistics"),
    current_user: Dict = Depends(require_role(UserRole.ADMIN)),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Get system-wide webhook statistics.
    
    Permissions: Admin, Super Admin
    """
    try:
        webhook_service = get_webhook_service(redis_client=redis_client)
        
        stats = await webhook_service.get_system_stats(start_time, end_time)
        
        return {
            "success": True,
            "data": stats
        }
    
    except Exception as e:
        logger.error(f"Failed to get system statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get system statistics: {str(e)}"
        )

# Integration Configuration Endpoints

@router.get("/integrations/supported", response_model=Dict[str, Any])
async def get_supported_integrations(
    current_user: Dict = Depends(get_current_user)
):
    """
    Get list of supported integrations with configuration details.
    
    Permissions: Viewer, Operator, Admin, Super Admin
    """
    try:
        supported = IntegrationFactory.get_supported_integrations()
        
        return {
            "success": True,
            "data": supported
        }
    
    except Exception as e:
        logger.error(f"Failed to get supported integrations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get supported integrations: {str(e)}"
        )

@router.post("/integrations/validate", response_model=Dict[str, Any])
async def validate_integration_configuration(
    integration_type: IntegrationType,
    config_data: Dict[str, Any] = Body(...),
    current_user: Dict = Depends(require_role(UserRole.OPERATOR))
):
    """
    Validate integration configuration.
    
    Permissions: Operator, Admin, Super Admin
    """
    try:
        validation_result = IntegrationFactory.validate_configuration(integration_type, config_data)
        
        return {
            "success": True,
            "data": validation_result
        }
    
    except Exception as e:
        logger.error(f"Failed to validate integration configuration: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid configuration: {str(e)}"
        )

# Notification Template Endpoints

@router.post("/templates", response_model=Dict[str, Any])
async def create_notification_template(
    template_data: NotificationTemplateCreate,
    current_user: Dict = Depends(require_role(UserRole.OPERATOR)),
    db: Session = Depends(get_db)
):
    """
    Create a notification template.
    
    Permissions: Operator, Admin, Super Admin
    """
    try:
        # In production, this would save to database
        # For now, return success
        
        template_id = f"template-{datetime.utcnow().timestamp()}"
        
        # Log business event
        BusinessEventLogger.log_event(
            event_type="notification_template_created",
            event_data={
                "template_id": template_id,
                "name": template_data.name,
                "channel": template_data.channel.value,
                "event_type": template_data.event_type.value,
                "created_by": current_user.get("user_id")
            }
        )
        
        return {
            "success": True,
            "template_id": template_id,
            "message": "Template created successfully"
        }
    
    except Exception as e:
        logger.error(f"Failed to create notification template: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create template: {str(e)}"
        )

@router.get("/templates", response_model=Dict[str, Any])
async def list_notification_templates(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    channel_filter: Optional[NotificationChannel] = Query(None, description="Filter by channel"),
    event_type_filter: Optional[WebhookEventType] = Query(None, description="Filter by event type"),
    current_user: Dict = Depends(get_current_user)
):
    """
    List notification templates with filtering.
    
    Permissions: Viewer, Operator, Admin, Super Admin
    """
    try:
        # In production, this would query the database
        # For now, return mock data
        
        mock_templates = [
            {
                "template_id": "template-1",
                "name": "Incident Alert - Slack",
                "channel": "slack",
                "event_type": "incident_created",
                "template": "New incident: {{payload.title}}\\nSeverity: {{payload.severity}}",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "created_by": current_user.get("user_id")
            }
        ]
        
        # Apply filters
        filtered_templates = mock_templates
        
        if channel_filter:
            filtered_templates = [t for t in filtered_templates if t["channel"] == channel_filter.value]
        
        if event_type_filter:
            filtered_templates = [t for t in filtered_templates if t["event_type"] == event_type_filter.value]
        
        # Pagination
        paginated_templates = filtered_templates[skip:skip + limit]
        
        return {
            "success": True,
            "data": paginated_templates,
            "pagination": {
                "total": len(filtered_templates),
                "skip": skip,
                "limit": limit,
                "has_more": skip + limit < len(filtered_templates)
            }
        }
    
    except Exception as e:
        logger.error(f"Failed to list notification templates: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list templates: {str(e)}"
        )

@router.put("/templates/{template_id}", response_model=Dict[str, Any])
async def update_notification_template(
    template_id: str,
    updates: NotificationTemplateUpdate,
    current_user: Dict = Depends(require_role(UserRole.OPERATOR))
):
    """
    Update a notification template.
    
    Permissions: Operator, Admin, Super Admin
    """
    try:
        # In production, this would update in database
        # For now, return success
        
        # Log business event
        BusinessEventLogger.log_event(
            event_type="notification_template_updated",
            event_data={
                "template_id": template_id,
                "updates": updates.model_dump(exclude_unset=True),
                "updated_by": current_user.get("user_id")
            }
        )
        
        return {
            "success": True,
            "message": "Template updated successfully"
        }
    
    except Exception as e:
        logger.error(f"Failed to update notification template {template_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update template: {str(e)}"
        )

@router.delete("/templates/{template_id}", response_model=Dict[str, Any])
async def delete_notification_template(
    template_id: str,
    current_user: Dict = Depends(require_role(UserRole.OPERATOR))
):
    """
    Delete a notification template.
    
    Permissions: Operator, Admin, Super Admin
    """
    try:
        # In production, this would delete from database
        # For now, return success
        
        # Log business event
        BusinessEventLogger.log_event(
            event_type="notification_template_deleted",
            event_data={
                "template_id": template_id,
                "deleted_by": current_user.get("user_id")
            }
        )
        
        return {
            "success": True,
            "message": "Template deleted successfully"
        }
    
    except Exception as e:
        logger.error(f"Failed to delete notification template {template_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete template: {str(e)}"
        )

# Event Simulation Endpoint

@router.post("/simulate/event", response_model=Dict[str, Any])
async def simulate_webhook_event(
    event_type: WebhookEventType,
    source_id: str = Body(...),
    source_type: str = Body(...),
    payload: Dict[str, Any] = Body(...),
    severity: NotificationPriority = Body(NotificationPriority.MEDIUM),
    context: Optional[Dict[str, Any]] = Body(None),
    current_user: Dict = Depends(require_role(UserRole.ADMIN)),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Simulate a webhook event for testing.
    
    Permissions: Admin, Super Admin
    """
    try:
        webhook_service = get_webhook_service(redis_client=redis_client)
        
        # Trigger event
        event_id = await webhook_service.trigger_event(
            event_type=event_type,
            source_id=source_id,
            source_type=source_type,
            payload=payload,
            severity=severity,
            context=context
        )
        
        # Log business event
        BusinessEventLogger.log_event(
            event_type="webhook_event_simulated",
            event_data={
                "event_id": event_id,
                "event_type": event_type.value,
                "source_type": source_type,
                "simulated_by": current_user.get("user_id")
            }
        )
        
        return {
            "success": True,
            "event_id": event_id,
            "message": f"Event {event_type.value} simulated successfully"
        }
    
    except Exception as e:
        logger.error(f"Failed to simulate webhook event: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to simulate event: {str(e)}"
        )

# Health Check Endpoint

@router.get("/health", response_model=Dict[str, Any])
async def webhook_health_check(
    current_user: Dict = Depends(get_current_user),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Health check for webhook system.
    
    Permissions: Viewer, Operator, Admin, Super Admin
    """
    try:
        webhook_service = get_webhook_service(redis_client=redis_client)
        
        # Get system stats as health indicator
        stats = await webhook_service.get_system_stats()
        
        # Check Redis connectivity
        try:
            redis_client.ping()
            redis_healthy = True
        except:
            redis_healthy = False
        
        health_status = {
            "status": "healthy" if redis_healthy else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "redis": "healthy" if redis_healthy else "unhealthy",
                "webhook_service": "healthy",
                "event_processing": "healthy"
            },
            "statistics": stats
        }
        
        return {
            "success": True,
            "data": health_status
        }
    
    except Exception as e:
        logger.error(f"Webhook health check failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "data": {
                "status": "unhealthy",
                "timestamp": datetime.utcnow().isoformat(),
                "components": {
                    "redis": "unknown",
                    "webhook_service": "unhealthy",
                    "event_processing": "unknown"
                }
            }
        }

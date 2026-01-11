"""
Rollback API endpoints for ARF.
Psychology: Safe, auditable rollback operations with comprehensive monitoring.
Intention: Provide complete lifecycle management for system recovery.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid

# Import WITHOUT UserDB type - just the dependencies
from src.auth.dependencies import require_operator, require_admin, get_current_user_optional
from src.services.rollback_service import RollbackService, get_rollback_service
from src.models.rollback import (
    RollbackAction, RollbackExecution, RollbackPlan, RollbackAnalysis,
    RollbackRequest, RollbackResponse, BulkRollbackRequest, BulkRollbackResponse,
    RollbackAuditLog, ActionType, RollbackStrategy, RiskLevel, RollbackStatus
)

router = APIRouter(prefix="/api/v1/rollback", tags=["rollback"])

@router.post("/actions", status_code=status.HTTP_201_CREATED)
async def log_action(
    action_data: Dict[str, Any],
    current_user = Depends(require_operator),  # No type hint to avoid SQLAlchemy model issues
    service: RollbackService = Depends(get_rollback_service)
) -> Dict[str, Any]:
    """
    Log an action for potential rollback.
    Authentication: Required
    Authorization: Operator role or higher
    """
    # Get email from user object
    user_email = getattr(current_user, 'email', 'unknown')
    
    action_id = service.log_action(action_data, user_email)
    
    return {
        "action_id": action_id,
        "message": "Action logged successfully",
        "logged_at": datetime.utcnow().isoformat(),
        "user": user_email
    }

@router.get("/actions/{action_id}")
async def get_action(
    action_id: str,
    current_user = Depends(require_operator),
    service: RollbackService = Depends(get_rollback_service)
) -> RollbackAction:
    """
    Get a logged action by ID.
    Authentication: Required
    Authorization: Operator role or higher
    """
    action = service.get_action(action_id)
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action not found: {action_id}"
        )
    
    return action

@router.post("/actions/{action_id}/analyze")
async def analyze_action_rollback(
    action_id: str,
    current_user = Depends(require_operator),
    service: RollbackService = Depends(get_rollback_service)
) -> RollbackAnalysis:
    """
    Analyze feasibility of rolling back an action.
    Authentication: Required
    Authorization: Operator role or higher
    """
    try:
        user_email = getattr(current_user, 'email', 'unknown')
        analysis = service.analyze_rollback(action_id, user_email)
        return analysis
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/actions/{action_id}/execute")
async def execute_rollback(
    action_id: str,
    request: RollbackRequest,
    current_user = Depends(require_admin),
    service: RollbackService = Depends(get_rollback_service)
) -> RollbackResponse:
    """
    Execute rollback of an action.
    Authentication: Required
    Authorization: Admin role or higher
    """
    # Ensure action_id matches
    if request.action_id != action_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Action ID in path doesn't match request body"
        )
    
    try:
        user_email = getattr(current_user, 'email', 'unknown')
        response = service.execute_rollback(request, user_email)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rollback execution failed: {str(e)}"
        )

@router.post("/bulk")
async def execute_bulk_rollback(
    request: BulkRollbackRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(require_admin),
    service: RollbackService = Depends(get_rollback_service)
) -> BulkRollbackResponse:
    """
    Execute rollback of multiple actions.
    Authentication: Required
    Authorization: Admin role or higher
    """
    try:
        user_email = getattr(current_user, 'email', 'unknown')
        
        # Execute in background if large
        if len(request.action_ids) > 10:
            # This would be async in production
            pass
        
        response = service.execute_bulk_rollback(request, user_email)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Bulk rollback failed: {str(e)}"
        )

@router.get("/actions")
async def search_actions(
    action_type: Optional[ActionType] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    status_param: Optional[RollbackStatus] = Query(None, alias="status"),
    risk_level: Optional[RiskLevel] = None,
    limit: int = Query(50, ge=1, le=1000),
    page: int = Query(1, ge=1),
    current_user = Depends(require_operator),
    service: RollbackService = Depends(get_rollback_service)
) -> Dict[str, Any]:
    """
    Search rollback actions with filters.
    Authentication: Required
    Authorization: Operator role or higher
    """
    # Build filters
    filters = {}
    if action_type:
        filters['action_type'] = action_type.value
    if start_time:
        filters['start_time'] = start_time.timestamp()
    if end_time:
        filters['end_time'] = end_time.timestamp()
    if status_param:
        filters['status'] = status_param.value
    if risk_level:
        filters['risk_level'] = risk_level.value
    
    offset = (page - 1) * limit
    actions, total = service.search_actions(filters, limit, offset)
    
    return {
        "actions": actions,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit,
            "has_more": (page * limit) < total
        },
        "filters": filters
    }

@router.get("/statistics")
async def get_rollback_statistics(
    # FIXED: Changed regex= to pattern= for Pydantic v2 compatibility
    time_range: str = Query("7d", pattern="^(1d|7d|30d|90d|all)$"),
    current_user = Depends(require_operator),
    service: RollbackService = Depends(get_rollback_service)
) -> Dict[str, Any]:
    """
    Get rollback statistics.
    Authentication: Required
    Authorization: Operator role or higher
    """
    # Calculate time range
    now = datetime.utcnow()
    if time_range == "1d":
        start_time = now - timedelta(days=1)
    elif time_range == "7d":
        start_time = now - timedelta(days=7)
    elif time_range == "30d":
        start_time = now - timedelta(days=30)
    elif time_range == "90d":
        start_time = now - timedelta(days=90)
    else:  # all
        start_time = datetime.min
    
    # Get actions in time range
    filters = {
        'start_time': start_time.timestamp(),
        'end_time': now.timestamp()
    }
    
    actions, total = service.search_actions(filters, limit=10000, offset=0)
    
    # Calculate statistics
    stats = {
        "time_range": time_range,
        "start_time": start_time.isoformat(),
        "end_time": now.isoformat(),
        "total_actions": total,
        "by_type": {},
        "by_status": {},
        "by_risk_level": {},
        "rollback_success_rate": 0.0
    }
    
    successful_rollbacks = 0
    total_rollbacks = 0
    
    for action in actions:
        # Count by type
        action_type = action.action_type.value
        stats["by_type"][action_type] = stats["by_type"].get(action_type, 0) + 1
        
        # Count by status
        status_val = action.current_status.value
        stats["by_status"][status_val] = stats["by_status"].get(status_val, 0) + 1
        
        # Count by risk level
        risk = action.risk_level.value
        stats["by_risk_level"][risk] = stats["by_risk_level"].get(risk, 0) + 1
        
        # Calculate rollback success
        if action.rollback_count > 0:
            total_rollbacks += 1
            if action.current_status == RollbackStatus.ROLLED_BACK:
                successful_rollbacks += 1
    
    if total_rollbacks > 0:
        stats["rollback_success_rate"] = successful_rollbacks / total_rollbacks
    
    # Add rollback executions count
    stats["total_rollback_executions"] = sum(
        len(action.rollback_executions) for action in actions
    )
    
    return stats

@router.post("/cleanup")
async def cleanup_expired_actions(
    batch_size: int = Query(1000, ge=1, le=10000),
    current_user = Depends(require_admin),
    service: RollbackService = Depends(get_rollback_service)
) -> Dict[str, Any]:
    """
    Clean up expired rollback actions.
    Authentication: Required
    Authorization: Admin role or higher
    """
    result = service.cleanup_expired_actions(batch_size)
    
    return {
        **result,
        "message": "Cleanup completed successfully",
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/health")
async def rollback_health(
    service: RollbackService = Depends(get_rollback_service)
) -> Dict[str, Any]:
    """Health check for rollback service"""
    try:
        # Test service by logging a test action
        test_action_id = service.log_action({
            "action_type": "system_update",
            "description": "Health check test action",
            "rollback_strategy": "ignore",
            "ttl_seconds": 300  # 5 minutes
        }, executed_by="system:health_check")
        
        # Clean up test action
        test_action = service.get_action(test_action_id)
        
        return {
            "status": "healthy",
            "service": "rollback",
            "test_action_id": test_action_id,
            "test_action_status": test_action.current_status.value if test_action else "unknown",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "service": "rollback",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

# Admin endpoints
@router.get("/admin/export", dependencies=[Depends(require_admin)])
async def export_rollback_data(
    # FIXED: Changed regex= to pattern= for Pydantic v2 compatibility
    format: str = Query("json", pattern="^(json|csv)$"),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    service: RollbackService = Depends(get_rollback_service)
) -> Dict[str, Any]:
    """
    Export rollback data (admin only).
    Authentication: Required
    Authorization: Admin role or higher
    """
    # Build filters
    filters = {}
    if start_time:
        filters['start_time'] = start_time.timestamp()
    if end_time:
        filters['end_time'] = end_time.timestamp()
    
    actions, total = service.search_actions(filters, limit=10000, offset=0)
    
    if format == "csv":
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "action_id", "action_type", "description", "executed_at",
            "executed_by", "status", "risk_level", "rollback_count",
            "affected_resources_count"
        ])
        
        # Write data
        for action in actions:
            writer.writerow([
                action.action_id,
                action.action_type.value,
                action.description[:100],  # Truncate
                action.executed_at.isoformat(),
                action.executed_by or "",
                action.current_status.value,
                action.risk_level.value,
                action.rollback_count,
                len(action.affected_resources)
            ])
        
        return {
            "content": output.getvalue(),
            "filename": f"rollback_export_{datetime.utcnow().date()}.csv",
            "content_type": "text/csv",
            "total_actions": total
        }
    
    return {
        "actions": actions,
        "total": total,
        "exported_at": datetime.utcnow().isoformat()
    }

@router.get("/dashboard")
async def rollback_dashboard(
    current_user = Depends(require_operator),
    service: RollbackService = Depends(get_rollback_service)
) -> Dict[str, Any]:
    """
    Get rollback dashboard data.
    Authentication: Required
    Authorization: Operator role or higher
    """
    # Get recent actions
    recent_actions, _ = service.search_actions(
        {}, limit=10, offset=0
    )
    
    # Get statistics for different time ranges
    stats_24h = await get_rollback_statistics("1d", current_user, service)
    stats_7d = await get_rollback_statistics("7d", current_user, service)
    stats_30d = await get_rollback_statistics("30d", current_user, service)
    
    # Get high-risk actions
    high_risk_actions = []
    for action in recent_actions:
        if action.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            high_risk_actions.append({
                "action_id": action.action_id,
                "description": action.description,
                "risk_level": action.risk_level.value,
                "executed_at": action.executed_at.isoformat(),
                "status": action.current_status.value
            })
    
    return {
        "summary": {
            "recent_actions_count": len(recent_actions),
            "high_risk_actions_count": len(high_risk_actions),
            "rollback_success_rate_24h": stats_24h.get("rollback_success_rate", 0),
            "rollback_success_rate_7d": stats_7d.get("rollback_success_rate", 0),
            "rollback_success_rate_30d": stats_30d.get("rollback_success_rate", 0)
        },
        "recent_actions": [
            {
                "action_id": a.action_id,
                "type": a.action_type.value,
                "description": a.description[:50] + ("..." if len(a.description) > 50 else ""),
                "executed_at": a.executed_at.isoformat(),
                "status": a.current_status.value,
                "risk": a.risk_level.value
            }
            for a in recent_actions
        ],
        "high_risk_actions": high_risk_actions[:5],  # Top 5
        "time_series_data": {
            "24h": stats_24h,
            "7d": stats_7d,
            "30d": stats_30d
        },
        "generated_at": datetime.utcnow().isoformat()
    }

"""
Secured incidents router with authentication and authorization.
Psychology: Principle of least privilege - each endpoint has appropriate permission level.
Intention: Secure all incident operations while maintaining usability.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc
from typing import List, Optional
import redis
from datetime import datetime, timedelta
import json
import uuid

from database import get_db  # Import from the file, not the package
from src.database.redis_client import get_redis
from src.auth.dependencies import (
    require_viewer, require_operator, require_admin,
    get_current_user_optional, UserDB
)
from src.models.incident import (
    IncidentDB, IncidentCreate, IncidentUpdate, IncidentResponse, 
    IncidentListResponse, IncidentSeverity, IncidentStatus, IncidentType
)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

# Cache keys
INCIDENTS_CACHE_KEY = "api:incidents:list:{filters}:{user_id}"
INCIDENT_CACHE_KEY = "api:incidents:{incident_id}:{user_id}"
CACHE_TTL = 300  # 5 minutes

@router.get("/", response_model=IncidentListResponse)
async def get_incidents(
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
    current_user: Optional[UserDB] = Depends(get_current_user_optional),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    severity: Optional[IncidentSeverity] = None,
    status: Optional[IncidentStatus] = None,
    incident_type: Optional[IncidentType] = None,
    agent_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    sort_by: str = Query("created_at", regex="^(created_at|severity|status)$"),
    sort_order: str = Query("desc", regex="^(asc|desc)$")
):
    """
    Get incidents with filtering and pagination.
    Authentication: Optional (public data view)
    Authorization: Authenticated users see all, anonymous see public only
    """
    user_id = current_user.id if current_user else "anonymous"
    
    # Build cache key
    cache_key = INCIDENTS_CACHE_KEY.format(
        filters=hash((
            page, page_size, severity, status, incident_type, 
            agent_id, start_date, end_date, sort_by, sort_order
        )),
        user_id=user_id
    )
    
    # Try cache first
    cached = redis_client.get(cache_key)
    if cached:
        return IncidentListResponse.model_validate_json(cached)
    
    # Build query
    query = db.query(IncidentDB)
    
    # Apply filters
    if severity:
        query = query.filter(IncidentDB.severity == severity.value)
    if status:
        query = query.filter(IncidentDB.status == status.value)
    if incident_type:
        query = query.filter(IncidentDB.incident_type == incident_type.value)
    if agent_id:
        query = query.filter(IncidentDB.agent_id == agent_id)
    if start_date:
        query = query.filter(IncidentDB.created_at >= start_date)
    if end_date:
        query = query.filter(IncidentDB.created_at <= end_date)
    
    # Anonymous users only see low/medium severity incidents
    if not current_user:
        query = query.filter(
            (IncidentDB.severity == IncidentSeverity.LOW.value) |
            (IncidentDB.severity == IncidentSeverity.MEDIUM.value)
        )
    
    # Get total count
    total = query.count()
    
    # Apply sorting
    order_column = getattr(IncidentDB, sort_by)
    if sort_order == "desc":
        query = query.order_by(desc(order_column))
    else:
        query = query.order_by(asc(order_column))
    
    # Apply pagination
    incidents = query.offset((page - 1) * page_size).limit(page_size).all()
    
    # Prepare response
    response = IncidentListResponse(
        incidents=incidents,
        total=total,
        page=page,
        page_size=page_size,
        has_more=(page * page_size) < total
    )
    
    # Cache response
    redis_client.setex(cache_key, CACHE_TTL, response.model_dump_json())
    
    return response

@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
    current_user: Optional[UserDB] = Depends(get_current_user_optional)
):
    """
    Get a specific incident by ID.
    Authentication: Optional
    Authorization: Anonymous users can't access high/critical incidents
    """
    user_id = current_user.id if current_user else "anonymous"
    cache_key = INCIDENT_CACHE_KEY.format(incident_id=incident_id, user_id=user_id)
    
    # Try cache first
    cached = redis_client.get(cache_key)
    if cached:
        return IncidentResponse.model_validate_json(cached)
    
    # Query database
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Authorization check for anonymous users
    if not current_user and incident.severity in [IncidentSeverity.HIGH.value, IncidentSeverity.CRITICAL.value]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication required to view this incident"
        )
    
    # Cache response
    incident_response = IncidentResponse.model_validate(incident)
    redis_client.setex(cache_key, CACHE_TTL, incident_response.model_dump_json())
    
    return incident_response

@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_data: IncidentCreate,
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
    current_user: UserDB = Depends(require_operator)  # Changed: Requires authentication
):
    """
    Create a new incident.
    Authentication: Required
    Authorization: Operator role or higher
    """
    # Generate ID if not provided
    incident_dict = incident_data.model_dump()
    if 'id' not in incident_dict or not incident_dict['id']:
        incident_dict['id'] = str(uuid.uuid4())
    
    # Add created_by metadata
    incident_dict['metadata'] = incident_dict.get('metadata', {})
    incident_dict['metadata']['created_by'] = current_user.email
    
    # Create incident in database
    db_incident = IncidentDB(**incident_dict)
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    
    # Invalidate caches
    cache_pattern = "api:incidents:*"
    for key in redis_client.scan_iter(cache_pattern):
        redis_client.delete(key)
    
    return db_incident

@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    incident_data: IncidentUpdate,
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
    current_user: UserDB = Depends(require_operator)  # Changed: Requires authentication
):
    """
    Update an existing incident.
    Authentication: Required
    Authorization: Operator role or higher
    """
    # Get incident
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Update fields
    update_data = incident_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(incident, field, value)
    
    # Add updated_by metadata
    if 'metadata' not in update_data:
        incident.metadata = incident.metadata or {}
    incident.metadata['updated_by'] = current_user.email
    incident.metadata['updated_at'] = datetime.utcnow().isoformat()
    
    # Set resolved_at if status changed to RESOLVED or CLOSED
    if incident_data.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
        if not incident.resolved_at:
            incident.resolved_at = datetime.utcnow()
    
    incident.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(incident)
    
    # Invalidate caches
    cache_pattern = f"api:incidents:*{incident_id}*"
    for key in redis_client.scan_iter(cache_pattern):
        redis_client.delete(key)
    
    cache_pattern = "api:incidents:list:*"
    for key in redis_client.scan_iter(cache_pattern):
        redis_client.delete(key)
    
    return incident

@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
    current_user: UserDB = Depends(require_admin)  # Changed: Requires admin role
):
    """
    Delete an incident (soft delete via status change).
    Authentication: Required
    Authorization: Admin role or higher
    """
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Soft delete - mark as closed
    incident.status = IncidentStatus.CLOSED.value
    incident.updated_at = datetime.utcnow()
    
    # Add deleted_by metadata
    incident.metadata = incident.metadata or {}
    incident.metadata['deleted_by'] = current_user.email
    incident.metadata['deleted_at'] = datetime.utcnow().isoformat()
    
    db.commit()
    
    # Invalidate caches
    cache_pattern = f"api:incidents:*{incident_id}*"
    for key in redis_client.scan_iter(cache_pattern):
        redis_client.delete(key)
    
    cache_pattern = "api:incidents:list:*"
    for key in redis_client.scan_iter(cache_pattern):
        redis_client.delete(key)

# Add admin-only endpoints
@router.get("/admin/export", dependencies=[Depends(require_admin)])
async def export_incidents(
    db: Session = Depends(get_db),
    format: str = Query("json", regex="^(json|csv)$")
):
    """
    Export all incidents (admin only).
    Authentication: Required
    Authorization: Admin role or higher
    """
    incidents = db.query(IncidentDB).all()
    
    if format == "csv":
        # Generate CSV
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(["ID", "Title", "Severity", "Status", "Created At", "Agent ID"])
        
        # Write data
        for incident in incidents:
            writer.writerow([
                incident.id,
                incident.title,
                incident.severity,
                incident.status,
                incident.created_at.isoformat(),
                incident.agent_id or ""
            ])
        
        return {
            "content": output.getvalue(),
            "filename": f"incidents_export_{datetime.utcnow().date()}.csv",
            "content_type": "text/csv"
        }
    
    return {"incidents": incidents, "total": len(incidents)}

# src/api/v1/incidents.py - COMPLETE FIXED VERSION
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc
from typing import List, Optional
import redis
from datetime import datetime, timedelta
import json  # FIX: Added missing import
import uuid  # For generating IDs

from src.database import get_db
from src.database.redis_client import get_redis
from src.models.incident import (
    IncidentDB, IncidentCreate, IncidentUpdate, IncidentResponse, 
    IncidentListResponse, IncidentSeverity, IncidentStatus, IncidentType
)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

# Cache keys
INCIDENTS_CACHE_KEY = "api:incidents:list:{filters}"
INCIDENT_CACHE_KEY = "api:incidents:{incident_id}"
CACHE_TTL = 300  # 5 minutes

@router.get("/", response_model=IncidentListResponse)
async def get_incidents(
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis),
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
    Get incidents with filtering and pagination
    """
    # Build cache key
    cache_key = INCIDENTS_CACHE_KEY.format(filters=hash((
        page, page_size, severity, status, incident_type, 
        agent_id, start_date, end_date, sort_by, sort_order
    )))
    
    # Try cache first
    cached = redis_client.get(cache_key)
    if cached:
        return IncidentListResponse.model_validate_json(cached)  # FIX: Changed from parse_raw
    
    # Build query
    query = db.query(IncidentDB)
    
    # Apply filters
    if severity:
        query = query.filter(IncidentDB.severity == severity.value)  # FIX: Use .value
    if status:
        query = query.filter(IncidentDB.status == status.value)      # FIX: Use .value
    if incident_type:
        query = query.filter(IncidentDB.incident_type == incident_type.value)  # FIX: Use .value
    if agent_id:
        query = query.filter(IncidentDB.agent_id == agent_id)
    if start_date:
        query = query.filter(IncidentDB.created_at >= start_date)
    if end_date:
        query = query.filter(IncidentDB.created_at <= end_date)
    
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
    redis_client.setex(cache_key, CACHE_TTL, response.model_dump_json())  # FIX: Changed from .json()
    
    return response

@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Get a specific incident by ID
    """
    cache_key = INCIDENT_CACHE_KEY.format(incident_id=incident_id)
    
    # Try cache first
    cached = redis_client.get(cache_key)
    if cached:
        return IncidentResponse.model_validate_json(cached)  # FIX: Changed from parse_raw
    
    # Query database
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Cache response
    incident_response = IncidentResponse.model_validate(incident)  # FIX: Changed from from_orm
    redis_client.setex(cache_key, CACHE_TTL, incident_response.model_dump_json())  # FIX: Changed from .json()
    
    return incident_response

@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_data: IncidentCreate,
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Create a new incident
    """
    # Generate ID if not provided
    incident_dict = incident_data.model_dump()
    if 'id' not in incident_dict or not incident_dict['id']:
        incident_dict['id'] = str(uuid.uuid4())
    
    # Create incident in database
    db_incident = IncidentDB(**incident_dict)
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    
    # Invalidate list caches
    cache_pattern = "api:incidents:list:*"
    for key in redis_client.scan_iter(cache_pattern):
        redis_client.delete(key)
    
    # Also invalidate stats cache
    redis_client.delete("api:incidents:stats:summary")
    
    return db_incident

@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    incident_data: IncidentUpdate,
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Update an existing incident
    """
    # Get incident
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Update fields
    update_data = incident_data.model_dump(exclude_unset=True)  # FIX: Changed from dict()
    for field, value in update_data.items():
        setattr(incident, field, value)
    
    # Set resolved_at if status changed to RESOLVED or CLOSED
    if incident_data.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
        if not incident.resolved_at:
            incident.resolved_at = datetime.utcnow()
    
    incident.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(incident)
    
    # Invalidate caches
    redis_client.delete(INCIDENT_CACHE_KEY.format(incident_id=incident_id))
    cache_pattern = "api:incidents:list:*"
    for key in redis_client.scan_iter(cache_pattern):
        redis_client.delete(key)
    redis_client.delete("api:incidents:stats:summary")
    
    return incident

@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Delete an incident (soft delete via status change)
    """
    incident = db.query(IncidentDB).filter(IncidentDB.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Soft delete - mark as closed
    incident.status = IncidentStatus.CLOSED.value  # FIX: Use .value
    incident.updated_at = datetime.utcnow()
    
    db.commit()
    
    # Invalidate caches
    redis_client.delete(INCIDENT_CACHE_KEY.format(incident_id=incident_id))
    cache_pattern = "api:incidents:list:*"
    for key in redis_client.scan_iter(cache_pattern):
        redis_client.delete(key)
    redis_client.delete("api:incidents:stats:summary")

@router.get("/stats/summary")
async def get_incident_stats(
    db: Session = Depends(get_db),
    redis_client: redis.Redis = Depends(get_redis)
):
    """
    Get incident statistics summary
    """
    cache_key = "api:incidents:stats:summary"
    
    # Try cache first
    cached = redis_client.get(cache_key)
    if cached:
        return json.loads(cached)
    
    # Calculate stats
    total = db.query(IncidentDB).count()
    
    # By severity
    severity_stats = {}
    for severity in IncidentSeverity:
        count = db.query(IncidentDB).filter(IncidentDB.severity == severity.value).count()  # FIX: Use .value
        severity_stats[severity.value] = count
    
    # By status
    status_stats = {}
    for status in IncidentStatus:
        count = db.query(IncidentDB).filter(IncidentDB.status == status.value).count()  # FIX: Use .value
        status_stats[status.value] = count
    
    # By type
    type_stats = {}
    for incident_type in IncidentType:
        count = db.query(IncidentDB).filter(IncidentDB.incident_type == incident_type.value).count()  # FIX: Use .value
        type_stats[incident_type.value] = count
    
    # Last 24 hours
    last_24h = datetime.utcnow() - timedelta(days=1)
    recent_count = db.query(IncidentDB).filter(IncidentDB.created_at >= last_24h).count()
    
    # Open incidents
    open_count = db.query(IncidentDB).filter(IncidentDB.status == IncidentStatus.OPEN.value).count()  # FIX: Use .value
    
    stats = {
        "total": total,
        "severity_distribution": severity_stats,
        "status_distribution": status_stats,
        "type_distribution": type_stats,
        "recent_24h": recent_count,
        "open_incidents": open_count,
        "last_updated": datetime.utcnow().isoformat()
    }
    
    # Cache for 1 minute
    redis_client.setex(cache_key, 60, json.dumps(stats))
    
    return stats

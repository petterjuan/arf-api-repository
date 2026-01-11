from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, Enum, Index
from sqlalchemy.sql import func
from datetime import datetime
from enum import Enum as PyEnum
import uuid
from src.database import Base
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

# Enums
class IncidentSeverity(PyEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(PyEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"

class IncidentType(PyEnum):
    SYSTEM = "system"
    SECURITY = "security"
    PERFORMANCE = "performance"
    DATA_LOSS = "data_loss"
    LLM = "llm"
    AGENT = "agent"
    OTHER = "other"

# SQLAlchemy Model
class IncidentDB(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    incident_type = Column(Enum(IncidentType), default=IncidentType.SYSTEM)
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    # Source/Context
    source_system = Column(String(200))
    component = Column(String(200))
    agent_id = Column(String(100))
    llm_provider = Column(String(100))
    
    # Additional data
    tags = Column(JSON, default=list)
    custom_metadata = Column(JSON, default=dict)  # CHANGED: metadata → custom_metadata
    affected_users = Column(Integer, default=0)
    
    # Timeline/Resolution
    root_cause = Column(Text, nullable=True)
    resolution = Column(Text, nullable=True)
    
    # Indexes (to be created in migrations)
    __table_args__ = (
        Index('ix_incidents_created_at', 'created_at'),
        Index('ix_incidents_severity', 'severity'),
        Index('ix_incidents_status', 'status'),
    )
    
    # Compatibility property - maps custom_metadata to metadata for API
    @property
    def metadata(self):
        """Get metadata for API compatibility"""
        return self.custom_metadata
    
    @metadata.setter
    def metadata(self, value):
        """Set metadata for API compatibility"""
        self.custom_metadata = value

# Pydantic Models for API
class IncidentBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    incident_type: IncidentType = IncidentType.SYSTEM
    source_system: Optional[str] = None
    component: Optional[str] = None
    agent_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    affected_users: int = 0

class IncidentCreate(IncidentBase):
    pass

class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    incident_type: Optional[IncidentType] = None
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

class IncidentResponse(IncidentBase):
    id: str
    status: IncidentStatus
    created_at: datetime
    updated_at: Optional[datetime]
    resolved_at: Optional[datetime]
    root_cause: Optional[str]
    resolution: Optional[str]
    
    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

# For list responses
class IncidentListResponse(BaseModel):
    incidents: List[IncidentResponse]
    total: int
    page: int
    page_size: int
    has_more: bool

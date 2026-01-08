"""
Rollback models for ARF.
Psychology: Immutable action logging with causal relationships for reliable rollback.
Intention: Track all system changes with enough context to undo them safely.
"""
from enum import Enum
from typing import List, Optional, Dict, Any, Set
from datetime import datetime
from pydantic import BaseModel, Field, validator
import uuid

class RollbackStatus(str, Enum):
    """Rollback action status"""
    PENDING = "pending"
    EXECUTED = "executed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    COMPENSATED = "compensated"  # Alternative action taken

class ActionType(str, Enum):
    """Types of actions that can be rolled back"""
    CONFIG_CHANGE = "config_change"
    AGENT_ACTION = "agent_action"
    DATA_MODIFICATION = "data_modification"
    POLICY_UPDATE = "policy_update"
    PERMISSION_CHANGE = "permission_change"
    SYSTEM_UPDATE = "system_update"
    EXTERNAL_API_CALL = "external_api_call"

class RollbackStrategy(str, Enum):
    """Strategies for rolling back actions"""
    INVERSE_ACTION = "inverse_action"  # Execute opposite action
    STATE_RESTORE = "state_restore"    # Restore previous state
    COMPENSATING_ACTION = "compensating_action"  # Different action to compensate
    MANUAL_INTERVENTION = "manual_intervention"  # Requires human
    IGNORE = "ignore"                  # No rollback, just log

class RiskLevel(str, Enum):
    """Risk level of rollback operations"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Base Models
class RollbackActionBase(BaseModel):
    """Base model for rollback actions"""
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: ActionType
    description: str = Field(..., min_length=1, max_length=500)
    
    # Context
    executed_by: Optional[str] = None  # User/agent ID
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    
    # Action details
    parameters: Dict[str, Any] = Field(default_factory=dict)
    pre_state: Dict[str, Any] = Field(default_factory=dict)  # State before action
    post_state: Dict[str, Any] = Field(default_factory=dict)  # State after action
    
    # Rollback configuration
    rollback_strategy: RollbackStrategy = RollbackStrategy.INVERSE_ACTION
    rollback_parameters: Dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: Optional[int] = Field(None, ge=0)  # Time to live for rollback
    
    # Dependencies
    depends_on: List[str] = Field(default_factory=list)  # Other action IDs
    affected_resources: List[str] = Field(default_factory=list)
    
    # Risk assessment
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_reason: Optional[str] = None
    
    @validator('pre_state', 'post_state')
    def validate_state_size(cls, v):
        """Prevent excessively large state storage"""
        import json
        if len(json.dumps(v)) > 10000:  # 10KB limit
            raise ValueError("State too large, consider storing externally")
        return v

class RollbackExecutionBase(BaseModel):
    """Base model for rollback execution"""
    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str
    status: RollbackStatus = RollbackStatus.PENDING
    
    # Execution context
    executed_by: Optional[str] = None
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Results
    success: Optional[bool] = None
    error_message: Optional[str] = None
    logs: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Metrics
    duration_ms: Optional[float] = None
    resources_affected: List[str] = Field(default_factory=list)
    
    class Config:
        from_attributes = True

# Full Models
class RollbackAction(RollbackActionBase):
    """Full rollback action model"""
    current_status: RollbackStatus = RollbackStatus.EXECUTED
    rollback_executions: List[RollbackExecutionBase] = Field(default_factory=list)
    
    # Statistics
    rollback_count: int = 0
    last_rollback_attempt: Optional[datetime] = None
    
    # Metadata
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        from_attributes = True

class RollbackExecution(RollbackExecutionBase):
    """Full rollback execution model"""
    action_snapshot: Optional[RollbackActionBase] = None  # Action at time of rollback
    compensation_action: Optional[Dict[str, Any]] = None  # If compensating action taken
    
    # Verification
    verification_passed: Optional[bool] = None
    verification_details: Optional[str] = None
    
    # Chain of custody
    initiated_by: Optional[str] = None
    approved_by: Optional[str] = None
    
    class Config:
        from_attributes = True

class RollbackPlan(BaseModel):
    """Plan for rolling back multiple actions"""
    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    
    # Actions to rollback
    action_ids: List[str] = Field(default_factory=list)
    execution_order: List[str] = Field(default_factory=list)  # Ordered action IDs
    
    # Configuration
    dry_run: bool = False
    stop_on_failure: bool = True
    verify_after_each: bool = False
    
    # Schedule
    execute_immediately: bool = True
    scheduled_for: Optional[datetime] = None
    
    # Risk assessment
    overall_risk: RiskLevel = RiskLevel.MEDIUM
    risk_assessment: Dict[str, Any] = Field(default_factory=dict)
    
    # Status
    status: str = Field("draft", regex="^(draft|approved|executing|completed|failed|cancelled)$")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    
    class Config:
        from_attributes = True

class RollbackAnalysis(BaseModel):
    """Analysis of rollback feasibility and impact"""
    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str
    
    # Feasibility assessment
    is_feasible: bool
    feasibility_score: float = Field(0.0, ge=0.0, le=1.0)
    feasibility_reasons: List[str] = Field(default_factory=list)
    
    # Impact analysis
    affected_resources: List[Dict[str, Any]] = Field(default_factory=list)
    estimated_duration_seconds: Optional[float] = None
    estimated_risk: RiskLevel = RiskLevel.MEDIUM
    
    # Dependencies
    blocking_actions: List[str] = Field(default_factory=list)
    dependent_actions: List[str] = Field(default_factory=list)
    
    # Recommendations
    recommended_strategy: RollbackStrategy
    alternative_strategies: List[RollbackStrategy] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    
    # Metadata
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    analyzed_by: Optional[str] = None
    
    class Config:
        from_attributes = True

# Request/Response Models
class RollbackRequest(BaseModel):
    """Request to rollback an action"""
    action_id: str
    strategy: Optional[RollbackStrategy] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    verification_required: bool = True
    
    @validator('parameters')
    def validate_parameters(cls, v):
        """Ensure no destructive parameters without confirmation"""
        destructive_keys = {'force', 'skip_verification', 'ignore_dependencies'}
        if any(key in v for key in destructive_keys):
            if not v.get('confirmed', False):
                raise ValueError("Destructive parameters require confirmation")
        return v

class RollbackResponse(BaseModel):
    """Response from rollback execution"""
    execution_id: str
    action_id: str
    status: RollbackStatus
    success: bool
    
    # Details
    message: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    
    # Results
    new_state: Optional[Dict[str, Any]] = None
    verification_result: Optional[Dict[str, Any]] = None
    
    # Metrics
    started_at: datetime
    completed_at: datetime
    duration_ms: float
    
    class Config:
        from_attributes = True

class BulkRollbackRequest(BaseModel):
    """Request to rollback multiple actions"""
    action_ids: List[str] = Field(..., min_items=1)
    strategy: Optional[RollbackStrategy] = None
    execution_order: Optional[List[str]] = None  # Custom order, else auto-determined
    stop_on_failure: bool = True
    dry_run: bool = False
    
    @validator('action_ids')
    def validate_unique_ids(cls, v):
        """Ensure no duplicate action IDs"""
        if len(v) != len(set(v)):
            raise ValueError("Duplicate action IDs not allowed")
        return v

class BulkRollbackResponse(BaseModel):
    """Response from bulk rollback"""
    plan_id: str
    status: str
    total_actions: int
    successful: int
    failed: int
    skipped: int
    
    # Details
    executions: List[RollbackResponse] = Field(default_factory=list)
    execution_order: List[str] = Field(default_factory=list)
    
    # Summary
    overall_success: bool
    message: Optional[str] = None
    
    # Metadata
    started_at: datetime
    completed_at: Optional[datetime] = None
    total_duration_ms: Optional[float] = None
    
    class Config:
        from_attributes = True

# Audit Models
class RollbackAuditLog(BaseModel):
    """Audit log entry for rollback operations"""
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Event
    event_type: str = Field(..., regex="^(action_logged|rollback_executed|rollback_failed|status_changed)$")
    event_data: Dict[str, Any] = Field(default_factory=dict)
    
    # Actor
    actor_id: Optional[str] = None
    actor_type: str = Field("system", regex="^(user|agent|system|cron)$")
    
    # Context
    action_id: Optional[str] = None
    execution_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    
    # Metadata
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    
    class Config:
        from_attributes = True

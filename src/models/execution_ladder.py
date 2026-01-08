"""
Execution Ladder models for ARF.
Psychology: Graph-based representation of policy hierarchy with causal relationships.
Intention: Model agent decision-making policies as interconnected nodes with weights and conditions.
"""
from enum import Enum
from typing import List, Optional, Dict, Any, Set
from datetime import datetime
from pydantic import BaseModel, Field, validator
import uuid

class PolicyType(str, Enum):
    """Types of policies in the execution ladder"""
    SAFETY = "safety"
    COMPLIANCE = "compliance"
    PERFORMANCE = "performance"
    COST = "cost"
    SECURITY = "security"
    CUSTOM = "custom"

class PolicySeverity(str, Enum):
    """Policy severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ConditionOperator(str, Enum):
    """Condition operators for policy evaluation"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    MATCHES_REGEX = "matches_regex"
    IN = "in"
    NOT_IN = "not_in"

class ActionType(str, Enum):
    """Types of actions that can be taken"""
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    LOG = "log"
    NOTIFY = "notify"
    ROLLBACK = "rollback"
    HUMAN_REVIEW = "human_review"

class NodeType(str, Enum):
    """Types of nodes in the execution graph"""
    POLICY = "policy"
    CONDITION = "condition"
    ACTION = "action"
    DECISION_POINT = "decision_point"
    GATEWAY = "gateway"

# Base Models
class ExecutionNodeBase(BaseModel):
    """Base model for execution graph nodes"""
    node_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    node_type: NodeType
    label: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    weight: float = Field(1.0, ge=0.0, le=1.0)  # Importance weight
    enabled: bool = True
    version: int = 1

class PolicyBase(ExecutionNodeBase):
    """Base policy model"""
    policy_type: PolicyType
    severity: PolicySeverity = PolicySeverity.MEDIUM
    priority: int = Field(5, ge=1, le=10)  # 1 = highest priority
    
    # Evaluation criteria
    conditions: List[Dict[str, Any]] = Field(default_factory=list)  # Serialized conditions
    requires_approval: bool = False
    approval_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    
    # Temporal constraints
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    time_window: Optional[str] = None  # e.g., "9-17" for business hours
    
    @validator('conditions')
    def validate_conditions(cls, v):
        """Validate condition structure"""
        for condition in v:
            if not isinstance(condition, dict):
                raise ValueError("Condition must be a dictionary")
            required_fields = {'field', 'operator', 'value'}
            if not required_fields.issubset(condition.keys()):
                raise ValueError(f"Condition missing required fields: {required_fields}")
        return v

class ConditionBase(BaseModel):
    """Condition model for policy evaluation"""
    condition_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    field: str  # e.g., "agent.risk_score", "input.length", "context.user_tier"
    operator: ConditionOperator
    value: Any  # Could be string, number, list, etc.
    negate: bool = False
    weight: float = Field(1.0, ge=0.0, le=1.0)
    
    # For complex conditions
    sub_conditions: List['ConditionBase'] = Field(default_factory=list)
    logical_operator: str = Field("AND", regex="^(AND|OR)$")

class ActionBase(BaseModel):
    """Action model for policy outcomes"""
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: ActionType
    parameters: Dict[str, Any] = Field(default_factory=dict)
    delay_seconds: Optional[float] = Field(None, ge=0.0)
    retry_count: int = Field(0, ge=0)
    retry_delay: float = Field(1.0, ge=0.0)
    
    # Notification/Logging
    message_template: Optional[str] = None
    notification_channels: List[str] = Field(default_factory=list)
    log_level: str = Field("INFO", regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")

# Full Models with Relationships
class ExecutionNode(ExecutionNodeBase):
    """Full execution node with relationships"""
    incoming_edges: List[str] = Field(default_factory=list)  # Source node IDs
    outgoing_edges: List[str] = Field(default_factory=list)  # Target node IDs
    position: Optional[Dict[str, float]] = None  # For UI visualization {x, y}
    
    class Config:
        from_attributes = True

class Policy(PolicyBase):
    """Full policy model"""
    default_action: Optional[ActionBase] = None
    fallback_policy_id: Optional[str] = None
    depends_on: List[str] = Field(default_factory=list)  # Policy IDs
    
    # Statistics
    evaluation_count: int = 0
    last_evaluated: Optional[datetime] = None
    match_count: int = 0
    action_count: int = 0
    
    class Config:
        from_attributes = True

class ExecutionGraph(BaseModel):
    """Complete execution graph"""
    graph_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    version: str = "1.0.0"
    
    # Graph structure
    nodes: Dict[str, ExecutionNode] = Field(default_factory=dict)
    edges: List[Dict[str, str]] = Field(default_factory=list)  # [{source: id, target: id, relationship: type}]
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    
    # Graph properties
    is_active: bool = True
    is_template: bool = False
    clone_of: Optional[str] = None  # If cloned from another graph
    
    class Config:
        from_attributes = True

# Evaluation Models
class EvaluationContext(BaseModel):
    """Context for policy evaluation"""
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    input_data: Dict[str, Any] = Field(default_factory=dict)
    context_vars: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Timestamps
    evaluation_time: datetime = Field(default_factory=datetime.utcnow)
    request_id: Optional[str] = None

class EvaluationResult(BaseModel):
    """Result of policy evaluation"""
    evaluation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str
    triggered: bool
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    
    # Details
    matched_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    failed_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Actions
    recommended_actions: List[ActionBase] = Field(default_factory=list)
    executed_actions: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Metadata
    evaluation_time: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: float = 0.0
    context: Optional[EvaluationContext] = None
    
    class Config:
        from_attributes = True

class ExecutionTrace(BaseModel):
    """Trace of execution through the ladder"""
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    
    # Path through graph
    node_sequence: List[Dict[str, Any]] = Field(default_factory=list)
    evaluations: List[EvaluationResult] = Field(default_factory=list)
    
    # Outcome
    final_action: Optional[ActionBase] = None
    outcome: str = Field("pending", regex="^(pending|allowed|denied|escalated|rolled_back)$")
    
    # Statistics
    total_nodes_visited: int = 0
    total_evaluations: int = 0
    total_duration_ms: float = 0.0
    
    class Config:
        from_attributes = True

# Request/Response Models
class PolicyEvaluationRequest(BaseModel):
    """Request to evaluate policies against context"""
    context: EvaluationContext
    policy_ids: Optional[List[str]] = None  # If None, evaluate all active policies
    graph_id: Optional[str] = None  # Specific execution graph to use
    dry_run: bool = False  # Evaluate but don't execute actions
    
    @validator('context')
    def validate_context(cls, v):
        """Ensure context has at least some data"""
        if not v.input_data and not v.context_vars:
            raise ValueError("Context must contain either input_data or context_vars")
        return v

class PolicyEvaluationResponse(BaseModel):
    """Response from policy evaluation"""
    request_id: Optional[str] = None
    evaluations: List[EvaluationResult] = Field(default_factory=list)
    trace: Optional[ExecutionTrace] = None
    final_decision: Optional[ActionBase] = None
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    
    # Metadata
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
    total_duration_ms: float = 0.0
    warnings: List[str] = Field(default_factory=list)
    
    class Config:
        from_attributes = True

# Update forward references
ConditionBase.update_forward_refs()

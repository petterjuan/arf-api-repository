"""
Execution Ladder API endpoints - ENHANCED WITH MECHANICAL ENFORCEMENT
Psychology: RESTful API with graph operations AND mechanical execution gates.
Intention: Provide complete lifecycle management with license-gated authority.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import os
import logging

# ==================== ENTERPRISE INTEGRATION IMPORTS ====================
try:
    # Try to import Enterprise components
    from arf_enterprise import (
        LicenseManager, LicenseError, get_license_manager,
        ExecutionMode, ExecutionAuthority, can_execute,
        DeterministicConfidence, ConfidenceComponent,
        AuditTrail, AuditEntry,
        OSS_AVAILABLE, OSS_VERSION
    )
    from arf_enterprise.types import LicenseTier, MCPMode
    
    # Try to import our integration service
    try:
        from src.services.execution_authority_service import (
            get_execution_authority_service,
            require_enterprise_license,
            ExecutionAuthorityService,
            LicenseValidationError
        )
        EXECUTION_AUTHORITY_AVAILABLE = True
    except ImportError:
        # Create minimal integration service
        EXECUTION_AUTHORITY_AVAILABLE = False
        
        class ExecutionAuthorityService:
            def __init__(self):
                self.edition = "oss"
                self.license_info = {"valid": False, "tier": "oss"}
            
            async def evaluate_with_authority(self, *args, **kwargs):
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail="Enterprise license required for mechanical enforcement."
                )
            
            def get_license_info(self):
                return {"edition": "oss", "valid": False, "tier": "oss"}
        
        def get_execution_authority_service():
            return ExecutionAuthorityService()
        
        def require_enterprise_license(feature=None):
            def decorator(func):
                async def wrapper(*args, **kwargs):
                    # In OSS mode, check if feature requires Enterprise
                    if feature and feature not in ["advisory", "basic_policy_evaluation"]:
                        raise HTTPException(
                            status_code=status.HTTP_402_PAYMENT_REQUIRED,
                            detail=f"Enterprise license required for {feature}."
                        )
                    return await func(*args, **kwargs)
                return wrapper
            return decorator
    
    ENTERPRISE_IMPORTS_AVAILABLE = True
    
except ImportError as e:
    # Enterprise not available - full OSS mode
    ENTERPRISE_IMPORTS_AVAILABLE = False
    EXECUTION_AUTHORITY_AVAILABLE = False
    logging.warning(f"Enterprise imports not available: {e}")

# ==================== EXISTING IMPORTS ====================
from src.auth.dependencies import require_operator, require_admin, get_current_user_optional, UserDB
from src.services.neo4j_service import get_execution_ladder_service
from src.models.execution_ladder import (
    ExecutionGraph, ExecutionNode, Policy, EvaluationResult, ExecutionTrace,
    PolicyEvaluationRequest, PolicyEvaluationResponse, PolicyType, NodeType, ActionType
)

router = APIRouter(prefix="/api/v1/execution-ladder", tags=["execution-ladder"])
logger = logging.getLogger(__name__)

# ==================== HELPER FUNCTIONS ====================

def get_arf_edition() -> str:
    """Get ARF edition from environment"""
    return os.getenv("ARF_EDITION", "oss").lower()

def is_enterprise_edition() -> bool:
    """Check if running Enterprise edition"""
    edition = get_arf_edition()
    return edition == "enterprise" and ENTERPRISE_IMPORTS_AVAILABLE

def get_license_key() -> Optional[str]:
    """Get license key from environment"""
    return os.getenv("ARF_LICENSE_KEY")

# ==================== ENHANCED ENDPOINTS ====================

@router.post("/graphs", response_model=Dict[str, str], status_code=status.HTTP_201_CREATED)
async def create_execution_graph(
    graph: ExecutionGraph,
    current_user: UserDB = Depends(require_admin),
    service = Depends(get_execution_ladder_service)
):
    """
    Create a new execution graph.
    Authentication: Required
    Authorization: Admin role or higher
    """
    # Set created_by if not specified
    if not graph.created_by:
        graph.created_by = current_user.email
    
    graph_id = service.create_execution_graph(graph)
    
    # Log to audit trail if Enterprise available
    if is_enterprise_edition() and EXECUTION_AUTHORITY_AVAILABLE:
        try:
            authority_service = get_execution_authority_service()
            if hasattr(authority_service, 'audit_trail') and authority_service.audit_trail:
                authority_service.audit_trail.record_action(
                    action="create_execution_graph",
                    customer=current_user.email.split("@")[-1] if "@" in current_user.email else "unknown",
                    severity="info",
                    user=current_user.email,
                    component="execution_ladder",
                    details={
                        "graph_id": graph_id,
                        "graph_name": graph.name,
                        "node_count": len(graph.nodes),
                        "edge_count": len(graph.edges)
                    }
                )
        except Exception as e:
            logger.warning(f"Failed to log to audit trail: {e}")
    
    return {"graph_id": graph_id, "message": "Execution graph created successfully"}

@router.get("/graphs/{graph_id}", response_model=ExecutionGraph)
async def get_execution_graph(
    graph_id: str,
    current_user: UserDB = Depends(require_operator),
    service = Depends(get_execution_ladder_service)
):
    """
    Get an execution graph by ID.
    Authentication: Required
    Authorization: Operator role or higher
    """
    graph = service.get_execution_graph(graph_id)
    if not graph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution graph not found: {graph_id}"
        )
    
    return graph

@router.put("/graphs/{graph_id}")
async def update_execution_graph(
    graph_id: str,
    updates: Dict[str, Any],
    current_user: UserDB = Depends(require_admin),
    service = Depends(get_execution_ladder_service)
):
    """
    Update execution graph metadata.
    Authentication: Required
    Authorization: Admin role or higher
    """
    success = service.update_execution_graph(graph_id, updates)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution graph not found: {graph_id}"
        )
    
    return {"message": "Execution graph updated successfully"}

@router.post("/graphs/{graph_id}/nodes", response_model=Dict[str, str])
async def add_node_to_graph(
    graph_id: str,
    node: ExecutionNode,
    current_user: UserDB = Depends(require_admin),
    service = Depends(get_execution_ladder_service)
):
    """
    Add a node to an execution graph.
    Authentication: Required
    Authorization: Admin role or higher
    """
    node_id = service.add_node_to_graph(graph_id, node)
    
    return {
        "graph_id": graph_id,
        "node_id": node_id,
        "message": "Node added to execution graph"
    }

@router.post("/graphs/{graph_id}/edges")
async def create_edge(
    graph_id: str,
    source_id: str = Query(..., description="Source node ID"),
    target_id: str = Query(..., description="Target node ID"),
    relationship: str = Query("flows_to", description="Relationship type"),
    current_user: UserDB = Depends(require_admin),
    service = Depends(get_execution_ladder_service)
):
    """
    Create an edge between two nodes in a graph.
    Authentication: Required
    Authorization: Admin role or higher
    """
    # Verify both nodes exist in the graph
    graph = service.get_execution_graph(graph_id)
    if not graph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution graph not found: {graph_id}"
        )
    
    if source_id not in graph.nodes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Source node not found in graph: {source_id}"
        )
    
    if target_id not in graph.nodes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target node not found in graph: {target_id}"
        )
    
    success = service.create_edge(source_id, target_id, relationship)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to create edge"
        )
    
    return {"message": "Edge created successfully"}

@router.get("/policies", response_model=List[Policy])
async def get_policies_by_type(
    policy_type: Optional[PolicyType] = None,
    active_only: bool = Query(True, description="Only return active policies"),
    current_user: UserDB = Depends(require_operator),
    service = Depends(get_execution_ladder_service)
):
    """
    Get policies, optionally filtered by type.
    Authentication: Required
    Authorization: Operator role or higher
    """
    if policy_type:
        policies = service.find_policies_by_type(policy_type, active_only)
    else:
        # Get all policies (simplified - in production would paginate)
        # This is a placeholder - would need additional service method
        policies = []
    
    return policies

@router.post("/evaluate", response_model=PolicyEvaluationResponse)
async def evaluate_policies(
    evaluation_request: PolicyEvaluationRequest,
    background_tasks: BackgroundTasks,
    current_user: Optional[UserDB] = Depends(get_current_user_optional),
    service = Depends(get_execution_ladder_service)
):
    """
    ENHANCED: Evaluate policies against context WITH MECHANICAL ENFORCEMENT.
    
    Features by Edition:
    - OSS: Basic policy evaluation only
    - ENTERPRISE: Full mechanical enforcement with:
        * License validation
        * Confidence scoring
        * Risk assessment
        * Execution gates
        * Audit trails
    
    Authentication: Optional (but recommended for tracking)
    Authorization: None required for evaluation
    """
    start_time = datetime.utcnow()
    edition = get_arf_edition()
    
    # Add user context if authenticated
    user_roles = []
    if current_user:
        if not evaluation_request.context.context_vars:
            evaluation_request.context.context_vars = {}
        evaluation_request.context.context_vars['user_id'] = current_user.id
        evaluation_request.context.context_vars['user_email'] = current_user.email
        user_roles = current_user.roles
    
    # ============ EDITION-SPECIFIC LOGIC ============
    
    if edition == "enterprise" and EXECUTION_AUTHORITY_AVAILABLE:
        # ==================== ENTERPRISE MODE ====================
        try:
            authority_service = get_execution_authority_service()
            
            # Validate license first
            license_info = authority_service.get_license_info()
            if not license_info.get("valid", False):
                logger.warning("Invalid Enterprise license, falling back to OSS mode")
                # Fall through to OSS mode
                evaluations, confidence = await _evaluate_oss_mode(
                    service, evaluation_request
                )
                edition_used = "oss_fallback"
            else:
                # Use Enterprise mechanical enforcement
                response = await authority_service.evaluate_with_authority(
                    evaluation_request=evaluation_request,
                    user_id=current_user.id if current_user else None,
                    user_roles=user_roles
                )
                
                # Add Enterprise metadata
                response.metadata = {
                    "edition": "enterprise",
                    "license_tier": license_info.get("tier", "unknown"),
                    "mechanical_enforcement": True,
                    "execution_mode": getattr(response, 'execution_mode', 'advisory'),
                    "gates_passed": getattr(response, 'gates_passed', []),
                    "requires_human_approval": getattr(response, 'requires_human_approval', False)
                }
                
                return response
                
        except HTTPException:
            # Re-raise HTTP exceptions (like payment required)
            raise
        except Exception as e:
            logger.error(f"Enterprise evaluation failed: {e}")
            # Fall back to OSS mode
            evaluations, confidence = await _evaluate_oss_mode(
                service, evaluation_request
            )
            edition_used = "oss_fallback"
    
    else:
        # ==================== OSS MODE ====================
        evaluations, confidence = await _evaluate_oss_mode(
            service, evaluation_request
        )
        edition_used = "oss"
    
    # ============ COMMON POST-EVALUATION LOGIC ============
    
    # Create execution trace
    trace = ExecutionTrace(
        session_id=evaluation_request.context.session_id or str(uuid.uuid4()),
        evaluations=evaluations,
        total_evaluations=len(evaluations),
        total_duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000
    )
    
    # Determine final decision
    triggered_evaluations = [e for e in evaluations if e.triggered]
    if triggered_evaluations:
        # For now, use the first triggered policy's recommended action
        final_decision = triggered_evaluations[0].recommended_actions[0] if triggered_evaluations[0].recommended_actions else None
        outcome = "denied" if final_decision and final_decision.action_type == ActionType.DENY else "allowed"
        confidence = max(e.confidence for e in triggered_evaluations)
    else:
        final_decision = None
        outcome = "allowed"
        confidence = 0.9  # High confidence when no policies trigger
    
    trace.final_action = final_decision
    trace.outcome = outcome
    trace.end_time = datetime.utcnow()
    
    # Store trace in background (async)
    background_tasks.add_task(
        service.create_execution_trace,
        trace
    )
    
    # Add metadata based on edition
    metadata = {
        "edition": edition_used,
        "mechanical_enforcement": edition_used == "enterprise",
        "execution_mode": "advisory",  # OSS only supports advisory
        "upgrade_available": edition_used != "enterprise",
        "upgrade_url": "https://arf.dev/enterprise" if edition_used != "enterprise" else None
    }
    
    return PolicyEvaluationResponse(
        evaluations=evaluations,
        trace=trace,
        final_decision=final_decision,
        confidence=confidence,
        total_duration_ms=trace.total_duration_ms,
        metadata=metadata
    )

async def _evaluate_oss_mode(service, evaluation_request):
    """OSS mode evaluation (basic policy evaluation only)"""
    evaluations = service.evaluate_policies(
        evaluation_request.context.model_dump(),
        evaluation_request.policy_ids
    )
    
    # Calculate basic confidence
    if evaluations:
        confidence = sum(e.confidence for e in evaluations) / len(evaluations)
    else:
        confidence = 0.5
    
    return evaluations, confidence

@router.get("/traces/{trace_id}", response_model=ExecutionTrace)
async def get_execution_trace(
    trace_id: str,
    current_user: UserDB = Depends(require_operator),
    service = Depends(get_execution_ladder_service)
):
    """
    Get an execution trace by ID.
    Authentication: Required
    Authorization: Operator role or higher
    """
    # This would require a service method to retrieve traces
    # For now, returning a placeholder
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Trace retrieval not yet implemented"
    )

@router.get("/graphs/{graph_id}/path")
async def get_execution_path(
    graph_id: str,
    start_node_id: str = Query(..., description="Starting node ID"),
    max_depth: int = Query(10, ge=1, le=50, description="Maximum path depth"),
    current_user: UserDB = Depends(require_operator),
    service = Depends(get_execution_ladder_service)
):
    """
    Get execution path from a starting node.
    Authentication: Required
    Authorization: Operator role or higher
    """
    path = service.get_execution_path(start_node_id, max_depth)
    
    return {
        "graph_id": graph_id,
        "start_node_id": start_node_id,
        "path": path,
        "path_length": len(path)
    }

@router.get("/graphs/{graph_id}/statistics")
async def get_graph_statistics(
    graph_id: str,
    current_user: UserDB = Depends(require_operator),
    service = Depends(get_execution_ladder_service)
):
    """
    Get statistics for an execution graph.
    Authentication: Required
    Authorization: Operator role or higher
    """
    stats = service.get_graph_statistics(graph_id)
    
    if not stats:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution graph not found: {graph_id}"
        )
    
    return stats

@router.post("/graphs/{graph_id}/clone", response_model=Dict[str, str])
async def clone_execution_graph(
    graph_id: str,
    new_name: str = Query(..., description="Name for the cloned graph"),
    current_user: UserDB = Depends(require_admin),
    service = Depends(get_execution_ladder_service)
):
    """
    Clone an execution graph.
    Authentication: Required
    Authorization: Admin role or higher
    """
    try:
        new_graph_id = service.clone_execution_graph(
            graph_id, new_name, current_user.email
        )
        
        return {
            "original_graph_id": graph_id,
            "new_graph_id": new_graph_id,
            "message": "Graph cloned successfully"
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clone graph: {str(e)}"
        )

@router.get("/nodes/{node_id}/connections")
async def get_node_connections(
    node_id: str,
    # FIXED: Changed regex= to pattern= for Pydantic v2 compatibility
    direction: str = Query("both", pattern="^(incoming|outgoing|both)$"),
    current_user: UserDB = Depends(require_operator),
    service = Depends(get_execution_ladder_service)
):
    """
    Get nodes connected to a given node.
    Authentication: Required
    Authorization: Operator role or higher
    """
    connections = service.find_connected_nodes(node_id, direction)
    
    return {
        "node_id": node_id,
        "direction": direction,
        "connections": connections,
        "connection_count": len(connections)
    }

# ==================== NEW ENTERPRISE-ONLY ENDPOINTS ====================

@router.get("/license-info")
async def get_license_information(
    current_user: UserDB = Depends(get_current_user_optional),
):
    """
    Get license information and available features.
    
    Returns different information based on edition:
    - OSS: Basic capabilities and upgrade information
    - ENTERPRISE: License details, features, and execution modes
    """
    edition = get_arf_edition()
    
    if edition == "enterprise" and EXECUTION_AUTHORITY_AVAILABLE:
        try:
            authority_service = get_execution_authority_service()
            license_info = authority_service.get_license_info()
            
            # Add edition-specific features
            license_info["edition"] = "enterprise"
            license_info["mechanical_enforcement"] = True
            license_info["audit_trail"] = True
            license_info["deterministic_confidence"] = True
            license_info["upgrade_required"] = False
            
            return license_info
            
        except Exception as e:
            logger.error(f"Failed to get license info: {e}")
            # Fall back to OSS info
    
    # OSS mode or Enterprise failed
    return {
        "edition": "oss",
        "valid": False,
        "features": ["advisory_mode", "basic_policy_evaluation"],
        "execution_modes": ["advisory"],
        "mechanical_enforcement": False,
        "audit_trail": False,
        "deterministic_confidence": False,
        "upgrade_required": True,
        "upgrade_url": "https://arf.dev/enterprise",
        "upgrade_features": [
            "mechanical_execution_gates",
            "license-based_authorization",
            "deterministic_confidence_scoring",
            "comprehensive_audit_trails",
            "risk_assessment_integration",
            "rollback_feasibility_checks"
        ]
    }

@router.post("/can-execute")
async def can_execute_action(
    action: Dict[str, Any],
    current_user: UserDB = Depends(require_operator),
):
    """
    ENTERPRISE-ONLY: Check if an action can be executed with mechanical authority.
    
    This implements the mechanical gates:
    1. License validation
    2. Confidence threshold
    3. Risk assessment
    4. Rollback feasibility
    5. Human approval requirements
    
    Requires Enterprise license.
    """
    edition = get_arf_edition()
    
    if edition != "enterprise" or not EXECUTION_AUTHORITY_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Enterprise license required for mechanical execution authority. "
                   f"Current edition: {edition}. Upgrade at https://arf.dev/enterprise"
        )
    
    try:
        authority_service = get_execution_authority_service()
        
        # Check license
        license_info = authority_service.get_license_info()
        if not license_info.get("valid", False):
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=f"Invalid Enterprise license. License tier: {license_info.get('tier', 'unknown')}"
            )
        
        # Use authority service to check execution
        result = await authority_service.can_execute_action(
            action=action.get("action"),
            component=action.get("component"),
            parameters=action.get("parameters", {}),
            user_id=current_user.id,
            user_roles=current_user.roles
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Action validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Action validation failed: {str(e)}"
        )

@router.get("/execution-modes")
async def get_available_execution_modes(
    current_user: UserDB = Depends(get_current_user_optional),
):
    """
    Get available execution modes based on edition and user roles.
    
    Returns:
    - OSS: Only "advisory" mode
    - ENTERPRISE: Available modes based on license tier and user roles
    """
    edition = get_arf_edition()
    user_roles = current_user.roles if current_user else []
    
    if edition == "enterprise" and EXECUTION_AUTHORITY_AVAILABLE:
        try:
            authority_service = get_execution_authority_service()
            
            # Get license info
            license_info = authority_service.get_license_info()
            
            if license_info.get("valid", False):
                # Map license tier to available modes
                tier = license_info.get("tier", "oss")
                tier_modes = {
                    "starter": ["advisory", "approval"],
                    "professional": ["advisory", "approval", "autonomous"],
                    "enterprise": ["advisory", "approval", "autonomous", "novel_execution"],
                    "trial": ["advisory", "approval", "autonomous"]
                }
                
                available_modes = tier_modes.get(tier.lower(), ["advisory"])
                
                # Filter by user roles
                role_constraints = {
                    "viewer": ["advisory"],
                    "operator": ["advisory", "approval"],
                    "admin": ["advisory", "approval", "autonomous"],
                    "super_admin": ["advisory", "approval", "autonomous", "novel_execution"]
                }
                
                # Find most permissive role
                user_max_mode = "advisory"
                for role in user_roles:
                    role_lower = role.lower()
                    for role_name, modes in role_constraints.items():
                        if role_lower == role_name:
                            # Get the most permissive mode for this role
                            mode_hierarchy = ["advisory", "approval", "autonomous", "novel_execution"]
                            for mode in reversed(mode_hierarchy):
                                if mode in modes:
                                    # Check if this mode is more permissive than current max
                                    if mode_hierarchy.index(mode) > mode_hierarchy.index(user_max_mode):
                                        user_max_mode = mode
                                    break
                
                # Intersect available modes with user permissions
                user_available_modes = [
                    mode for mode in available_modes 
                    if mode_hierarchy.index(mode) <= mode_hierarchy.index(user_max_mode)
                ]
                
                return {
                    "edition": "enterprise",
                    "license_tier": tier,
                    "user_roles": user_roles,
                    "available_modes": user_available_modes,
                    "current_mode": user_max_mode,
                    "license_valid": True
                }
            
        except Exception as e:
            logger.error(f"Failed to get execution modes: {e}")
            # Fall through to OSS
    
    # OSS mode or Enterprise failed
    return {
        "edition": edition,
        "available_modes": ["advisory"],
        "current_mode": "advisory",
        "license_valid": False,
        "upgrade_required": edition != "enterprise",
        "upgrade_url": "https://arf.dev/enterprise"
    }

# Health check endpoint for execution ladder service
@router.get("/health")
async def execution_ladder_health(
    service = Depends(get_execution_ladder_service)
):
    """Health check for execution ladder service with edition info"""
    try:
        # Try a simple Neo4j query to verify connection
        with service.driver.session() as session:
            result = session.run("RETURN 1 as test")
            test_value = result.single()["test"]
            
            if test_value == 1:
                health_data = {
                    "status": "healthy",
                    "neo4j_connection": "connected",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                # Add edition information
                edition = get_arf_edition()
                health_data["edition"] = edition
                health_data["mechanical_enforcement_available"] = (
                    edition == "enterprise" and EXECUTION_AUTHORITY_AVAILABLE
                )
                
                return health_data
    except Exception as e:
        return {
            "status": "unhealthy",
            "neo4j_connection": "disconnected",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
            "edition": get_arf_edition()
        }
    
    return {
        "status": "unhealthy",
        "neo4j_connection": "unknown",
        "timestamp": datetime.utcnow().isoformat(),
        "edition": get_arf_edition()
    }

# ==================== ENTERPRISE HEALTH ENDPOINT ====================

@router.get("/enterprise-health")
async def enterprise_health_check():
    """
    Enterprise-specific health check.
    
    Checks:
    1. Enterprise imports available
    2. License validation
    3. Execution authority service
    4. Mechanical enforcement readiness
    """
    edition = get_arf_edition()
    
    health_data = {
        "edition": edition,
        "enterprise_imports_available": ENTERPRISE_IMPORTS_AVAILABLE,
        "execution_authority_available": EXECUTION_AUTHORITY_AVAILABLE,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if edition == "enterprise" and EXECUTION_AUTHORITY_AVAILABLE:
        try:
            authority_service = get_execution_authority_service()
            license_info = authority_service.get_license_info()
            
            health_data.update({
                "license_valid": license_info.get("valid", False),
                "license_tier": license_info.get("tier", "unknown"),
                "mechanical_enforcement_ready": license_info.get("valid", False),
                "available_features": license_info.get("features", []),
                "execution_modes": license_info.get("execution_modes", ["advisory"])
            })
            
            health_data["status"] = "healthy" if license_info.get("valid", False) else "degraded"
            
        except Exception as e:
            health_data.update({
                "status": "unhealthy",
                "error": str(e),
                "license_valid": False,
                "mechanical_enforcement_ready": False
            })
    else:
        health_data.update({
            "status": "oss_mode",
            "license_valid": False,
            "mechanical_enforcement_ready": False,
            "upgrade_required": True,
            "upgrade_url": "https://arf.dev/enterprise"
        })
    
    return health_data

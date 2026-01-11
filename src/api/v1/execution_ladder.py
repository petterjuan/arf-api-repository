"""
Execution Ladder API endpoints.
Psychology: RESTful API with graph operations, supporting both management and evaluation.
Intention: Provide complete lifecycle management for execution policies and real-time evaluation.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid

from src.auth.dependencies import require_operator, require_admin, get_current_user_optional, UserDB
from src.services.neo4j_service import get_execution_ladder_service
from src.models.execution_ladder import (
    ExecutionGraph, ExecutionNode, Policy, EvaluationResult, ExecutionTrace,
    PolicyEvaluationRequest, PolicyEvaluationResponse, PolicyType, NodeType, ActionType
)

router = APIRouter(prefix="/api/v1/execution-ladder", tags=["execution-ladder"])

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
    Evaluate policies against context.
    Authentication: Optional (but recommended for tracking)
    Authorization: None required for evaluation
    """
    start_time = datetime.utcnow()
    
    # Add user context if authenticated
    if current_user:
        if not evaluation_request.context.context_vars:
            evaluation_request.context.context_vars = {}
        evaluation_request.context.context_vars['user_id'] = current_user.id
        evaluation_request.context.context_vars['user_email'] = current_user.email
    
    # Evaluate policies
    evaluations = service.evaluate_policies(
        evaluation_request.context.model_dump(),
        evaluation_request.policy_ids
    )
    
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
        # In production, this would be more sophisticated
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
    
    return PolicyEvaluationResponse(
        evaluations=evaluations,
        trace=trace,
        final_decision=final_decision,
        confidence=confidence,
        total_duration_ms=trace.total_duration_ms
    )

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

# Health check endpoint for execution ladder service
@router.get("/health")
async def execution_ladder_health(
    service = Depends(get_execution_ladder_service)
):
    """Health check for execution ladder service"""
    try:
        # Try a simple Neo4j query to verify connection
        with service.driver.session() as session:
            result = session.run("RETURN 1 as test")
            test_value = result.single()["test"]
            
            if test_value == 1:
                return {
                    "status": "healthy",
                    "neo4j_connection": "connected",
                    "timestamp": datetime.utcnow().isoformat()
                }
    except Exception as e:
        return {
            "status": "unhealthy",
            "neo4j_connection": "disconnected",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    return {
        "status": "unhealthy",
        "neo4j_connection": "unknown",
        "timestamp": datetime.utcnow().isoformat()
    }

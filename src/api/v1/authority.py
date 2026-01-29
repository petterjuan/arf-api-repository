"""
EXECUTION AUTHORITY API - Public Bridge to Enterprise

Psychology: RESTful design with clear upgrade paths
Intention: Seamless OSS → Enterprise transition with graceful degradation
Business: Monetization through license-gated execution modes
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, validator

# Try to import Enterprise service with graceful degradation
try:
    from arf_enterprise.execution_authority_service import (
        ExecutionAuthorityService,
        get_execution_authority_service as get_enterprise_service,
        ExecutionMode,
        LicenseTier,
        EscalationGate,
        AuthorityEvaluationRequest as EnterpriseAuthorityEvaluationRequest,
        AuthorityEvaluationResponse as EnterpriseAuthorityEvaluationResponse,
        EvaluationContext as EnterpriseEvaluationContext,
    )
    ENTERPRISE_AVAILABLE = True
except ImportError:
    ENTERPRISE_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.info("Enterprise execution authority unavailable - running in OSS mode")

# Import existing OSS components
from src.api.v1.execution_ladder import (
    get_execution_ladder,
    ExecutionRequest,
    ExecutionResponse,
)
from src.auth.dependencies import get_current_user
from src.auth.models import UserRole

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/authority",
    tags=["execution-authority"],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden - License or permission required"},
        500: {"description": "Internal server error"},
    },
)


# ============================================================================
# Public API Models
# ============================================================================

class AuthorityRequest(BaseModel):
    """Public API request for execution authority evaluation."""
    action: str = Field(..., min_length=1, max_length=200, description="Action to execute")
    component: str = Field(..., min_length=1, max_length=100, description="Component performing action")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    requested_mode: Optional[str] = Field(
        None,
        description="Requested execution mode: advisory, approval, autonomous, novel_execution"
    )
    environment: str = Field(default="production", description="Execution environment")
    emergency_mode: bool = Field(default=False, description="Emergency execution mode")
    
    @validator('requested_mode')
    def validate_requested_mode(cls, v):
        if v and v not in ['advisory', 'approval', 'autonomous', 'novel_execution']:
            raise ValueError("Invalid execution mode")
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "action": "deploy_service",
                "component": "kubernetes",
                "parameters": {"service": "api", "version": "v1.0.0", "replicas": 3},
                "requested_mode": "autonomous",
                "environment": "staging",
                "emergency_mode": False,
            }
        }


class AuthorityResponse(BaseModel):
    """Public API response for execution authority."""
    can_execute: bool = Field(..., description="Whether execution is permitted")
    required_mode: str = Field(..., description="Required execution mode")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Deterministic confidence score")
    risk_level: str = Field(..., description="Risk assessment level")
    escalation_gates_passed: List[str] = Field(..., description="Gates that passed validation")
    escalation_gates_failed: List[str] = Field(..., description="Gates that failed validation")
    requires_human_approval: bool = Field(..., description="Whether human approval is required")
    license_tier: str = Field(..., description="Current license tier")
    audit_trail_id: str = Field(..., description="Audit trail identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    reasoning: Optional[str] = Field(None, description="Human-readable reasoning")
    upgrade_required: Optional[str] = Field(None, description="License tier required for execution")
    edition: str = Field(..., description="ARF edition (oss/enterprise)")
    
    class Config:
        schema_extra = {
            "example": {
                "can_execute": True,
                "required_mode": "approval",
                "confidence_score": 0.85,
                "risk_level": "medium",
                "escalation_gates_passed": ["license_validation", "confidence_threshold"],
                "escalation_gates_failed": [],
                "requires_human_approval": True,
                "license_tier": "professional",
                "audit_trail_id": "arf_audit_20240101120000_abc123",
                "reasoning": "Execution approved with operator review",
                "upgrade_required": None,
                "edition": "enterprise",
            }
        }


class PreflightRequest(BaseModel):
    """Pre-flight check request."""
    action: str = Field(..., min_length=1, max_length=200)
    component: str = Field(..., min_length=1, max_length=100)
    parameters: Dict[str, Any] = Field(default_factory=dict)


class PreflightResponse(BaseModel):
    """Pre-flight check response with detailed analysis."""
    approved: bool = Field(..., description="Whether action is approved")
    required_gates: List[Dict[str, Any]] = Field(..., description="Required escalation gates")
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    risk_assessment: Dict[str, Any] = Field(..., description="Risk assessment details")
    license_valid: bool = Field(..., description="Whether license is valid for action")
    execution_mode: str = Field(..., description="Required execution mode")
    reasoning: Optional[str] = Field(None, description="Detailed reasoning")
    audit_trail_id: str = Field(..., description="Audit trail identifier")
    edition: str = Field(..., description="ARF edition")


class LicenseInfoResponse(BaseModel):
    """License information response."""
    valid: bool = Field(..., description="Whether license is valid")
    tier: str = Field(..., description="License tier")
    organization: Optional[str] = Field(None, description="Organization name")
    expires_at: Optional[datetime] = Field(None, description="License expiration")
    available_modes: List[str] = Field(..., description="Available execution modes")
    entitlements: List[Dict[str, Any]] = Field(..., description="Feature entitlements")
    usage: Optional[Dict[str, Any]] = Field(None, description="Usage statistics")
    edition: str = Field(..., description="ARF edition")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Overall status")
    edition: str = Field(..., description="ARF edition")
    enterprise_available: bool = Field(..., description="Enterprise features available")
    mechanical_enforcement: bool = Field(..., description="Mechanical enforcement enabled")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# OSS Fallback Implementation
# ============================================================================

class OSSAuthorityService:
    """OSS fallback when Enterprise service is unavailable."""
    
    def __init__(self):
        self.edition = "oss"
        self.enterprise_available = False
        self.enable_mechanical_enforcement = False
    
    async def evaluate_with_authority(
        self,
        request: AuthorityRequest,
        user_id: str,
        user_roles: List[str],
        organization_id: str
    ) -> Dict[str, Any]:
        """OSS fallback using existing execution ladder."""
        try:
            # Use existing execution ladder
            ladder = get_execution_ladder()
            
            # Convert to execution ladder request
            exec_request = ExecutionRequest(
                action=request.action,
                component=request.component,
                parameters=request.parameters,
                context={
                    "environment": request.environment,
                    "emergency_mode": request.emergency_mode,
                },
                user_id=user_id,
                user_roles=user_roles,
            )
            
            # Get OSS evaluation
            response = await ladder.evaluate(exec_request)
            
            # Convert to authority format
            return {
                "can_execute": response.can_execute,
                "required_mode": "advisory",
                "confidence_score": response.confidence_score,
                "risk_level": response.risk_level.value if hasattr(response.risk_level, 'value') else str(response.risk_level),
                "escalation_gates_passed": [],
                "escalation_gates_failed": ["license_validation"],
                "requires_human_approval": True,
                "license_tier": "oss",
                "audit_trail_id": response.audit_id,
                "reasoning": "OSS mode - upgrade to Enterprise for mechanical enforcement",
                "upgrade_required": "starter",
                "edition": "oss",
            }
            
        except Exception as e:
            logger.error(f"OSS evaluation failed: {e}", exc_info=True)
            return {
                "can_execute": False,
                "required_mode": "advisory",
                "confidence_score": 0.0,
                "risk_level": "critical",
                "escalation_gates_passed": [],
                "escalation_gates_failed": ["license_validation"],
                "requires_human_approval": True,
                "license_tier": "oss",
                "audit_trail_id": "error",
                "reasoning": f"Evaluation failed: {str(e)}",
                "upgrade_required": "starter",
                "edition": "oss",
            }
    
    async def preflight_check(
        self,
        request: PreflightRequest,
        user_id: str,
        user_roles: List[str],
        organization_id: str
    ) -> Dict[str, Any]:
        """OSS pre-flight check."""
        return {
            "approved": False,
            "required_gates": [],
            "confidence_score": 0.0,
            "risk_assessment": {"level": "unknown", "score": 1.0},
            "license_valid": False,
            "execution_mode": "advisory",
            "reasoning": "OSS mode - execution authority not available",
            "audit_trail_id": "oss_preflight",
            "edition": "oss",
        }
    
    async def get_license_info(
        self,
        organization_id: str
    ) -> Dict[str, Any]:
        """OSS license information."""
        return {
            "valid": True,
            "tier": "oss",
            "organization": "OSS Community",
            "expires_at": None,
            "available_modes": ["advisory"],
            "entitlements": [],
            "usage": None,
            "edition": "oss",
        }


# ============================================================================
# Service Factory
# ============================================================================

def get_authority_service():
    """
    Factory function that returns appropriate authority service.
    
    Returns Enterprise service if available, otherwise OSS fallback.
    """
    if ENTERPRISE_AVAILABLE:
        try:
            service = get_enterprise_service()
            logger.info("Using Enterprise execution authority service")
            return service
        except Exception as e:
            logger.warning(f"Enterprise service failed: {e}")
    
    logger.info("Using OSS execution authority service")
    return OSSAuthorityService()


# ============================================================================
# FastAPI Endpoints
# ============================================================================

@router.post(
    "/evaluate",
    response_model=AuthorityResponse,
    summary="Evaluate execution authority",
    description="""
    Evaluate whether an action can be executed with mechanical enforcement.
    
    This endpoint provides:
    - License validation and tier enforcement
    - Deterministic confidence scoring
    - Risk assessment with blast radius analysis
    - Mechanical escalation gate validation
    - Clear upgrade paths for blocked actions
    
    Mechanical gates include:
    - license_validation: Check enterprise license tier
    - confidence_threshold: Minimum confidence score (default: 0.8)
    - risk_assessment: Evaluate blast radius and dangerous patterns
    - rollback_feasibility: Ensure actions can be rolled back
    - human_approval_required: Flag for high-risk operations
    - admin_approval: Administrative approval gates
    - novel_action_review: Experimental action review boards
    
    License tiers control available execution modes:
    - oss: advisory only
    - starter: advisory + approval
    - professional: advisory + approval + autonomous
    - enterprise: all modes including novel_execution
    """,
    response_description="Execution authority evaluation result",
)
async def evaluate_authority(
    request: AuthorityRequest,
    http_request: Request,
    current_user: Dict = Depends(get_current_user),
) -> AuthorityResponse:
    """
    Evaluate execution authority with mechanical enforcement.
    
    Args:
        request: Authority evaluation request
        http_request: HTTP request for additional context
        current_user: Authenticated user information
        
    Returns:
        AuthorityResponse with enforcement results
    """
    try:
        # Get user and organization context
        user_id = current_user.get("id", "anonymous")
        user_roles = current_user.get("roles", [])
        
        # Extract organization from request headers or user context
        organization_id = http_request.headers.get("X-Organization-ID") or current_user.get("organization_id", "oss")
        
        logger.info(
            f"Authority evaluation requested: "
            f"user={user_id}, "
            f"organization={organization_id}, "
            f"action={request.action}"
        )
        
        # Get appropriate service
        service = get_authority_service()
        
        if ENTERPRISE_AVAILABLE and isinstance(service, ExecutionAuthorityService):
            # Enterprise flow
            evaluation_context = EnterpriseEvaluationContext(
                actor_id=user_id,
                actor_roles=user_roles,
                organization_id=organization_id,
                environment=request.environment,
                business_hours=True,  # Would calculate from timezone
                emergency_mode=request.emergency_mode,
            )
            
            enterprise_request = EnterpriseAuthorityEvaluationRequest(
                action=request.action,
                component=request.component,
                parameters=request.parameters,
                requested_mode=(
                    ExecutionMode(request.requested_mode)
                    if request.requested_mode
                    else None
                ),
                context=evaluation_context,
            )
            
            result = await service.evaluate_with_authority(enterprise_request)
            
            return AuthorityResponse(
                can_execute=result.can_execute,
                required_mode=result.required_mode.value,
                confidence_score=result.confidence_score,
                risk_level=result.risk_assessment.get("level", "unknown"),
                escalation_gates_passed=[g.value for g in result.escalation_gates_passed],
                escalation_gates_failed=[g.value for g in result.escalation_gates_failed],
                requires_human_approval=result.requires_human_approval,
                license_tier=result.license_tier.value,
                audit_trail_id=result.audit_trail_id,
                reasoning=result.reasoning,
                upgrade_required=result.upgrade_required.value if result.upgrade_required else None,
                edition="enterprise",
            )
        else:
            # OSS fallback flow
            result = await service.evaluate_with_authority(
                request=request,
                user_id=user_id,
                user_roles=user_roles,
                organization_id=organization_id,
            )
            
            return AuthorityResponse(**result)
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authority evaluation failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Execution authority evaluation failed: {str(e)}"
        )


@router.post(
    "/preflight",
    response_model=PreflightResponse,
    summary="Pre-flight execution check",
    description="""
    Perform detailed pre-flight check before executing an action.
    
    This endpoint provides comprehensive analysis:
    - All required escalation gates with validation status
    - Confidence scoring breakdown
    - Detailed risk assessment
    - License validation results
    - Execution mode requirements
    - Clear upgrade paths for blocked actions
    
    Use this for:
    - Debugging enforcement decisions
    - Understanding why actions are blocked
    - Planning license upgrades
    - Training and documentation
    """,
    response_description="Detailed pre-flight check results",
)
async def preflight_check(
    request: PreflightRequest,
    http_request: Request,
    current_user: Dict = Depends(get_current_user),
) -> PreflightResponse:
    """
    Detailed pre-flight check with mechanical enforcement analysis.
    
    Args:
        request: Pre-flight check request
        http_request: HTTP request for context
        current_user: Authenticated user information
        
    Returns:
        PreflightResponse with detailed analysis
    """
    try:
        user_id = current_user.get("id", "anonymous")
        user_roles = current_user.get("roles", [])
        organization_id = http_request.headers.get("X-Organization-ID") or current_user.get("organization_id", "oss")
        
        service = get_authority_service()
        
        if ENTERPRISE_AVAILABLE and isinstance(service, ExecutionAuthorityService):
            # Enterprise pre-flight
            preflight_result = await service.preflight_check(
                action=request.action,
                component=request.component,
                parameters=request.parameters,
                context=EnterpriseEvaluationContext(
                    actor_id=user_id,
                    actor_roles=user_roles,
                    organization_id=organization_id,
                ),
            )
            
            return PreflightResponse(
                approved=preflight_result.get("approved", False),
                required_gates=preflight_result.get("gate_analysis", []),
                confidence_score=preflight_result.get("confidence_score", 0.0),
                risk_assessment=preflight_result.get("risk_assessment", {}),
                license_valid=preflight_result.get("license_tier", "oss") != "oss",
                execution_mode=preflight_result.get("required_mode", "advisory"),
                reasoning=preflight_result.get("reasoning"),
                audit_trail_id=preflight_result.get("preflight_id", "unknown"),
                edition="enterprise",
            )
        else:
            # OSS pre-flight
            result = await service.preflight_check(
                request=request,
                user_id=user_id,
                user_roles=user_roles,
                organization_id=organization_id,
            )
            
            return PreflightResponse(**result)
            
    except Exception as e:
        logger.error(f"Pre-flight check failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Pre-flight check failed: {str(e)}"
        )


@router.get(
    "/license",
    response_model=LicenseInfoResponse,
    summary="Get license information",
    description="""
    Get detailed license information for current organization.
    
    Returns:
    - License validity and tier
    - Available execution modes
    - Feature entitlements with gate requirements
    - Usage statistics
    - Organization details
    - Expiration information
    
    License tiers determine execution authority:
    - oss: Advisory recommendations only
    - starter: Human approval required for all executions
    - professional: Autonomous execution for low-risk actions
    - enterprise: Full mechanical enforcement including novel actions
    
    This endpoint helps users understand their current capabilities
    and provides clear upgrade paths.
    """,
    response_description="License information and entitlements",
)
async def get_license_info(
    http_request: Request,
    current_user: Dict = Depends(get_current_user),
) -> LicenseInfoResponse:
    """
    Get license information and entitlements.
    
    Args:
        http_request: HTTP request for organization context
        current_user: Authenticated user information
        
    Returns:
        LicenseInfoResponse with license details
    """
    try:
        organization_id = http_request.headers.get("X-Organization-ID") or current_user.get("organization_id", "oss")
        
        service = get_authority_service()
        
        if ENTERPRISE_AVAILABLE and isinstance(service, ExecutionAuthorityService):
            # Enterprise license info
            entitlements = await service.get_license_entitlements(organization_id)
            
            return LicenseInfoResponse(
                valid=entitlements.get("valid", False),
                tier=entitlements.get("tier", "oss"),
                organization=entitlements.get("organization"),
                expires_at=entitlements.get("expires_at"),
                available_modes=entitlements.get("available_modes", ["advisory"]),
                entitlements=entitlements.get("entitlements", []),
                usage=entitlements.get("usage"),
                edition="enterprise",
            )
        else:
            # OSS license info
            result = await service.get_license_info(organization_id)
            return LicenseInfoResponse(**result)
            
    except Exception as e:
        logger.error(f"License info retrieval failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"License information retrieval failed: {str(e)}"
        )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="""
    Health check for execution authority service.
    
    Returns:
    - Overall service status
    - ARF edition (oss/enterprise)
    - Enterprise feature availability
    - Mechanical enforcement status
    - Timestamp
    
    Use this for:
    - Monitoring and alerting
    - Feature detection
    - Service discovery
    - Capacity planning
    """,
    response_description="Service health status",
)
async def health_check(
    current_user: Dict = Depends(get_current_user),
) -> HealthResponse:
    """
    Health check endpoint.
    
    Args:
        current_user: Authenticated user information
        
    Returns:
        HealthResponse with service status
    """
    try:
        service = get_authority_service()
        
        return HealthResponse(
            status="healthy",
            edition=service.edition,
            enterprise_available=(
                ENTERPRISE_AVAILABLE and 
                hasattr(service, 'enterprise_available') and 
                service.enterprise_available
            ),
            mechanical_enforcement=getattr(service, 'enable_mechanical_enforcement', False),
            timestamp=datetime.utcnow(),
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )


# ============================================================================
# Dependency Injection and Decorators
# ============================================================================

def require_execution_mode(mode: str):
    """
    Decorator to require specific execution mode.
    
    Args:
        mode: Required execution mode
    
    Raises:
        HTTPException 403 if mode not available
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Find request in args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, AuthorityRequest):
                    request = arg
                    break
            
            if not request:
                for key, value in kwargs.items():
                    if isinstance(value, AuthorityRequest):
                        request = value
                        break
            
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Authority request required"
                )
            
            # Get service and check mode availability
            service = get_authority_service()
            
            if service.edition == "oss" and mode != "advisory":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"{mode} mode requires Enterprise license"
                )
            
            # In Enterprise mode, check license
            if service.edition == "enterprise":
                # This would check license entitlements
                # For now, just pass through
                pass
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def get_authority_service_dependency():
    """FastAPI dependency for authority service."""
    return get_authority_service()


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "router",
    "get_authority_service",
    "get_authority_service_dependency",
    "require_execution_mode",
    "AuthorityRequest",
    "AuthorityResponse",
    "PreflightRequest",
    "PreflightResponse",
    "LicenseInfoResponse",
    "HealthResponse",
]

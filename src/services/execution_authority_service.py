# src/services/execution_authority_service.py
"""
Execution Authority Service - Integrates API Policy Evaluation with Enterprise Mechanical Enforcement

Psychology: Bridge pattern connecting policy decisions to mechanical execution gates.
Intention: Provide the missing link between Neo4j policy evaluation and Enterprise execution ladder.

This service is the core integration point that makes your architecture work as promised.
"""

import os
from typing import Dict, Any, Optional, List, Tuple, Union
from datetime import datetime
import logging
from functools import wraps

# Try to import Enterprise components (might fail in OSS mode)
try:
    from arf_enterprise import (
        LicenseManager, LicenseError, get_license_manager,
        ExecutionMode, ExecutionAuthority, can_execute, 
        requires_human_approval, get_execution_ladder,
        DeterministicConfidence, ConfidenceComponent,
        AuditTrail, AuditEntry,
        RollbackController, RollbackError,
        OSS_AVAILABLE, OSS_VERSION, HealingIntent
    )
    from arf_enterprise.types import LicenseTier, MCPMode
    
    ENTERPRISE_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Enterprise components not available: {e}")
    ENTERPRISE_AVAILABLE = False
    
    # Mock classes for OSS mode
    class LicenseManager:
        def validate_license(self, key): 
            return {"valid": False, "tier": "oss", "error": "OSS mode"}
    
    class ExecutionMode:
        ADVISORY = "advisory"
        APPROVAL = "approval"
        AUTONOMOUS = "autonomous"
    
    class DeterministicConfidence:
        def __init__(self, score=0.0, risk_score=0.0, components=None):
            self.score = score
            self.risk_score = risk_score
            self.components = components or []
            self.is_acceptable = score >= 0.9 and risk_score <= 0.2
    
    class ExecutionAuthority:
        def __init__(self):
            self.mode = ExecutionMode.ADVISORY
    
    ENTERPRISE_AVAILABLE = False

# Import API components
from src.database.neo4j_client import get_neo4j
from src.database.redis_client import get_redis
from src.models.execution_ladder import (
    PolicyEvaluationRequest, PolicyEvaluationResponse,
    EvaluationResult, ExecutionTrace, ActionBase, ActionType
)
from .neo4j_service import ExecutionLadderService, get_execution_ladder_service

logger = logging.getLogger(__name__)


class ExecutionAuthorityError(Exception):
    """Execution authority integration error"""
    pass


class LicenseValidationError(Exception):
    """License validation error"""
    pass


class ExecutionAuthorityService:
    """
    Core Integration Service that connects:
    1. API's Neo4j Policy Evaluation
    2. Enterprise's Mechanical Execution Authority
    3. License-based Feature Gating
    
    This service implements the "mechanical enforcement" promised in your architecture.
    """
    
    def __init__(self, 
                 license_key: Optional[str] = None,
                 enable_enterprise: bool = True,
                 default_execution_mode: str = "advisory"):
        """
        Initialize execution authority service.
        
        Args:
            license_key: Enterprise license key (ARF-ENT-... or ARF-TRIAL-...)
            enable_enterprise: Whether to enable Enterprise features
            default_execution_mode: Default execution mode
        """
        self.license_key = license_key or os.getenv("ARF_LICENSE_KEY")
        self.enable_enterprise = enable_enterprise and ENTERPRISE_AVAILABLE
        self.default_execution_mode = default_execution_mode
        
        # Initialize API services
        self.neo4j_service = get_execution_ladder_service()
        self.redis_client = get_redis()
        
        # Initialize Enterprise components if available
        self.license_manager = None
        self.execution_authority = None
        self.audit_trail = None
        self.rollback_controller = None
        
        if self.enable_enterprise:
            self._initialize_enterprise_components()
        
        # Cache for license validation
        self.license_cache = {}
        self.license_cache_ttl = 300  # 5 minutes
        
        logger.info(f"""
        ╔══════════════════════════════════════════════════════════╗
        ║          Execution Authority Service Initialized         ║
        ╠══════════════════════════════════════════════════════════╣
        ║  Enterprise Available: {'✅ YES' if self.enable_enterprise else '❌ NO'}                    
        ║  License Key: {'✅ Provided' if self.license_key else '❌ Not provided'}              
        ║  Default Mode: {self.default_execution_mode}             
        ║  Integration: {'✅ ACTIVE' if self.enable_enterprise else '⚠️ OSS Only'}            
        ╚══════════════════════════════════════════════════════════╝
        """)
    
    def _initialize_enterprise_components(self):
        """Initialize Enterprise components"""
        try:
            # Initialize license manager
            self.license_manager = get_license_manager()
            
            # Validate license if provided
            self.license_info = None
            if self.license_key:
                self.license_info = self.license_manager.validate_license(self.license_key)
                
                if not self.license_info.get("valid", False):
                    logger.warning(f"Invalid license: {self.license_info.get('error')}")
                    self.enable_enterprise = False
                    return
            
            # Initialize execution authority
            self.execution_authority = ExecutionAuthority()
            
            # Initialize audit trail
            self.audit_trail = AuditTrail(
                db_path=os.getenv("AUDIT_DB_PATH", "audit_trail.db"),
                retention_days=int(os.getenv("AUDIT_RETENTION_DAYS", "365"))
            )
            
            # Initialize rollback controller if configured
            if os.getenv("ENABLE_ROLLBACK", "false").lower() == "true":
                try:
                    self.rollback_controller = RollbackController()
                except Exception as e:
                    logger.warning(f"Rollback controller not available: {e}")
            
            logger.info(f"Enterprise components initialized. License: {self.license_info.get('tier', 'oss') if self.license_info else 'no license'}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Enterprise components: {e}")
            self.enable_enterprise = False
    
    # ==================== LICENSE ENFORCEMENT ====================
    
    def require_license(self, feature: Optional[str] = None):
        """
        Decorator to enforce license requirements on API endpoints.
        
        Args:
            feature: Specific feature requiring license (e.g., "autonomous_execution")
        
        Returns:
            Decorator function
        """
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Skip license check if Enterprise not enabled
                if not self.enable_enterprise:
                    logger.warning(f"Enterprise not enabled, skipping license check for {func.__name__}")
                    return await func(*args, **kwargs)
                
                # Validate license
                try:
                    license_valid = self._validate_license_for_feature(feature)
                    
                    if not license_valid:
                        raise HTTPException(
                            status_code=status.HTTP_402_PAYMENT_REQUIRED,
                            detail=f"Enterprise license required for {feature or 'this feature'}. "
                                   f"Upgrade at https://arf.dev/enterprise"
                        )
                    
                    return await func(*args, **kwargs)
                    
                except LicenseValidationError as e:
                    raise HTTPException(
                        status_code=status.HTTP_402_PAYMENT_REQUIRED,
                        detail=str(e)
                    )
                except Exception as e:
                    logger.error(f"License validation error in {func.__name__}: {e}")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="License validation failed"
                    )
            
            return wrapper
        return decorator
    
    def _validate_license_for_feature(self, feature: Optional[str] = None) -> bool:
        """
        Validate license for specific feature.
        
        Args:
            feature: Feature requiring license validation
            
        Returns:
            bool: True if license valid for feature
        """
        # If no license key, only OSS features allowed
        if not self.license_key:
            return feature is None  # Only allow if no specific feature required
        
        # Check cache first
        cache_key = f"license:{self.license_key}:{feature or 'general'}"
        if cache_key in self.license_cache:
            cached = self.license_cache[cache_key]
            if cached["valid_until"] > datetime.now():
                return cached["valid"]
        
        # Validate with license manager
        try:
            license_info = self.license_manager.validate_license(self.license_key)
            
            if not license_info.get("valid", False):
                error = license_info.get("error", "Invalid license")
                logger.warning(f"License invalid: {error}")
                self._cache_license_result(cache_key, False)
                return False
            
            # Check feature-specific requirements
            if feature:
                features = license_info.get("features", [])
                if feature not in features:
                    logger.warning(f"License missing feature: {feature}. Available: {features}")
                    self._cache_license_result(cache_key, False)
                    return False
            
            # Check expiration
            expires_at = license_info.get("expires_at")
            if expires_at and expires_at < datetime.now():
                logger.warning("License expired")
                self._cache_license_result(cache_key, False)
                return False
            
            self._cache_license_result(cache_key, True)
            return True
            
        except Exception as e:
            logger.error(f"License validation error: {e}")
            self._cache_license_result(cache_key, False)
            return False
    
    def _cache_license_result(self, cache_key: str, valid: bool):
        """Cache license validation result"""
        self.license_cache[cache_key] = {
            "valid": valid,
            "valid_until": datetime.now().timestamp() + self.license_cache_ttl
        }
    
    # ==================== POLICY EVALUATION INTEGRATION ====================
    
    async def evaluate_with_authority(
        self,
        evaluation_request: PolicyEvaluationRequest,
        user_id: Optional[str] = None,
        user_roles: List[str] = None
    ) -> PolicyEvaluationResponse:
        """
        Enhanced policy evaluation with mechanical execution authority.
        
        This is the core integration point:
        1. API evaluates policies (Neo4j)
        2. Enterprise applies mechanical gates
        3. License determines execution mode
        
        Args:
            evaluation_request: Policy evaluation request
            user_id: User ID for authorization
            user_roles: User roles for permission checks
            
        Returns:
            Enhanced policy evaluation response with authority checks
        """
        start_time = datetime.utcnow()
        
        # Step 1: Run policy evaluation through Neo4j service
        api_response = await self._evaluate_policies_api(evaluation_request)
        
        # Step 2: Apply mechanical execution authority
        authority_response = await self._apply_execution_authority(
            api_response=api_response,
            context=evaluation_request.context,
            user_id=user_id,
            user_roles=user_roles or []
        )
        
        # Step 3: Create comprehensive trace
        trace = await self._create_authority_trace(
            api_response=api_response,
            authority_response=authority_response,
            context=evaluation_request.context,
            start_time=start_time
        )
        
        # Step 4: Determine final decision with confidence
        final_decision, confidence = self._determine_final_decision(
            api_response, authority_response
        )
        
        # Step 5: Log to audit trail if Enterprise available
        if self.enable_enterprise and self.audit_trail:
            self._log_to_audit_trail(
                action="policy_evaluation_with_authority",
                user_id=user_id,
                context=evaluation_request.context,
                api_response=api_response,
                authority_response=authority_response,
                final_decision=final_decision
            )
        
        return PolicyEvaluationResponse(
            evaluations=api_response.evaluations,
            trace=trace,
            final_decision=final_decision,
            confidence=confidence,
            total_duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
            authority_checks=authority_response,
            execution_mode=self._get_execution_mode_for_user(user_roles or [])
        )
    
    async def _evaluate_policies_api(
        self, 
        evaluation_request: PolicyEvaluationRequest
    ) -> PolicyEvaluationResponse:
        """Run policy evaluation through API's Neo4j service"""
        # This would normally call the API endpoint
        # For integration, we'll call the service directly
        evaluations = self.neo4j_service.evaluate_policies(
            evaluation_request.context.model_dump(),
            evaluation_request.policy_ids
        )
        
        # Simplified response - in production, this would be more comprehensive
        return PolicyEvaluationResponse(
            evaluations=evaluations,
            trace=None,
            final_decision=None,
            confidence=0.8,  # Default confidence
            total_duration_ms=0
        )
    
    async def _apply_execution_authority(
        self,
        api_response: PolicyEvaluationResponse,
        context: Dict[str, Any],
        user_id: Optional[str],
        user_roles: List[str]
    ) -> Dict[str, Any]:
        """
        Apply mechanical execution authority to policy evaluation results.
        
        This implements the "escalation gates" from Enterprise Execution Ladder.
        """
        authority_checks = {
            "license_valid": False,
            "execution_mode": self.default_execution_mode,
            "gates_passed": [],
            "gates_failed": [],
            "requires_human_approval": False,
            "confidence_score": 0.0,
            "risk_assessment": "pending",
            "rollback_feasible": False
        }
        
        # Check 1: License validation
        if self.enable_enterprise and self.license_info:
            authority_checks["license_valid"] = True
            authority_checks["license_tier"] = self.license_info.get("tier", "oss")
        else:
            authority_checks["gates_failed"].append("license_validation")
            authority_checks["execution_mode"] = "advisory"  # Force advisory mode
        
        # Check 2: Determine execution mode based on user roles and license
        execution_mode = self._determine_execution_mode(user_roles)
        authority_checks["execution_mode"] = execution_mode
        
        # Check 3: Confidence scoring (Enterprise feature)
        if self.enable_enterprise:
            confidence = self._calculate_deterministic_confidence(
                api_response.evaluations,
                context
            )
            authority_checks["confidence_score"] = confidence.score
            authority_checks["confidence_acceptable"] = confidence.is_acceptable
            
            if not confidence.is_acceptable:
                authority_checks["gates_failed"].append("confidence_threshold")
                authority_checks["requires_human_approval"] = True
        
        # Check 4: Risk assessment
        risk_level = self._assess_risk(api_response.evaluations, context)
        authority_checks["risk_assessment"] = risk_level
        
        if risk_level in ["high", "critical"]:
            authority_checks["gates_failed"].append("risk_assessment")
            authority_checks["requires_human_approval"] = True
        
        # Check 5: Rollback feasibility
        if self.rollback_controller and self.enable_enterprise:
            try:
                # Check if actions can be rolled back
                rollback_feasible = self._check_rollback_feasibility(
                    api_response.evaluations,
                    context
                )
                authority_checks["rollback_feasible"] = rollback_feasible
                
                if not rollback_feasible:
                    authority_checks["gates_failed"].append("rollback_feasibility")
                    authority_checks["requires_human_approval"] = True
            except Exception as e:
                logger.warning(f"Rollback check failed: {e}")
                authority_checks["rollback_feasible"] = False
        
        # Check 6: Human approval requirement
        if authority_checks["requires_human_approval"]:
            authority_checks["execution_mode"] = "approval"  # Downgrade to approval mode
        
        # Determine which gates passed
        all_gates = [
            "license_validation",
            "confidence_threshold", 
            "risk_assessment",
            "rollback_feasibility"
        ]
        authority_checks["gates_passed"] = [
            gate for gate in all_gates 
            if gate not in authority_checks["gates_failed"]
        ]
        
        return authority_checks
    
    def _determine_execution_mode(self, user_roles: List[str]) -> str:
        """Determine execution mode based on user roles and license"""
        if not self.enable_enterprise or not self.license_info:
            return "advisory"
        
        license_tier = self.license_info.get("tier", "oss")
        
        # Map user roles to execution modes
        role_hierarchy = {
            "viewer": "advisory",
            "operator": "approval",
            "admin": "autonomous",
            "super_admin": "autonomous"
        }
        
        # Find highest role
        user_max_mode = "advisory"
        for role in user_roles:
            mode = role_hierarchy.get(role.lower(), "advisory")
            if self._compare_execution_modes(mode, user_max_mode) > 0:
                user_max_mode = mode
        
        # Apply license constraints
        tier_constraints = {
            "oss": "advisory",
            "starter": "approval",
            "professional": "autonomous",
            "enterprise": "autonomous",
            "trial": "autonomous"
        }
        
        license_max_mode = tier_constraints.get(license_tier.lower(), "advisory")
        
        # Return most restrictive mode
        if self._compare_execution_modes(user_max_mode, license_max_mode) < 0:
            return user_max_mode
        return license_max_mode
    
    def _compare_execution_modes(self, mode1: str, mode2: str) -> int:
        """Compare execution modes (higher = more autonomous)"""
        mode_levels = {
            "advisory": 0,
            "approval": 1,
            "autonomous": 2
        }
        return mode_levels.get(mode1, 0) - mode_levels.get(mode2, 0)
    
    def _calculate_deterministic_confidence(
        self,
        evaluations: List[EvaluationResult],
        context: Dict[str, Any]
    ) -> DeterministicConfidence:
        """Calculate deterministic confidence score"""
        if not self.enable_enterprise:
            # Fallback to simple confidence
            avg_confidence = sum(e.confidence for e in evaluations) / max(len(evaluations), 1)
            return DeterministicConfidence(
                score=avg_confidence,
                risk_score=1.0 - avg_confidence,
                components=[]
            )
        
        # Use Enterprise's deterministic confidence engine
        components = []
        
        # Component 1: Policy evaluation confidence
        policy_scores = [e.confidence for e in evaluations if e.triggered]
        policy_confidence = sum(policy_scores) / max(len(policy_scores), 1) if policy_scores else 0.5
        
        components.append(ConfidenceComponent(
            name="policy_evaluation",
            score=policy_confidence,
            weight=0.6,
            rationale=f"Average confidence of {len(policy_scores)} triggered policies",
            evidence={
                "triggered_policies": len(policy_scores),
                "total_policies": len(evaluations),
                "confidence_scores": policy_scores
            }
        ))
        
        # Component 2: Context completeness
        context_keys = len(context.keys())
        context_completeness = min(context_keys / 10, 1.0)  # Normalize to 0-1
        
        components.append(ConfidenceComponent(
            name="context_completeness",
            score=context_completeness,
            weight=0.2,
            rationale=f"Context has {context_keys} keys",
            evidence={"context_keys": list(context.keys())}
        ))
        
        # Component 3: Historical success rate (simplified)
        historical_success = 0.8  # Would come from audit trail
        
        components.append(ConfidenceComponent(
            name="historical_success",
            score=historical_success,
            weight=0.2,
            rationale="Historical success rate for similar actions",
            evidence={"estimated_success_rate": historical_success}
        ))
        
        # Calculate weighted score
        weighted_score = sum(c.score * c.weight for c in components)
        
        # Calculate risk score (inverse of confidence with adjustments)
        risk_score = 1.0 - weighted_score
        
        # Adjust risk based on context
        if "high_risk" in context.get("tags", []):
            risk_score = min(1.0, risk_score + 0.2)
        
        return DeterministicConfidence(
            score=weighted_score,
            risk_score=risk_score,
            components=components
        )
    
    def _assess_risk(
        self,
        evaluations: List[EvaluationResult],
        context: Dict[str, Any]
    ) -> str:
        """Assess risk level of proposed action"""
        if not evaluations:
            return "low"
        
        # Count high-severity triggered policies
        high_severity_count = sum(
            1 for e in evaluations 
            if e.triggered and getattr(e, "severity", "medium") == "high"
        )
        
        # Check context for risk indicators
        context_risk = 0
        if context.get("production_environment", False):
            context_risk += 1
        if context.get("business_hours", False):
            context_risk += 1
        if context.get("critical_service", False):
            context_risk += 1
        
        total_risk = high_severity_count + context_risk
        
        if total_risk >= 3:
            return "critical"
        elif total_risk >= 2:
            return "high"
        elif total_risk >= 1:
            return "medium"
        else:
            return "low"
    
    def _check_rollback_feasibility(
        self,
        evaluations: List[EvaluationResult],
        context: Dict[str, Any]
    ) -> bool:
        """Check if actions can be rolled back"""
        if not self.rollback_controller:
            return False
        
        # Check for irreversible actions
        irreversible_actions = [
            "delete", "drop", "destroy", "terminate", 
            "revoke", "remove", "purge", "wipe"
        ]
        
        for evaluation in evaluations:
            if evaluation.triggered:
                for action in evaluation.recommended_actions:
                    action_type = getattr(action, "action_type", "").lower()
                    if any(irreversible in action_type for irreversible in irreversible_actions):
                        return False
        
        return True
    
    async def _create_authority_trace(
        self,
        api_response: PolicyEvaluationResponse,
        authority_response: Dict[str, Any],
        context: Dict[str, Any],
        start_time: datetime
    ) -> ExecutionTrace:
        """Create comprehensive execution trace with authority checks"""
        trace = ExecutionTrace(
            session_id=context.get("session_id", "unknown"),
            start_time=start_time,
            end_time=datetime.utcnow(),
            evaluations=api_response.evaluations,
            total_evaluations=len(api_response.evaluations),
            total_duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
            authority_checks=authority_response
        )
        
        # Add metadata
        trace.metadata = {
            "execution_mode": authority_response.get("execution_mode", "advisory"),
            "license_tier": authority_response.get("license_tier", "oss"),
            "requires_human_approval": authority_response.get("requires_human_approval", False),
            "gates_passed": authority_response.get("gates_passed", []),
            "gates_failed": authority_response.get("gates_failed", [])
        }
        
        return trace
    
    def _determine_final_decision(
        self,
        api_response: PolicyEvaluationResponse,
        authority_response: Dict[str, Any]
    ) -> Tuple[Optional[ActionBase], float]:
        """Determine final decision with confidence"""
        # If any gates failed, block execution
        if authority_response.get("gates_failed"):
            return None, 0.0
        
        # If human approval required, return approval action
        if authority_response.get("requires_human_approval", False):
            approval_action = ActionBase(
                action_type=ActionType.HUMAN_REVIEW,
                parameters={
                    "reason": "Mechanical gates require human approval",
                    "failed_gates": authority_response.get("gates_failed", []),
                    "confidence": authority_response.get("confidence_score", 0.0)
                }
            )
            return approval_action, authority_response.get("confidence_score", 0.5)
        
        # Otherwise, use the highest confidence triggered policy
        triggered = [e for e in api_response.evaluations if e.triggered]
        if not triggered:
            return None, 0.0
        
        # Find highest confidence triggered policy
        best_evaluation = max(triggered, key=lambda e: e.confidence)
        
        # Use first recommended action
        if best_evaluation.recommended_actions:
            return best_evaluation.recommended_actions[0], best_evaluation.confidence
        
        return None, best_evaluation.confidence
    
    def _log_to_audit_trail(
        self,
        action: str,
        user_id: Optional[str],
        context: Dict[str, Any],
        api_response: PolicyEvaluationResponse,
        authority_response: Dict[str, Any],
        final_decision: Optional[ActionBase]
    ):
        """Log to Enterprise audit trail"""
        if not self.audit_trail:
            return
        
        details = {
            "context_summary": {k: type(v).__name__ for k, v in context.items()},
            "evaluation_count": len(api_response.evaluations),
            "triggered_count": sum(1 for e in api_response.evaluations if e.triggered),
            "authority_checks": authority_response,
            "final_decision": final_decision.action_type if final_decision else "blocked",
            "confidence": authority_response.get("confidence_score", 0.0)
        }
        
        self.audit_trail.record_action(
            action=action,
            customer=self.license_info.get("customer_name", "unknown") if self.license_info else "oss",
            severity="info",
            user=user_id,
            component="execution_authority",
            details=details
        )
    
    def _get_execution_mode_for_user(self, user_roles: List[str]) -> str:
        """Get execution mode for user based on roles and license"""
        return self._determine_execution_mode(user_roles)
    
    # ==================== API ENDPOINT INTEGRATION ====================
    
    async def can_execute_action(
        self,
        action: str,
        component: str,
        parameters: Dict[str, Any],
        user_id: Optional[str] = None,
        user_roles: List[str] = None
    ) -> Dict[str, Any]:
        """
        Check if an action can be executed with mechanical authority.
        
        This is the method API endpoints should call before executing any action.
        """
        # Create mock evaluation for the action
        evaluation_request = PolicyEvaluationRequest(
            context={
                "action": action,
                "component": component,
                "parameters": parameters,
                "user_id": user_id,
                "user_roles": user_roles or [],
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # Evaluate with authority
        response = await self.evaluate_with_authority(
            evaluation_request,
            user_id=user_id,
            user_roles=user_roles or []
        )
        
        return {
            "can_execute": response.final_decision is not None,
            "requires_approval": response.trace.metadata.get("requires_human_approval", False),
            "execution_mode": response.trace.metadata.get("execution_mode", "advisory"),
            "confidence": response.confidence,
            "final_decision": response.final_decision.action_type if response.final_decision else None,
            "authority_checks": response.authority_checks
        }
    
    def get_license_info(self) -> Dict[str, Any]:
        """Get license information for API responses"""
        if not self.enable_enterprise or not self.license_info:
            return {
                "edition": "oss",
                "valid": False,
                "features": ["advisory_mode"],
                "execution_modes": ["advisory"]
            }
        
        return {
            "edition": "enterprise",
            "valid": self.license_info.get("valid", False),
            "tier": self.license_info.get("tier", "oss"),
            "customer": self.license_info.get("customer_name", "unknown"),
            "expires": self.license_info.get("expires_at"),
            "features": self.license_info.get("features", []),
            "execution_modes": self._get_available_execution_modes(),
            "requires_upgrade": self.license_info.get("tier") in ["oss", "starter"]
        }
    
    def _get_available_execution_modes(self) -> List[str]:
        """Get available execution modes based on license"""
        if not self.license_info:
            return ["advisory"]
        
        tier = self.license_info.get("tier", "oss")
        
        tier_modes = {
            "oss": ["advisory"],
            "starter": ["advisory", "approval"],
            "professional": ["advisory", "approval", "autonomous"],
            "enterprise": ["advisory", "approval", "autonomous"],
            "trial": ["advisory", "approval", "autonomous"]
        }
        
        return tier_modes.get(tier.lower(), ["advisory"])


# ============================================================================
# DEPENDENCY INJECTION FOR FASTAPI
# ============================================================================

from fastapi import Depends, HTTPException, status

_execution_authority_service = None

def get_execution_authority_service() -> ExecutionAuthorityService:
    """Get singleton ExecutionAuthorityService instance"""
    global _execution_authority_service
    if _execution_authority_service is None:
        _execution_authority_service = ExecutionAuthorityService()
    return _execution_authority_service


def require_enterprise_license(feature: Optional[str] = None):
    """
    FastAPI dependency to require Enterprise license.
    
    Usage:
        @router.post("/execute")
        @require_enterprise_license("autonomous_execution")
        async def execute_action(...):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            service = get_execution_authority_service()
            
            # Extract user info from request
            user_id = kwargs.get("user_id")
            user_roles = kwargs.get("user_roles", [])
            
            # Check license
            if not service._validate_license_for_feature(feature):
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=f"Enterprise license required for {feature or 'this feature'}. "
                           f"Current license: {service.license_info.get('tier', 'oss') if service.license_info else 'none'}. "
                           f"Upgrade at https://arf.dev/enterprise"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# ============================================================================
# HEALTH CHECK INTEGRATION
# ============================================================================

def get_integration_health() -> Dict[str, Any]:
    """Get integration health status"""
    service = get_execution_authority_service()
    
    return {
        "integration": {
            "status": "active" if service.enable_enterprise else "oss_only",
            "enterprise_available": service.enable_enterprise,
            "license_valid": service.license_info.get("valid", False) if service.license_info else False,
            "license_tier": service.license_info.get("tier", "oss") if service.license_info else "oss",
            "execution_modes_available": service._get_available_execution_modes(),
            "audit_trail": service.audit_trail is not None,
            "rollback_controller": service.rollback_controller is not None
        },
        "api_services": {
            "neo4j_service": service.neo4j_service is not None,
            "redis_client": service.redis_client is not None
        },
        "timestamp": datetime.utcnow().isoformat()
    }


__all__ = [
    "ExecutionAuthorityService",
    "get_execution_authority_service",
    "require_enterprise_license",
    "get_integration_health",
    "ExecutionAuthorityError",
    "LicenseValidationError"
]

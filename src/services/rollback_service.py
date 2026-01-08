"""
Rollback service for ARF.
Psychology: Transactional safety with compensation and verification patterns.
Intention: Provide reliable, auditable rollback operations with dependency management.
"""
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from functools import wraps
import uuid
import logging
import json
from enum import Enum

from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, and_, or_, func
import redis

from src.database import get_db
from src.database.redis_client import get_redis
from src.models.rollback import (
    RollbackAction, RollbackExecution, RollbackPlan, RollbackAnalysis,
    RollbackRequest, RollbackResponse, BulkRollbackRequest, BulkRollbackResponse,
    RollbackStatus, ActionType, RollbackStrategy, RiskLevel,
    RollbackAuditLog
)

logger = logging.getLogger(__name__)

class RollbackError(Exception):
    """Custom rollback error with context"""
    def __init__(self, message: str, action_id: Optional[str] = None, 
                 execution_id: Optional[str] = None, recoverable: bool = False):
        self.message = message
        self.action_id = action_id
        self.execution_id = execution_id
        self.recoverable = recoverable
        super().__init__(self.message)

def with_audit_log(func):
    """Decorator to audit all rollback operations"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        start_time = datetime.utcnow()
        actor_id = kwargs.get('executed_by') or 'system'
        
        try:
            result = func(self, *args, **kwargs)
            
            # Log success
            self._log_audit_event(
                event_type=f"{func.__name__}_success",
                actor_id=actor_id,
                duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
                metadata={'result': str(result)[:500] if result else None}
            )
            
            return result
            
        except Exception as e:
            # Log failure
            self._log_audit_event(
                event_type=f"{func.__name__}_failed",
                actor_id=actor_id,
                duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
                metadata={'error': str(e), 'error_type': type(e).__name__}
            )
            raise
    
    return wrapper

class RollbackService:
    """Service for rollback operations"""
    
    def __init__(self, db_session: Optional[Session] = None, 
                 redis_client: Optional[redis.Redis] = None):
        self.db = db_session
        self.redis = redis_client or get_redis()
        self._cache_prefix = "rollback:cache:"
    
    def _get_db(self):
        """Get database session (lazy initialization)"""
        if self.db is None:
            from src.database import SessionLocal
            self.db = SessionLocal()
        return self.db
    
    def _log_audit_event(self, event_type: str, actor_id: str, 
                        duration_ms: float = 0.0, **metadata):
        """Log audit event"""
        try:
            log = RollbackAuditLog(
                event_type=event_type,
                actor_id=actor_id,
                actor_type="system",
                event_data=metadata,
                timestamp=datetime.utcnow()
            )
            
            # In production, this would save to database
            logger.info(f"Rollback Audit: {event_type} by {actor_id} - {metadata}")
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
    
    @with_audit_log
    def log_action(self, action_data: Dict[str, Any], 
                  executed_by: Optional[str] = None) -> str:
        """
        Log an action for potential rollback.
        
        Psychology: Capture enough context to undo the action later.
        Intention: Create immutable record of system changes.
        """
        db = self._get_db()
        
        # Validate action data
        required_fields = {'action_type', 'description'}
        if not required_fields.issubset(action_data.keys()):
            raise ValueError(f"Missing required fields: {required_fields}")
        
        # Create action record
        action = RollbackAction(
            action_id=action_data.get('action_id', str(uuid.uuid4())),
            action_type=ActionType(action_data['action_type']),
            description=action_data['description'],
            executed_by=executed_by or action_data.get('executed_by'),
            executed_at=datetime.utcnow(),
            parameters=action_data.get('parameters', {}),
            pre_state=action_data.get('pre_state', {}),
            post_state=action_data.get('post_state', {}),
            rollback_strategy=RollbackStrategy(
                action_data.get('rollback_strategy', 'inverse_action')
            ),
            rollback_parameters=action_data.get('rollback_parameters', {}),
            ttl_seconds=action_data.get('ttl_seconds'),
            depends_on=action_data.get('depends_on', []),
            affected_resources=action_data.get('affected_resources', []),
            risk_level=RiskLevel(action_data.get('risk_level', 'medium')),
            risk_reason=action_data.get('risk_reason'),
            tags=action_data.get('tags', []),
            metadata=action_data.get('metadata', {})
        )
        
        # Save to database (in memory for now - would be SQLAlchemy in production)
        # For now, we'll cache in Redis
        cache_key = f"{self._cache_prefix}action:{action.action_id}"
        self.redis.setex(
            cache_key,
            action.ttl_seconds or 86400 * 30,  # Default 30 days
            json.dumps(action.model_dump())
        )
        
        # Also store in list for queries
        self.redis.zadd(
            f"{self._cache_prefix}actions:by_time",
            {action.action_id: action.executed_at.timestamp()}
        )
        
        # Index by type
        self.redis.sadd(
            f"{self._cache_prefix}actions:type:{action.action_type.value}",
            action.action_id
        )
        
        logger.info(f"Logged action {action.action_id}: {action.description}")
        
        return action.action_id
    
    @with_audit_log
    def get_action(self, action_id: str) -> Optional[RollbackAction]:
        """Retrieve a logged action"""
        cache_key = f"{self._cache_prefix}action:{action_id}"
        cached = self.redis.get(cache_key)
        
        if cached:
            action_data = json.loads(cached)
            
            # Convert string enums back to Enum instances
            action_data['action_type'] = ActionType(action_data['action_type'])
            action_data['rollback_strategy'] = RollbackStrategy(action_data['rollback_strategy'])
            action_data['risk_level'] = RiskLevel(action_data['risk_level'])
            action_data['current_status'] = RollbackStatus(action_data['current_status'])
            
            # Convert string dates back to datetime
            for date_field in ['executed_at', 'last_rollback_attempt']:
                if action_data.get(date_field):
                    action_data[date_field] = datetime.fromisoformat(action_data[date_field])
            
            return RollbackAction(**action_data)
        
        return None
    
    @with_audit_log
    def analyze_rollback(self, action_id: str, 
                        executed_by: Optional[str] = None) -> RollbackAnalysis:
        """
        Analyze feasibility and impact of rolling back an action.
        
        Psychology: Risk assessment before execution.
        Intention: Prevent dangerous rollbacks and provide alternatives.
        """
        action = self.get_action(action_id)
        if not action:
            raise RollbackError(f"Action not found: {action_id}", action_id)
        
        # Check if already rolled back
        if action.current_status == RollbackStatus.ROLLED_BACK:
            return RollbackAnalysis(
                action_id=action_id,
                is_feasible=False,
                feasibility_score=0.0,
                feasibility_reasons=["Action already rolled back"],
                recommended_strategy=RollbackStrategy.IGNORE,
                estimated_risk=RiskLevel.LOW
            )
        
        # Check TTL
        if action.ttl_seconds:
            age_seconds = (datetime.utcnow() - action.executed_at).total_seconds()
            if age_seconds > action.ttl_seconds:
                return RollbackAnalysis(
                    action_id=action_id,
                    is_feasible=False,
                    feasibility_score=0.0,
                    feasibility_reasons=["Rollback TTL expired"],
                    recommended_strategy=RollbackStrategy.IGNORE,
                    estimated_risk=RiskLevel.MEDIUM
                )
        
        # Analyze dependencies
        blocking_actions = []
        for dep_id in action.depends_on:
            dep_action = self.get_action(dep_id)
            if dep_action and dep_action.current_status != RollbackStatus.ROLLED_BACK:
                blocking_actions.append(dep_id)
        
        # Determine feasibility
        is_feasible = len(blocking_actions) == 0
        feasibility_score = 0.8 if is_feasible else 0.2
        
        # Determine strategy
        if action.rollback_strategy == RollbackStrategy.MANUAL_INTERVENTION:
            recommended_strategy = RollbackStrategy.MANUAL_INTERVENTION
            feasibility_score *= 0.5  # Manual intervention reduces feasibility
        else:
            recommended_strategy = action.rollback_strategy
        
        # Assess risk
        estimated_risk = action.risk_level
        if action.risk_level == RiskLevel.CRITICAL:
            feasibility_score *= 0.3
        elif action.risk_level == RiskLevel.HIGH:
            feasibility_score *= 0.6
        
        # Check resource availability
        resource_warnings = []
        for resource in action.affected_resources:
            # In production, check resource state
            resource_warnings.append(f"Verify resource state: {resource}")
        
        return RollbackAnalysis(
            analysis_id=str(uuid.uuid4()),
            action_id=action_id,
            is_feasible=is_feasible,
            feasibility_score=feasibility_score,
            feasibility_reasons=[] if is_feasible else [
                f"Blocked by dependent actions: {blocking_actions}"
            ],
            affected_resources=[
                {"resource": r, "status": "unknown"} for r in action.affected_resources
            ],
            estimated_duration_seconds=30.0,  # Default estimate
            estimated_risk=estimated_risk,
            blocking_actions=blocking_actions,
            dependent_actions=action.depends_on,
            recommended_strategy=recommended_strategy,
            alternative_strategies=[
                s for s in RollbackStrategy 
                if s != recommended_strategy and s != RollbackStrategy.IGNORE
            ],
            warnings=resource_warnings,
            analyzed_at=datetime.utcnow(),
            analyzed_by=executed_by
        )
    
    @with_audit_log
    def execute_rollback(self, request: RollbackRequest,
                        executed_by: Optional[str] = None) -> RollbackResponse:
        """
        Execute rollback of a single action.
        
        Psychology: Transactional execution with verification.
        Intention: Safe, auditable reversal of system changes.
        """
        start_time = datetime.utcnow()
        
        # Get action
        action = self.get_action(request.action_id)
        if not action:
            return RollbackResponse(
                execution_id=str(uuid.uuid4()),
                action_id=request.action_id,
                status=RollbackStatus.FAILED,
                success=False,
                message=f"Action not found: {request.action_id}",
                errors=[f"Action not found: {request.action_id}"],
                started_at=start_time,
                completed_at=datetime.utcnow(),
                duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000
            )
        
        # Check if already rolled back
        if action.current_status == RollbackStatus.ROLLED_BACK:
            return RollbackResponse(
                execution_id=str(uuid.uuid4()),
                action_id=request.action_id,
                status=RollbackStatus.ROLLED_BACK,
                success=True,
                message="Action already rolled back",
                started_at=start_time,
                completed_at=datetime.utcnow(),
                duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000
            )
        
        # Analyze feasibility
        analysis = self.analyze_rollback(request.action_id, executed_by)
        if not analysis.is_feasible:
            return RollbackResponse(
                execution_id=str(uuid.uuid4()),
                action_id=request.action_id,
                status=RollbackStatus.FAILED,
                success=False,
                message="Rollback not feasible",
                errors=analysis.feasibility_reasons,
                started_at=start_time,
                completed_at=datetime.utcnow(),
                duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000
            )
        
        # Create execution record
        execution = RollbackExecution(
            execution_id=str(uuid.uuid4()),
            action_id=request.action_id,
            status=RollbackStatus.PENDING,
            executed_by=executed_by,
            initiated_by=executed_by
        )
        
        try:
            # Execute based on strategy
            strategy = request.strategy or analysis.recommended_strategy
            execution.status = RollbackStatus.EXECUTED
            
            if request.dry_run:
                execution.status = RollbackStatus.PENDING
                execution.logs.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "level": "INFO",
                    "message": "Dry run - no changes made"
                })
            else:
                # Execute rollback logic based on strategy
                rollback_result = self._execute_rollback_strategy(
                    action, strategy, request.parameters
                )
                
                execution.success = rollback_result.get('success', False)
                execution.logs.extend(rollback_result.get('logs', []))
                execution.error_message = rollback_result.get('error_message')
                
                if execution.success:
                    execution.status = RollbackStatus.ROLLED_BACK
                    # Update action status
                    action.current_status = RollbackStatus.ROLLED_BACK
                    action.rollback_count += 1
                    action.last_rollback_attempt = datetime.utcnow()
                    
                    # Save updated action
                    cache_key = f"{self._cache_prefix}action:{action.action_id}"
                    self.redis.setex(
                        cache_key,
                        action.ttl_seconds or 86400 * 30,
                        json.dumps(action.model_dump())
                    )
                else:
                    execution.status = RollbackStatus.FAILED
            
            # Verify if requested
            if request.verification_required and execution.success and not request.dry_run:
                verification_result = self._verify_rollback(action)
                execution.verification_passed = verification_result.get('passed', False)
                execution.verification_details = verification_result.get('details')
                
                if not execution.verification_passed:
                    execution.status = RollbackStatus.FAILED
                    execution.success = False
                    execution.logs.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "level": "ERROR",
                        "message": f"Verification failed: {execution.verification_details}"
                    })
            
            execution.completed_at = datetime.utcnow()
            execution.duration_ms = (
                execution.completed_at - start_time
            ).total_seconds() * 1000
            
            # Save execution
            exec_key = f"{self._cache_prefix}execution:{execution.execution_id}"
            self.redis.setex(
                exec_key,
                86400 * 90,  # 90 days
                json.dumps(execution.model_dump())
            )
            
            # Link execution to action
            action.rollback_executions.append(execution)
            
            # Prepare response
            response = RollbackResponse(
                execution_id=execution.execution_id,
                action_id=request.action_id,
                status=execution.status,
                success=execution.success or False,
                message="Rollback executed successfully" if execution.success else "Rollback failed",
                errors=[execution.error_message] if execution.error_message else [],
                warnings=[log['message'] for log in execution.logs if log['level'] == 'WARNING'],
                new_state={},  # Would be populated from verification
                verification_result={
                    "passed": execution.verification_passed,
                    "details": execution.verification_details
                } if execution.verification_passed is not None else None,
                started_at=start_time,
                completed_at=execution.completed_at,
                duration_ms=execution.duration_ms
            )
            
            return response
            
        except Exception as e:
            execution.status = RollbackStatus.FAILED
            execution.success = False
            execution.error_message = str(e)
            execution.completed_at = datetime.utcnow()
            execution.duration_ms = (
                execution.completed_at - start_time
            ).total_seconds() * 1000
            
            logger.error(f"Rollback failed for action {request.action_id}: {e}")
            
            return RollbackResponse(
                execution_id=execution.execution_id,
                action_id=request.action_id,
                status=RollbackStatus.FAILED,
                success=False,
                message=f"Rollback failed: {str(e)}",
                errors=[str(e)],
                started_at=start_time,
                completed_at=execution.completed_at,
                duration_ms=execution.duration_ms
            )
    
    def _execute_rollback_strategy(self, action: RollbackAction, 
                                  strategy: RollbackStrategy,
                                  parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute specific rollback strategy.
        
        Note: In production, this would integrate with actual systems.
        This is a placeholder implementation.
        """
        logs = []
        
        try:
            if strategy == RollbackStrategy.INVERSE_ACTION:
                # Execute inverse of original action
                logs.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "level": "INFO",
                    "message": f"Executing inverse action for {action.action_type}"
                })
                
                # Placeholder logic - would call actual systems
                success = True
                
            elif strategy == RollbackStrategy.STATE_RESTORE:
                # Restore previous state
                logs.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "level": "INFO", 
                    "message": f"Restoring state for {len(action.pre_state)} items"
                })
                
                success = True
                
            elif strategy == RollbackStrategy.COMPENSATING_ACTION:
                # Execute compensating action
                logs.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "level": "INFO",
                    "message": "Executing compensating action"
                })
                
                success = True
                
            elif strategy == RollbackStrategy.MANUAL_INTERVENTION:
                # Flag for manual intervention
                logs.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "level": "WARNING",
                    "message": "Manual intervention required"
                })
                
                success = False  # Manual not yet done
                
            elif strategy == RollbackStrategy.IGNORE:
                logs.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "level": "INFO",
                    "message": "Ignoring rollback as per strategy"
                })
                
                success = True
                
            else:
                raise ValueError(f"Unknown strategy: {strategy}")
            
            return {
                "success": success,
                "logs": logs
            }
            
        except Exception as e:
            logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "level": "ERROR",
                "message": f"Strategy execution failed: {str(e)}"
            })
            
            return {
                "success": False,
                "logs": logs,
                "error_message": str(e)
            }
    
    def _verify_rollback(self, action: RollbackAction) -> Dict[str, Any]:
        """
        Verify rollback was successful.
        
        Placeholder implementation - would check system state.
        """
        # In production, this would verify the system is in expected state
        # For now, simulate verification
        
        import random
        passed = random.random() > 0.1  # 90% success rate for simulation
        
        return {
            "passed": passed,
            "details": "Verification completed" if passed else "State mismatch detected"
        }
    
    @with_audit_log
    def execute_bulk_rollback(self, request: BulkRollbackRequest,
                             executed_by: Optional[str] = None) -> BulkRollbackResponse:
        """
        Execute rollback of multiple actions.
        
        Psychology: Coordinated rollback with dependency resolution.
        Intention: Handle complex rollback scenarios safely.
        """
        start_time = datetime.utcnow()
        
        # Analyze all actions
        analyses = {}
        for action_id in request.action_ids:
            analyses[action_id] = self.analyze_rollback(action_id, executed_by)
        
        # Determine execution order
        if request.execution_order:
            execution_order = request.execution_order
        else:
            # Auto-determine order based on dependencies
            execution_order = self._determine_rollback_order(request.action_ids, analyses)
        
        # Create rollback plan
        plan = RollbackPlan(
            plan_id=str(uuid.uuid4()),
            name=f"Bulk rollback {len(request.action_ids)} actions",
            description="Auto-generated bulk rollback plan",
            action_ids=request.action_ids,
            execution_order=execution_order,
            dry_run=request.dry_run,
            stop_on_failure=request.stop_on_failure,
            execute_immediately=True,
            status="executing",
            created_at=datetime.utcnow(),
            created_by=executed_by
        )
        
        # Execute rollbacks
        executions = []
        successful = 0
        failed = 0
        skipped = 0
        
        for action_id in execution_order:
            analysis = analyses[action_id]
            
            if not analysis.is_feasible:
                skipped += 1
                executions.append(RollbackResponse(
                    execution_id=str(uuid.uuid4()),
                    action_id=action_id,
                    status=RollbackStatus.FAILED,
                    success=False,
                    message="Skipped - not feasible",
                    errors=analysis.feasibility_reasons,
                    started_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                    duration_ms=0.0
                ))
                continue
            
            # Execute rollback
            rollback_request = RollbackRequest(
                action_id=action_id,
                strategy=request.strategy or analysis.recommended_strategy,
                parameters={},
                dry_run=request.dry_run,
                verification_required=True
            )
            
            response = self.execute_rollback(rollback_request, executed_by)
            executions.append(response)
            
            if response.success:
                successful += 1
            else:
                failed += 1
                
                # Stop on failure if configured
                if request.stop_on_failure:
                    break
        
        # Update plan status
        plan.status = "completed" if failed == 0 else "partially_completed"
        
        completed_at = datetime.utcnow()
        total_duration_ms = (completed_at - start_time).total_seconds() * 1000
        
        return BulkRollbackResponse(
            plan_id=plan.plan_id,
            status=plan.status,
            total_actions=len(request.action_ids),
            successful=successful,
            failed=failed,
            skipped=skipped,
            executions=executions,
            execution_order=execution_order,
            overall_success=failed == 0,
            message=f"Bulk rollback completed: {successful} successful, {failed} failed, {skipped} skipped",
            started_at=start_time,
            completed_at=completed_at,
            total_duration_ms=total_duration_ms
        )
    
    def _determine_rollback_order(self, action_ids: List[str],
                                 analyses: Dict[str, RollbackAnalysis]) -> List[str]:
        """
        Determine optimal rollback order based on dependencies.
        
        Uses topological sort to respect dependencies.
        """
        from collections import defaultdict, deque
        
        # Build graph
        graph = defaultdict(list)
        in_degree = defaultdict(int)
        
        for action_id in action_ids:
            analysis = analyses[action_id]
            in_degree[action_id] = len(analysis.blocking_actions)
            
            for blocking_id in analysis.blocking_actions:
                if blocking_id in action_ids:
                    graph[blocking_id].append(action_id)
        
        # Topological sort
        queue = deque([action_id for action_id in action_ids if in_degree[action_id] == 0])
        order = []
        
        while queue:
            current = queue.popleft()
            order.append(current)
            
            for neighbor in graph[current]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        
        # Check for cycles
        if len(order) != len(action_ids):
            # Fallback: sort by feasibility score
            sorted_actions = sorted(
                action_ids,
                key=lambda x: analyses[x].feasibility_score if x in analyses else 0,
                reverse=True
            )
            return sorted_actions
        
        return order
    
    @with_audit_log
    def search_actions(self, filters: Dict[str, Any], 
                      limit: int = 100, offset: int = 0) -> Tuple[List[RollbackAction], int]:
        """
        Search rollback actions with filters.
        """
        # This is a simplified Redis-based search
        # In production, would use Elasticsearch or database queries
        
        action_ids = set()
        
        # Filter by type
        if 'action_type' in filters:
            type_key = f"{self._cache_prefix}actions:type:{filters['action_type']}"
            type_actions = self.redis.smembers(type_key)
            if action_ids:
                action_ids = action_ids.intersection(type_actions)
            else:
                action_ids = set(type_actions)
        
        # Filter by time range
        if 'start_time' in filters or 'end_time' in filters:
            start = filters.get('start_time', 0)
            end = filters.get('end_time', float('inf'))
            
            time_key = f"{self._cache_prefix}actions:by_time"
            time_actions = self.redis.zrangebyscore(
                time_key, start, end, withscores=False
            )
            
            if action_ids:
                action_ids = action_ids.intersection(set(time_actions))
            else:
                action_ids = set(time_actions)
        
        # If no filters, get all actions
        if not action_ids and not filters:
            time_key = f"{self._cache_prefix}actions:by_time"
            action_ids = set(self.redis.zrange(time_key, 0, -1))
        
        # Paginate
        action_ids_list = list(action_ids)
        total = len(action_ids_list)
        
        paginated_ids = action_ids_list[offset:offset + limit]
        
        # Load actions
        actions = []
        for action_id in paginated_ids:
            action = self.get_action(action_id)
            if action:
                actions.append(action)
        
        return actions, total
    
    @with_audit_log
    def cleanup_expired_actions(self, batch_size: int = 1000) -> Dict[str, int]:
        """
        Clean up expired rollback actions.
        """
        # Get all actions
        time_key = f"{self._cache_prefix}actions:by_time"
        all_action_ids = self.redis.zrange(time_key, 0, -1)
        
        expired_count = 0
        cleaned_resources = 0
        
        for action_id in all_action_ids[:batch_size]:
            action = self.get_action(action_id)
            if not action:
                continue
            
            # Check if expired
            if action.ttl_seconds:
                age_seconds = (datetime.utcnow() - action.executed_at).total_seconds()
                if age_seconds > action.ttl_seconds:
                    # Clean up
                    cache_key = f"{self._cache_prefix}action:{action_id}"
                    self.redis.delete(cache_key)
                    
                    # Remove from indices
                    self.redis.zrem(time_key, action_id)
                    self.redis.srem(
                        f"{self._cache_prefix}actions:type:{action.action_type.value}",
                        action_id
                    )
                    
                    expired_count += 1
                    cleaned_resources += 1
        
        return {
            "expired_actions_cleaned": expired_count,
            "total_resources_cleaned": cleaned_resources
        }

# Singleton instance
_rollback_service = None

def get_rollback_service(
    db_session: Optional[Session] = None,
    redis_client: Optional[redis.Redis] = None
) -> RollbackService:
    """Get singleton RollbackService instance"""
    global _rollback_service
    if _rollback_service is None:
        _rollback_service = RollbackService(db_session, redis_client)
    return _rollback_service

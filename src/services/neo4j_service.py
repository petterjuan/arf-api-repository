"""
Neo4j service for execution ladder graph operations.
Psychology: Repository pattern with transaction management and error resilience.
Intention: Abstract complex Cypher queries behind clean Python interfaces.
"""
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from functools import wraps
import uuid
import logging

from neo4j import Transaction, Result, Driver
from neo4j.exceptions import Neo4jError, ConstraintError

from src.database.neo4j_client import get_neo4j
from src.models.execution_ladder import (
    ExecutionNode, Policy, ExecutionGraph, EvaluationResult,
    ExecutionTrace, PolicyType, NodeType, ActionType
)

logger = logging.getLogger(__name__)

def with_transaction(func):
    """Decorator to handle Neo4j transactions with error handling"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        session = self.driver.session()
        try:
            result = func(self, session, *args, **kwargs)
            return result
        except Neo4jError as e:
            logger.error(f"Neo4j error in {func.__name__}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}")
            raise
        finally:
            session.close()
    return wrapper

class ExecutionLadderService:
    """Service for execution ladder graph operations"""
    
    def __init__(self, driver: Optional[Driver] = None):
        self.driver = driver or get_neo4j()
        self._initialize_constraints()
    
    def _initialize_constraints(self):
        """Initialize Neo4j constraints and indexes"""
        with self.driver.session() as session:
            # Unique constraints
            session.run(
                "CREATE CONSTRAINT IF NOT EXISTS FOR (g:ExecutionGraph) "
                "REQUIRE g.graph_id IS UNIQUE"
            )
            session.run(
                "CREATE CONSTRAINT IF NOT EXISTS FOR (n:ExecutionNode) "
                "REQUIRE n.node_id IS UNIQUE"
            )
            session.run(
                "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Policy) "
                "REQUIRE p.policy_id IS UNIQUE"
            )
            
            # Indexes for common queries
            session.run(
                "CREATE INDEX IF NOT EXISTS FOR (g:ExecutionGraph) "
                "ON (g.is_active, g.updated_at)"
            )
            session.run(
                "CREATE INDEX IF NOT EXISTS FOR (p:Policy) "
                "ON (p.policy_type, p.severity)"
            )
            session.run(
                "CREATE INDEX IF NOT EXISTS FOR (t:ExecutionTrace) "
                "ON (t.session_id, t.start_time)"
            )
    
    @with_transaction
    def create_execution_graph(self, session, graph: ExecutionGraph) -> str:
        """Create a new execution graph"""
        # Create graph node
        graph_data = graph.model_dump()
        graph_data['created_at'] = graph_data['created_at'].isoformat()
        if graph_data['updated_at']:
            graph_data['updated_at'] = graph_data['updated_at'].isoformat()
        
        result = session.run(
            """
            CREATE (g:ExecutionGraph $graph_data)
            RETURN g.graph_id as graph_id
            """,
            graph_data=graph_data
        )
        
        graph_id = result.single()["graph_id"]
        
        # Create all nodes
        for node_id, node_data in graph.nodes.items():
            node_data = node_data.model_dump()
            node_data['created_at'] = datetime.utcnow().isoformat()
            
            session.run(
                """
                MATCH (g:ExecutionGraph {graph_id: $graph_id})
                CREATE (n:ExecutionNode $node_data)
                CREATE (g)-[:CONTAINS]->(n)
                """,
                graph_id=graph_id,
                node_data=node_data
            )
        
        # Create edges
        for edge in graph.edges:
            session.run(
                """
                MATCH (source:ExecutionNode {node_id: $source_id})
                MATCH (target:ExecutionNode {node_id: $target_id})
                CREATE (source)-[:CONNECTED_TO {
                    relationship: $relationship,
                    created_at: $created_at
                }]->(target)
                """,
                source_id=edge['source'],
                target_id=edge['target'],
                relationship=edge.get('relationship', 'flows_to'),
                created_at=datetime.utcnow().isoformat()
            )
        
        return graph_id
    
    @with_transaction
    def get_execution_graph(self, session, graph_id: str) -> Optional[ExecutionGraph]:
        """Retrieve an execution graph with all nodes and edges"""
        # Get graph metadata
        graph_result = session.run(
            """
            MATCH (g:ExecutionGraph {graph_id: $graph_id})
            RETURN properties(g) as graph_props
            """,
            graph_id=graph_id
        )
        
        graph_record = graph_result.single()
        if not graph_record:
            return None
        
        graph_props = graph_record["graph_props"]
        
        # Get all nodes in this graph
        nodes_result = session.run(
            """
            MATCH (g:ExecutionGraph {graph_id: $graph_id})-[:CONTAINS]->(n:ExecutionNode)
            RETURN n.node_id as node_id, properties(n) as node_props
            """,
            graph_id=graph_id
        )
        
        nodes = {}
        for record in nodes_result:
            node_props = record["node_props"]
            node_id = record["node_id"]
            nodes[node_id] = ExecutionNode(**node_props)
        
        # Get all edges
        edges_result = session.run(
            """
            MATCH (g:ExecutionGraph {graph_id: $graph_id})-[:CONTAINS]->(source:ExecutionNode)
            MATCH (source)-[r:CONNECTED_TO]->(target:ExecutionNode)
            RETURN source.node_id as source, target.node_id as target, 
                   r.relationship as relationship
            """,
            graph_id=graph_id
        )
        
        edges = []
        for record in edges_result:
            edges.append({
                "source": record["source"],
                "target": record["target"],
                "relationship": record["relationship"]
            })
        
        # Reconstruct graph
        graph_props['nodes'] = nodes
        graph_props['edges'] = edges
        
        return ExecutionGraph(**graph_props)
    
    @with_transaction
    def update_execution_graph(self, session, graph_id: str, updates: Dict[str, Any]) -> bool:
        """Update execution graph metadata"""
        updates['updated_at'] = datetime.utcnow().isoformat()
        
        result = session.run(
            """
            MATCH (g:ExecutionGraph {graph_id: $graph_id})
            SET g += $updates
            RETURN count(g) as updated
            """,
            graph_id=graph_id,
            updates=updates
        )
        
        return result.single()["updated"] > 0
    
    @with_transaction
    def add_node_to_graph(self, session, graph_id: str, node: ExecutionNode) -> str:
        """Add a node to an execution graph"""
        node_data = node.model_dump()
        node_data['created_at'] = datetime.utcnow().isoformat()
        
        result = session.run(
            """
            MATCH (g:ExecutionGraph {graph_id: $graph_id})
            CREATE (n:ExecutionNode $node_data)
            CREATE (g)-[:CONTAINS]->(n)
            RETURN n.node_id as node_id
            """,
            graph_id=graph_id,
            node_data=node_data
        )
        
        return result.single()["node_id"]
    
    @with_transaction
    def create_edge(self, session, source_id: str, target_id: str, 
                   relationship: str = "flows_to") -> bool:
        """Create an edge between two nodes"""
        result = session.run(
            """
            MATCH (source:ExecutionNode {node_id: $source_id})
            MATCH (target:ExecutionNode {node_id: $target_id})
            CREATE (source)-[:CONNECTED_TO {
                relationship: $relationship,
                created_at: $created_at
            }]->(target)
            RETURN count(*) as created
            """,
            source_id=source_id,
            target_id=target_id,
            relationship=relationship,
            created_at=datetime.utcnow().isoformat()
        )
        
        return result.single()["created"] > 0
    
    @with_transaction
    def find_policies_by_type(self, session, policy_type: PolicyType, 
                             active_only: bool = True) -> List[Policy]:
        """Find policies by type"""
        query = """
            MATCH (p:Policy {policy_type: $policy_type})
            WHERE $active_only = false OR p.enabled = true
            RETURN properties(p) as policy_props
            ORDER BY p.priority DESC, p.severity DESC
        """
        
        result = session.run(
            query,
            policy_type=policy_type.value,
            active_only=active_only
        )
        
        policies = []
        for record in result:
            policies.append(Policy(**record["policy_props"]))
        
        return policies
    
    @with_transaction
    def evaluate_policies(self, session, context: Dict[str, Any], 
                         policy_ids: Optional[List[str]] = None) -> List[EvaluationResult]:
        """
        Evaluate policies against context.
        This is a simplified version - in production, this would be more complex.
        """
        # Build WHERE clause for policy filtering
        where_clause = ""
        params = {"context": context}
        
        if policy_ids:
            where_clause = "AND p.policy_id IN $policy_ids"
            params["policy_ids"] = policy_ids
        
        query = f"""
            MATCH (p:Policy)
            WHERE p.enabled = true {where_clause}
            RETURN p.policy_id as policy_id, properties(p) as policy_props
        """
        
        result = session.run(query, **params)
        
        evaluations = []
        for record in result:
            policy = Policy(**record["policy_props"])
            
            # Simplified evaluation logic
            # In production, this would evaluate conditions against context
            triggered = self._evaluate_policy(policy, context)
            confidence = 0.8 if triggered else 0.2
            
            evaluation = EvaluationResult(
                policy_id=policy.node_id,
                triggered=triggered,
                confidence=confidence,
                evaluation_time=datetime.utcnow()
            )
            
            evaluations.append(evaluation)
            
            # Update policy statistics
            if triggered:
                session.run(
                    """
                    MATCH (p:Policy {policy_id: $policy_id})
                    SET p.match_count = coalesce(p.match_count, 0) + 1,
                        p.last_evaluated = $now
                    """,
                    policy_id=policy.node_id,
                    now=datetime.utcnow().isoformat()
                )
        
        return evaluations
    
    def _evaluate_policy(self, policy: Policy, context: Dict[str, Any]) -> bool:
        """Evaluate a single policy against context (simplified)"""
        # This is a placeholder for complex evaluation logic
        # In production, this would evaluate all conditions
        if not policy.conditions:
            return True  # Policy with no conditions always triggers
        
        # Simplified: check if any context field matches any condition
        for condition in policy.conditions:
            field = condition.get('field', '')
            value = condition.get('value')
            operator = condition.get('operator', 'equals')
            
            # Extract field from nested context (e.g., "agent.risk_score")
            context_value = self._extract_from_context(context, field)
            
            if self._evaluate_condition(context_value, operator, value):
                return True
        
        return False
    
    def _extract_from_context(self, context: Dict[str, Any], field_path: str) -> Any:
        """Extract value from nested context using dot notation"""
        parts = field_path.split('.')
        value = context
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        
        return value
    
    def _evaluate_condition(self, actual_value: Any, operator: str, expected_value: Any) -> bool:
        """Evaluate a single condition"""
        if operator == "equals":
            return actual_value == expected_value
        elif operator == "not_equals":
            return actual_value != expected_value
        elif operator == "greater_than":
            return actual_value > expected_value
        elif operator == "less_than":
            return actual_value < expected_value
        elif operator == "contains":
            return expected_value in actual_value if isinstance(actual_value, (list, str)) else False
        elif operator == "not_contains":
            return expected_value not in actual_value if isinstance(actual_value, (list, str)) else True
        # Add more operators as needed
        
        return False
    
    @with_transaction
    def create_execution_trace(self, session, trace: ExecutionTrace) -> str:
        """Create an execution trace"""
        trace_data = trace.model_dump()
        trace_data['start_time'] = trace_data['start_time'].isoformat()
        if trace_data['end_time']:
            trace_data['end_time'] = trace_data['end_time'].isoformat()
        
        # Store evaluations as separate nodes
        evaluation_nodes = []
        for eval_result in trace.evaluations:
            eval_data = eval_result.model_dump()
            eval_data['evaluation_time'] = eval_data['evaluation_time'].isoformat()
            evaluation_nodes.append(eval_data)
        
        result = session.run(
            """
            CREATE (t:ExecutionTrace $trace_data)
            WITH t
            UNWIND $evaluations as eval_data
            CREATE (e:EvaluationResult)
            SET e = eval_data
            CREATE (t)-[:INCLUDES]->(e)
            RETURN t.trace_id as trace_id
            """,
            trace_data=trace_data,
            evaluations=evaluation_nodes
        )
        
        return result.single()["trace_id"]
    
    @with_transaction
    def get_execution_path(self, session, start_node_id: str, 
                          max_depth: int = 10) -> List[Dict[str, Any]]:
        """Get execution path from a starting node"""
        result = session.run(
            """
            MATCH path = (start:ExecutionNode {node_id: $start_node_id})
            -[:CONNECTED_TO*1..$max_depth]->(end:ExecutionNode)
            RETURN [node in nodes(path) | {
                node_id: node.node_id,
                node_type: node.node_type,
                label: node.label
            }] as path_nodes
            ORDER BY length(path) DESC
            LIMIT 1
            """,
            start_node_id=start_node_id,
            max_depth=max_depth
        )
        
        record = result.single()
        return record["path_nodes"] if record else []
    
    @with_transaction
    def find_connected_nodes(self, session, node_id: str, 
                            direction: str = "both") -> List[Dict[str, Any]]:
        """Find nodes connected to a given node"""
        if direction == "incoming":
            relationship = "<-[:CONNECTED_TO]-"
        elif direction == "outgoing":
            relationship = "-[:CONNECTED_TO]->"
        else:  # both
            relationship = "-[:CONNECTED_TO]-"
        
        query = f"""
            MATCH (n:ExecutionNode {{node_id: $node_id}}){relationship}(connected:ExecutionNode)
            RETURN connected.node_id as node_id, 
                   connected.node_type as node_type,
                   connected.label as label,
                   labels(connected) as labels
        """
        
        result = session.run(query, node_id=node_id)
        
        nodes = []
        for record in result:
            nodes.append({
                "node_id": record["node_id"],
                "node_type": record["node_type"],
                "label": record["label"],
                "labels": record["labels"]
            })
        
        return nodes
    
    @with_transaction
    def get_graph_statistics(self, session, graph_id: str) -> Dict[str, Any]:
        """Get statistics for an execution graph"""
        result = session.run(
            """
            MATCH (g:ExecutionGraph {graph_id: $graph_id})-[:CONTAINS]->(n:ExecutionNode)
            WITH g, collect(n) as nodes
            UNWIND nodes as node
            WITH g, 
                 size([n in nodes WHERE n.node_type = 'policy']) as policy_count,
                 size([n in nodes WHERE n.node_type = 'condition']) as condition_count,
                 size([n in nodes WHERE n.node_type = 'action']) as action_count,
                 size([n in nodes WHERE n.enabled = true]) as enabled_count
            OPTIONAL MATCH (g)-[:CONTAINS]->(source)-[r:CONNECTED_TO]->(target)
            RETURN g.graph_id as graph_id,
                   policy_count,
                   condition_count,
                   action_count,
                   enabled_count,
                   count(r) as edge_count,
                   g.created_at as created_at,
                   g.updated_at as updated_at
            """,
            graph_id=graph_id
        )
        
        record = result.single()
        if not record:
            return {}
        
        return {
            "graph_id": record["graph_id"],
            "node_counts": {
                "total": record["policy_count"] + record["condition_count"] + record["action_count"],
                "policies": record["policy_count"],
                "conditions": record["condition_count"],
                "actions": record["action_count"]
            },
            "enabled_nodes": record["enabled_count"],
            "edge_count": record["edge_count"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"]
        }
    
    @with_transaction  
    def clone_execution_graph(self, session, source_graph_id: str, 
                             new_name: str, created_by: str) -> str:
        """Clone an execution graph"""
        # Get source graph
        source_graph = self.get_execution_graph(source_graph_id)
        if not source_graph:
            raise ValueError(f"Source graph not found: {source_graph_id}")
        
        # Create new graph with cloned properties
        new_graph = ExecutionGraph(
            name=new_name,
            description=f"Clone of {source_graph.name}",
            is_template=source_graph.is_template,
            created_by=created_by,
            clone_of=source_graph_id
        )
        
        # Copy nodes with new IDs
        new_nodes = {}
        node_id_mapping = {}
        
        for old_node_id, node in source_graph.nodes.items():
            new_node_id = str(uuid.uuid4())
            node_id_mapping[old_node_id] = new_node_id
            
            new_node = node.model_copy()
            new_node.node_id = new_node_id
            new_nodes[new_node_id] = new_node
        
        # Copy edges with new node IDs
        new_edges = []
        for edge in source_graph.edges:
            new_edges.append({
                "source": node_id_mapping[edge["source"]],
                "target": node_id_mapping[edge["target"]],
                "relationship": edge.get("relationship", "flows_to")
            })
        
        new_graph.nodes = new_nodes
        new_graph.edges = new_edges
        
        # Save new graph
        return self.create_execution_graph(new_graph)

# Singleton instance for dependency injection
_execution_ladder_service = None

def get_execution_ladder_service() -> ExecutionLadderService:
    """Get singleton ExecutionLadderService instance"""
    global _execution_ladder_service
    if _execution_ladder_service is None:
        _execution_ladder_service = ExecutionLadderService()
    return _execution_ladder_service

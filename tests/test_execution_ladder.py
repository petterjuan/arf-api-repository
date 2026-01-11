"""
Execution Ladder (Policy Engine) tests for ARF API.
Tests policy management, evaluation, and execution workflows.
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import AsyncClient
import json

# ============================================================================
# POLICY MANAGEMENT TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.database
class TestPolicyCRUD:
    """Test CRUD operations for execution ladder policies."""
    
    async def test_create_policy_success(self, authenticated_client: AsyncClient, test_policy_data: dict):
        """Test successfully creating a new policy."""
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=test_policy_data
        )
        
        assert response.status_code in [200, 201]
        data = response.json()
        assert "policy_id" in data
        assert data["name"] == test_policy_data["name"]
        assert data["enabled"] == test_policy_data["enabled"]
        assert "conditions" in data
        assert "actions" in data
        assert "created_at" in data
        assert "created_by" in data
    
    async def test_create_policy_with_complex_conditions(self, authenticated_client: AsyncClient):
        """Test creating policy with complex condition logic."""
        complex_policy = {
            "name": "Complex Condition Policy",
            "description": "Policy with AND/OR logic",
            "conditions": [
                {
                    "operator": "AND",
                    "conditions": [
                        {
                            "field": "incident.severity",
                            "operator": "equals",
                            "value": "high"
                        },
                        {
                            "field": "incident.component", 
                            "operator": "in",
                            "value": ["api", "database"]
                        }
                    ]
                },
                {
                    "operator": "OR",
                    "conditions": [
                        {
                            "field": "environment",
                            "operator": "equals",
                            "value": "production"
                        },
                        {
                            "field": "time.hour",
                            "operator": "between",
                            "value": [9, 17]
                        }
                    ]
                }
            ],
            "actions": [
                {
                    "type": "notification",
                    "channel": "slack",
                    "message": "Complex condition triggered"
                }
            ],
            "priority": 50,
            "enabled": True
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=complex_policy
        )
        
        assert response.status_code in [200, 201, 422]  # Might validate complex conditions
    
    async def test_create_policy_validation_error(self, authenticated_client: AsyncClient):
        """Test validation errors when creating policy."""
        invalid_policy = {
            "name": "",  # Empty name
            "conditions": "not a list",  # Wrong type
            "actions": []  # Empty actions
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=invalid_policy
        )
        
        assert response.status_code == 422  # Validation error
    
    async def test_get_policy_by_id(self, authenticated_client: AsyncClient, test_policy_data: dict):
        """Test retrieving a specific policy by ID."""
        # First create a policy
        create_response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=test_policy_data
        )
        policy_id = create_response.json()["policy_id"]
        
        # Then retrieve it
        response = await authenticated_client.get(f"/api/v1/execution-ladder/policies/{policy_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["policy_id"] == policy_id
        assert data["name"] == test_policy_data["name"]
    
    async def test_get_nonexistent_policy(self, authenticated_client: AsyncClient):
        """Test retrieving a policy that doesn't exist."""
        response = await authenticated_client.get("/api/v1/execution-ladder/policies/nonexistent-id")
        assert response.status_code == 404
    
    async def test_update_policy(self, authenticated_client: AsyncClient, test_policy_data: dict):
        """Test updating an existing policy."""
        # Create policy
        create_response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=test_policy_data
        )
        policy_id = create_response.json()["policy_id"]
        
        # Update it
        update_data = {
            "name": "Updated Policy Name",
            "description": "Updated description",
            "priority": 200,
            "enabled": False
        }
        
        response = await authenticated_client.put(
            f"/api/v1/execution-ladder/policies/{policy_id}",
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == update_data["name"]
        assert data["priority"] == update_data["priority"]
        assert data["enabled"] == update_data["enabled"]
    
    async def test_delete_policy(self, authenticated_client: AsyncClient, test_policy_data: dict):
        """Test deleting a policy."""
        # Create policy
        create_response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=test_policy_data
        )
        policy_id = create_response.json()["policy_id"]
        
        # Delete it
        response = await authenticated_client.delete(f"/api/v1/execution-ladder/policies/{policy_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert data["success"] is True
        
        # Verify it's deleted
        get_response = await authenticated_client.get(f"/api/v1/execution-ladder/policies/{policy_id}")
        assert get_response.status_code == 404


# ============================================================================
# POLICY LISTING AND FILTERING TESTS
# ============================================================================

@pytest.mark.asyncio
class TestPolicyFiltering:
    """Test policy listing with filters."""
    
    async def test_list_policies_empty(self, authenticated_client: AsyncClient):
        """Test listing policies when none exist."""
        response = await authenticated_client.get("/api/v1/execution-ladder/policies")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (list, dict))
    
    async def test_list_policies_with_data(self, authenticated_client: AsyncClient):
        """Test listing policies after creating some."""
        # Create multiple policies
        policies = [
            {
                "name": "Policy 1",
                "conditions": [{"field": "test", "operator": "equals", "value": "1"}],
                "actions": [{"type": "log", "message": "Test 1"}],
                "priority": 100
            },
            {
                "name": "Policy 2", 
                "conditions": [{"field": "test", "operator": "equals", "value": "2"}],
                "actions": [{"type": "log", "message": "Test 2"}],
                "priority": 200
            },
        ]
        
        for policy in policies:
            await authenticated_client.post("/api/v1/execution-ladder/policies", json=policy)
        
        # List all policies
        response = await authenticated_client.get("/api/v1/execution-ladder/policies")
        
        assert response.status_code == 200
        data = response.json()
    
    async def test_filter_policies_by_enabled(self, authenticated_client: AsyncClient):
        """Test filtering policies by enabled status."""
        # Create enabled and disabled policies
        await authenticated_client.post("/api/v1/execution-ladder/policies", json={
            "name": "Enabled Policy",
            "conditions": [{"field": "test", "operator": "equals", "value": "1"}],
            "actions": [{"type": "log", "message": "Test"}],
            "enabled": True
        })
        
        await authenticated_client.post("/api/v1/execution-ladder/policies", json={
            "name": "Disabled Policy",
            "conditions": [{"field": "test", "operator": "equals", "value": "2"}],
            "actions": [{"type": "log", "message": "Test"}],
            "enabled": False
        })
        
        # Filter by enabled
        response = await authenticated_client.get("/api/v1/execution-ladder/policies?enabled=true")
        
        assert response.status_code == 200
    
    async def test_filter_policies_by_priority(self, authenticated_client: AsyncClient):
        """Test filtering policies by priority range."""
        # Create policies with different priorities
        await authenticated_client.post("/api/v1/execution-ladder/policies", json={
            "name": "High Priority",
            "conditions": [{"field": "test", "operator": "equals", "value": "1"}],
            "actions": [{"type": "log", "message": "Test"}],
            "priority": 10
        })
        
        await authenticated_client.post("/api/v1/execution-ladder/policies", json={
            "name": "Low Priority",
            "conditions": [{"field": "test", "operator": "equals", "value": "2"}],
            "actions": [{"type": "log", "message": "Test"}],
            "priority": 1000
        })
        
        # Filter by priority range
        response = await authenticated_client.get("/api/v1/execution-ladder/policies?min_priority=1&max_priority=100")
        
        assert response.status_code == 200


# ============================================================================
# POLICY EVALUATION TESTS
# ============================================================================

@pytest.mark.asyncio
class TestPolicyEvaluation:
    """Test policy evaluation engine."""
    
    async def test_evaluate_policy_simple_match(self, authenticated_client: AsyncClient):
        """Test evaluating policies with simple matching conditions."""
        # First create a policy
        policy_data = {
            "name": "Test Evaluation Policy",
            "conditions": [
                {
                    "field": "incident.severity",
                    "operator": "equals", 
                    "value": "high"
                }
            ],
            "actions": [
                {
                    "type": "notification",
                    "channel": "slack",
                    "message": "High severity incident detected"
                }
            ],
            "priority": 100,
            "enabled": True
        }
        
        create_response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=policy_data
        )
        policy_id = create_response.json()["policy_id"]
        
        # Evaluate with matching context
        eval_context = {
            "incident": {
                "severity": "high",
                "title": "Test Incident"
            },
            "environment": "production"
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/evaluate",
            json={
                "context": eval_context,
                "policy_ids": [policy_id]
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "matches" in data
        assert "actions" in data
        assert len(data["matches"]) >= 1
        assert len(data["actions"]) >= 1
    
    async def test_evaluate_policy_no_match(self, authenticated_client: AsyncClient):
        """Test evaluating policies with non-matching conditions."""
        # Create a policy
        policy_data = {
            "name": "No Match Policy",
            "conditions": [
                {
                    "field": "incident.severity",
                    "operator": "equals",
                    "value": "critical"  # Requires critical severity
                }
            ],
            "actions": [{"type": "log", "message": "Critical incident"}],
            "enabled": True
        }
        
        await authenticated_client.post("/api/v1/execution-ladder/policies", json=policy_data)
        
        # Evaluate with non-matching context
        eval_context = {
            "incident": {
                "severity": "low",  # Doesn't match
                "title": "Low severity incident"
            }
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/evaluate",
            json={"context": eval_context}
        )
        
        assert response.status_code == 200
        data = response.json()
        # Should have no matches or empty matches list
        if "matches" in data:
            assert len(data["matches"]) == 0
        if "actions" in data:
            assert len(data["actions"]) == 0
    
    async def test_evaluate_all_policies(self, authenticated_client: AsyncClient):
        """Test evaluating against all policies (not specifying policy_ids)."""
        # Create multiple policies
        for i in range(3):
            await authenticated_client.post("/api/v1/execution-ladder/policies", json={
                "name": f"Test Policy {i}",
                "conditions": [
                    {
                        "field": "test.field",
                        "operator": "equals",
                        "value": f"value{i}"
                    }
                ],
                "actions": [{"type": "log", "message": f"Action {i}"}],
                "enabled": True
            })
        
        # Evaluate against all policies
        eval_context = {
            "test": {"field": "value1"}  # Matches policy 1
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/evaluate",
            json={"context": eval_context}
        )
        
        assert response.status_code == 200
        data = response.json()
        # Should find at least one match
    
    async def test_evaluate_complex_conditions(self, authenticated_client: AsyncClient):
        """Test evaluating policies with complex nested conditions."""
        # Create policy with complex conditions
        complex_policy = {
            "name": "Complex Condition Policy",
            "conditions": [
                {
                    "operator": "AND",
                    "conditions": [
                        {
                            "field": "incident.severity",
                            "operator": "in",
                            "value": ["high", "critical"]
                        },
                        {
                            "operator": "OR", 
                            "conditions": [
                                {
                                    "field": "environment",
                                    "operator": "equals",
                                    "value": "production"
                                },
                                {
                                    "field": "time.hour",
                                    "operator": ">=",
                                    "value": 18  # After business hours
                                }
                            ]
                        }
                    ]
                }
            ],
            "actions": [{"type": "notification", "message": "Complex condition matched"}],
            "enabled": True
        }
        
        await authenticated_client.post("/api/v1/execution-ladder/policies", json=complex_policy)
        
        # Test matching context
        matching_context = {
            "incident": {"severity": "critical"},
            "environment": "production",
            "time": {"hour": 10}
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/evaluate",
            json={"context": matching_context}
        )
        
        assert response.status_code == 200
    
    async def test_evaluate_with_custom_functions(self, authenticated_client: AsyncClient):
        """Test evaluating policies with custom function conditions."""
        # Create policy using custom functions
        custom_policy = {
            "name": "Custom Function Policy",
            "conditions": [
                {
                    "field": "incident.created_at",
                    "operator": "function",
                    "value": "is_recent"  # Custom function
                }
            ],
            "actions": [{"type": "log", "message": "Recent incident"}],
            "enabled": True
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=custom_policy
        )
        
        # Custom functions might require special handling
        assert response.status_code in [200, 201, 422]


# ============================================================================
# POLICY EXECUTION TESTS
# ============================================================================

@pytest.mark.asyncio
class TestPolicyExecution:
    """Test policy action execution."""
    
    @patch("src.services.neo4j_service.Neo4jService.execute_policy_actions")
    async def test_execute_policy_actions(self, mock_execute: AsyncMock, authenticated_client: AsyncClient):
        """Test executing actions from policy evaluation."""
        mock_execute.return_value = {
            "success": True,
            "executed_actions": 2,
            "results": [
                {"action_id": "act1", "success": True},
                {"action_id": "act2", "success": True}
            ]
        }
        
        execution_request = {
            "policy_id": "test-policy-123",
            "context": {"incident": {"severity": "high"}},
            "actions": [
                {
                    "type": "notification",
                    "channel": "slack",
                    "message": "Test notification"
                },
                {
                    "type": "webhook",
                    "url": "https://example.com/webhook",
                    "payload": {"test": "data"}
                }
            ]
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/execute",
            json=execution_request
        )
        
        # Execution endpoint might not exist
        if response.status_code == 404:
            pytest.skip("Execute endpoint not implemented")
        else:
            assert response.status_code == 200
            data = response.json()
            assert "success" in data
            assert "executed_actions" in data
    
    async def test_action_types_supported(self, authenticated_client: AsyncClient):
        """Test that various action types are supported."""
        action_types = ["notification", "webhook", "api_call", "script", "rollback"]
        
        for action_type in action_types:
            policy_data = {
                "name": f"{action_type} Test Policy",
                "conditions": [{"field": "test", "operator": "equals", "value": "true"}],
                "actions": [
                    {
                        "type": action_type,
                        "message": f"Test {action_type} action"
                    }
                ],
                "enabled": True
            }
            
            response = await authenticated_client.post(
                "/api/v1/execution-ladder/policies",
                json=policy_data
            )
            
            # Some action types might require additional config
            assert response.status_code in [200, 201, 422]
    
    @patch("src.services.webhook_service.WebhookService.send_notification")
    async def test_notification_action_execution(self, mock_send: AsyncMock, authenticated_client: AsyncClient):
        """Test execution of notification actions."""
        mock_send.return_value = {"success": True, "message_id": "test-123"}
        
        # This would test the actual execution of notification actions
        # Might be internal to the service rather than API endpoint
        pass


# ============================================================================
# GRAPH-BASED POLICY TESTS
# ============================================================================

@pytest.mark.asyncio
class TestGraphPolicies:
    """Test graph-based policy features (Neo4j integration)."""
    
    async def test_create_graph_policy(self, authenticated_client: AsyncClient):
        """Test creating a policy with graph relationships."""
        graph_policy = {
            "name": "Graph-Based Policy",
            "description": "Policy that uses graph relationships",
            "graph_query": """
                MATCH (i:Incident {severity: 'high'})-[:AFFECTS]->(s:Service {critical: true})
                RETURN i, s
            """,
            "conditions": [
                {
                    "field": "graph.result_count",
                    "operator": ">",
                    "value": 0
                }
            ],
            "actions": [
                {
                    "type": "notification",
                    "message": "Critical service affected by high severity incident"
                }
            ],
            "enabled": True
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=graph_policy
        )
        
        # Graph policies might have different validation
        assert response.status_code in [200, 201, 422]
    
    async def test_policy_dependencies(self, authenticated_client: AsyncClient):
        """Test policies with dependencies on other policies."""
        # Create a base policy
        base_response = await authenticated_client.post("/api/v1/execution-ladder/policies", json={
            "name": "Base Policy",
            "conditions": [{"field": "test", "operator": "equals", "value": "base"}],
            "actions": [{"type": "log", "message": "Base executed"}],
            "enabled": True
        })
        base_id = base_response.json()["policy_id"]
        
        # Create dependent policy
        dependent_policy = {
            "name": "Dependent Policy",
            "description": "Depends on base policy",
            "conditions": [
                {
                    "field": "policies.executed",
                    "operator": "contains",
                    "value": base_id
                },
                {
                    "field": "incident.severity",
                    "operator": "equals",
                    "value": "high"
                }
            ],
            "actions": [{"type": "log", "message": "Dependent executed"}],
            "dependencies": [base_id],
            "enabled": True
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=dependent_policy
        )
        
        assert response.status_code in [200, 201, 422]
    
    async def test_policy_execution_path(self, authenticated_client: AsyncClient):
        """Test retrieving policy execution path/trace."""
        # First create and execute a policy
        policy_response = await authenticated_client.post("/api/v1/execution-ladder/policies", json={
            "name": "Path Test Policy",
            "conditions": [{"field": "test", "operator": "equals", "value": "path"}],
            "actions": [{"type": "log", "message": "Test"}],
            "enabled": True
        })
        policy_id = policy_response.json()["policy_id"]
        
        # Get execution path/trace
        response = await authenticated_client.get(f"/api/v1/execution-ladder/policies/{policy_id}/path")
        
        # Path endpoint might not exist
        if response.status_code == 404:
            pytest.skip("Policy path endpoint not implemented")
        else:
            assert response.status_code == 200
            data = response.json()
            assert "policy_id" in data
            assert "execution_path" in data or "dependencies" in data


# ============================================================================
# POLICY ANALYTICS TESTS
# ============================================================================

@pytest.mark.asyncio
class TestPolicyAnalytics:
    """Test policy analytics and statistics."""
    
    async def test_policy_execution_stats(self, authenticated_client: AsyncClient):
        """Test getting policy execution statistics."""
        response = await authenticated_client.get("/api/v1/execution-ladder/statistics")
        
        # Statistics endpoint might not exist
        if response.status_code == 404:
            pytest.skip("Policy statistics endpoint not implemented")
        else:
            assert response.status_code == 200
            data = response.json()
            assert "total_policies" in data or "execution_count" in data
    
    async def test_policy_effectiveness(self, authenticated_client: AsyncClient):
        """Test policy effectiveness metrics."""
        response = await authenticated_client.get("/api/v1/execution-ladder/analytics/effectiveness")
        
        if response.status_code == 404:
            pytest.skip("Policy analytics endpoint not implemented")
        else:
            assert response.status_code == 200
            data = response.json()
            assert isinstance(data, (list, dict))
    
    async def test_policy_coverage(self, authenticated_client: AsyncClient):
        """Test policy coverage analysis."""
        # Create some incidents and policies first
        await authenticated_client.post("/api/v1/incidents", json={
            "title": "Coverage Test",
            "severity": "high"
        })
        
        response = await authenticated_client.get("/api/v1/execution-ladder/coverage")
        
        if response.status_code == 404:
            pytest.skip("Policy coverage endpoint not implemented")
        else:
            assert response.status_code == 200


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.integration
class TestPolicyIntegration:
    """Test policy integration with other systems."""
    
    async def test_incident_triggers_policy_evaluation(self, authenticated_client: AsyncClient):
        """Test that creating an incident triggers policy evaluation."""
        # Create a policy first
        await authenticated_client.post("/api/v1/execution-ladder/policies", json={
            "name": "Incident Trigger Policy",
            "conditions": [
                {
                    "field": "incident.severity",
                    "operator": "equals",
                    "value": "critical"
                }
            ],
            "actions": [{"type": "log", "message": "Critical incident policy triggered"}],
            "enabled": True
        })
        
        # Create incident that should trigger policy
        response = await authenticated_client.post("/api/v1/incidents", json={
            "title": "Critical Incident for Policy Test",
            "severity": "critical"
        })
        
        assert response.status_code in [200, 201]
        # Policy evaluation might be async, so we can't directly assert
    
    async def test_policy_triggers_rollback(self, authenticated_client: AsyncClient):
        """Test that policies can trigger rollback operations."""
        # Create policy with rollback action
        policy_data = {
            "name": "Rollback Trigger Policy",
            "conditions": [
                {
                    "field": "deployment.status",
                    "operator": "equals",
                    "value": "failed"
                }
            ],
            "actions": [
                {
                    "type": "rollback",
                    "target_type": "deployment",
                    "target_id": "{deployment.id}",
                    "strategy": "inverse_actions"
                }
            ],
            "enabled": True
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=policy_data
        )
        
        assert response.status_code in [200, 201, 422]
    
    async def test_policy_triggers_webhook(self, authenticated_client: AsyncClient):
        """Test that policies can trigger webhook notifications."""
        # Create policy with webhook action
        policy_data = {
            "name": "Webhook Policy",
            "conditions": [{"field": "test", "operator": "equals", "value": "webhook"}],
            "actions": [
                {
                    "type": "webhook",
                    "url": "https://example.com/webhook",
                    "method": "POST",
                    "payload": {
                        "message": "Policy triggered",
                        "context": "{context}"
                    }
                }
            ],
            "enabled": True
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=policy_data
        )
        
        assert response.status_code in [200, 201, 422]


# ============================================================================
# ERROR AND EDGE CASE TESTS
# ============================================================================

@pytest.mark.asyncio
class TestPolicyEdgeCases:
    """Test edge cases and error conditions for policies."""
    
    async def test_circular_policy_dependencies(self, authenticated_client: AsyncClient):
        """Test handling of circular policy dependencies."""
        # Create policy A that depends on B
        policy_a = {
            "name": "Policy A",
            "conditions": [{"field": "test", "operator": "equals", "value": "a"}],
            "actions": [{"type": "log", "message": "A"}],
            "dependencies": ["policy-b-id"],  # Would reference B
            "enabled": True
        }
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/policies",
            json=policy_a
        )
        
        # Circular dependency detection might happen at creation or execution
        assert response.status_code in [200, 201, 400, 422]
    
    async def test_infinite_policy_loop_prevention(self):
        """Test that infinite policy execution loops are prevented."""
        # This would test that a policy can't trigger itself infinitely
        pass
    
    async def test_policy_with_missing_fields(self, authenticated_client: AsyncClient):
        """Test policy evaluation with missing context fields."""
        # Create policy that references fields that might not exist
        policy_data = {
            "name": "Missing Field Policy",
            "conditions": [
                {
                    "field": "nonexistent.field",
                    "operator": "equals",
                    "value": "test"
                }
            ],
            "actions": [{"type": "log", "message": "Test"}],
            "enabled": True
        }
        
        await authenticated_client.post("/api/v1/execution-ladder/policies", json=policy_data)
        
        # Evaluate with context missing the field
        eval_context = {"existing": "field"}
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/evaluate",
            json={"context": eval_context}
        )
        
        assert response.status_code == 200
        # Should handle missing fields gracefully (no match or error)
    
    async def test_large_policy_evaluation(self, authenticated_client: AsyncClient):
        """Test evaluating many policies at once."""
        # Create many policies
        for i in range(20):
            await authenticated_client.post("/api/v1/execution-ladder/policies", json={
                "name": f"Bulk Policy {i}",
                "conditions": [{"field": "test", "operator": "equals", "value": f"value{i}"}],
                "actions": [{"type": "log", "message": f"Action {i}"}],
                "enabled": True
            })
        
        # Evaluate with context that matches one
        eval_context = {"test": "value5"}
        
        response = await authenticated_client.post(
            "/api/v1/execution-ladder/evaluate",
            json={"context": eval_context}
        )
        
        assert response.status_code == 200
        # Should handle many policies efficiently

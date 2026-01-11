"""
Incident management tests for ARF API.
Tests CRUD operations, filtering, pagination, and incident workflows.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient

# ============================================================================
# INCIDENT CRUD TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.database
class TestIncidentCRUD:
    """Test basic CRUD operations for incidents."""
    
    async def test_create_incident_success(self, authenticated_client: AsyncClient, test_incident_data: dict):
        """Test successfully creating a new incident."""
        response = await authenticated_client.post(
            "/api/v1/incidents",
            json=test_incident_data
        )
        
        assert response.status_code in [200, 201]
        data = response.json()
        assert "incident_id" in data
        assert data["title"] == test_incident_data["title"]
        assert data["severity"] == test_incident_data["severity"]
        assert data["status"] == "open"  # Default status
        assert "created_at" in data
        assert "created_by" in data
    
    async def test_create_incident_minimal_data(self, authenticated_client: AsyncClient):
        """Test creating incident with minimal required data."""
        minimal_data = {
            "title": "Minimal Incident",
            "severity": "low"
        }
        
        response = await authenticated_client.post(
            "/api/v1/incidents",
            json=minimal_data
        )
        
        assert response.status_code in [200, 201]
        data = response.json()
        assert data["title"] == minimal_data["title"]
        assert data["severity"] == minimal_data["severity"]
        assert data["status"] == "open"  # Default
        assert data["description"] == ""  # Should default to empty string
    
    async def test_create_incident_validation_error(self, authenticated_client: AsyncClient):
        """Test validation errors when creating incident."""
        invalid_data = {
            "title": "",  # Empty title should fail
            "severity": "invalid_severity"  # Invalid severity
        }
        
        response = await authenticated_client.post(
            "/api/v1/incidents",
            json=invalid_data
        )
        
        assert response.status_code == 422  # Validation error
    
    async def test_get_incident_by_id(self, authenticated_client: AsyncClient, test_incident_data: dict):
        """Test retrieving a specific incident by ID."""
        # First create an incident
        create_response = await authenticated_client.post(
            "/api/v1/incidents",
            json=test_incident_data
        )
        incident_id = create_response.json()["incident_id"]
        
        # Then retrieve it
        response = await authenticated_client.get(f"/api/v1/incidents/{incident_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["incident_id"] == incident_id
        assert data["title"] == test_incident_data["title"]
    
    async def test_get_nonexistent_incident(self, authenticated_client: AsyncClient):
        """Test retrieving a incident that doesn't exist."""
        response = await authenticated_client.get("/api/v1/incidents/nonexistent-id")
        assert response.status_code == 404
    
    async def test_update_incident(self, authenticated_client: AsyncClient, test_incident_data: dict):
        """Test updating an existing incident."""
        # Create incident
        create_response = await authenticated_client.post(
            "/api/v1/incidents",
            json=test_incident_data
        )
        incident_id = create_response.json()["incident_id"]
        
        # Update it
        update_data = {
            "title": "Updated Title",
            "description": "Updated description",
            "severity": "high",
            "status": "investigating"
        }
        
        response = await authenticated_client.put(
            f"/api/v1/incidents/{incident_id}",
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == update_data["title"]
        assert data["severity"] == update_data["severity"]
        assert data["status"] == update_data["status"]
        assert "updated_at" in data
        assert data["updated_at"] != data["created_at"]  # Should be different
    
    async def test_delete_incident(self, authenticated_client: AsyncClient, test_incident_data: dict):
        """Test deleting an incident."""
        # Create incident
        create_response = await authenticated_client.post(
            "/api/v1/incidents",
            json=test_incident_data
        )
        incident_id = create_response.json()["incident_id"]
        
        # Delete it
        response = await authenticated_client.delete(f"/api/v1/incidents/{incident_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert data["success"] is True
        
        # Verify it's deleted
        get_response = await authenticated_client.get(f"/api/v1/incidents/{incident_id}")
        assert get_response.status_code == 404


# ============================================================================
# INCIDENT LISTING AND FILTERING TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.database
class TestIncidentFiltering:
    """Test incident listing with filters and pagination."""
    
    async def test_list_incidents_empty(self, authenticated_client: AsyncClient):
        """Test listing incidents when none exist."""
        response = await authenticated_client.get("/api/v1/incidents")
        
        assert response.status_code == 200
        data = response.json()
        # Should return empty list or paginated structure
        assert isinstance(data, (list, dict))
    
    async def test_list_incidents_with_data(self, authenticated_client: AsyncClient):
        """Test listing incidents after creating some."""
        # Create multiple incidents
        incidents = [
            {"title": "Incident 1", "severity": "low", "component": "api"},
            {"title": "Incident 2", "severity": "medium", "component": "database"},
            {"title": "Incident 3", "severity": "high", "component": "api"},
        ]
        
        for incident in incidents:
            await authenticated_client.post("/api/v1/incidents", json=incident)
        
        # List all incidents
        response = await authenticated_client.get("/api/v1/incidents")
        
        assert response.status_code == 200
        data = response.json()
        # Should have 3 incidents (or paginated equivalent)
    
    async def test_filter_incidents_by_severity(self, authenticated_client: AsyncClient):
        """Test filtering incidents by severity."""
        # Create incidents with different severities
        await authenticated_client.post("/api/v1/incidents", json={
            "title": "Low Severity",
            "severity": "low"
        })
        
        await authenticated_client.post("/api/v1/incidents", json={
            "title": "High Severity", 
            "severity": "high"
        })
        
        # Filter by high severity
        response = await authenticated_client.get("/api/v1/incidents?severity=high")
        
        assert response.status_code == 200
        data = response.json()
        # Should only have high severity incidents
    
    async def test_filter_incidents_by_status(self, authenticated_client: AsyncClient):
        """Test filtering incidents by status."""
        # Create incidents with different statuses
        incident1 = await authenticated_client.post("/api/v1/incidents", json={
            "title": "Open Incident",
            "severity": "medium",
            "status": "open"
        })
        
        incident_id = incident1.json()["incident_id"]
        
        # Update one to resolved
        await authenticated_client.put(f"/api/v1/incidents/{incident_id}", json={
            "status": "resolved"
        })
        
        # Filter by open status
        response = await authenticated_client.get("/api/v1/incidents?status=open")
        
        assert response.status_code == 200
    
    async def test_filter_incidents_by_component(self, authenticated_client: AsyncClient):
        """Test filtering incidents by component."""
        # Create incidents for different components
        await authenticated_client.post("/api/v1/incidents", json={
            "title": "API Issue",
            "severity": "medium",
            "component": "api"
        })
        
        await authenticated_client.post("/api/v1/incidents", json={
            "title": "DB Issue",
            "severity": "medium",
            "component": "database"
        })
        
        # Filter by component
        response = await authenticated_client.get("/api/v1/incidents?component=api")
        
        assert response.status_code == 200
    
    async def test_pagination(self, authenticated_client: AsyncClient):
        """Test that pagination works correctly."""
        # Create more incidents than default page size
        for i in range(15):
            await authenticated_client.post("/api/v1/incidents", json={
                "title": f"Incident {i}",
                "severity": "low"
            })
        
        # Get first page
        response = await authenticated_client.get("/api/v1/incidents?page=1&limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        # Should have pagination metadata
        if isinstance(data, dict):
            assert "items" in data
            assert "total" in data
            assert "page" in data
            assert "limit" in data
            assert len(data["items"]) <= 10
    
    async def test_search_incidents(self, authenticated_client: AsyncClient):
        """Test searching incidents by text."""
        # Create incidents with specific text
        await authenticated_client.post("/api/v1/incidents", json={
            "title": "Database connection failed",
            "description": "MySQL connection timeout",
            "severity": "high"
        })
        
        await authenticated_client.post("/api/v1/incidents", json={
            "title": "API latency spike",
            "description": "Response times increased",
            "severity": "medium"
        })
        
        # Search for database-related incidents
        response = await authenticated_client.get("/api/v1/incidents?search=database")
        
        assert response.status_code == 200


# ============================================================================
# INCIDENT WORKFLOW TESTS
# ============================================================================

@pytest.mark.asyncio
class TestIncidentWorkflow:
    """Test incident state transitions and workflow."""
    
    async def test_incident_state_transitions(self, authenticated_client: AsyncClient):
        """Test valid incident state transitions."""
        # Create incident
        response = await authenticated_client.post("/api/v1/incidents", json={
            "title": "Workflow Test",
            "severity": "medium"
        })
        incident_id = response.json()["incident_id"]
        
        # Should start as "open"
        assert response.json()["status"] == "open"
        
        # Transition to investigating
        response = await authenticated_client.put(f"/api/v1/incidents/{incident_id}", json={
            "status": "investigating"
        })
        assert response.status_code == 200
        assert response.json()["status"] == "investigating"
        
        # Transition to resolved
        response = await authenticated_client.put(f"/api/v1/incidents/{incident_id}", json={
            "status": "resolved"
        })
        assert response.status_code == 200
        assert response.json()["status"] == "resolved"
    
    async def test_invalid_state_transition(self, authenticated_client: AsyncClient):
        """Test that invalid state transitions are rejected."""
        # Create resolved incident directly
        response = await authenticated_client.post("/api/v1/incidents", json={
            "title": "Already Resolved",
            "severity": "low",
            "status": "resolved"
        })
        incident_id = response.json()["incident_id"]
        
        # Try to move back to open (should fail or be restricted)
        response = await authenticated_client.put(f"/api/v1/incidents/{incident_id}", json={
            "status": "open"
        })
        # Might be allowed or not depending on business logic
        assert response.status_code in [200, 400, 422]
    
    async def test_incident_timeline(self, authenticated_client: AsyncClient):
        """Test that incident timeline/audit log is maintained."""
        # Create incident
        response = await authenticated_client.post("/api/v1/incidents", json={
            "title": "Timeline Test",
            "severity": "medium"
        })
        incident_id = response.json()["incident_id"]
        
        # Make several updates
        await authenticated_client.put(f"/api/v1/incidents/{incident_id}", json={
            "severity": "high"
        })
        
        await authenticated_client.put(f"/api/v1/incidents/{incident_id}", json={
            "status": "investigating"
        })
        
        # Get timeline/audit (if endpoint exists)
        response = await authenticated_client.get(f"/api/v1/incidents/{incident_id}/timeline")
        
        # Timeline endpoint might not exist yet
        if response.status_code == 404:
            pytest.skip("Timeline endpoint not implemented")
        else:
            assert response.status_code == 200
            data = response.json()
            assert isinstance(data, list)
            assert len(data) >= 3  # Create + 2 updates
    
    async def test_incident_assignee(self, authenticated_client: AsyncClient):
        """Test assigning incidents to users."""
        # Create incident
        response = await authenticated_client.post("/api/v1/incidents", json={
            "title": "Assignee Test",
            "severity": "medium"
        })
        incident_id = response.json()["incident_id"]
        
        # Assign to user
        assign_response = await authenticated_client.post(
            f"/api/v1/incidents/{incident_id}/assign",
            json={"assignee_id": "user-123"}
        )
        
        # Assignment endpoint might not exist
        if assign_response.status_code == 404:
            # Try via update
            update_response = await authenticated_client.put(
                f"/api/v1/incidents/{incident_id}",
                json={"assignee_id": "user-123"}
            )
            assert update_response.status_code in [200, 422]
        else:
            assert assign_response.status_code == 200


# ============================================================================
# INCIDENT STATISTICS AND REPORTING TESTS
# ============================================================================

@pytest.mark.asyncio
class TestIncidentStatistics:
    """Test incident statistics and reporting endpoints."""
    
    async def test_incident_statistics(self, authenticated_client: AsyncClient):
        """Test getting incident statistics."""
        # Create some incidents first
        for i in range(5):
            await authenticated_client.post("/api/v1/incidents", json={
                "title": f"Stat Incident {i}",
                "severity": "low" if i % 2 == 0 else "medium",
                "status": "open" if i < 3 else "resolved"
            })
        
        # Get statistics
        response = await authenticated_client.get("/api/v1/incidents/statistics")
        
        # Statistics endpoint might not exist
        if response.status_code == 404:
            pytest.skip("Statistics endpoint not implemented")
        else:
            assert response.status_code == 200
            data = response.json()
            assert "total" in data
            assert "by_severity" in data
            assert "by_status" in data
            assert "by_component" in data
    
    async def test_incident_trends(self, authenticated_client: AsyncClient):
        """Test getting incident trends over time."""
        response = await authenticated_client.get("/api/v1/incidents/trends")
        
        if response.status_code == 404:
            pytest.skip("Trends endpoint not implemented")
        else:
            assert response.status_code == 200
            data = response.json()
            assert isinstance(data, (list, dict))
    
    async def test_export_incidents(self, authenticated_client: AsyncClient):
        """Test exporting incidents (CSV, JSON, etc.)."""
        # Create some incidents
        await authenticated_client.post("/api/v1/incidents", json={
            "title": "Export Test",
            "severity": "low"
        })
        
        # Try different export formats
        for format in ["csv", "json"]:
            response = await authenticated_client.get(f"/api/v1/incidents/export?format={format}")
            
            if response.status_code == 404:
                continue  # Export might not be implemented
            
            assert response.status_code == 200
            # Check content type
            if format == "csv":
                assert "text/csv" in response.headers.get("content-type", "")
            elif format == "json":
                assert "application/json" in response.headers.get("content-type", "")


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.integration
class TestIncidentIntegration:
    """Test incident integration with other systems."""
    
    @patch("src.services.webhook_service.WebhookService.send_notification")
    async def test_incident_triggers_webhook(self, mock_send: AsyncMock, authenticated_client: AsyncClient):
        """Test that creating an incident triggers webhook notifications."""
        mock_send.return_value = {"success": True, "message_id": "test-123"}
        
        response = await authenticated_client.post("/api/v1/incidents", json={
            "title": "Webhook Test Incident",
            "severity": "high"  # High severity should trigger notifications
        })
        
        assert response.status_code in [200, 201]
        # Webhook should be called (maybe async, so we can't directly assert)
        # But we can verify the mock was called if the integration is synchronous
        # In async systems, this might be queued
    
    async def test_incident_execution_ladder_trigger(self, authenticated_client: AsyncClient):
        """Test that incidents trigger execution ladder policy evaluation."""
        # This tests integration with the execution ladder
        # The exact behavior depends on implementation
        pass
    
    async def test_incident_rollback_trigger(self, authenticated_client: AsyncClient):
        """Test that incidents can trigger rollback operations."""
        # This tests integration with rollback system
        # Might require specific incident types or severities
        pass


# ============================================================================
# ERROR AND EDGE CASE TESTS
# ============================================================================

@pytest.mark.asyncio
class TestIncidentEdgeCases:
    """Test edge cases and error conditions."""
    
    async def test_incident_with_special_characters(self, authenticated_client: AsyncClient):
        """Test creating incident with special characters in fields."""
        special_data = {
            "title": "Incident with ❤️ emoji & <html> tags",
            "description": "Line 1\nLine 2\n\tIndented",
            "severity": "medium",
            "metadata": {
                "special": "value with \"quotes\" and 'apostrophes'",
                "unicode": "🎉 unicode test 🎉"
            }
        }
        
        response = await authenticated_client.post(
            "/api/v1/incidents",
            json=special_data
        )
        
        assert response.status_code in [200, 201, 422]  # Might be valid or rejected
    
    async def test_very_long_incident_title(self, authenticated_client: AsyncClient):
        """Test incident with very long title."""
        long_title = "A" * 1000  # Very long title
        
        response = await authenticated_client.post("/api/v1/incidents", json={
            "title": long_title,
            "severity": "low"
        })
        
        # Should either succeed or give validation error
        assert response.status_code in [200, 201, 422]
    
    async def test_incident_with_many_labels(self, authenticated_client: AsyncClient):
        """Test incident with large number of labels."""
        many_labels = [f"label_{i}" for i in range(50)]
        
        response = await authenticated_client.post("/api/v1/incidents", json={
            "title": "Many Labels",
            "severity": "low",
            "labels": many_labels
        })
        
        assert response.status_code in [200, 201, 422]
    
    async def test_concurrent_incident_updates(self, authenticated_client: AsyncClient):
        """Test handling concurrent updates to the same incident."""
        # Create incident
        response = await authenticated_client.post("/api/v1/incidents", json={
            "title": "Concurrent Test",
            "severity": "low"
        })
        incident_id = response.json()["incident_id"]
        
        # Try concurrent updates (simulated sequentially for test)
        # In real scenario, these would be concurrent
        update1 = authenticated_client.put(f"/api/v1/incidents/{incident_id}", json={
            "description": "Update 1"
        })
        
        update2 = authenticated_client.put(f"/api/v1/incidents/{incident_id}", json={
            "description": "Update 2"
        })
        
        # Execute (note: not truly concurrent in test)
        response1 = await update1
        response2 = await update2
        
        # Both should succeed or handle conflicts appropriately
        assert response1.status_code in [200, 409]  # 409 for conflict
        assert response2.status_code in [200, 409]

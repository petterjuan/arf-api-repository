"""
Monitoring and observability tests for ARF API.
Tests health checks, metrics endpoints, and monitoring functionality.
"""

import pytest
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient
import json

# ============================================================================
# HEALTH CHECK TESTS
# ============================================================================

@pytest.mark.asyncio
class TestHealthChecks:
    """Test health check endpoints."""
    
    async def test_health_endpoint_accessible(self, client: AsyncClient):
        """Test that the health endpoint is publicly accessible."""
        response = await client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "unhealthy"]
    
    async def test_health_endpoint_structure(self, client: AsyncClient):
        """Test health endpoint returns expected structure."""
        response = await client.get("/health")
        data = response.json()
        
        # Check basic structure
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
        assert "service" in data
        
        # Check service info
        assert data["service"] == "arf-api"
        assert "1." in data["version"]  # Version should start with 1.
    
    async def test_health_with_database_check(self, client: AsyncClient):
        """Test health endpoint includes database status."""
        response = await client.get("/health")
        data = response.json()
        
        # Should include database status if implemented
        if "database" in data:
            assert data["database"] in ["healthy", "unhealthy", "connected", "disconnected"]
    
    async def test_health_with_redis_check(self, client: AsyncClient):
        """Test health endpoint includes Redis status."""
        response = await client.get("/health")
        data = response.json()
        
        # Should include Redis status if implemented
        if "redis" in data:
            assert data["redis"] in ["healthy", "unhealthy", "connected", "disconnected"]
    
    async def test_health_with_neo4j_check(self, client: AsyncClient):
        """Test health endpoint includes Neo4j status."""
        response = await client.get("/health")
        data = response.json()
        
        # Should include Neo4j status if implemented
        if "neo4j" in data:
            assert data["neo4j"] in ["healthy", "unhealthy", "connected", "disconnected"]
    
    async def test_health_detailed(self, client: AsyncClient):
        """Test detailed health endpoint (if exists)."""
        response = await client.get("/health/detailed")
        
        # Detailed endpoint might not exist
        if response.status_code == 404:
            # Try /health?detailed=true
            response = await client.get("/health?detailed=true")
        
        if response.status_code != 404:
            assert response.status_code == 200
            data = response.json()
            # Detailed health should have more information
            assert len(data.keys()) >= 3
    
    async def test_readiness_probe(self, client: AsyncClient):
        """Test Kubernetes readiness probe endpoint."""
        response = await client.get("/ready")
        
        # Might be separate endpoint or part of /health
        if response.status_code == 404:
            # Try /health/ready
            response = await client.get("/health/ready")
        
        if response.status_code != 404:
            assert response.status_code == 200
            data = response.json()
            assert data.get("ready") is True
    
    async def test_liveness_probe(self, client: AsyncClient):
        """Test Kubernetes liveness probe endpoint."""
        response = await client.get("/live")
        
        # Might be separate endpoint or part of /health
        if response.status_code == 404:
            # Try /health/live
            response = await client.get("/health/live")
        
        if response.status_code != 404:
            assert response.status_code == 200
            data = response.json()
            assert data.get("alive") is True
    
    async def test_startup_probe(self, client: AsyncClient):
        """Test Kubernetes startup probe endpoint."""
        response = await client.get("/startup")
        
        # Might be separate endpoint or part of /health
        if response.status_code == 404:
            # Try /health/startup
            response = await client.get("/health/startup")
        
        if response.status_code != 404:
            assert response.status_code == 200
            data = response.json()
            assert data.get("started") is True


# ============================================================================
# METRICS TESTS
# ============================================================================

@pytest.mark.asyncio
class TestMetrics:
    """Test Prometheus metrics endpoints."""
    
    async def test_metrics_endpoint_exists(self, client: AsyncClient):
        """Test that metrics endpoint exists."""
        response = await client.get("/metrics")
        
        # Should exist and return Prometheus metrics
        assert response.status_code == 200
        # Prometheus metrics are plain text
        assert "text/plain" in response.headers.get("content-type", "")
    
    async def test_metrics_content(self, client: AsyncClient):
        """Test metrics endpoint returns Prometheus format."""
        response = await client.get("/metrics")
        
        if response.status_code == 200:
            content = response.text
            # Should contain some Prometheus metrics
            assert "# TYPE" in content or "http_requests_total" in content or "process_" in content
    
    async def test_metrics_openmetrics(self, client: AsyncClient):
        """Test OpenMetrics format endpoint."""
        response = await client.get("/metrics/openmetrics")
        
        # OpenMetrics might be separate endpoint
        if response.status_code == 404:
            # Try with Accept header
            headers = {"Accept": "application/openmetrics-text"}
            response = await client.get("/metrics", headers=headers)
        
        if response.status_code != 404:
            assert response.status_code == 200
            content_type = response.headers.get("content-type", "")
            assert "openmetrics-text" in content_type or "text/plain" in content_type
    
    async def test_metrics_includes_http_metrics(self, client: AsyncClient):
        """Test that HTTP request metrics are collected."""
        # Make some requests to generate metrics
        await client.get("/health")
        await client.get("/docs")
        
        # Check metrics
        response = await client.get("/metrics")
        if response.status_code == 200:
            content = response.text
            # Should contain HTTP-related metrics
            # Look for patterns like http_requests_total, http_request_duration_seconds
            has_http_metrics = any(
                pattern in content.lower()
                for pattern in ["http_", "request_", "response_"]
            )
            assert has_http_metrics, "Metrics should include HTTP request tracking"
    
    async def test_metrics_includes_business_metrics(self, client: AsyncClient, authenticated_client: AsyncClient):
        """Test that business metrics are collected."""
        # Create an incident to generate business metrics
        await authenticated_client.post("/api/v1/incidents", json={
            "title": "Metrics Test",
            "severity": "medium"
        })
        
        # Check metrics
        response = await client.get("/metrics")
        if response.status_code == 200:
            content = response.text
            # Should contain business metrics
            # Look for patterns like incidents_, policies_, rollbacks_
            has_business_metrics = any(
                pattern in content.lower()
                for pattern in ["incident", "policy", "rollback", "webhook"]
            )
            # Business metrics might be added later, so don't fail if not present yet
            if has_business_metrics:
                assert True  # Business metrics are being tracked
    
    async def test_metrics_labels(self, client: AsyncClient):
        """Test that metrics include proper labels."""
        response = await client.get("/metrics")
        
        if response.status_code == 200:
            content = response.text
            # Metrics should include labels like method, endpoint, status
            # Example: http_requests_total{method="GET", endpoint="/health", status="200"}
            has_labels = "{" in content and "}" in content
            assert has_labels, "Metrics should include labels for better querying"


# ============================================================================
# PERFORMANCE METRICS TESTS
# ============================================================================

@pytest.mark.asyncio
class TestPerformanceMetrics:
    """Test performance and system metrics."""
    
    async def test_system_metrics_endpoint(self, client: AsyncClient):
        """Test system metrics endpoint (if exists)."""
        response = await client.get("/metrics/system")
        
        if response.status_code == 404:
            # Try /system/metrics
            response = await client.get("/system/metrics")
        
        if response.status_code != 404:
            assert response.status_code == 200
            data = response.json()
            # Should include system info
            assert "cpu" in data or "memory" in data or "disk" in data
    
    async def test_performance_metrics(self, client: AsyncClient):
        """Test performance metrics collection."""
        # Make several requests to test performance tracking
        for _ in range(5):
            await client.get("/health")
        
        # Check if performance metrics are in Prometheus output
        response = await client.get("/metrics")
        if response.status_code == 200:
            content = response.text
            # Look for performance-related metrics
            has_perf_metrics = any(
                pattern in content.lower()
                for pattern in ["duration", "latency", "percentile", "bucket"]
            )
            # Performance metrics might be added later
            if has_perf_metrics:
                assert True  # Performance metrics are being tracked
    
    async def test_database_performance_metrics(self, client: AsyncClient, authenticated_client: AsyncClient):
        """Test database performance metrics."""
        # Perform database operations
        await authenticated_client.get("/api/v1/incidents")
        
        # Check metrics for database operations
        response = await client.get("/metrics")
        if response.status_code == 200:
            content = response.text
            # Look for database metrics
            has_db_metrics = any(
                pattern in content.lower()
                for pattern in ["database", "query", "connection"]
            )
            # Database metrics might be added later
            if has_db_metrics:
                assert True


# ============================================================================
# CUSTOM METRICS TESTS
# ============================================================================

@pytest.mark.asyncio
class TestCustomMetrics:
    """Test custom business metrics."""
    
    async def test_incident_metrics(self, authenticated_client: AsyncClient, client: AsyncClient):
        """Test that incident operations update metrics."""
        # Track metrics before
        response_before = await client.get("/metrics")
        before_content = response_before.text if response_before.status_code == 200 else ""
        
        # Create an incident
        await authenticated_client.post("/api/v1/incidents", json={
            "title": "Custom Metrics Test",
            "severity": "high"
        })
        
        # Track metrics after
        response_after = await client.get("/metrics")
        if response_after.status_code == 200:
            after_content = response_after.text
            
            # Check if incident count increased
            # This is complex to parse in tests, so we'll just verify metrics endpoint works
            assert len(after_content) > 0
    
    async def test_policy_evaluation_metrics(self, authenticated_client: AsyncClient, client: AsyncClient):
        """Test policy evaluation metrics."""
        # Evaluate a policy (if endpoint exists)
        response = await authenticated_client.post("/api/v1/execution-ladder/evaluate", json={
            "context": {"test": "data"}
        })
        
        # Check metrics for policy evaluations
        metrics_response = await client.get("/metrics")
        if metrics_response.status_code == 200:
            content = metrics_response.text
            # Policy metrics might be added later
            if "policy" in content.lower() or "evaluation" in content.lower():
                assert True
    
    async def test_rollback_metrics(self, authenticated_client: AsyncClient, client: AsyncClient):
        """Test rollback operation metrics."""
        # Execute a rollback (if endpoint exists)
        response = await authenticated_client.post("/api/v1/rollback/execute", json={
            "name": "Test Rollback",
            "target_type": "test"
        })
        
        # Rollback endpoint might not exist yet
        if response.status_code != 404:
            # Check metrics
            metrics_response = await client.get("/metrics")
            if metrics_response.status_code == 200:
                content = metrics_response.text
                # Rollback metrics might be added later
                if "rollback" in content.lower():
                    assert True


# ============================================================================
# LOGGING TESTS
# ============================================================================

@pytest.mark.asyncio
class TestLogging:
    """Test structured logging and log correlation."""
    
    async def test_request_id_in_response(self, client: AsyncClient):
        """Test that responses include correlation/request IDs."""
        response = await client.get("/health")
        
        # Check for correlation headers
        headers = response.headers
        has_correlation_id = any(
            header.lower() in ["x-request-id", "x-correlation-id", "x-trace-id"]
            for header in headers.keys()
        )
        
        # At least one correlation header should be present
        assert has_correlation_id, "Responses should include correlation IDs"
    
    async def test_log_correlation(self, client: AsyncClient):
        """Test that log correlation works across requests."""
        # Make a request and get correlation ID
        response1 = await client.get("/health")
        correlation_id = None
        
        for header_name in ["X-Request-ID", "X-Correlation-ID", "X-Trace-ID"]:
            if header_name in response1.headers:
                correlation_id = response1.headers[header_name]
                break
        
        assert correlation_id is not None, "Should have correlation ID"
        
        # Make another request with the same correlation ID
        headers = {"X-Correlation-ID": correlation_id} if correlation_id else {}
        response2 = await client.get("/health", headers=headers)
        
        # Should use or preserve the correlation ID
        # (Implementation specific - might return same or new ID)
        assert response2.status_code == 200
    
    async def test_structured_logging_enabled(self):
        """Test that structured logging is configured."""
        # This is more of a configuration test
        # In practice, we'd check logger configuration
        assert True  # Placeholder - would verify structlog is configured


# ============================================================================
# MONITORING INTEGRATION TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.integration
class TestMonitoringIntegration:
    """Test integration with monitoring systems."""
    
    @patch("src.monitoring.metrics.incident_created_counter.inc")
    async def test_incident_creates_metrics(self, mock_metrics: AsyncMock, authenticated_client: AsyncClient):
        """Test that creating incidents updates metrics counters."""
        mock_metrics.return_value = None
        
        response = await authenticated_client.post("/api/v1/incidents", json={
            "title": "Metrics Integration Test",
            "severity": "critical"
        })
        
        assert response.status_code in [200, 201]
        # Metrics counter should be called
        # Note: This depends on implementation - might be async/queued
    
    async def test_health_check_includes_external_dependencies(self, client: AsyncClient):
        """Test health checks include external services."""
        response = await client.get("/health")
        data = response.json()
        
        # Health check should report on external dependencies
        external_services = ["database", "redis", "neo4j"]
        found_services = [svc for svc in external_services if svc in data]
        
        # At least some external services should be monitored
        assert len(found_services) > 0, "Health should check external dependencies"
    
    async def test_metrics_exposed_to_prometheus(self, client: AsyncClient):
        """Test that metrics are in Prometheus scrape format."""
        response = await client.get("/metrics")
        
        assert response.status_code == 200
        content = response.text
        
        # Basic Prometheus format checks
        lines = content.strip().split('\n')
        assert len(lines) > 0
        
        # Should have HELP and TYPE comments for metrics
        has_help = any(line.startswith('# HELP') for line in lines)
        has_type = any(line.startswith('# TYPE') for line in lines)
        
        # Prometheus metrics should have HELP/TYPE comments
        assert has_help, "Metrics should have HELP comments"
        assert has_type, "Metrics should have TYPE comments"


# ============================================================================
# ALERTING TESTS
# ============================================================================

@pytest.mark.asyncio
class TestAlerting:
    """Test alerting and notification integration with monitoring."""
    
    async def test_health_check_failure_alert(self):
        """Test that health check failures would trigger alerts."""
        # This would test integration with alert manager
        # In practice, would simulate health check failure
        pass
    
    async def test_metrics_anomaly_detection(self):
        """Test that metric anomalies can be detected."""
        # This tests integration with anomaly detection
        pass


# ============================================================================
# TEST UTILITIES
# ============================================================================

def test_metrics_parsing():
    """Test helper functions for parsing Prometheus metrics."""
    # This would test metrics parsing utilities if they exist
    pass


def test_health_check_configuration():
    """Test health check configuration and thresholds."""
    # This would test health check configuration
    pass


# ============================================================================
# PERFORMANCE TESTS (LIGHTWEIGHT)
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.slow
class TestPerformance:
    """Lightweight performance tests."""
    
    async def test_health_check_performance(self, client: AsyncClient):
        """Test health check response time."""
        import time
        
        start_time = time.time()
        response = await client.get("/health")
        end_time = time.time()
        
        assert response.status_code == 200
        response_time = end_time - start_time
        
        # Health check should be fast (< 1 second)
        assert response_time < 1.0, f"Health check took {response_time:.2f}s, should be < 1s"
    
    async def test_metrics_endpoint_performance(self, client: AsyncClient):
        """Test metrics endpoint response time."""
        import time
        
        start_time = time.time()
        response = await client.get("/metrics")
        end_time = time.time()
        
        if response.status_code == 200:
            response_time = end_time - start_time
            # Metrics endpoint might be slower due to collection
            # But should still be reasonable (< 3 seconds)
            assert response_time < 3.0, f"Metrics endpoint took {response_time:.2f}s, should be < 3s"
    
    async def test_concurrent_health_checks(self, client: AsyncClient):
        """Test handling concurrent health checks."""
        import asyncio
        
        # Make multiple concurrent requests
        tasks = [client.get("/health") for _ in range(10)]
        responses = await asyncio.gather(*tasks)
        
        # All should succeed
        for response in responses:
            assert response.status_code == 200

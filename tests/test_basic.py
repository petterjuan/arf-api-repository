# tests/test_basic.py - SIMPLE STARTER TESTS
import pytest

def test_imports():
    """Test that core modules can be imported"""
    # This is what your CI should test
    import sys
    import os
    os.environ['TESTING'] = '1'
    sys.path.insert(0, 'src')
    
    # Simple imports only
    from main import app
    assert app.title == "ARF API"
    assert len(app.routes) > 0

def test_health_endpoint():
    """Test health endpoint"""
    from main import app
    from fastapi.testclient import TestClient
    
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert "status" in response.json()

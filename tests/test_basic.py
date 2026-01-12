# tests/test_basic.py - SIMPLE STARTER TESTS
import pytest
import sys
import os

# Add src to path for imports
src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
sys.path.insert(0, src_path)

def test_imports():
    """Test that core modules can be imported"""
    # This is what your CI should test
    
    try:
        # Simple imports only
        from main import app
        assert app.title == "ARF API"
        assert len(app.routes) > 0
    except ImportError as e:
        # Try alternative import
        from src.main import app
        assert app.title == "ARF API"
        assert len(app.routes) > 0

def test_health_endpoint():
    """Test health endpoint"""
    try:
        from main import app
    except ImportError:
        from src.main import app
        
    from fastapi.testclient import TestClient
    
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert "status" in response.json()

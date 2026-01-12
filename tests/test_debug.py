# tests/test_debug.py
"""Debug test to understand fixture issues."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_debug_client_type(client):
    """Debug what type the client fixture returns."""
    print(f"Client type: {type(client)}")
    print(f"Client is AsyncClient: {isinstance(client, AsyncClient)}")
    print(f"Client has get method: {hasattr(client, 'get')}")
    
    # Try to access methods
    try:
        response = await client.get("/health")
        print(f"Success! Response status: {response.status_code}")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")
    
    assert isinstance(client, AsyncClient)


@pytest.mark.asyncio
async def test_debug_simple_get():
    """Test creating client directly without fixture."""
    import asyncio
    from httpx import AsyncClient
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/health")
        print(f"Direct client works! Status: {response.status_code}")
        assert response.status_code in [200, 503]

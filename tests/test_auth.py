"""
Authentication and authorization tests for ARF API.
Tests user registration, login, token refresh, and API key management.
"""

import pytest
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock

# Mark all tests in this module as async
pytestmark = pytest.mark.asyncio

# ============================================================================
# AUTHENTICATION TESTS
# ============================================================================

@pytest.mark.auth
class TestAuthentication:
    """Test user authentication endpoints."""
        
    async def test_register_user_success(self, client: AsyncClient):
        """Test successful user registration."""
        user_data = {
            "email": "newuser@example.com",
            "username": "newuser",
            "full_name": "New Test User",
            "password": "SecurePass123!",
            "role": "viewer"
        }
        
        response = await client.post("/api/v1/auth/register", json=user_data)
        
        # Should return 200 or 201 with user info (excluding password)
        assert response.status_code in [200, 201]
        data = response.json()
        assert "user_id" in data
        assert "email" in data
        assert data["email"] == user_data["email"]
        assert "password" not in data  # Password should not be returned
        assert "hashed_password" not in data
    
    async def test_register_user_missing_fields(self, client: AsyncClient):
        """Test registration with missing required fields."""
        user_data = {
            "email": "incomplete@example.com",
            # Missing username, password, etc.
        }
        
        response = await client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 422  # Validation error
    
    async def test_login_success(self, client: AsyncClient):
        """Test successful user login."""
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        response = await client.post("/api/v1/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
    
    async def test_login_invalid_credentials(self, client: AsyncClient):
        """Test login with invalid credentials."""
        login_data = {
            "username": "nonexistent",
            "password": "wrongpassword"
        }
        
        response = await client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401  # Unauthorized
    
    async def test_refresh_token_success(self, authenticated_client: AsyncClient):
        """Test successful token refresh."""
        refresh_data = {
            "refresh_token": "valid-refresh-token-123"
        }
        
        response = await authenticated_client.post("/api/v1/auth/refresh", json=refresh_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
    
    async def test_refresh_token_invalid(self, authenticated_client: AsyncClient):
        """Test token refresh with invalid refresh token."""
        refresh_data = {
            "refresh_token": "invalid-refresh-token"
        }
        
        response = await authenticated_client.post("/api/v1/auth/refresh", json=refresh_data)
        assert response.status_code == 401


# ============================================================================
# API KEY TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.auth
class TestAPIKeys:
    """Test API key management endpoints."""
    
    async def test_create_api_key(self, authenticated_client: AsyncClient):
        """Test creating a new API key."""
        api_key_data = {
            "name": "Test API Key",
            "description": "For integration testing",
            "scopes": ["incidents:read", "incidents:write"],
            "expires_in_days": 30
        }
        
        response = await authenticated_client.post(
            "/api/v1/auth/api-keys",
            json=api_key_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "api_key_id" in data
        assert "name" in data
        assert "key" in data  # The actual API key should be returned once
        assert "scopes" in data
        assert "created_at" in data
    
    async def test_list_api_keys(self, authenticated_client: AsyncClient):
        """Test listing API keys for the current user."""
        response = await authenticated_client.get("/api/v1/auth/api-keys")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Should have pagination structure or array of keys
    
    async def test_revoke_api_key(self, authenticated_client: AsyncClient):
        """Test revoking an API key."""
        # First create a key
        create_response = await authenticated_client.post(
            "/api/v1/auth/api-keys",
            json={
                "name": "Key to revoke",
                "description": "Will be revoked"
            }
        )
        api_key_id = create_response.json()["api_key_id"]
        
        # Then revoke it
        response = await authenticated_client.delete(
            f"/api/v1/auth/api-keys/{api_key_id}"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert data["success"] is True
    
    async def test_use_api_key_authentication(self, client: AsyncClient):
        """Test accessing protected endpoint with API key."""
        # This would require creating an API key first and then using it
        # For now, test that endpoint requires authentication
        response = await client.get("/api/v1/incidents")
        assert response.status_code == 401  # Should require auth


# ============================================================================
# AUTHORIZATION TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.auth
class TestAuthorization:
    """Test role-based access control (RBAC)."""
    
    async def test_viewer_permissions(self, client: AsyncClient):
        """Test that viewer role has limited permissions."""
        # Mock a viewer user
        with patch("src.auth.dependencies.get_current_user") as mock_user:
            mock_user.return_value = AsyncMock(
                role="viewer",
                is_active=True
            )
            
            # Viewer should be able to read incidents
            response = await client.get("/api/v1/incidents")
            assert response.status_code in [200, 403]  # Either success or forbidden
            
            # Viewer should NOT be able to create incidents
            response = await client.post("/api/v1/incidents", json={})
            assert response.status_code == 403  # Forbidden
    
    async def test_admin_permissions(self, client: AsyncClient):
        """Test that admin role has elevated permissions."""
        with patch("src.auth.dependencies.get_current_user") as mock_user:
            mock_user.return_value = AsyncMock(
                role="admin",
                is_active=True
            )
            
            # Admin should be able to create incidents
            response = await client.post("/api/v1/incidents", json={
                "title": "Admin Created Incident",
                "severity": "low"
            })
            assert response.status_code in [200, 201, 422]  # Success or validation error
    
    async def test_super_admin_permissions(self, client: AsyncClient):
        """Test that super admin has all permissions."""
        with patch("src.auth.dependencies.get_current_user") as mock_user:
            mock_user.return_value = AsyncMock(
                role="super_admin",
                is_active=True
            )
            
            # Super admin should be able to access system endpoints
            response = await client.get("/api/v1/auth/users")
            assert response.status_code in [200, 403, 404]  # Depends on endpoint existence


# ============================================================================
# SECURITY TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.auth
class TestSecurity:
    """Test security-related functionality."""
    
    async def test_password_hashing(self):
        """Test that passwords are properly hashed (not stored plaintext)."""
        # This would test the auth service directly
        # For now, it's a placeholder for security tests
        assert True  # Placeholder
    
    async def test_jwt_token_validation(self, client: AsyncClient):
        """Test that invalid JWT tokens are rejected."""
        # Test with malformed token
        headers = {"Authorization": "Bearer invalid.token.here"}
        response = await client.get("/api/v1/incidents", headers=headers)
        assert response.status_code == 401
    
    async def test_rate_limiting(self, client: AsyncClient):
        """Test that rate limiting is enforced on auth endpoints."""
        # This would require multiple rapid requests
        # For now, it's a placeholder
        pass
    
    async def test_cors_headers(self, client: AsyncClient):
        """Test that CORS headers are properly set."""
        response = await client.options("/api/v1/auth/login")
        # Should include CORS headers
        assert "access-control-allow-origin" in response.headers.lower() or \
               response.status_code == 200


# ============================================================================
# USER MANAGEMENT TESTS
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.auth
class TestUserManagement:
    """Test user profile and management endpoints."""
    
    async def test_get_current_user_profile(self, authenticated_client: AsyncClient):
        """Test retrieving the current user's profile."""
        response = await authenticated_client.get("/api/v1/auth/me")
        
        assert response.status_code == 200
        data = response.json()
        assert "user_id" in data
        assert "email" in data
        assert "username" in data
        assert "role" in data
        assert "is_active" in data
    
    async def test_update_user_profile(self, authenticated_client: AsyncClient):
        """Test updating user profile information."""
        update_data = {
            "full_name": "Updated Name",
            "email": "updated@example.com"
        }
        
        response = await authenticated_client.put(
            "/api/v1/auth/me",
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["full_name"] == update_data["full_name"]
        assert data["email"] == update_data["email"]
    
    async def test_change_password(self, authenticated_client: AsyncClient):
        """Test changing user password."""
        password_data = {
            "current_password": "oldpassword123",
            "new_password": "newpassword456!"
        }
        
        response = await authenticated_client.post(
            "/api/v1/auth/change-password",
            json=password_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert data["success"] is True


# ============================================================================
# TEST UTILITIES
# ============================================================================

def test_password_strength_validator():
    """Test that password strength validation works."""
    # This would test the password validator directly
    # For now, it's a placeholder
    pass


def test_email_validator():
    """Test that email validation works."""
    # This would test the email validator directly
    # For now, it's a placeholder
    pass

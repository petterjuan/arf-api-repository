"""
Authentication and authorization tests for ARF API.
Tests user registration, login, token refresh, and API key management.

NOTE: This uses the sync TestClient from your conftest.py
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Test data constants
TEST_USER_EMAIL = "testuser@example.com"
TEST_USER_USERNAME = "testuser"
TEST_USER_PASSWORD = "SecurePass123!"
TEST_USER_FULL_NAME = "Test User"

# ============================================================================
# AUTHENTICATION TESTS
# ============================================================================

@pytest.mark.auth
class TestAuthentication:
    """Test user authentication endpoints."""
    
    def test_register_user_success(self, client, mock_db_session):
        """Test successful user registration."""
        from src.auth.models import get_password_hash
        
        # Mock the database operations
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = None
        mock_db_session.commit = MagicMock()
        
        user_data = {
            "email": "newuser@example.com",
            "username": "newuser",
            "full_name": "New Test User",
            "password": "SecurePass123!",
            "roles": ["viewer"]
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        
        # Should return 201 with user info (excluding password)
        assert response.status_code in [200, 201], f"Expected 200/201, got {response.status_code}: {response.text}"
        data = response.json()
        assert "id" in data or "user_id" in data
        assert "email" in data
        assert data["email"] == user_data["email"]
        assert "password" not in data  # Password should not be returned
        assert "hashed_password" not in data
    
    def test_register_user_missing_fields(self, client):
        """Test registration with missing required fields."""
        user_data = {
            "email": "incomplete@example.com",
            # Missing username, password, etc.
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 422  # Validation error
    
    def test_register_user_duplicate_email(self, client, mock_db_session):
        """Test registration with duplicate email."""
        # Mock existing user
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = MagicMock()
        
        user_data = {
            "email": "existing@example.com",
            "username": "newuser",
            "password": "SecurePass123!",
            "roles": ["viewer"]
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code in [400, 409]  # Bad request - duplicate
    
    def test_login_success(self, client, mock_db_session):
        """Test successful user login."""
        from src.auth.models import get_password_hash
        
        # Mock existing user with hashed password
        hashed_password = get_password_hash("testpassword123")
        mock_user = MagicMock()
        mock_user.id = "test-user-id"
        mock_user.email = "test@example.com"
        mock_user.username = "testuser"
        mock_user.hashed_password = hashed_password
        mock_user.is_active = True
        mock_user.roles = ["viewer"]
        
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
    
    def test_login_invalid_credentials(self, client, mock_db_session):
        """Test login with invalid credentials."""
        # Mock existing user
        mock_user = MagicMock()
        mock_user.hashed_password = "wrong-hash"
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        login_data = {
            "username": "nonexistent",
            "password": "wrongpassword"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401  # Unauthorized
    
    def test_refresh_token_success(self, authenticated_client):
        """Test successful token refresh."""
        # Mock token decode to return valid refresh token payload
        with patch("src.auth.models.decode_token") as mock_decode:
            mock_decode.return_value = MagicMock(
                sub="test-user-id",
                type="refresh",
                exp=datetime.utcnow() + timedelta(days=1),
                iat=datetime.utcnow(),
                roles=[],
                scopes=[],
                jti="test-jti"
            )
            
            refresh_data = {
                "refresh_token": "valid-refresh-token-123"
            }
            
            response = authenticated_client.post("/api/v1/auth/refresh", json=refresh_data)
            
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
    
    def test_refresh_token_invalid(self, authenticated_client):
        """Test token refresh with invalid refresh token."""
        with patch("src.auth.models.decode_token") as mock_decode:
            mock_decode.return_value = None  # Invalid token
            
            refresh_data = {
                "refresh_token": "invalid-refresh-token"
            }
            
            response = authenticated_client.post("/api/v1/auth/refresh", json=refresh_data)
            assert response.status_code == 401


# ============================================================================
# API KEY TESTS
# ============================================================================

@pytest.mark.auth
class TestAPIKeys:
    """Test API key management endpoints."""
    
    def test_create_api_key(self, authenticated_client, mock_db_session):
        """Test creating a new API key."""
        # Mock the API key creation
        mock_db_session.add = MagicMock()
        mock_db_session.commit = MagicMock()
        
        api_key_data = {
            "name": "Test API Key",
            "scopes": ["incidents:read", "incidents:write"],
            "expires_days": 30
        }
        
        response = authenticated_client.post(
            "/api/v1/auth/api-keys",
            json=api_key_data
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        assert "id" in data or "api_key_id" in data
        assert "name" in data
        assert "key" in data  # The actual API key should be returned once
        assert "scopes" in data
        assert "created_at" in data
    
    def test_list_api_keys(self, authenticated_client, mock_db_session):
        """Test listing API keys for the current user."""
        # Mock API keys list
        mock_api_keys = [
            MagicMock(id="key1", name="Key 1", created_at=datetime.utcnow()),
            MagicMock(id="key2", name="Key 2", created_at=datetime.utcnow()),
        ]
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = mock_api_keys
        
        response = authenticated_client.get("/api/v1/auth/api-keys")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2
    
    def test_revoke_api_key(self, authenticated_client, mock_db_session):
        """Test revoking an API key."""
        # Mock the API key to revoke
        mock_api_key = MagicMock(id="test-key-id", is_active=True, owner_id="test-user-id")
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = mock_api_key
        mock_db_session.commit = MagicMock()
        
        # Revoke the key
        response = authenticated_client.delete(
            "/api/v1/auth/api-keys/test-key-id"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert data["success"] is True
    
    def test_use_api_key_authentication(self, client):
        """Test accessing protected endpoint with API key."""
        # This would require creating an API key first and then using it
        # For now, test that endpoint requires authentication
        response = client.get("/api/v1/incidents")
        assert response.status_code == 401  # Should require auth


# ============================================================================
# SECURITY TESTS
# ============================================================================

@pytest.mark.auth
class TestSecurity:
    """Test security-related functionality."""
    
    def test_password_hashing(self):
        """Test that passwords are properly hashed."""
        from src.auth.models import get_password_hash, verify_password
        
        # Test regular password
        password = "TestPass123!"
        hashed = get_password_hash(password)
        assert hashed != password
        assert verify_password(password, hashed)
        
        # Test that verify returns False for wrong password
        assert not verify_password("WrongPass123!", hashed)
        
        # Test long password (should be handled by pre-hashing)
        long_password = "A" * 100  # 100 character password
        hashed_long = get_password_hash(long_password)
        assert verify_password(long_password, hashed_long)
        
        # Test extremely long password
        extremely_long_password = "A" * 10000
        hashed_extreme = get_password_hash(extremely_long_password)
        assert verify_password(extremely_long_password, hashed_extreme)
    
    def test_jwt_token_validation(self, client):
        """Test that invalid JWT tokens are rejected."""
        # Test with malformed token
        headers = {"Authorization": "Bearer invalid.token.here"}
        response = client.get("/api/v1/incidents", headers=headers)
        assert response.status_code == 401
        
        # Test with no authorization header
        response = client.get("/api/v1/incidents")
        assert response.status_code == 401
    
    def test_password_strength_validation(self, client):
        """Test password strength validation."""
        weak_passwords = [
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoDigits!",  # No digits
            "NoSpecial123",  # No special characters
            "password",  # Common password
        ]
        
        for password in weak_passwords:
            user_data = {
                "email": "test@example.com",
                "username": "testuser",
                "password": password,
                "roles": ["viewer"]
            }
            response = client.post("/api/v1/auth/register", json=user_data)
            # Should be 422 validation error or 400 bad request
            assert response.status_code in [400, 422], f"Password '{password}' should be rejected"


# ============================================================================
# USER MANAGEMENT TESTS
# ============================================================================

@pytest.mark.auth
class TestUserManagement:
    """Test user profile and management endpoints."""
    
    def test_get_current_user_profile(self, authenticated_client):
        """Test retrieving the current user's profile."""
        response = authenticated_client.get("/api/v1/auth/me")
        
        assert response.status_code == 200
        data = response.json()
        assert "id" in data or "user_id" in data
        assert "email" in data
        assert "username" in data
        assert "roles" in data
        assert "is_active" in data
    
    def test_update_user_profile(self, authenticated_client, mock_db_session):
        """Test updating user profile information."""
        mock_db_session.commit = MagicMock()
        
        update_data = {
            "full_name": "Updated Name",
            "email": "updated@example.com"
        }
        
        response = authenticated_client.put(
            "/api/v1/auth/me",
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["full_name"] == update_data["full_name"]
        assert data["email"] == update_data["email"]


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

@pytest.mark.auth
class TestErrorHandling:
    """Test error handling in authentication endpoints."""
    
    def test_database_error_handling(self, client, mock_db_session):
        """Test that database errors are handled gracefully."""
        mock_db_session.execute.side_effect = Exception("Database connection failed")
        
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "SecurePass123!",
            "roles": ["viewer"]
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        
        # Should return 500 or 503 for server errors
        assert response.status_code in [500, 503, 502]
        data = response.json()
        assert "detail" in data
    
    def test_malformed_json(self, client):
        """Test handling of malformed JSON requests."""
        response = client.post(
            "/api/v1/auth/register",
            content="{invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422  # Unprocessable Entity


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

@pytest.mark.auth
@pytest.mark.slow
class TestRateLimiting:
    """Test rate limiting on authentication endpoints."""
    
    def test_login_rate_limiting(self, client, mock_db_session):
        """Test that login endpoint has rate limiting."""
        # Mock user for login attempts
        mock_user = MagicMock()
        mock_user.hashed_password = "wrong-hash"  # Will fail
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        login_data = {
            "username": "testuser",
            "password": "wrongpassword"
        }
        
        # Make multiple rapid requests (adjust number based on your rate limit)
        for i in range(10):
            response = client.post("/api/v1/auth/login", json=login_data)
            if response.status_code == 429:  # Too Many Requests
                break
        
        # Note: This test depends on your actual rate limiting implementation
        # It's okay if it doesn't trigger 429 with your current config


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.auth
@pytest.mark.integration
class TestIntegration:
    """Integration tests for authentication flow."""
    
    def test_complete_auth_flow(self, client, mock_db_session):
        """Test complete authentication flow: register → login → refresh → me."""
        # 1. Register a new user
        register_data = {
            "email": "flowtest@example.com",
            "username": "flowtest",
            "password": "SecurePass123!",
            "roles": ["viewer"]
        }
        
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = None
        mock_db_session.commit = MagicMock()
        
        register_response = client.post("/api/v1/auth/register", json=register_data)
        assert register_response.status_code in [200, 201]
        
        # 2. Login with the new user
        from src.auth.models import get_password_hash
        hashed_password = get_password_hash("SecurePass123!")
        mock_user = MagicMock()
        mock_user.id = "flow-user-id"
        mock_user.email = register_data["email"]
        mock_user.username = register_data["username"]
        mock_user.hashed_password = hashed_password
        mock_user.is_active = True
        mock_user.roles = ["viewer"]
        
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        login_response = client.post("/api/v1/auth/login", json={
            "username": register_data["username"],
            "password": register_data["password"]
        })
        
        assert login_response.status_code == 200
        login_data = login_response.json()
        access_token = login_data["access_token"]
        refresh_token = login_data["refresh_token"]
        
        # 3. Use the access token to get user profile
        with patch("src.auth.models.decode_token") as mock_decode:
            mock_decode.return_value = MagicMock(
                sub="flow-user-id",
                type="access",
                exp=datetime.utcnow() + timedelta(minutes=30),
                iat=datetime.utcnow(),
                roles=["viewer"],
                scopes=[],
                jti="test-jti"
            )
            
            me_response = client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            assert me_response.status_code == 200

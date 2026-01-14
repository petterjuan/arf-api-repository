"""
Authentication and authorization tests for ARF API.
Tests user registration, login, token refresh, and API key management.

NOTE: This uses the sync TestClient from your conftest.py
"""

import pytest
import json
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession

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
    
    def test_register_user_success(self, client, db_session):
        """Test successful user registration."""
        # Mock database session dependency
        with patch('src.database.postgres_client.get_db') as mock_get_db:
            mock_get_db.return_value = db_session
            
            user_data = {
                "email": "newuser@example.com",
                "username": "newuser",
                "full_name": "New Test User",
                "password": "SecurePass123!",
                "password_confirm": "SecurePass123!",
                "roles": ["viewer"]
            }
            
            response = client.post("/api/v1/auth/register", json=user_data)
            
            # Should return 201 with user info (excluding password)
            assert response.status_code in [200, 201], (
                f"Expected 200/201, got {response.status_code}: {response.text}"
            )
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
    
    def test_register_user_password_mismatch(self, client):
        """Test registration with mismatched passwords."""
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "Password123!",
            "password_confirm": "DifferentPassword123!",
            "roles": ["viewer"]
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 422
        data = response.json()
        assert "detail" in str(data).lower() or "password" in str(data).lower()
    
    def test_register_user_weak_password(self, client):
        """Test registration with weak password."""
        weak_passwords = [
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoDigits!",  # No digits
            "NoSpecial123",  # No special characters
            "password",  # Common password
            "12345678",  # Common numeric
            "aaaabbbbcccc",  # Sequential letters
            "111222333",  # Sequential numbers
        ]
        
        for password in weak_passwords:
            user_data = {
                "email": f"test_{password}@example.com",
                "username": f"user_{password}",
                "password": password,
                "password_confirm": password,
                "roles": ["viewer"]
            }
            
            response = client.post("/api/v1/auth/register", json=user_data)
            # Should be 422 validation error
            assert response.status_code == 422, f"Password '{password}' should be rejected"
    
    @patch('src.auth.models.get_password_hash')
    def test_login_success(self, mock_get_password_hash, client, db_session):
        """Test successful user login."""
        from src.auth.models import verify_password
        
        # Mock password hash
        mock_hashed_password = "$2b$14$fakehashedpassword1234567890"
        mock_get_password_hash.return_value = mock_hashed_password
        
        # Mock verify_password to return True
        with patch('src.auth.models.verify_password') as mock_verify:
            mock_verify.return_value = True
            
            # Mock database query to return a user
            mock_user = MagicMock()
            mock_user.id = "test-user-id"
            mock_user.email = "test@example.com"
            mock_user.username = "testuser"
            mock_user.hashed_password = mock_hashed_password
            mock_user.is_active = True
            mock_user.roles = ["viewer"]
            mock_user.failed_login_attempts = 0
            mock_user.account_locked_until = None
            
            with patch.object(db_session, 'execute') as mock_execute:
                mock_result = MagicMock()
                mock_result.scalar_one_or_none.return_value = mock_user
                mock_execute.return_value = mock_result
                
                login_data = {
                    "username": "testuser",
                    "password": "testpassword123"
                }
                
                response = client.post("/api/v1/auth/login", json=login_data)
                
                assert response.status_code == 200, (
                    f"Expected 200, got {response.status_code}: {response.text}"
                )
                data = response.json()
                assert "access_token" in data
                assert "refresh_token" in data
                assert "token_type" in data
                assert data["token_type"] == "bearer"
                assert "expires_in" in data
    
    def test_login_invalid_credentials(self, client, db_session):
        """Test login with invalid credentials."""
        # Mock database query to return a user
        mock_user = MagicMock()
        mock_user.hashed_password = "$2b$14$fakehashedpassword1234567890"
        
        with patch.object(db_session, 'execute') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_execute.return_value = mock_result
            
            # Mock verify_password to return False
            with patch('src.auth.models.verify_password') as mock_verify:
                mock_verify.return_value = False
                
                login_data = {
                    "username": "nonexistent",
                    "password": "wrongpassword"
                }
                
                response = client.post("/api/v1/auth/login", json=login_data)
                assert response.status_code == 401  # Unauthorized
    
    def test_login_account_locked(self, client, db_session):
        """Test login with locked account."""
        # Mock database query to return a locked user
        mock_user = MagicMock()
        mock_user.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
        mock_user.failed_login_attempts = 5
        
        with patch.object(db_session, 'execute') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_execute.return_value = mock_result
            
            login_data = {
                "username": "lockeduser",
                "password": "anypassword"
            }
            
            response = client.post("/api/v1/auth/login", json=login_data)
            assert response.status_code == 423  # Locked
    
    def test_refresh_token_success(self, authenticated_client):
        """Test successful token refresh."""
        # Mock token decode to return valid refresh token payload
        with patch("src.auth.models.decode_token") as mock_decode:
            mock_decode.return_value = MagicMock(
                sub="test-user-id",
                type="refresh",
                exp=datetime.utcnow() + timedelta(days=1),
                iat=datetime.utcnow(),
                nbf=datetime.utcnow(),
                roles=[],
                scopes=[],
                jti="test-jti",
                iss="arf-api",
                aud="arf-client"
            )
            
            refresh_data = {
                "refresh_token": "valid-refresh-token-123"
            }
            
            response = authenticated_client.post("/api/v1/auth/refresh", json=refresh_data)
            
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"
    
    def test_refresh_token_invalid(self, authenticated_client):
        """Test token refresh with invalid refresh token."""
        with patch("src.auth.models.decode_token") as mock_decode:
            mock_decode.return_value = None  # Invalid token
            
            refresh_data = {
                "refresh_token": "invalid-refresh-token"
            }
            
            response = authenticated_client.post("/api/v1/auth/refresh", json=refresh_data)
            assert response.status_code == 401
    
    def test_refresh_token_expired(self, authenticated_client):
        """Test token refresh with expired refresh token."""
        with patch("src.auth.models.decode_token") as mock_decode:
            mock_decode.return_value = MagicMock(
                sub="test-user-id",
                type="refresh",
                exp=datetime.utcnow() - timedelta(days=1),  # Expired
                iat=datetime.utcnow() - timedelta(days=8),
                nbf=datetime.utcnow() - timedelta(days=8),
                roles=[],
                scopes=[],
                jti="test-jti"
            )
            
            refresh_data = {
                "refresh_token": "expired-refresh-token"
            }
            
            response = authenticated_client.post("/api/v1/auth/refresh", json=refresh_data)
            assert response.status_code == 401
    
    def test_logout(self, authenticated_client):
        """Test user logout."""
        with patch("src.auth.models.decode_token") as mock_decode:
            mock_decode.return_value = MagicMock(
                sub="test-user-id",
                type="access",
                exp=datetime.utcnow() + timedelta(minutes=30),
                iat=datetime.utcnow(),
                jti="test-jti-to-revoke"
            )
            
            # Mock token revocation
            with patch("src.database.redis_client.redis_client.setex") as mock_redis:
                mock_redis.return_value = AsyncMock(return_value=True)
                
                response = authenticated_client.post("/api/v1/auth/logout")
                assert response.status_code == 200
                data = response.json()
                assert "success" in data
                assert data["success"] is True


# ============================================================================
# API KEY TESTS
# ============================================================================

@pytest.mark.auth
class TestAPIKeys:
    """Test API key management endpoints."""
    
    def test_create_api_key(self, authenticated_client, db_session):
        """Test creating a new API key."""
        with patch.object(db_session, 'add') as mock_add:
            with patch.object(db_session, 'commit') as mock_commit:
                with patch('src.auth.models.generate_api_key') as mock_generate:
                    mock_generate.return_value = "arf_test_api_key_1234567890"
                    
                    api_key_data = {
                        "name": "Test API Key",
                        "description": "For testing purposes",
                        "scopes": ["incidents:read", "incidents:write"],
                        "expires_days": 30
                    }
                    
                    response = authenticated_client.post(
                        "/api/v1/auth/api-keys",
                        json=api_key_data
                    )
                    
                    assert response.status_code == 201, (
                        f"Expected 201, got {response.status_code}: {response.text}"
                    )
                    data = response.json()
                    assert "id" in data
                    assert "name" in data
                    assert "key" in data  # The actual API key should be returned once
                    assert data["key"] == "arf_test_api_key_1234567890"
                    assert "scopes" in data
                    assert "created_at" in data
                    assert "expires_at" in data
    
    def test_list_api_keys(self, authenticated_client, db_session):
        """Test listing API keys for the current user."""
        # Mock API keys list
        mock_api_keys = [
            MagicMock(
                id="key1",
                name="Key 1",
                description="First key",
                created_at=datetime.utcnow(),
                last_used=None,
                is_active=True,
                key_prefix="arf_abcd"
            ),
            MagicMock(
                id="key2",
                name="Key 2",
                description="Second key",
                created_at=datetime.utcnow(),
                last_used=datetime.utcnow(),
                is_active=True,
                key_prefix="arf_efgh"
            ),
        ]
        
        with patch.object(db_session, 'execute') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = mock_api_keys
            mock_execute.return_value = mock_result
            
            response = authenticated_client.get("/api/v1/auth/api-keys")
            
            assert response.status_code == 200
            data = response.json()
            assert isinstance(data, list)
            assert len(data) == 2
            assert data[0]["name"] == "Key 1"
            assert data[1]["name"] == "Key 2"
            # Should NOT include full key in list
            assert "key" not in data[0]
            assert "key" not in data[1]
    
    def test_revoke_api_key(self, authenticated_client, db_session):
        """Test revoking an API key."""
        # Mock the API key to revoke
        mock_api_key = MagicMock(
            id="test-key-id",
            name="Test Key",
            is_active=True,
            owner_id="test-user-id",
            revoked_at=None
        )
        
        with patch.object(db_session, 'execute') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_api_key
            mock_execute.return_value = mock_result
            
            with patch.object(db_session, 'commit') as mock_commit:
                # Revoke the key
                response = authenticated_client.delete(
                    "/api/v1/auth/api-keys/test-key-id"
                )
                
                assert response.status_code == 200
                data = response.json()
                assert "success" in data
                assert data["success"] is True
    
    def test_revoke_nonexistent_api_key(self, authenticated_client, db_session):
        """Test revoking a non-existent API key."""
        with patch.object(db_session, 'execute') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_execute.return_value = mock_result
            
            response = authenticated_client.delete(
                "/api/v1/auth/api-keys/nonexistent-key-id"
            )
            
            assert response.status_code == 404
    
    def test_api_key_authentication(self, client):
        """Test accessing protected endpoint with API key."""
        # Test that endpoint requires authentication
        response = client.get("/api/v1/incidents")
        assert response.status_code == 401  # Should require auth
        
        # Test with invalid API key
        headers = {"X-API-Key": "invalid-api-key"}
        response = client.get("/api/v1/incidents", headers=headers)
        assert response.status_code == 401
        
        # Test with valid API key (mock)
        with patch('src.auth.dependencies.verify_api_key') as mock_verify:
            mock_verify.return_value = True
            with patch('src.auth.dependencies.get_user_by_api_key') as mock_get_user:
                mock_get_user.return_value = MagicMock(
                    id="api-user-id",
                    email="api@example.com",
                    roles=["operator"],
                    is_active=True
                )
                
                headers = {"X-API-Key": "valid-api-key"}
                response = client.get("/api/v1/incidents", headers=headers)
                # Should succeed or at least not be 401
                assert response.status_code != 401


# ============================================================================
# SECURITY TESTS
# ============================================================================

@pytest.mark.auth
class TestSecurity:
    """Test security-related functionality."""
    
    def test_password_hashing(self):
        """Test that passwords are properly hashed and verified."""
        from src.auth.models import get_password_hash, verify_password
        
        # Test regular password
        password = "TestPass123!"
        hashed = get_password_hash(password)
        
        # Verify hash is different from plain text
        assert hashed != password
        assert hashed.startswith("$2b$")  # Should be bcrypt
        
        # Verify correct password works
        assert verify_password(password, hashed)
        
        # Verify wrong password fails
        assert not verify_password("WrongPass123!", hashed)
        
        # Test long password (should be handled by pre-hashing)
        long_password = "A" * 100  # 100 character password
        hashed_long = get_password_hash(long_password)
        assert verify_password(long_password, hashed_long)
        
        # Test extremely long password
        extremely_long_password = "A" * 10000
        hashed_extreme = get_password_hash(extremely_long_password)
        assert verify_password(extremely_long_password, hashed_extreme)
        
        # Test that same password produces different hashes (salting works)
        hashed2 = get_password_hash(password)
        assert hashed != hashed2
    
    def test_jwt_token_creation_and_validation(self):
        """Test JWT token creation and validation."""
        from src.auth.models import create_access_token, decode_token
        
        # Create a token
        user_data = {
            "sub": "test-user-id",
            "roles": ["admin"],
            "scopes": ["read", "write"]
        }
        
        token = create_access_token(user_data)
        assert token is not None
        assert len(token.split('.')) == 3  # JWT has 3 parts
        
        # Decode and validate the token
        payload = decode_token(token)
        assert payload is not None
        assert payload.sub == "test-user-id"
        assert payload.type.value == "access"
        assert "admin" in [role.value for role in payload.roles]
        assert "jti" in payload.dict()
    
    def test_invalid_jwt_tokens(self):
        """Test that invalid JWT tokens are rejected."""
        from src.auth.models import decode_token
        
        # Test with malformed token
        assert decode_token("invalid.token.here") is None
        
        # Test with empty token
        assert decode_token("") is None
        
        # Test with wrong algorithm token
        import jwt as pyjwt
        wrong_algo_token = pyjwt.encode(
            {"sub": "test", "exp": datetime.utcnow() + timedelta(hours=1)},
            "wrong-secret",
            algorithm="HS512"
        )
        assert decode_token(wrong_algo_token) is None
    
    def test_api_key_generation(self):
        """Test API key generation and verification."""
        from src.auth.models import generate_api_key, hash_api_key, verify_api_key
        
        # Generate API key
        api_key = generate_api_key()
        assert api_key.startswith("arf_")
        assert len(api_key) > 20
        
        # Hash the API key
        hashed_key = hash_api_key(api_key)
        assert len(hashed_key) == 64  # SHA-256 hex digest
        
        # Verify the API key
        assert verify_api_key(api_key, hashed_key)
        
        # Verify wrong API key fails
        assert not verify_api_key("wrong_key", hashed_key)
        
        # Test constant-time comparison (can't test directly, but verify function works)
        assert verify_api_key(api_key, hashed_key) is True
        assert verify_api_key(api_key + "x", hashed_key) is False


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
        # Should NOT include sensitive data
        assert "hashed_password" not in data
        assert "password" not in data
        assert "mfa_secret" not in data
    
    def test_update_user_profile(self, authenticated_client, db_session):
        """Test updating user profile information."""
        with patch.object(db_session, 'commit'):
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
    
    def test_change_password(self, authenticated_client, db_session):
        """Test changing user password."""
        with patch('src.auth.models.verify_password') as mock_verify:
            mock_verify.return_value = True
            
            with patch('src.auth.models.get_password_hash') as mock_hash:
                mock_hash.return_value = "$2b$14$newhashedpassword1234567890"
                
                with patch.object(db_session, 'commit'):
                    password_data = {
                        "current_password": "oldpassword123",
                        "new_password": "NewSecurePass123!",
                        "new_password_confirm": "NewSecurePass123!"
                    }
                    
                    response = authenticated_client.post(
                        "/api/v1/auth/change-password",
                        json=password_data
                    )
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert "success" in data
                    assert data["success"] is True
    
    def test_change_password_wrong_current(self, authenticated_client, db_session):
        """Test changing password with wrong current password."""
        with patch('src.auth.models.verify_password') as mock_verify:
            mock_verify.return_value = False
            
            password_data = {
                "current_password": "wrongpassword",
                "new_password": "NewSecurePass123!",
                "new_password_confirm": "NewSecurePass123!"
            }
            
            response = authenticated_client.post(
                "/api/v1/auth/change-password",
                json=password_data
            )
            
            assert response.status_code == 400


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

@pytest.mark.auth
class TestErrorHandling:
    """Test error handling in authentication endpoints."""
    
    def test_database_error_handling(self, client, db_session):
        """Test that database errors are handled gracefully."""
        with patch.object(db_session, 'execute') as mock_execute:
            mock_execute.side_effect = Exception("Database connection failed")
            
            user_data = {
                "email": "test@example.com",
                "username": "testuser",
                "password": "SecurePass123!",
                "password_confirm": "SecurePass123!",
                "roles": ["viewer"]
            }
            
            response = client.post("/api/v1/auth/register", json=user_data)
            
            # Should return 500 for server errors
            assert response.status_code == 500
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
    
    def test_invalid_content_type(self, client):
        """Test handling of invalid content type."""
        response = client.post(
            "/api/v1/auth/register",
            data="email=test@example.com",
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        # Should be 422 or 415 depending on FastAPI configuration
        assert response.status_code in [415, 422, 400]


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

@pytest.mark.auth
@pytest.mark.slow
@pytest.mark.integration
class TestRateLimiting:
    """Test rate limiting on authentication endpoints."""
    
    def test_login_rate_limiting(self, client, db_session):
        """Test that login endpoint has rate limiting."""
        # This is a basic test - actual rate limiting depends on your setup
        # Mock user for login attempts
        mock_user = MagicMock()
        mock_user.hashed_password = "$2b$14$fakehash"
        mock_user.is_active = True
        mock_user.failed_login_attempts = 0
        mock_user.account_locked_until = None
        
        with patch.object(db_session, 'execute') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_execute.return_value = mock_result
            
            # Mock verify_password to always fail
            with patch('src.auth.models.verify_password') as mock_verify:
                mock_verify.return_value = False
                
                login_data = {
                    "username": "testuser",
                    "password": "wrongpassword"
                }
                
                # Make multiple requests
                for i in range(5):
                    response = client.post("/api/v1/auth/login", json=login_data)
                    # All should fail with 401 (unless rate limited)
                    assert response.status_code in [401, 429]
    
    def test_register_rate_limiting(self, client, db_session):
        """Test that register endpoint has rate limiting."""
        # Mock empty database response
        with patch.object(db_session, 'execute') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_execute.return_value = mock_result
            
            user_data = {
                "email": "test@example.com",
                "username": "testuser",
                "password": "SecurePass123!",
                "password_confirm": "SecurePass123!",
                "roles": ["viewer"]
            }
            
            # Make multiple requests
            responses = []
            for i in range(10):
                response = client.post("/api/v1/auth/register", json=user_data)
                responses.append(response.status_code)
            
            # At least some should succeed (or fail with validation)
            # But we shouldn't get server errors from rate limiting in this test setup
            assert all(status != 500 for status in responses)


# ============================================================================
# COMPREHENSIVE AUTH FLOW TEST
# ============================================================================

@pytest.mark.auth
@pytest.mark.integration
class TestCompleteAuthFlow:
    """Test complete authentication flow."""
    
    def test_complete_auth_flow(self, client, db_session):
        """Test register → login → profile → refresh → logout flow."""
        # Mock database operations
        with patch.object(db_session, 'execute') as mock_execute:
            with patch.object(db_session, 'add') as mock_add:
                with patch.object(db_session, 'commit') as mock_commit:
                    # 1. Register a new user
                    register_data = {
                        "email": "flowtest@example.com",
                        "username": "flowtest",
                        "full_name": "Flow Test User",
                        "password": "SecureFlowPass123!",
                        "password_confirm": "SecureFlowPass123!",
                        "roles": ["viewer"]
                    }
                    
                    # First call returns None (user doesn't exist), second returns mock user
                    mock_execute.return_value.scalar_one_or_none.side_effect = [
                        None,  # For duplicate check
                        MagicMock(  # For login
                            id="flow-user-id",
                            email=register_data["email"],
                            username=register_data["username"],
                            hashed_password="$2b$14$fakehash",
                            is_active=True,
                            roles=["viewer"],
                            failed_login_attempts=0,
                            account_locked_until=None
                        )
                    ]
                    
                    register_response = client.post("/api/v1/auth/register", json=register_data)
                    assert register_response.status_code in [200, 201]
                    
                    # 2. Login with the new user
                    with patch('src.auth.models.verify_password') as mock_verify:
                        mock_verify.return_value = True
                        
                        login_response = client.post("/api/v1/auth/login", json={
                            "username": register_data["username"],
                            "password": register_data["password"]
                        })
                        
                        assert login_response.status_code == 200
                        login_data = login_response.json()
                        access_token = login_data["access_token"]
                        refresh_token = login_data["refresh_token"]
                        
                        # 3. Get user profile with access token
                        with patch('src.auth.models.decode_token') as mock_decode:
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
                            
                            # 4. Refresh token
                            mock_decode.return_value = MagicMock(
                                sub="flow-user-id",
                                type="refresh",
                                exp=datetime.utcnow() + timedelta(days=1),
                                iat=datetime.utcnow(),
                                roles=["viewer"],
                                scopes=[],
                                jti="refresh-jti"
                            )
                            
                            refresh_response = client.post("/api/v1/auth/refresh", json={
                                "refresh_token": refresh_token
                            })
                            assert refresh_response.status_code == 200
                            
                            # 5. Logout
                            logout_response = client.post(
                                "/api/v1/auth/logout",
                                headers={"Authorization": f"Bearer {access_token}"}
                            )
                            assert logout_response.status_code == 200

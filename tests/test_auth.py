"""
Authentication and authorization tests for ARF API.
Tests user registration, login, token refresh, and API key management.
"""

import pytest
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock, MagicMock
import asyncio

# Mark all tests in this module as async
pytestmark = pytest.mark.asyncio

# Test data constants
TEST_USER_EMAIL = "testuser@example.com"
TEST_USER_USERNAME = "testuser"
TEST_USER_PASSWORD = "SecurePass123!"
TEST_USER_FULL_NAME = "Test User"

# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
async def client():
    """Create a test client."""
    # Import your FastAPI app
    from src.main import app
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
async def authenticated_client():
    """Create an authenticated test client."""
    from src.main import app
    # Mock authentication for tests that require it
    with patch("src.auth.dependencies.get_current_user") as mock_auth:
        mock_auth.return_value = MagicMock(
            id="test-user-id",
            email=TEST_USER_EMAIL,
            username=TEST_USER_USERNAME,
            roles=["viewer"],
            is_active=True
        )
        async with AsyncClient(app=app, base_url="http://test") as client:
            yield client


@pytest.fixture
def mock_db_session():
    """Mock database session."""
    with patch("src.database.get_db") as mock_get_db:
        mock_session = MagicMock()
        mock_get_db.return_value = mock_session
        yield mock_session


# ============================================================================
# AUTHENTICATION TESTS
# ============================================================================

@pytest.mark.auth
class TestAuthentication:
    """Test user authentication endpoints."""
    
    async def test_register_user_success(self, client: AsyncClient, mock_db_session):
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
        
        response = await client.post("/api/v1/auth/register", json=user_data)
        
        # Should return 201 with user info (excluding password)
        assert response.status_code == 201, f"Expected 201, got {response.status_code}: {response.text}"
        data = response.json()
        assert "id" in data or "user_id" in data
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
    
    async def test_register_user_duplicate_email(self, client: AsyncClient, mock_db_session):
        """Test registration with duplicate email."""
        # Mock existing user
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = MagicMock()
        
        user_data = {
            "email": "existing@example.com",
            "username": "newuser",
            "password": "SecurePass123!",
            "roles": ["viewer"]
        }
        
        response = await client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 400  # Bad request - duplicate
    
    async def test_login_success(self, client: AsyncClient, mock_db_session):
        """Test successful user login."""
        from src.auth.models import get_password_hash, verify_password
        
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
        
        response = await client.post("/api/v1/auth/login", json=login_data)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
    
    async def test_login_invalid_credentials(self, client: AsyncClient, mock_db_session):
        """Test login with invalid credentials."""
        # Mock existing user
        mock_user = MagicMock()
        mock_user.hashed_password = "wrong-hash"
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        login_data = {
            "username": "nonexistent",
            "password": "wrongpassword"
        }
        
        response = await client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401  # Unauthorized
    
    async def test_refresh_token_success(self, authenticated_client: AsyncClient):
        """Test successful token refresh."""
        # Mock token decode to return valid refresh token payload
        with patch("src.auth.models.decode_token") as mock_decode:
            mock_decode.return_value = MagicMock(
                sub="test-user-id",
                type="refresh",
                exp=datetime.utcnow() + timedelta(days=1)
            )
            
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
        with patch("src.auth.models.decode_token") as mock_decode:
            mock_decode.return_value = None  # Invalid token
            
            refresh_data = {
                "refresh_token": "invalid-refresh-token"
            }
            
            response = await authenticated_client.post("/api/v1/auth/refresh", json=refresh_data)
            assert response.status_code == 401


# ============================================================================
# API KEY TESTS
# ============================================================================

@pytest.mark.auth
class TestAPIKeys:
    """Test API key management endpoints."""
    
    async def test_create_api_key(self, authenticated_client: AsyncClient, mock_db_session):
        """Test creating a new API key."""
        # Mock the API key creation
        mock_db_session.add = MagicMock()
        mock_db_session.commit = MagicMock()
        
        api_key_data = {
            "name": "Test API Key",
            "scopes": ["incidents:read", "incidents:write"],
            "expires_days": 30
        }
        
        response = await authenticated_client.post(
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
    
    async def test_list_api_keys(self, authenticated_client: AsyncClient, mock_db_session):
        """Test listing API keys for the current user."""
        # Mock API keys list
        mock_api_keys = [
            MagicMock(id="key1", name="Key 1", created_at=datetime.utcnow()),
            MagicMock(id="key2", name="Key 2", created_at=datetime.utcnow()),
        ]
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = mock_api_keys
        
        response = await authenticated_client.get("/api/v1/auth/api-keys")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2
    
    async def test_revoke_api_key(self, authenticated_client: AsyncClient, mock_db_session):
        """Test revoking an API key."""
        # Mock the API key to revoke
        mock_api_key = MagicMock(id="test-key-id", is_active=True, owner_id="test-user-id")
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = mock_api_key
        mock_db_session.commit = MagicMock()
        
        # Revoke the key
        response = await authenticated_client.delete(
            f"/api/v1/auth/api-keys/test-key-id"
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
# SECURITY TESTS
# ============================================================================

@pytest.mark.auth
class TestSecurity:
    """Test security-related functionality."""
    
    async def test_password_hashing(self):
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
    
    async def test_jwt_token_validation(self, client: AsyncClient):
        """Test that invalid JWT tokens are rejected."""
        # Test with malformed token
        headers = {"Authorization": "Bearer invalid.token.here"}
        response = await client.get("/api/v1/incidents", headers=headers)
        assert response.status_code == 401
        
        # Test with expired token
        from src.auth.models import create_access_token
        import jwt
        
        expired_token = jwt.encode(
            {"sub": "test", "exp": datetime.utcnow() - timedelta(hours=1)},
            "wrong-secret",
            algorithm="HS256"
        )
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = await client.get("/api/v1/incidents", headers=headers)
        assert response.status_code == 401
    
    async def test_password_strength_validation(self, client: AsyncClient):
        """Test password strength validation."""
        weak_passwords = [
            "short",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoDigits!",  # No digits
            "NoSpecial123",  # No special characters
        ]
        
        for password in weak_passwords:
            user_data = {
                "email": "test@example.com",
                "username": "testuser",
                "password": password,
                "roles": ["viewer"]
            }
            response = await client.post("/api/v1/auth/register", json=user_data)
            # Should be 422 validation error or 400 bad request
            assert response.status_code in [400, 422], f"Password '{password}' should be rejected"


# ============================================================================
# USER MANAGEMENT TESTS
# ============================================================================

@pytest.mark.auth
class TestUserManagement:
    """Test user profile and management endpoints."""
    
    async def test_get_current_user_profile(self, authenticated_client: AsyncClient):
        """Test retrieving the current user's profile."""
        response = await authenticated_client.get("/api/v1/auth/me")
        
        assert response.status_code == 200
        data = response.json()
        assert "id" in data or "user_id" in data
        assert "email" in data
        assert "username" in data
        assert "roles" in data
        assert "is_active" in data
    
    async def test_update_user_profile(self, authenticated_client: AsyncClient, mock_db_session):
        """Test updating user profile information."""
        mock_db_session.commit = MagicMock()
        
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


# ============================================================================
# CONCURRENCY TESTS
# ============================================================================

@pytest.mark.auth
@pytest.mark.stress
class TestConcurrency:
    """Test authentication under concurrent load."""
    
    async def test_concurrent_logins(self, client: AsyncClient, mock_db_session):
        """Test multiple concurrent login attempts."""
        # Mock user for all concurrent requests
        from src.auth.models import get_password_hash
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
        
        # Make multiple concurrent requests
        num_requests = 10
        tasks = [
            client.post("/api/v1/auth/login", json=login_data)
            for _ in range(num_requests)
        ]
        
        responses = await asyncio.gather(*tasks)
        
        # All should succeed
        for response in responses:
            assert response.status_code == 200
            assert "access_token" in response.json()


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

@pytest.mark.auth
class TestErrorHandling:
    """Test error handling in authentication endpoints."""
    
    async def test_database_error_handling(self, client: AsyncClient, mock_db_session):
        """Test that database errors are handled gracefully."""
        mock_db_session.execute.side_effect = Exception("Database connection failed")
        
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "SecurePass123!",
            "roles": ["viewer"]
        }
        
        response = await client.post("/api/v1/auth/register", json=user_data)
        
        # Should return 500 or 503 for server errors
        assert response.status_code in [500, 503, 502]
        data = response.json()
        assert "detail" in data
    
    async def test_malformed_json(self, client: AsyncClient):
        """Test handling of malformed JSON requests."""
        response = await client.post(
            "/api/v1/auth/register",
            content="{invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422  # Unprocessable Entity

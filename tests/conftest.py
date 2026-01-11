"""
Test configuration and fixtures for ARF API tests.
This file is automatically discovered by pytest and provides fixtures to all tests.
"""

import asyncio
from typing import AsyncGenerator, Generator, Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from src.database.database import Base, get_db
from src.auth.dependencies import get_current_user
from src.auth.models import User, UserRole
from src.main import app

# ============================================================================
# TEST DATABASE CONFIGURATION
# ============================================================================

TEST_DATABASE_URL = "postgresql+asyncpg://test:test@localhost:5432/arf_test"
TEST_REDIS_URL = "redis://localhost:6379/1"
TEST_NEO4J_URL = "bolt://localhost:7687"

# Create test engine and session
test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestingSessionLocal = sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


# ============================================================================
# DATABASE FIXTURES
# ============================================================================

@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function", autouse=True)
async def setup_test_database() -> AsyncGenerator[None, None]:
    """Set up and tear down test database for each test."""
    # Create all tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield
    
    # Drop all tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh database session for a test."""
    async with TestingSessionLocal() as session:
        yield session


@pytest.fixture
def override_get_db(db_session: AsyncSession):
    """Override the get_db dependency to use test database."""
    async def _override_get_db():
        try:
            yield db_session
        finally:
            pass
    
    return _override_get_db


# ============================================================================
# APPLICATION CLIENT FIXTURES
# ============================================================================

@pytest.fixture
async def client(override_get_db) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with overridden dependencies."""
    # Override database dependency
    app.dependency_overrides[get_db] = override_get_db
    
    # Override Redis dependency with mock
    with patch("src.database.redis_client.get_redis", return_value=AsyncMock()):
        # Override Neo4j dependency with mock
        with patch("src.database.neo4j_client.get_neo4j_driver", return_value=AsyncMock()):
            async with AsyncClient(app=app, base_url="http://test") as ac:
                yield ac
    
    # Clear overrides
    app.dependency_overrides.clear()


# ============================================================================
# AUTHENTICATION FIXTURES
# ============================================================================

@pytest.fixture
def mock_user() -> User:
    """Create a mock user object."""
    return User(
        id="test-user-123",
        email="test@example.com",
        username="testuser",
        full_name="Test User",
        role=UserRole.ADMIN,
        is_active=True,
        created_at="2024-01-01T00:00:00Z"
    )


@pytest.fixture
def auth_headers(mock_user: User) -> Dict[str, str]:
    """Generate authentication headers for tests."""
    # In a real test, you would generate a valid JWT token
    # For now, we'll mock the authentication dependency
    return {
        "Authorization": "Bearer test-jwt-token",
        "X-API-Key": "test-api-key-123"
    }


@pytest.fixture
def authenticated_client(client: AsyncClient, mock_user: User) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client with authenticated user."""
    # Mock the get_current_user dependency
    async def mock_get_current_user():
        return mock_user
    
    app.dependency_overrides[get_current_user] = mock_get_current_user
    
    yield client
    
    # Clean up
    if get_current_user in app.dependency_overrides:
        del app.dependency_overrides[get_current_user]


# ============================================================================
# SERVICE MOCK FIXTURES
# ============================================================================

@pytest.fixture
def mock_redis() -> AsyncMock:
    """Create a mock Redis client."""
    redis_mock = AsyncMock()
    # Common Redis method mocks
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock(return_value=True)
    redis_mock.delete = AsyncMock(return_value=1)
    redis_mock.exists = AsyncMock(return_value=False)
    redis_mock.expire = AsyncMock(return_value=True)
    return redis_mock


@pytest.fixture
def mock_neo4j() -> AsyncMock:
    """Create a mock Neo4j driver."""
    neo4j_mock = AsyncMock()
    session_mock = AsyncMock()
    transaction_mock = AsyncMock()
    
    # Mock chain: driver.session() -> session.begin_transaction() -> transaction.run()
    transaction_mock.run = AsyncMock(return_value=AsyncMock())
    transaction_mock.commit = AsyncMock()
    transaction_mock.rollback = AsyncMock()
    
    session_mock.begin_transaction = AsyncMock(return_value=transaction_mock)
    session_mock.close = AsyncMock()
    
    neo4j_mock.session = AsyncMock(return_value=session_mock)
    
    return neo4j_mock


@pytest.fixture
def mock_webhook_service() -> AsyncMock:
    """Create a mock webhook service."""
    webhook_mock = AsyncMock()
    webhook_mock.send_notification = AsyncMock(return_value={
        "success": True,
        "message_id": "test-message-123"
    })
    webhook_mock.process_webhook_queue = AsyncMock()
    return webhook_mock


# ============================================================================
# TEST DATA FIXTURES
# ============================================================================

@pytest.fixture
def test_incident_data() -> Dict[str, Any]:
    """Sample incident data for tests."""
    return {
        "title": "Test Incident",
        "description": "This is a test incident for unit testing",
        "severity": "medium",
        "status": "open",
        "component": "api",
        "environment": "test",
        "labels": ["test", "automated"],
        "metadata": {"test": True, "automated": True}
    }


@pytest.fixture
def test_policy_data() -> Dict[str, Any]:
    """Sample policy data for tests."""
    return {
        "name": "Test Policy",
        "description": "Test policy for execution ladder",
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


@pytest.fixture
def test_rollback_data() -> Dict[str, Any]:
    """Sample rollback data for tests."""
    return {
        "name": "Test Rollback",
        "description": "Test rollback operation",
        "target_type": "deployment",
        "target_id": "deploy-123",
        "strategy": "inverse_actions",
        "actions": [
            {
                "type": "api_call",
                "method": "POST",
                "url": "https://api.example.com/rollback",
                "payload": {"rollback": True}
            }
        ]
    }


@pytest.fixture
def test_webhook_data() -> Dict[str, Any]:
    """Sample webhook data for tests."""
    return {
        "name": "Test Webhook",
        "description": "Test webhook for notifications",
        "channel": "slack",
        "url": "https://hooks.slack.com/services/TEST/TEST/TEST",
        "event_types": ["incident_created", "incident_resolved"],
        "config": {
            "channel": "#alerts",
            "username": "ARF Bot",
            "icon_emoji": ":warning:"
        },
        "enabled": True
    }


# ============================================================================
# TEST CONFIGURATION
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test (requires external services)"
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow-running"
    )
    config.addinivalue_line(
        "markers",
        "auth: mark test as authentication-related"
    )
    config.addinivalue_line(
        "markers",
        "database: mark test as database-intensive"
    )


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

async def assert_status_code(response, expected_code: int):
    """Helper to assert HTTP status code with helpful error message."""
    assert response.status_code == expected_code, \
        f"Expected status {expected_code}, got {response.status_code}. Response: {response.text}"


async def assert_response_keys(response, expected_keys: list):
    """Helper to assert response contains expected keys."""
    data = response.json()
    for key in expected_keys:
        assert key in data, f"Key '{key}' not found in response: {data}"

"""
Test configuration and fixtures for ARF API tests - ENHANCED VERSION.
This file provides fixtures and configuration for pytest, ensuring
consistent test behavior and preventing external dependencies.
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import AsyncGenerator, Dict, Any, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import respx
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

# ============================================================================
# IMPORTS WITH PROPER ERROR HANDLING
# ============================================================================

try:
    # Try direct imports first
    from database.postgres_client import Base, get_db
    from auth.dependencies import get_current_user
    from auth.models import UserInDB, UserRole
    from main import app
except ImportError:
    # Fallback for different import scenarios
    import sys
    from pathlib import Path
    
    # Add project root to path
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from src.database.postgres_client import Base, get_db
    from src.auth.dependencies import get_current_user
    from src.auth.models import UserInDB, UserRole
    from src.main import app

# ============================================================================
# TEST CONFIGURATION CONSTANTS
# ============================================================================

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
TEST_USER_ID = "test-user-123"
TEST_API_KEY = "test-api-key-123"
TEST_JWT_TOKEN = "test-jwt-token"

# ============================================================================
# DATABASE ENGINE AND SESSION FACTORY
# ============================================================================

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    poolclass=StaticPool,
    connect_args={"check_same_thread": False},
    future=True,
)

TestingSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# ============================================================================
# EVENT LOOP MANAGEMENT
# ============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """
    Create an event loop for the test session.
    
    Yields:
        asyncio.AbstractEventLoop: Event loop for async tests
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


# ============================================================================
# DATABASE SETUP AND TEARDOWN
# ============================================================================

@pytest.fixture(scope="session", autouse=True)
async def setup_test_database():
    """
    Set up and tear down test database schema.
    
    This runs once per test session to create/drop all tables.
    """
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield
    
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Create a fresh database session for each test.
    
    Yields:
        AsyncSession: Database session with automatic rollback
    """
    async with TestingSessionLocal() as session:
        # Start a nested transaction
        await session.begin_nested()
        
        try:
            yield session
        finally:
            # Always rollback to keep tests isolated
            await session.rollback()
            await session.close()


@pytest.fixture
def override_get_db(db_session: AsyncSession):
    """
    Override the get_db dependency for FastAPI app.
    
    Args:
        db_session: Database session to use
        
    Returns:
        Callable: Dependency override function
    """
    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session
    
    return _override_get_db


# ============================================================================
# HTTP CLIENT FIXTURE WITH COMPREHENSIVE MOCKING
# ============================================================================

@pytest.fixture
async def client(override_get_db) -> AsyncGenerator[AsyncClient, None]:
    """
    Create test HTTP client with all external dependencies mocked.
    
    This prevents external API calls, database connections, and timeouts.
    
    Yields:
        AsyncClient: Test HTTP client with mocked dependencies
    """
    # Store original dependency overrides
    original_overrides = app.dependency_overrides.copy()
    
    # Override database dependency
    app.dependency_overrides[get_db] = override_get_db
    
    # Mock all external services
    mock_patches = {
        "src.database.redis_client.redis_client": AsyncMock(),
        "src.database.neo4j_client.neo4j_driver": AsyncMock(),
        "src.integrations.discord.DiscordIntegration": AsyncMock(),
        "src.integrations.slack_integration.SlackIntegration": AsyncMock(),
        "src.integrations.pagerduty.PagerDutyIntegration": AsyncMock(),
        "src.integrations.opsgenie.OpsgenieIntegration": AsyncMock(),
        "src.integrations.teams.TeamsIntegration": AsyncMock(),
        "src.integrations.email.EmailIntegration": AsyncMock(),
    }
    
    # Apply all patches
    patches = [patch(target, new_callable) for target, new_callable in mock_patches.items()]
    mocks = []
    
    try:
        # Start all patches
        for p in patches:
            mocks.append(p.start())
        
        # Configure Redis mock
        redis_mock = mocks[0]
        _configure_redis_mock(redis_mock)
        
        # Configure Neo4j mock
        neo4j_mock = mocks[1]
        _configure_neo4j_mock(neo4j_mock)
        
        # Configure integration mocks
        for integration_mock in mocks[2:]:
            _configure_integration_mock(integration_mock.return_value)
        
        # Create test client
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            yield test_client
            
    finally:
        # Stop all patches
        for p in patches:
            p.stop()
        
        # Restore original overrides
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)


def _configure_redis_mock(redis_mock: AsyncMock):
    """Configure Redis mock with common method responses."""
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock(return_value=True)
    redis_mock.setex = AsyncMock(return_value=True)
    redis_mock.delete = AsyncMock(return_value=1)
    redis_mock.exists = AsyncMock(return_value=False)
    redis_mock.incr = AsyncMock(return_value=1)
    redis_mock.expire = AsyncMock(return_value=True)
    redis_mock.flushdb = AsyncMock(return_value=True)
    redis_mock.pipeline = AsyncMock(return_value=AsyncMock())


def _configure_neo4j_mock(neo4j_mock: AsyncMock):
    """Configure Neo4j mock with session and transaction mocks."""
    # Create mock transaction
    tx_mock = AsyncMock()
    result_mock = AsyncMock()
    record_mock = MagicMock()
    
    record_mock.values = MagicMock(return_value=["result"])
    result_mock.single = AsyncMock(return_value=record_mock)
    result_mock.data = AsyncMock(return_value=[{"data": "test"}])
    
    tx_mock.run = AsyncMock(return_value=result_mock)
    tx_mock.commit = AsyncMock()
    
    # Create mock session
    session_mock = AsyncMock()
    session_mock.begin_transaction = AsyncMock(return_value=tx_mock)
    session_mock.execute_read = AsyncMock(return_value=result_mock)
    session_mock.execute_write = AsyncMock(return_value=result_mock)
    
    neo4j_mock.session = AsyncMock(return_value=session_mock)


def _configure_integration_mock(integration_mock: AsyncMock):
    """Configure integration service mock."""
    integration_mock.send_message = AsyncMock(
        return_value={"success": True, "message_id": "test-123"}
    )
    integration_mock.is_configured = True


# ============================================================================
# AUTHENTICATION FIXTURES
# ============================================================================

@pytest.fixture
def mock_user() -> UserInDB:
    """
    Create a mock user object for testing.
    
    Returns:
        UserInDB: Mock user with admin privileges
    """
    now = datetime.now()
    
    return UserInDB(
        id=TEST_USER_ID,
        email="test@example.com",
        full_name="Test User",
        is_active=True,
        roles=[UserRole.ADMIN],
        hashed_password="hashed_password_for_testing",
        created_at=now,
        updated_at=now,
        last_login=now,
        api_key=TEST_API_KEY,
        api_key_expires=now + timedelta(days=30),
    )


@pytest.fixture
async def authenticated_client(client: AsyncClient, mock_user: UserInDB):
    """
    Create authenticated test client with mocked user.
    
    Args:
        client: Base test client
        mock_user: Mock user object
        
    Yields:
        AsyncClient: Authenticated test client
    """
    # Mock authentication dependency
    async def mock_get_current_user():
        return mock_user
    
    app.dependency_overrides[get_current_user] = mock_get_current_user
    
    # Add authentication headers
    client.headers.update({
        "Authorization": f"Bearer {TEST_JWT_TOKEN}",
        "X-API-Key": TEST_API_KEY,
    })
    
    yield client
    
    # Clean up
    if get_current_user in app.dependency_overrides:
        del app.dependency_overrides[get_current_user]


# ============================================================================
# SERVICE MOCK FIXTURES
# ============================================================================

@pytest.fixture
def mock_redis_client():
    """
    Create a comprehensive Redis client mock.
    
    Returns:
        AsyncMock: Mock Redis client
    """
    redis_mock = AsyncMock()
    _configure_redis_mock(redis_mock)
    return redis_mock


@pytest.fixture
def mock_neo4j_driver():
    """
    Create a comprehensive Neo4j driver mock.
    
    Returns:
        AsyncMock: Mock Neo4j driver
    """
    neo4j_mock = AsyncMock()
    _configure_neo4j_mock(neo4j_mock)
    return neo4j_mock


@pytest.fixture
def mock_http_client():
    """
    Mock HTTPX client for external API calls.
    
    Yields:
        respx.mock: Mocked HTTP routes
    """
    with respx.mock(
        assert_all_called=False,  # Don't fail if mocks aren't used
        assert_all_mocked=True,   # Fail if unmocked requests are made
    ) as mock:
        # Mock common external endpoints
        mock.post("https://discord.com/api/webhooks/.*").respond(
            200, json={"id": "123"}
        )
        mock.post("https://slack.com/api/chat.postMessage").respond(
            200, json={"ok": True}
        )
        mock.post("https://api.pagerduty.com/.*").respond(202, json={})
        mock.post("https://api.opsgenie.com/v2/alerts").respond(202, json={})
        mock.post("https://outlook.office.com/webhook/.*").respond(200, json={})
        mock.post("https://smtp.example.com/.*").respond(250, json={})
        
        yield mock


# ============================================================================
# INTEGRATION SERVICE MOCKS
# ============================================================================

@pytest.fixture
def mock_discord_integration():
    """Mock Discord integration service."""
    with _mock_integration_service(
        "src.integrations.discord.DiscordIntegration",
        response={"success": True, "message_id": "discord-123"},
    ) as mock:
        yield mock


@pytest.fixture
def mock_slack_integration():
    """Mock Slack integration service."""
    with _mock_integration_service(
        "src.integrations.slack_integration.SlackIntegration",
        response={"ok": True, "ts": "123.456"},
    ) as mock:
        yield mock


@pytest.fixture
def mock_pagerduty_integration():
    """Mock PagerDuty integration service."""
    with _mock_integration_service(
        "src.integrations.pagerduty.PagerDutyIntegration",
        response={"id": "pd-inc-123"},
        method_name="trigger_incident",
    ) as mock:
        yield mock


@pytest.fixture
def mock_opsgenie_integration():
    """Mock OpsGenie integration service."""
    with _mock_integration_service(
        "src.integrations.opsgenie.OpsgenieIntegration",
        response={"alertId": "opsgenie-123"},
        method_name="create_alert",
    ) as mock:
        yield mock


@contextlib.contextmanager
def _mock_integration_service(
    target: str,
    response: Dict[str, Any],
    method_name: str = "send_message",
):
    """
    Context manager to mock an integration service.
    
    Args:
        target: Import path to mock
        response: Response to return from the mocked method
        method_name: Name of the method to mock
        
    Yields:
        AsyncMock: Mocked integration service instance
    """
    with patch(target) as mock_class:
        instance = AsyncMock()
        instance.is_configured = True
        
        # Set the specified method
        getattr(instance, method_name).return_value = response
        
        # Add common methods
        if hasattr(instance, "send_message"):
            instance.send_message.return_value = response
        
        mock_class.return_value = instance
        yield instance


# ============================================================================
# TEST DATA FACTORIES
# ============================================================================

@pytest.fixture
def create_incident_data():
    """
    Factory for creating incident test data.
    
    Returns:
        Callable: Function that creates incident data
    """
    def _create(**kwargs) -> Dict[str, Any]:
        """Create incident test data with defaults."""
        default = {
            "title": "Test Incident",
            "description": "This is a test incident",
            "severity": "medium",
            "status": "open",
            "component": "api",
            "environment": "test",
            "labels": ["test", "unit"],
            "metadata": {"test": True},
            "created_by": TEST_USER_ID,
        }
        default.update(kwargs)
        return default
    
    return _create


@pytest.fixture
def create_rollback_data():
    """
    Factory for creating rollback test data.
    
    Returns:
        Callable: Function that creates rollback data
    """
    def _create(**kwargs) -> Dict[str, Any]:
        """Create rollback test data with defaults."""
        default = {
            "name": "Test Rollback Plan",
            "description": "Rollback for failed deployment",
            "target_type": "deployment",
            "target_id": "deploy-123",
            "strategy": "inverse_actions",
            "actions": [
                {
                    "type": "api_call",
                    "method": "POST",
                    "url": "http://localhost:8080/rollback",
                    "headers": {"Content-Type": "application/json"},
                    "body": {"rollback": True, "reason": "test"},
                }
            ],
            "created_by": TEST_USER_ID,
        }
        default.update(kwargs)
        return default
    
    return _create


@pytest.fixture
def create_webhook_data():
    """
    Factory for creating webhook test data.
    
    Returns:
        Callable: Function that creates webhook data
    """
    def _create(**kwargs) -> Dict[str, Any]:
        """Create webhook test data with defaults."""
        default = {
            "name": "Test Webhook",
            "description": "Test webhook configuration",
            "channel": "slack",
            "url": "https://hooks.slack.com/services/TEST/TEST/TEST",
            "event_types": ["incident.created", "incident.updated"],
            "config": {
                "channel": "#alerts",
                "username": "ARF Bot",
                "icon_emoji": ":warning:",
            },
            "enabled": True,
            "created_by": TEST_USER_ID,
        }
        default.update(kwargs)
        return default
    
    return _create


# ============================================================================
# TEST CONFIGURATION AND HELPERS
# ============================================================================

def pytest_collection_modifyitems(config, items):
    """
    Modify test collection order for better test performance.
    
    Unit tests run first, followed by other tests, then integration tests.
    """
    unit_tests = []
    integration_tests = []
    other_tests = []
    
    for item in items:
        if "integration" in item.keywords:
            integration_tests.append(item)
        elif "unit" in item.keywords:
            unit_tests.append(item)
        else:
            other_tests.append(item)
    
    # Reorder tests for performance
    items[:] = unit_tests + other_tests + integration_tests


@pytest.fixture(autouse=True)
async def cleanup_test_state():
    """
    Clean up test state before and after each test.
    
    This ensures test isolation by clearing app dependencies.
    """
    # Clear dependency overrides before test
    app.dependency_overrides.clear()
    
    yield
    
    # Clear dependency overrides after test
    app.dependency_overrides.clear()


# ============================================================================
# ASSERTION HELPERS
# ============================================================================

async def assert_async_response(
    response: Response,
    expected_status: int = 200,
    expected_keys: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Assert HTTP response status and structure.
    
    Args:
        response: HTTP response to validate
        expected_status: Expected HTTP status code
        expected_keys: Keys expected in response JSON
        
    Returns:
        Optional[Dict]: Response JSON data if validation passes
        
    Raises:
        AssertionError: If response doesn't match expectations
    """
    assert response.status_code == expected_status, (
        f"Expected status {expected_status}, got {response.status_code}. "
        f"Response: {response.text}"
    )
    
    if expected_status == 204:  # No content expected
        return None
    
    data = response.json()
    
    if expected_keys:
        for key in expected_keys:
            assert key in data, f"Missing key '{key}' in response: {data}"
    
    return data


async def assert_exception_raised(
    async_func,
    exception_type,
    match: Optional[str] = None,
):
    """
    Assert that an async function raises a specific exception.
    
    Args:
        async_func: Async function to execute
        exception_type: Expected exception type
        match: Optional regex pattern to match exception message
        
    Returns:
        Exception: The raised exception
        
    Raises:
        AssertionError: If exception is not raised
    """
    with pytest.raises(exception_type, match=match) as exc_info:
        await async_func()
    
    return exc_info.value


@asynccontextmanager
async def mock_async_method(target, return_value=None, side_effect=None):
    """
    Context manager to mock an async method.
    
    Args:
        target: Method to mock
        return_value: Value to return
        side_effect: Side effect function
        
    Yields:
        AsyncMock: The mock object
    """
    mock = AsyncMock()
    if side_effect:
        mock.side_effect = side_effect
    else:
        mock.return_value = return_value
    
    with patch(target, mock):
        yield mock


# ============================================================================
# PYTEST HOOKS
# ============================================================================

def pytest_sessionfinish(session, exitstatus):
    """
    Clean up after test session.
    
    This ensures proper cleanup of database connections.
    """
    loop = asyncio.get_event_loop()
    
    async def cleanup():
        await test_engine.dispose()
    
    loop.run_until_complete(cleanup())


# ============================================================================
# TYPE HINTS FOR BETTER IDE SUPPORT
# ============================================================================

__all__ = [
    # Fixtures
    "client",
    "authenticated_client",
    "db_session",
    "mock_user",
    "mock_redis_client",
    "mock_neo4j_driver",
    "mock_http_client",
    "mock_discord_integration",
    "mock_slack_integration",
    "mock_pagerduty_integration",
    "mock_opsgenie_integration",
    "create_incident_data",
    "create_rollback_data",
    "create_webhook_data",
    
    # Helper functions
    "assert_async_response",
    "assert_exception_raised",
    "mock_async_method",
]

"""
Test configuration and fixtures for ARF API tests - PRECISE AND RELIABLE.
Every mock targets exactly what exists, nothing more, nothing less.
"""

import asyncio
import contextlib
import json
import os
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
# IMPORTS - PRECISE AND PREDICTABLE
# ============================================================================

try:
    from database.postgres_client import Base, get_db
    from auth.dependencies import get_current_user
    from auth.models import UserInDB, UserRole
    from main import app
except ImportError:
    import sys
    from pathlib import Path
    
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from src.database.postgres_client import Base, get_db
    from src.auth.dependencies import get_current_user
    from src.auth.models import UserInDB, UserRole
    from src.main import app

# ============================================================================
# TEST CONSTANTS - NO MAGIC VALUES
# ============================================================================

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
TEST_USER_ID = "test-user-123"
TEST_API_KEY = "test-api-key-123"
TEST_JWT_TOKEN = "test-jwt-token"

# ============================================================================
# DATABASE - ISOLATED AND CONTROLLED
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
# EVENT LOOP - CLEAN AND PREDICTABLE
# ============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """One loop per session, cleanly created and destroyed."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()

# ============================================================================
# DATABASE LIFECYCLE - FRESH STATE EVERY TIME
# ============================================================================

@pytest.fixture(scope="session", autouse=True)
async def setup_test_database():
    """Schema created once, destroyed once - no lingering state."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield
    
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Each test gets its own transactional session with automatic rollback."""
    async with TestingSessionLocal() as session:
        await session.begin_nested()
        
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()

@pytest.fixture
def override_get_db(db_session: AsyncSession):
    """Inject test database into FastAPI dependency system."""
    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session
    
    return _override_get_db

# ============================================================================
# HTTP CLIENT - COMPLETELY MOCKED, ZERO EXTERNAL CALLS
# ============================================================================

@pytest.fixture
async def client(override_get_db) -> AsyncGenerator[AsyncClient, None]:
    """
    Test client that cannot reach the outside world.
    Every external dependency is replaced with predictable mocks.
    """
    original_overrides = app.dependency_overrides.copy()
    app.dependency_overrides[get_db] = override_get_db
    
    # Patch Redis - target exactly what exists
    redis_patch = patch("src.database.redis_client.redis_client", new_callable=AsyncMock)
    redis_mock = redis_patch.start()
    
    # Configure Redis mock
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock(return_value=True)
    redis_mock.setex = AsyncMock(return_value=True)
    redis_mock.delete = AsyncMock(return_value=1)
    redis_mock.exists = AsyncMock(return_value=False)
    redis_mock.incr = AsyncMock(return_value=1)
    redis_mock.expire = AsyncMock(return_value=True)
    redis_mock.flushdb = AsyncMock(return_value=True)
    redis_mock.pipeline = AsyncMock(return_value=AsyncMock())
    
    # Patch Neo4j - using the exact attribute name from neo4j_client.py
    neo4j_patch = patch("src.database.neo4j_client.driver", new_callable=AsyncMock)
    neo4j_mock = neo4j_patch.start()
    
    # Configure Neo4j mock
    tx_mock = AsyncMock()
    result_mock = AsyncMock()
    record_mock = MagicMock()
    
    record_mock.values = MagicMock(return_value=["result"])
    result_mock.single = AsyncMock(return_value=record_mock)
    result_mock.data = AsyncMock(return_value=[{"data": "test"}])
    
    tx_mock.run = AsyncMock(return_value=result_mock)
    tx_mock.commit = AsyncMock()
    
    session_mock = AsyncMock()
    session_mock.begin_transaction = AsyncMock(return_value=tx_mock)
    session_mock.execute_read = AsyncMock(return_value=result_mock)
    session_mock.execute_write = AsyncMock(return_value=result_mock)
    
    neo4j_mock.session = AsyncMock(return_value=session_mock)
    
    # Patch all integration services
    integration_patches = [
        patch("src.integrations.discord.DiscordIntegration"),
        patch("src.integrations.slack_integration.SlackIntegration"),
        patch("src.integrations.pagerduty.PagerDutyIntegration"),
        patch("src.integrations.opsgenie.OpsgenieIntegration"),
        patch("src.integrations.teams.TeamsIntegration"),
        patch("src.integrations.email.EmailIntegration"),
    ]
    
    integration_mocks = []
    for patch_obj in integration_patches:
        mock = patch_obj.start()
        integration_mocks.append((patch_obj, mock))
        
        instance = mock.return_value
        instance.send_message = AsyncMock(
            return_value={"success": True, "message_id": "test-123"}
        )
        instance.is_configured = True
    
    try:
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            yield test_client
    finally:
        # Stop all patches in reverse order
        for patch_obj, _ in reversed(integration_mocks):
            patch_obj.stop()
        
        neo4j_patch.stop()
        redis_patch.stop()
        
        # Restore original dependencies
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)

# ============================================================================
# AUTHENTICATION - PREDICTABLE USERS
# ============================================================================

@pytest.fixture
def mock_user() -> UserInDB:
    """Standard test user - always the same, always predictable."""
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
    """Client that believes it's authenticated as our test user."""
    async def mock_get_current_user():
        return mock_user
    
    app.dependency_overrides[get_current_user] = mock_get_current_user
    
    client.headers.update({
        "Authorization": f"Bearer {TEST_JWT_TOKEN}",
        "X-API-Key": TEST_API_KEY,
    })
    
    yield client
    
    if get_current_user in app.dependency_overrides:
        del app.dependency_overrides[get_current_user]

# ============================================================================
# SERVICE MOCKS - FOR DIRECT USE IN UNIT TESTS
# ============================================================================

@pytest.fixture
def mock_redis():
    """Redis mock for unit tests that need direct Redis access."""
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock(return_value=True)
    redis_mock.setex = AsyncMock(return_value=True)
    redis_mock.delete = AsyncMock(return_value=1)
    redis_mock.exists = AsyncMock(return_value=False)
    redis_mock.incr = AsyncMock(return_value=1)
    redis_mock.expire = AsyncMock(return_value=True)
    redis_mock.flushdb = AsyncMock(return_value=True)
    redis_mock.pipeline = AsyncMock(return_value=AsyncMock())
    return redis_mock

@pytest.fixture
def mock_neo4j():
    """Neo4j driver mock for unit tests."""
    driver_mock = AsyncMock()
    
    tx_mock = AsyncMock()
    result_mock = AsyncMock()
    record_mock = MagicMock()
    
    record_mock.values = MagicMock(return_value=["result"])
    result_mock.single = AsyncMock(return_value=record_mock)
    result_mock.data = AsyncMock(return_value=[{"data": "test"}])
    
    tx_mock.run = AsyncMock(return_value=result_mock)
    tx_mock.commit = AsyncMock()
    
    session_mock = AsyncMock()
    session_mock.begin_transaction = AsyncMock(return_value=tx_mock)
    session_mock.execute_read = AsyncMock(return_value=result_mock)
    session_mock.execute_write = AsyncMock(return_value=result_mock)
    
    driver_mock.session = AsyncMock(return_value=session_mock)
    return driver_mock

@pytest.fixture
def mock_http():
    """HTTP mock that blocks all external network calls."""
    with respx.mock(
        assert_all_called=False,
        assert_all_mocked=True,
    ) as mock:
        # Mock endpoints that might be called
        mock.post("https://discord.com/api/webhooks/.*").respond(200, json={"id": "123"})
        mock.post("https://slack.com/api/chat.postMessage").respond(200, json={"ok": True})
        mock.post("https://api.pagerduty.com/.*").respond(202, json={})
        mock.post("https://api.opsgenie.com/v2/alerts").respond(202, json={})
        mock.post("https://outlook.office.com/webhook/.*").respond(200, json={})
        mock.post("https://smtp.example.com/.*").respond(250, json={})
        
        yield mock

# ============================================================================
# INTEGRATION MOCKS - FOR TESTING SPECIFIC INTEGRATIONS
# ============================================================================

@pytest.fixture
def mock_discord():
    """Mock Discord integration without touching Discord's API."""
    with patch("src.integrations.discord.DiscordIntegration") as mock_class:
        instance = AsyncMock()
        instance.send_message = AsyncMock(return_value={"success": True, "message_id": "discord-123"})
        instance.send_embed = AsyncMock(return_value={"success": True})
        instance.is_configured = True
        mock_class.return_value = instance
        yield instance

@pytest.fixture
def mock_slack():
    """Mock Slack integration without touching Slack's API."""
    with patch("src.integrations.slack_integration.SlackIntegration") as mock_class:
        instance = AsyncMock()
        instance.send_message = AsyncMock(return_value={"ok": True, "ts": "123.456"})
        instance.send_blocks = AsyncMock(return_value={"ok": True})
        instance.is_configured = True
        mock_class.return_value = instance
        yield instance

@pytest.fixture
def mock_pagerduty():
    """Mock PagerDuty integration without touching PagerDuty's API."""
    with patch("src.integrations.pagerduty.PagerDutyIntegration") as mock_class:
        instance = AsyncMock()
        instance.trigger_incident = AsyncMock(return_value={"id": "pd-inc-123"})
        instance.acknowledge_incident = AsyncMock(return_value={})
        instance.resolve_incident = AsyncMock(return_value={})
        instance.is_configured = True
        mock_class.return_value = instance
        yield instance

# ============================================================================
# TEST DATA FACTORIES - CONSISTENT AND CONFIGURABLE
# ============================================================================

@pytest.fixture
def incident_data():
    """Factory for creating incident test data."""
    def _create(**kwargs) -> Dict[str, Any]:
        base = {
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
        return {**base, **kwargs}
    
    return _create

@pytest.fixture
def rollback_data():
    """Factory for creating rollback test data."""
    def _create(**kwargs) -> Dict[str, Any]:
        base = {
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
        return {**base, **kwargs}
    
    return _create

@pytest.fixture
def webhook_data():
    """Factory for creating webhook test data."""
    def _create(**kwargs) -> Dict[str, Any]:
        base = {
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
        return {**base, **kwargs}
    
    return _create

# ============================================================================
# TEST CONFIGURATION - OPTIMIZED FOR DEVELOPER FLOW
# ============================================================================

def pytest_collection_modifyitems(config, items):
    """Fast tests run first - immediate feedback is precious."""
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
    
    # Unit tests first for speed, integration last when you have time
    items[:] = unit_tests + other_tests + integration_tests

@pytest.fixture(autouse=True)
async def cleanup_test_state():
    """Every test starts with a clean slate - no hidden dependencies."""
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()

# ============================================================================
# ASSERTION HELPERS - CLEAR ERRORS, FAST DEBUGGING
# ============================================================================

async def assert_response(
    response: Response,
    expected_status: int = 200,
    expected_keys: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Validate HTTP response with helpful error messages.
    
    When tests fail, you should know exactly why - not just that they failed.
    """
    assert response.status_code == expected_status, (
        f"Expected status {expected_status}, got {response.status_code}. "
        f"Response: {response.text}"
    )
    
    if expected_status == 204:
        return None
    
    data = response.json()
    
    if expected_keys:
        for key in expected_keys:
            assert key in data, f"Missing key '{key}' in response: {data}"
    
    return data

async def assert_exception(
    async_func,
    exception_type,
    match: Optional[str] = None,
):
    """Assert that an async function raises a specific exception."""
    with pytest.raises(exception_type, match=match) as exc_info:
        await async_func()
    
    return exc_info.value

@contextlib.contextmanager
def mock_method(target, return_value=None, side_effect=None):
    """Context manager to mock a method - clean and predictable."""
    mock = AsyncMock()
    if side_effect:
        mock.side_effect = side_effect
    else:
        mock.return_value = return_value
    
    with patch(target, mock):
        yield mock

# ============================================================================
# SESSION CLEANUP - NO LINGERING RESOURCES
# ============================================================================

def pytest_sessionfinish(session, exitstatus):
    """Clean up database connections when tests are done."""
    loop = asyncio.get_event_loop()
    
    async def cleanup():
        await test_engine.dispose()
    
    loop.run_until_complete(cleanup())

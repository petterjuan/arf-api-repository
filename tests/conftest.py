"""
Test configuration and fixtures for ARF API tests - PRODUCTION READY.
This file provides fixtures and configuration for pytest with zero-tolerance for external dependencies.
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
# IMPORTS WITH FALLBACK MECHANISM
# ============================================================================

try:
    # Production import path
    from database.postgres_client import Base, get_db
    from auth.dependencies import get_current_user
    from auth.models import UserInDB, UserRole
    from main import app
except ImportError:
    # Development/CI import path
    import sys
    from pathlib import Path
    
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from src.database.postgres_client import Base, get_db
    from src.auth.dependencies import get_current_user
    from src.auth.models import UserInDB, UserRole
    from src.main import app

# ============================================================================
# TEST CONSTANTS - SINGLE SOURCE OF TRUTH
# ============================================================================

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
TEST_USER_ID = "test-user-123"
TEST_API_KEY = "test-api-key-123"
TEST_JWT_TOKEN = "test-jwt-token"

# ============================================================================
# DATABASE INFRASTRUCTURE - ISOLATED AND PREDICTABLE
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
# EVENT LOOP MANAGEMENT - NO LEAKS, NO SURPRISES
# ============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create a clean event loop for the test session."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()

# ============================================================================
# DATABASE LIFECYCLE - EACH TEST GETS A FRESH START
# ============================================================================

@pytest.fixture(scope="session", autouse=True)
async def setup_test_database():
    """Create and destroy database schema once per session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield
    
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Transactional database session with automatic rollback."""
    async with TestingSessionLocal() as session:
        await session.begin_nested()
        
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()

@pytest.fixture
def override_get_db(db_session: AsyncSession):
    """Dependency override for FastAPI database sessions."""
    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session
    
    return _override_get_db

# ============================================================================
# HTTP CLIENT - COMPLETELY ISOLATED FROM THE REAL WORLD
# ============================================================================

@pytest.fixture
async def client(override_get_db) -> AsyncGenerator[AsyncClient, None]:
    """Test client with all external services mocked to prevent any real calls."""
    original_overrides = app.dependency_overrides.copy()
    app.dependency_overrides[get_db] = override_get_db
    
    # Mock everything that could reach outside
    with patch("src.database.redis_client.redis_client", new_callable=AsyncMock) as redis_mock, \
         patch("src.database.neo4j_client.neo4j_driver", new_callable=AsyncMock) as neo4j_mock, \
         patch("src.integrations.discord.DiscordIntegration") as discord_mock, \
         patch("src.integrations.slack_integration.SlackIntegration") as slack_mock, \
         patch("src.integrations.pagerduty.PagerDutyIntegration") as pagerduty_mock, \
         patch("src.integrations.opsgenie.OpsgenieIntegration") as opsgenie_mock, \
         patch("src.integrations.teams.TeamsIntegration") as teams_mock, \
         patch("src.integrations.email.EmailIntegration") as email_mock:
        
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
        
        # Configure all integration mocks
        for integration_mock in [discord_mock, slack_mock, pagerduty_mock, 
                                 opsgenie_mock, teams_mock, email_mock]:
            instance = integration_mock.return_value
            instance.send_message = AsyncMock(
                return_value={"success": True, "message_id": "test-123"}
            )
            instance.is_configured = True
        
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            yield test_client
    
    app.dependency_overrides.clear()
    app.dependency_overrides.update(original_overrides)

# ============================================================================
# AUTHENTICATION - PREDICTABLE IDENTITIES
# ============================================================================

@pytest.fixture
def mock_user() -> UserInDB:
    """Standard test user with admin privileges."""
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
    """Client with pre-authenticated user context."""
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
# SERVICE MOCKS - READY FOR UNIT TESTING
# ============================================================================

@pytest.fixture
def mock_redis_client():
    """Standalone Redis mock for unit tests."""
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
def mock_neo4j_driver():
    """Standalone Neo4j mock for unit tests."""
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
def mock_http_client():
    """HTTP mock that prevents any real network calls."""
    with respx.mock(
        assert_all_called=False,
        assert_all_mocked=True,
    ) as mock:
        # Block all external calls
        mock.post("https://discord.com/api/webhooks/.*").respond(200, json={"id": "123"})
        mock.post("https://slack.com/api/chat.postMessage").respond(200, json={"ok": True})
        mock.post("https://api.pagerduty.com/.*").respond(202, json={})
        mock.post("https://api.opsgenie.com/v2/alerts").respond(202, json={})
        mock.post("https://outlook.office.com/webhook/.*").respond(200, json={})
        mock.post("https://smtp.example.com/.*").respond(250, json={})
        
        yield mock

# ============================================================================
# INTEGRATION SERVICE MOCKS - TARGETED AND SPECIFIC
# ============================================================================

@pytest.fixture
def mock_discord_integration():
    """Mock Discord integration without touching the API."""
    with patch("src.integrations.discord.DiscordIntegration") as mock:
        instance = AsyncMock()
        instance.send_message = AsyncMock(return_value={"success": True, "message_id": "discord-123"})
        instance.send_embed = AsyncMock(return_value={"success": True})
        instance.is_configured = True
        mock.return_value = instance
        yield instance

@pytest.fixture
def mock_slack_integration():
    """Mock Slack integration without touching the API."""
    with patch("src.integrations.slack_integration.SlackIntegration") as mock:
        instance = AsyncMock()
        instance.send_message = AsyncMock(return_value={"ok": True, "ts": "123.456"})
        instance.send_blocks = AsyncMock(return_value={"ok": True})
        instance.is_configured = True
        mock.return_value = instance
        yield instance

@pytest.fixture
def mock_pagerduty_integration():
    """Mock PagerDuty integration without touching the API."""
    with patch("src.integrations.pagerduty.PagerDutyIntegration") as mock:
        instance = AsyncMock()
        instance.trigger_incident = AsyncMock(return_value={"id": "pd-inc-123"})
        instance.acknowledge_incident = AsyncMock(return_value={})
        instance.resolve_incident = AsyncMock(return_value={})
        instance.is_configured = True
        mock.return_value = instance
        yield instance

@pytest.fixture
def mock_opsgenie_integration():
    """Mock OpsGenie integration without touching the API."""
    with patch("src.integrations.opsgenie.OpsgenieIntegration") as mock:
        instance = AsyncMock()
        instance.create_alert = AsyncMock(return_value={"alertId": "opsgenie-123"})
        instance.close_alert = AsyncMock(return_value={})
        instance.is_configured = True
        mock.return_value = instance
        yield instance

# ============================================================================
# TEST DATA FACTORIES - CONSISTENT AND PREDICTABLE
# ============================================================================

@pytest.fixture
def create_incident_data():
    """Factory for incident test data with sensible defaults."""
    def _create(**kwargs) -> Dict[str, Any]:
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
    """Factory for rollback test data with sensible defaults."""
    def _create(**kwargs) -> Dict[str, Any]:
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
    """Factory for webhook test data with sensible defaults."""
    def _create(**kwargs) -> Dict[str, Any]:
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
# TEST CONFIGURATION - OPTIMIZED FOR FLOW
# ============================================================================

def pytest_collection_modifyitems(config, items):
    """Run fast tests first for quicker feedback."""
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
    
    items[:] = unit_tests + other_tests + integration_tests

@pytest.fixture(autouse=True)
async def cleanup_test_state():
    """Ensure test isolation by clearing all state before each test."""
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()

# ============================================================================
# ASSERTION HELPERS - CLEAR AND ACTIONABLE
# ============================================================================

async def assert_async_response(
    response: Response,
    expected_status: int = 200,
    expected_keys: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Validate HTTP response with clear error messages."""
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

async def assert_exception_raised(
    async_func,
    exception_type,
    match: Optional[str] = None,
):
    """Assert that an async function raises a specific exception."""
    with pytest.raises(exception_type, match=match) as exc_info:
        await async_func()
    
    return exc_info.value

@contextlib.contextmanager
def mock_async_method(target, return_value=None, side_effect=None):
    """Context manager to mock an async method."""
    mock = AsyncMock()
    if side_effect:
        mock.side_effect = side_effect
    else:
        mock.return_value = return_value
    
    with patch(target, mock):
        yield mock

# ============================================================================
# SESSION CLEANUP - NO LINGERING STATE
# ============================================================================

def pytest_sessionfinish(session, exitstatus):
    """Ensure clean disposal of database connections."""
    loop = asyncio.get_event_loop()
    
    async def cleanup():
        await test_engine.dispose()
    
    loop.run_until_complete(cleanup())

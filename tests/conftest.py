"""
Test configuration and fixtures for ARF API tests - FIXED VERSION.
This file is automatically discovered by pytest and provides fixtures to all tests.
"""

import asyncio
from datetime import datetime, timedelta
from typing import AsyncGenerator, Generator, Dict, Any, Callable, List
from unittest.mock import AsyncMock, MagicMock, patch, create_autospec
import os
import json

import pytest
import respx
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import (
    AsyncSession, 
    create_async_engine, 
    async_sessionmaker
)
from sqlalchemy.pool import StaticPool

# Add src to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.database.postgres_client import Base, get_db
from src.auth.dependencies import get_current_user
from src.auth.models import UserInDB, UserRole
from src.main import app

# ============================================================================
# TEST CONFIGURATION - FIXED FOR PROPER MOCKING
# ============================================================================

# Use SQLite in-memory for ALL tests with PostgreSQL compatibility settings
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

# Create test engine with PostgreSQL compatibility
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    poolclass=StaticPool,  # Important for SQLite
    connect_args={"check_same_thread": False},
)

# Async session factory
TestingSessionLocal = async_sessionmaker(
    test_engine, 
    class_=AsyncSession, 
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# ============================================================================
# EVENT LOOP FIXTURE - FIXED
# ============================================================================

@pytest.fixture(scope="session")
def event_loop_policy():
    """Set up asyncio event loop policy for tests."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def setup_test_database():
    """Set up test database once per session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield
    
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ============================================================================
# DATABASE FIXTURES - FIXED WITH BETTER MOCKING
# ============================================================================

@pytest.fixture
async def db_session(setup_test_database) -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh database session for a test."""
    async with TestingSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@pytest.fixture
def override_get_db(db_session: AsyncSession):
    """Override the get_db dependency to use test database."""
    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        try:
            yield db_session
        finally:
            await db_session.close()
    
    return _override_get_db


# ============================================================================
# HTTP CLIENT FIXTURE - FIXED WITH COMPLETE MOCKING
# ============================================================================

@pytest.fixture
async def client(override_get_db) -> AsyncGenerator[AsyncClient, None]:
    """
    Create test client with ALL external dependencies mocked.
    This prevents timeouts and external API calls.
    """
    # Store original overrides
    original_overrides = app.dependency_overrides.copy()
    
    # 1. Override database
    app.dependency_overrides[get_db] = override_get_db
    
    # 2. Mock ALL external services to prevent timeouts
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
        redis_mock.delete = AsyncMock(return_value=1)
        redis_mock.exists = AsyncMock(return_value=False)
        
        # Configure Neo4j mock
        neo4j_session_mock = AsyncMock()
        neo4j_tx_mock = AsyncMock()
        neo4j_tx_mock.run = AsyncMock(return_value=[])
        neo4j_tx_mock.commit = AsyncMock()
        neo4j_session_mock.begin_transaction = AsyncMock(return_value=neo4j_tx_mock)
        neo4j_mock.session = AsyncMock(return_value=neo4j_session_mock)
        
        # Configure integration mocks
        for integration_mock in [discord_mock, slack_mock, pagerduty_mock, 
                                 opsgenie_mock, teams_mock, email_mock]:
            integration_mock.return_value.send_message = AsyncMock(
                return_value={"success": True, "message_id": "test-123"}
            )
            integration_mock.return_value.is_configured = True
        
        # Create async client
        async with AsyncClient(app=app, base_url="http://test") as test_client:
            yield test_client
    
    # Restore original overrides
    app.dependency_overrides.clear()
    app.dependency_overrides.update(original_overrides)


# ============================================================================
# AUTHENTICATION FIXTURES - FIXED
# ============================================================================

@pytest.fixture
def mock_user() -> UserInDB:
    """Create a mock user object with all required fields."""
    return UserInDB(
        id="test-user-123",
        email="test@example.com",
        full_name="Test User",
        is_active=True,
        roles=[UserRole.ADMIN],
        hashed_password="hashed_password_for_testing",
        created_at=datetime.now(),
        updated_at=datetime.now(),
        last_login=datetime.now(),
        api_key="test-api-key-123",
        api_key_expires=datetime.now() + timedelta(days=30),
    )


@pytest.fixture
async def authenticated_client(client: AsyncClient, mock_user: UserInDB):
    """Create a test client with authenticated user."""
    # Mock the authentication dependency
    async def mock_get_current_user():
        return mock_user
    
    app.dependency_overrides[get_current_user] = mock_get_current_user
    
    # Add auth headers to client
    client.headers.update({
        "Authorization": f"Bearer test-jwt-token",
        "X-API-Key": "test-api-key-123",
    })
    
    yield client
    
    # Clean up
    if get_current_user in app.dependency_overrides:
        del app.dependency_overrides[get_current_user]


# ============================================================================
# SERVICE MOCK FIXTURES - COMPREHENSIVE SET
# ============================================================================

@pytest.fixture
def mock_redis_client():
    """Create a comprehensive Redis mock."""
    redis_mock = AsyncMock()
    
    # Mock common Redis methods
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock(return_value=True)
    redis_mock.setex = AsyncMock(return_value=True)
    redis_mock.delete = AsyncMock(return_value=1)
    redis_mock.exists = AsyncMock(return_value=0)
    redis_mock.incr = AsyncMock(return_value=1)
    redis_mock.decr = AsyncMock(return_value=0)
    redis_mock.expire = AsyncMock(return_value=True)
    redis_mock.ttl = AsyncMock(return_value=-1)
    redis_mock.keys = AsyncMock(return_value=[])
    redis_mock.flushdb = AsyncMock(return_value=True)
    
    # Pipeline support
    pipeline_mock = AsyncMock()
    pipeline_mock.execute = AsyncMock(return_value=[])
    redis_mock.pipeline = AsyncMock(return_value=pipeline_mock)
    
    return redis_mock


@pytest.fixture
def mock_neo4j_driver():
    """Create a comprehensive Neo4j driver mock."""
    driver_mock = AsyncMock()
    
    # Mock session
    session_mock = AsyncMock()
    
    # Mock transaction
    tx_mock = AsyncMock()
    tx_mock.run = AsyncMock(return_value=[])
    tx_mock.commit = AsyncMock()
    tx_mock.rollback = AsyncMock()
    tx_mock.close = AsyncMock()
    
    # Mock results
    record_mock = MagicMock()
    record_mock.values = MagicMock(return_value=["result"])
    
    result_mock = AsyncMock()
    result_mock.single = AsyncMock(return_value=record_mock)
    result_mock.data = AsyncMock(return_value=[{"data": "test"}])
    result_mock.values = AsyncMock(return_value=["value1", "value2"])
    
    tx_mock.run.return_value = result_mock
    
    session_mock.begin_transaction = AsyncMock(return_value=tx_mock)
    session_mock.execute_read = AsyncMock(return_value=result_mock)
    session_mock.execute_write = AsyncMock(return_value=result_mock)
    session_mock.close = AsyncMock()
    
    driver_mock.session = AsyncMock(return_value=session_mock)
    
    return driver_mock


@pytest.fixture
def mock_http_client():
    """Mock HTTPX client for external API calls."""
    with respx.mock as mock:
        # Mock common endpoints
        mock.post("https://discord.com/api/webhooks/.*").respond(200, json={"id": "123"})
        mock.post("https://slack.com/api/chat.postMessage").respond(200, json={"ok": True})
        mock.post("https://api.pagerduty.com/.*").respond(202, json={})
        mock.post("https://api.opsgenie.com/v2/alerts").respond(202, json={})
        mock.post("https://outlook.office.com/webhook/.*").respond(200, json={})
        mock.post("https://smtp.example.com/.*").respond(250, json={})
        
        yield mock


# ============================================================================
# INTEGRATION SERVICE MOCKS - CRITICAL FOR PREVENTING TIMEOUTS
# ============================================================================

@pytest.fixture
def mock_discord_integration():
    """Mock Discord integration to prevent external API calls."""
    with patch("src.integrations.discord.DiscordIntegration") as mock:
        instance = AsyncMock()
        instance.send_message = AsyncMock(return_value={"success": True, "message_id": "discord-123"})
        instance.send_embed = AsyncMock(return_value={"success": True})
        instance.is_configured = True
        mock.return_value = instance
        yield instance


@pytest.fixture
def mock_slack_integration():
    """Mock Slack integration to prevent external API calls."""
    with patch("src.integrations.slack_integration.SlackIntegration") as mock:
        instance = AsyncMock()
        instance.send_message = AsyncMock(return_value={"ok": True, "ts": "123.456"})
        instance.send_blocks = AsyncMock(return_value={"ok": True})
        instance.is_configured = True
        mock.return_value = instance
        yield instance


@pytest.fixture
def mock_pagerduty_integration():
    """Mock PagerDuty integration to prevent external API calls."""
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
    """Mock OpsGenie integration to prevent external API calls."""
    with patch("src.integrations.opsgenie.OpsgenieIntegration") as mock:
        instance = AsyncMock()
        instance.create_alert = AsyncMock(return_value={"alertId": "opsgenie-123"})
        instance.close_alert = AsyncMock(return_value={})
        instance.is_configured = True
        mock.return_value = instance
        yield instance


# ============================================================================
# TEST DATA FACTORIES - IMPROVED
# ============================================================================

@pytest.fixture
def create_incident_data():
    """Factory for incident test data."""
    def _create(**kwargs):
        default = {
            "title": "Test Incident",
            "description": "This is a test incident",
            "severity": "medium",
            "status": "open",
            "component": "api",
            "environment": "test",
            "labels": ["test", "unit"],
            "metadata": {"test": True},
            "created_by": "test-user-123",
        }
        default.update(kwargs)
        return default
    return _create


@pytest.fixture
def create_rollback_data():
    """Factory for rollback test data."""
    def _create(**kwargs):
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
            "created_by": "test-user-123",
        }
        default.update(kwargs)
        return default
    return _create


@pytest.fixture
def create_webhook_data():
    """Factory for webhook test data."""
    def _create(**kwargs):
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
            "created_by": "test-user-123",
        }
        default.update(kwargs)
        return default
    return _create


# ============================================================================
# TEST CONFIGURATION
# ============================================================================

def pytest_collection_modifyitems(config, items):
    """Modify test collection to run fast tests first."""
    # Prioritize unit tests over integration tests
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
    
    # Reorder: unit tests first, then others, then integration tests
    items[:] = unit_tests + other_tests + integration_tests


@pytest.fixture(autouse=True)
async def cleanup_test_state():
    """Clean up test state before each test."""
    # Clear any global state
    if hasattr(app, "dependency_overrides"):
        app.dependency_overrides.clear()
    
    # Clear Redis/Neo4j mocks
    yield
    
    # Additional cleanup if needed


# ============================================================================
# HELPER FUNCTIONS FOR ASSERTIONS
# ============================================================================

async def assert_async_response(response, expected_status=200, expected_keys=None):
    """Helper to assert async HTTP response."""
    assert response.status_code == expected_status, \
        f"Expected status {expected_status}, got {response.status_code}. Response: {response.text}"
    
    if expected_status == 204:  # No content
        return None
    
    data = response.json()
    
    if expected_keys:
        for key in expected_keys:
            assert key in data, f"Missing key '{key}' in response: {data}"
    
    return data


async def assert_exception_raised(async_func, exception_type, match=None):
    """Helper to assert that an async function raises an exception."""
    with pytest.raises(exception_type, match=match) as exc_info:
        await async_func()
    return exc_info.value


def mock_async_method(method_name, return_value=None, side_effect=None):
    """Helper to mock an async method."""
    mock = AsyncMock()
    if side_effect:
        mock.side_effect = side_effect
    else:
        mock.return_value = return_value
    return mock

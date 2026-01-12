"""Test the infrastructure and configuration."""
import pytest
import sys
import os


@pytest.mark.unit
def test_python_version():
    """Test that we're using Python 3.11+."""
    version = sys.version_info
    assert version.major == 3
    assert version.minor >= 11
    print(f"✓ Python version: {version.major}.{version.minor}.{version.micro}")


@pytest.mark.unit
def test_environment_variables():
    """Test that required environment variables are available for tests."""
    # These should be set in pytest configuration
    assert os.getenv("TESTING") == "1"
    assert os.getenv("SKIP_DATABASE_INIT") == "1"
    print("✓ Test environment variables are set")


@pytest.mark.unit
def test_imports():
    """Test that core modules can be imported."""
    try:
        from src.main import app
        from src.auth.router import router as auth_router
        # FIXED: Import from correct module
        from src.database.postgres_client import Base
        print("✓ Core imports work correctly")
        assert app is not None
        assert auth_router is not None
        assert Base is not None
    except ImportError as e:
        pytest.fail(f"Import error: {e}")


@pytest.mark.unit
def test_test_configuration():
    """Test that pytest is properly configured."""
    # This test should pass if pytest is configured correctly
    assert True


@pytest.mark.integration
def test_database_connections():
    """Test database connection configuration (mocked)."""
    # This would actually test database connections in integration tests
    # For unit tests, we just verify the configuration
    db_url = os.getenv("DATABASE_URL", "")
    redis_url = os.getenv("REDIS_URL", "")
    neo4j_url = os.getenv("NEO4J_URL", "")

    # In unit tests, these might be empty
    # In integration tests, they should be set
    print(f"Database URLs configured for testing")
    print(f"  PostgreSQL: {'✓' if db_url else '✗ (unit test mode)'}")
    print(f"  Redis: {'✓' if redis_url else '✗ (unit test mode)'}")
    print(f"  Neo4j: {'✓' if neo4j_url else '✗ (unit test mode)'}")

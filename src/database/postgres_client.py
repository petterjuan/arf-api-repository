# src/database/postgres_client.py
"""
PostgreSQL client and session management.
Psychology: Single responsibility - handles only PostgreSQL connections.
Intention: Isolate database concerns for better maintainability.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from typing import Generator, AsyncGenerator
import os

# Database URLs - only store the URL, don't create engines yet
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/arf")
ASYNC_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

# Lazy-loaded engines
_engine = None
_async_engine = None
_SessionLocal = None
_AsyncSessionLocal = None
_Base = declarative_base()

def get_engine():
    """Get or create synchronous engine (lazy initialization)"""
    global _engine
    if _engine is None:
        # Check if we should skip database initialization
        if os.getenv("SKIP_DATABASE_INIT") or os.getenv("TESTING"):
            # Return a mock engine for validation/testing
            from unittest.mock import Mock
            mock_engine = Mock()
            mock_engine.connect.return_value.__enter__.return_value = Mock()
            _engine = mock_engine
        else:
            _engine = create_engine(DATABASE_URL)
    return _engine

def get_async_engine():
    """Get or create asynchronous engine (lazy initialization)"""
    global _async_engine
    if _async_engine is None:
        # Check if we should skip database initialization
        if os.getenv("SKIP_DATABASE_INIT") or os.getenv("TESTING"):
            from unittest.mock import Mock
            _async_engine = Mock()
        else:
            _async_engine = create_async_engine(ASYNC_DATABASE_URL)
    return _async_engine

def get_session_local():
    """Get or create session factory (lazy initialization)"""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionLocal

def get_async_session_local():
    """Get or create async session factory (lazy initialization)"""
    global _AsyncSessionLocal
    if _AsyncSessionLocal is None:
        _AsyncSessionLocal = sessionmaker(
            get_async_engine(), 
            class_=AsyncSession, 
            expire_on_commit=False
        )
    return _AsyncSessionLocal

# Public API - these will lazily initialize when accessed
engine = property(lambda self: get_engine())
async_engine = property(lambda self: get_async_engine())
SessionLocal = property(lambda self: get_session_local())
AsyncSessionLocal = property(lambda self: get_async_session_local())
Base = _Base

# Dependency for FastAPI
def get_db() -> Generator[Session, None, None]:
    """
    Get a synchronous database session.
    Psychology: Resource management - ensures sessions are properly closed.
    Intention: Provide clean session lifecycle management.
    """
    db = get_session_local()()
    try:
        yield db
    finally:
        db.close()

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get an asynchronous database session.
    Psychology: Async-first design for modern web applications.
    Intention: Support async/await patterns for better performance.
    """
    async with get_async_session_local()() as session:
        yield session

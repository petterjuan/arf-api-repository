# src/database/postgres_client.py
"""
PostgreSQL client and session management.
Psychology: Single responsibility - handles only PostgreSQL connections.
Intention: Isolate database concerns for better maintainability.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
import os

# Database URLs
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/arf")
ASYNC_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

# Create engines
engine = create_engine(DATABASE_URL)
async_engine = create_async_engine(ASYNC_DATABASE_URL)

# Session factories
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
AsyncSessionLocal = sessionmaker(
    async_engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)

Base = declarative_base()

# Dependency for FastAPI
def get_db():
    """
    Get a synchronous database session.
    Psychology: Resource management - ensures sessions are properly closed.
    Intention: Provide clean session lifecycle management.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_async_db():
    """
    Get an asynchronous database session.
    Psychology: Async-first design for modern web applications.
    Intention: Support async/await patterns for better performance.
    """
    async with AsyncSessionLocal() as session:
        yield session

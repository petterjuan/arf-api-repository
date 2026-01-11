"""
Database package initialization.
Exports database clients and utilities.
Psychology: Clean exports - provides a unified interface for all database operations.
Intention: Make it easy to import database utilities without knowing internal structure.
"""
from .neo4j_client import driver as neo4j_driver, get_neo4j
from .redis_client import redis_client, get_redis
from .postgres_client import get_db, get_async_db, Base  # Import from local module

__all__ = [
    'neo4j_driver',
    'get_neo4j',
    'redis_client', 
    'get_redis',
    'get_db',
    'get_async_db',
    'Base'
]

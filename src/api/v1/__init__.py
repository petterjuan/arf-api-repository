# src/api/v1/__init__.py
from .incidents import router as incidents_router

__all__ = ["incidents_router"]

"""
Service integration module for Enterprise features.

This module provides graceful integration between OSS public API
and Enterprise private features with proper fallback handling.
"""

import logging
import sys

logger = logging.getLogger(__name__)

# Try to import Enterprise modules with graceful degradation
ENTERPRISE_MODULES = {}

try:
    from arf_enterprise import execution_authority_service
    ENTERPRISE_MODULES["execution_authority"] = execution_authority_service
    logger.info("Enterprise execution authority service available")
except ImportError as e:
    logger.info(f"Enterprise execution authority unavailable: {e}")
    ENTERPRISE_MODULES["execution_authority"] = None

try:
    from arf_enterprise import license_manager
    ENTERPRISE_MODULES["license_manager"] = license_manager
    logger.info("Enterprise license manager available")
except ImportError:
    logger.info("Enterprise license manager unavailable")
    ENTERPRISE_MODULES["license_manager"] = None

try:
    from arf_enterprise import audit_trail
    ENTERPRISE_MODULES["audit_trail"] = audit_trail
    logger.info("Enterprise audit trail available")
except ImportError:
    logger.info("Enterprise audit trail unavailable")
    ENTERPRISE_MODULES["audit_trail"] = None


def is_enterprise_available(module: str) -> bool:
    """
    Check if Enterprise module is available.
    
    Args:
        module: Module name to check
        
    Returns:
        bool: True if Enterprise module is available
    """
    return ENTERPRISE_MODULES.get(module) is not None


def get_enterprise_module(module: str):
    """
    Get Enterprise module if available.
    
    Args:
        module: Module name to get
        
    Returns:
        Module or None if unavailable
    """
    return ENTERPRISE_MODULES.get(module)


def get_edition() -> str:
    """
    Get current ARF edition.
    
    Returns:
        str: "enterprise" if any Enterprise module is available, else "oss"
    """
    if any(module is not None for module in ENTERPRISE_MODULES.values()):
        return "enterprise"
    return "oss"


class EnterpriseIntegrationError(Exception):
    """Enterprise integration error."""
    pass


__all__ = [
    "is_enterprise_available",
    "get_enterprise_module",
    "get_edition",
    "EnterpriseIntegrationError",
    "ENTERPRISE_MODULES",
]

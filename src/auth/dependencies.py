"""
Authentication dependencies for FastAPI.
Psychology: Layered security - each dependency validates specific aspects.
Intention: Provide granular control over endpoint protection.
"""

from typing import Optional, List

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select

from src.database.postgres_client import get_db
from src.auth.models import (
    decode_token,
    TokenPayload,
    TokenType,
    UserRole,
    verify_api_key,
)
from src.auth.database_models import UserDB, APIKeyDB


# Security schemes
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    auto_error=False
)

api_key_scheme = HTTPBearer(
    scheme_name="APIKey",
    auto_error=False,
    description="API Key authentication"
)


class AuthError(Exception):
    """Custom authentication error"""
    def __init__(self, detail: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        self.detail = detail
        self.status_code = status_code


# Dependency: Get current user from token
async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> UserDB:
    """Get current user from JWT token"""
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload: Optional[TokenPayload] = decode_token(token)
    if not payload or payload.type != TokenType.ACCESS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    result = await db.execute(select(UserDB).where(UserDB.id == payload.sub))
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return user


# Dependency: Get current user from API key
async def get_current_user_from_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(api_key_scheme),
    db: AsyncSession = Depends(get_db)
) -> UserDB:
    """Get current user from API key"""

    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key required")

    # Lookup by prefix to reduce DB scan
    api_key_prefix = credentials.credentials[:12]

    result = await db.execute(
        select(APIKeyDB).where(
            APIKeyDB.key_prefix == api_key_prefix,
            APIKeyDB.is_active == True
        )
    )
    api_key_obj = result.scalars().first()

    if not api_key_obj:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    # Verify hash
    if not verify_api_key(credentials.credentials, api_key_obj.key_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    result = await db.execute(
        select(UserDB).where(
            UserDB.id == api_key_obj.owner_id,
            UserDB.is_active == True
        )
    )
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Update last used timestamp
    api_key_obj.last_used = func.now()
    await db.commit()

    return user


# Role-based authorization dependencies
def require_role(required_role: UserRole):
    """Factory function to create role-based dependencies"""
    async def role_dependency(
        current_user: UserDB = Depends(get_current_user)
    ) -> UserDB:
        user_roles = [UserRole(role) for role in current_user.roles]

        # Check if user has required role
        role_hierarchy = {
            UserRole.VIEWER: 0,
            UserRole.OPERATOR: 1,
            UserRole.ADMIN: 2,
            UserRole.SUPER_ADMIN: 3
        }

        user_max_role = max([role_hierarchy.get(role, 0) for role in user_roles], default=0)
        required_level = role_hierarchy.get(required_role, 0)

        if user_max_role < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {required_role.value}"
            )

        return current_user

    return role_dependency


# Convenience role dependencies
require_viewer = require_role(UserRole.VIEWER)
require_operator = require_role(UserRole.OPERATOR)
require_admin = require_role(UserRole.ADMIN)
require_super_admin = require_role(UserRole.SUPER_ADMIN)


# Flexible authentication dependency (accepts either JWT or API key)
async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[HTTPAuthorizationCredentials] = Depends(api_key_scheme),
    db: AsyncSession = Depends(get_db)
) -> Optional[UserDB]:
    """Get current user from either JWT or API key (optional)"""
    try:
        if token:
            return await get_current_user(token=token, db=db)
        elif api_key:
            return await get_current_user_from_api_key(credentials=api_key, db=db)
    except HTTPException:
        return None

    return None


# Public endpoint dependency (no auth required but validates if provided)
async def get_optional_auth(
    current_user: Optional[UserDB] = Depends(get_current_user_optional)
) -> Optional[UserDB]:
    """Dependency for endpoints that work with or without authentication"""
    return current_user

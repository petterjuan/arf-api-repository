"""
Authentication dependencies for FastAPI.
Psychology: Layered security - each dependency validates specific aspects.
Intention: Provide granular control over endpoint protection.
"""
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer
from typing import Optional, List
from sqlalchemy.orm import Session

from src.database import get_db
from src.auth.models import (
    decode_token, TokenPayload, TokenType, UserRole,
    SECRET_KEY, ALGORITHM
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
    db: Session = Depends(get_db)
) -> UserDB:
    """Get current user from JWT token"""
    if not token:
        raise AuthError("Not authenticated")
    
    payload = decode_token(token)
    if not payload or payload.type != TokenType.ACCESS:
        raise AuthError("Invalid token")
    
    user = db.query(UserDB).filter(UserDB.id == payload.sub).first()
    if not user or not user.is_active:
        raise AuthError("User not found or inactive")
    
    return user

# Dependency: Get current user from API key
async def get_current_user_from_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(api_key_scheme),
    db: Session = Depends(get_db)
) -> UserDB:
    """Get current user from API key"""
    if not credentials:
        raise AuthError("API key required")
    
    # In production, hash the API key before lookup
    api_key = db.query(APIKeyDB).filter(
        APIKeyDB.key_hash == credentials.credentials,
        APIKeyDB.is_active == True
    ).first()
    
    if not api_key:
        raise AuthError("Invalid API key")
    
    user = db.query(UserDB).filter(
        UserDB.id == api_key.owner_id,
        UserDB.is_active == True
    ).first()
    
    if not user:
        raise AuthError("User not found")
    
    # Update last used timestamp
    api_key.last_used = func.now()
    db.commit()
    
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
    db: Session = Depends(get_db)
) -> Optional[UserDB]:
    """Get current user from either JWT or API key (optional)"""
    try:
        if token:
            return await get_current_user(token, db)
        elif api_key:
            return await get_current_user_from_api_key(api_key, db)
    except AuthError:
        pass
    
    return None

# Public endpoint dependency (no auth required but validates if provided)
async def get_optional_auth(
    current_user: Optional[UserDB] = Depends(get_current_user_optional)
) -> Optional[UserDB]:
    """Dependency for endpoints that work with or without authentication"""
    return current_user

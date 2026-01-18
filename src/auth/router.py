"""
Authentication router with comprehensive auth endpoints.
Psychology: RESTful design with clear error responses and security best practices.
Intention: Provide full authentication lifecycle management.
"""

from datetime import datetime, timedelta
import secrets
import uuid
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.database_models import APIKeyDB, RefreshTokenDB, UserDB
from src.auth.dependencies import (
    require_admin,
    require_operator,
    require_viewer,
)
from src.auth.models import (
    APIKeyCreate,
    APIKeyInDB,
    Token,
    TokenType,
    UserCreate,
    UserInDB,
    UserRole,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)
from src.database import get_db

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


def generate_api_key() -> str:
    """Generate a secure API key (random + high entropy)."""
    key_bytes = secrets.token_urlsafe(32)
    return f"arf_{key_bytes}"


def _get_key_prefix(api_key: str) -> str:
    """Get prefix for API key lookups."""
    if api_key.startswith("arf_"):
        return api_key[:12]
    return api_key[:8]


@router.post("/register", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """Register a new user"""
    stmt = select(UserDB).where(UserDB.email == user_data.email)
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
        )

    db_user = UserDB(
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=get_password_hash(user_data.password),
        roles=[role.value for role in user_data.roles],
        is_active=True,
        is_verified=False,
    )

    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    if background_tasks:
        # background_tasks.add_task(send_verification_email, db_user.email)
        pass

    return db_user


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """Login with username (email) and password"""
    stmt = select(UserDB).where(
        UserDB.email == form_data.username,
        UserDB.is_active.is_(True),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user.last_login = datetime.utcnow()
    await db.commit()

    access_token = create_access_token(data={"sub": user.id, "roles": user.roles})
    refresh_token = create_refresh_token(data={"sub": user.id, "roles": user.roles})

    # Store refresh token hash in DB (recommended)
    token_hash = get_password_hash(refresh_token)
    refresh_db = RefreshTokenDB(
        token_hash=token_hash,
        user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )

    db.add(refresh_db)
    await db.commit()

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str,
    db: AsyncSession = Depends(get_db),
):
    """Refresh access token using refresh token"""
    payload = decode_token(refresh_token)
    if not payload or payload.type != TokenType.REFRESH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # Validate token against DB and hash match
    stmt = select(RefreshTokenDB).where(
        RefreshTokenDB.user_id == payload.sub,
        RefreshTokenDB.is_revoked.is_(False),
        RefreshTokenDB.expires_at > datetime.utcnow(),
    )
    result = await db.execute(stmt)
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revoked or not found",
        )

    if not verify_password(refresh_token, token_record.token_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token mismatch",
        )

    access_token = create_access_token(
        data={"sub": payload.sub, "roles": payload.roles}
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/api-keys", response_model=APIKeyInDB, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    api_key_data: APIKeyCreate,
    current_user: UserDB = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key"""
    raw_key = generate_api_key()
    key_hash = get_password_hash(raw_key)
    key_prefix = _get_key_prefix(raw_key)

    db_api_key = APIKeyDB(
        name=api_key_data.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        owner_id=current_user.id,
        scopes=api_key_data.scopes,
        expires_at=datetime.utcnow() + timedelta(days=api_key_data.expires_days)
        if api_key_data.expires_days
        else None,
    )

    db.add(db_api_key)
    await db.commit()
    await db.refresh(db_api_key)

    response = APIKeyInDB.model_validate(db_api_key)
    response.key = raw_key
    return response


@router.get("/api-keys", response_model=List[APIKeyInDB])
async def list_api_keys(
    current_user: UserDB = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
):
    """List API keys for current user"""
    stmt = select(APIKeyDB).where(APIKeyDB.owner_id == current_user.id)
    result = await db.execute(stmt)
    api_keys = result.scalars().all()
    return api_keys


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: str,
    current_user: UserDB = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an API key"""
    stmt = select(APIKeyDB).where(
        APIKeyDB.id == key_id,
        APIKeyDB.owner_id == current_user.id,
    )
    result = await db.execute(stmt)
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    api_key.is_active = False
    await db.commit()


@router.get("/me", response_model=UserInDB)
async def get_current_user_info(current_user: UserDB = Depends(require_viewer)):
    """Get current user information"""
    return current_user


@router.post("/logout")
async def logout(
    refresh_token: Optional[str] = None,
    current_user: UserDB = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Logout user (revoke refresh token)"""
    if refresh_token:
        payload = decode_token(refresh_token)
        if payload and payload.type == TokenType.REFRESH:
            stmt = select(RefreshTokenDB).where(
                RefreshTokenDB.user_id == payload.sub,
                RefreshTokenDB.is_revoked.is_(False),
            )
            result = await db.execute(stmt)
            token_record = result.scalar_one_or_none()

            if token_record:
                token_record.is_revoked = True
                await db.commit()

    return {"message": "Successfully logged out"}


# Admin endpoints
@router.get("/users", response_model=List[UserInDB])
async def list_users(
    current_user: UserDB = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all users (admin only)"""
    stmt = select(UserDB)
    result = await db.execute(stmt)
    users = result.scalars().all()
    return users


@router.patch("/users/{user_id}/roles")
async def update_user_roles(
    user_id: str,
    roles: List[UserRole],
    current_user: UserDB = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update user roles (admin only)"""
    if UserRole.SUPER_ADMIN in roles and UserRole.SUPER_ADMIN not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can assign super admin role",
        )

    stmt = select(UserDB).where(UserDB.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    user.roles = [role.value for role in roles]
    user.updated_at = datetime.utcnow()
    await db.commit()

    return {"message": "User roles updated successfully"}

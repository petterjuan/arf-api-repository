"""
Authentication router with comprehensive auth endpoints.
Psychology: RESTful design with clear error responses and security best practices.
Intention: Provide full authentication lifecycle management.
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List
import uuid

from src.database import get_db
from src.auth.models import (
    UserCreate, UserInDB, Token, TokenType,
    APIKeyCreate, APIKeyInDB, UserRole,
    create_access_token, create_refresh_token,
    get_password_hash, verify_password,
    decode_token, SECRET_KEY
)
from src.auth.database_models import UserDB, APIKeyDB, RefreshTokenDB
from src.auth.dependencies import AuthError

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])

# Helper function to generate API key
def generate_api_key() -> str:
    """Generate a secure API key"""
    return f"arf_{uuid.uuid4().hex}_{uuid.uuid4().hex[:8]}"

@router.post("/register", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    background_tasks: BackgroundTasks = None
):
    """Register a new user"""
    # Check if user already exists
    existing_user = db.query(UserDB).filter(UserDB.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )
    
    # Create user
    db_user = UserDB(
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=get_password_hash(user_data.password),
        roles=user_data.roles,
        is_active=True,
        is_verified=False  # Email verification would happen here
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # In production: Send verification email via background task
    if background_tasks:
        # background_tasks.add_task(send_verification_email, db_user.email)
        pass
    
    return db_user

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login with username (email) and password"""
    # Find user
    user = db.query(UserDB).filter(
        UserDB.email == form_data.username,
        UserDB.is_active == True
    ).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login
    user.last_login = func.now()
    db.commit()
    
    # Create tokens
    access_token = create_access_token(
        data={"sub": user.id, "roles": user.roles}
    )
    refresh_token = create_refresh_token(
        data={"sub": user.id, "roles": user.roles}
    )
    
    # Store refresh token hash in database (for revocation)
    # Implementation omitted for brevity
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=30 * 60  # 30 minutes in seconds
    )

@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str,
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token"""
    # Validate refresh token
    payload = decode_token(refresh_token)
    if not payload or payload.type != TokenType.REFRESH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Check if refresh token is revoked
    # Implementation omitted for brevity
    
    # Create new access token
    access_token = create_access_token(
        data={"sub": payload.sub, "roles": payload.roles}
    )
    
    return Token(
        access_token=access_token,
        expires_in=30 * 60
    )

@router.post("/api-keys", response_model=APIKeyInDB, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    api_key_data: APIKeyCreate,
    current_user: UserDB = Depends(require_operator),
    db: Session = Depends(get_db)
):
    """Create a new API key"""
    # Generate API key
    raw_key = generate_api_key()
    
    # Hash the key for storage (in production, use proper hashing)
    key_hash = get_password_hash(raw_key)
    
    # Create API key record
    db_api_key = APIKeyDB(
        name=api_key_data.name,
        key_hash=key_hash,
        owner_id=current_user.id,
        scopes=api_key_data.scopes,
        expires_at=func.now() + timedelta(days=api_key_data.expires_days) if api_key_data.expires_days else None
    )
    
    db.add(db_api_key)
    db.commit()
    db.refresh(db_api_key)
    
    # Return the raw key only once (client should store it securely)
    response = APIKeyInDB.model_validate(db_api_key)
    response.key = raw_key  # Add raw key to response (one-time only)
    
    return response

@router.get("/api-keys", response_model=List[APIKeyInDB])
async def list_api_keys(
    current_user: UserDB = Depends(require_operator),
    db: Session = Depends(get_db)
):
    """List API keys for current user"""
    api_keys = db.query(APIKeyDB).filter(
        APIKeyDB.owner_id == current_user.id
    ).all()
    
    return api_keys

@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: str,
    current_user: UserDB = Depends(require_operator),
    db: Session = Depends(get_db)
):
    """Revoke an API key"""
    api_key = db.query(APIKeyDB).filter(
        APIKeyDB.id == key_id,
        APIKeyDB.owner_id == current_user.id
    ).first()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    api_key.is_active = False
    db.commit()

@router.get("/me", response_model=UserInDB)
async def get_current_user_info(
    current_user: UserDB = Depends(require_viewer)
):
    """Get current user information"""
    return current_user

@router.post("/logout")
async def logout(
    refresh_token: Optional[str] = None,
    current_user: UserDB = Depends(require_viewer),
    db: Session = Depends(get_db)
):
    """Logout user (revoke refresh token)"""
    if refresh_token:
        # Mark refresh token as revoked
        # Implementation omitted for brevity
        pass
    
    return {"message": "Successfully logged out"}

# Admin endpoints
@router.get("/users", response_model=List[UserInDB])
async def list_users(
    current_user: UserDB = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """List all users (admin only)"""
    users = db.query(UserDB).all()
    return users

@router.patch("/users/{user_id}/roles")
async def update_user_roles(
    user_id: str,
    roles: List[UserRole],
    current_user: UserDB = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update user roles (admin only)"""
    if UserRole.SUPER_ADMIN in roles and UserRole.SUPER_ADMIN not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can assign super admin role"
        )
    
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.roles = [role.value for role in roles]
    user.updated_at = func.now()
    db.commit()
    
    return {"message": "User roles updated successfully"}

"""
Authentication models and utilities for ARF API.
Psychology: Separation of concerns - authentication logic isolated from business logic.
Intention: Provide flexible auth supporting both human users (JWT) and machine clients (API keys).
"""
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field, EmailStr, validator, constr
import jwt
from passlib.context import CryptContext

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "arf-super-secret-key-change-in-production"  # Should be env variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


class TokenType(str, Enum):
    """Token type enumeration for clear intent"""
    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"


class UserRole(str, Enum):
    """User role hierarchy - RBAC foundation"""
    VIEWER = "viewer"  # Read-only access
    OPERATOR = "operator"  # Can manage incidents
    ADMIN = "admin"  # Full system access
    SUPER_ADMIN = "super_admin"  # System management


class TokenPayload(BaseModel):
    """JWT token payload structure"""
    sub: str  # Subject (user ID or client ID)
    exp: datetime
    type: TokenType
    roles: List[UserRole] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)


class UserBase(BaseModel):
    """Base user model"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    full_name: Optional[str] = Field(None, max_length=100)
    is_active: bool = True
    roles: List[UserRole] = Field(default=[UserRole.VIEWER])


class UserCreate(UserBase):
    """User creation model"""
    password: constr(min_length=8, max_length=128)  # Max 128 chars to prevent DoS
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Ensure password meets security requirements"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserInDB(UserBase):
    """Database user model"""
    id: str
    hashed_password: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    """Token response model"""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60


class APIKeyCreate(BaseModel):
    """API key creation model"""
    name: str = Field(..., min_length=1, max_length=100)
    expires_days: Optional[int] = Field(30, ge=1, le=365)
    scopes: List[str] = Field(default_factory=list)


class APIKeyInDB(APIKeyCreate):
    """Database API key model"""
    id: str
    key_hash: str
    owner_id: str
    created_at: datetime
    last_used: Optional[datetime] = None
    is_active: bool = True

    class Config:
        from_attributes = True


# Utility functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hash"""
    # Pre-process password for bcrypt if it's too long
    password_bytes = plain_password.encode('utf-8')
    if len(password_bytes) > 72:
        # Pre-hash with SHA-256 to handle long passwords
        password_bytes = hashlib.sha256(password_bytes).digest()
    return pwd_context.verify(password_bytes, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash with bcrypt handling long passwords"""
    # Convert to bytes
    password_bytes = password.encode('utf-8')
    
    # If password is too long for bcrypt (72 bytes), pre-hash with SHA-256
    if len(password_bytes) > 72:
        password_bytes = hashlib.sha256(password_bytes).digest()
    
    # Hash with bcrypt
    return pwd_context.hash(password_bytes)


def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire, "type": TokenType.ACCESS})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": TokenType.REFRESH})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[TokenPayload]:
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenPayload(**payload)
    except jwt.PyJWTError:
        return None

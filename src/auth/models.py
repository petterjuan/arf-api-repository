"""
Authentication models and utilities for ARF API.
Psychology: Separation of concerns - authentication logic isolated from business logic.
Intention: Provide flexible auth supporting both human users (JWT) and machine clients (API keys).
"""
import hashlib
import os
from datetime import datetime, timedelta
from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field, EmailStr, validator, constr
import jwt
from passlib.context import CryptContext

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Password hashing context
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__ident="2b",  # Use modern bcrypt
    bcrypt__rounds=12,   # Secure default (can be increased for production)
)

# JWT settings from environment with fallbacks
SECRET_KEY = os.getenv("SECRET_KEY", "arf-super-secret-key-change-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Password policy from environment
MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "8"))
REQUIRE_UPPERCASE = os.getenv("REQUIRE_UPPERCASE", "true").lower() == "true"
REQUIRE_LOWERCASE = os.getenv("REQUIRE_LOWERCASE", "true").lower() == "true"
REQUIRE_DIGITS = os.getenv("REQUIRE_DIGITS", "true").lower() == "true"
REQUIRE_SPECIAL_CHARS = os.getenv("REQUIRE_SPECIAL_CHARS", "true").lower() == "true"


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
    iat: datetime
    type: TokenType
    roles: List[UserRole] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    jti: Optional[str] = None  # JWT ID for token revocation

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class UserBase(BaseModel):
    """Base user model"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_.-]+$')
    full_name: Optional[str] = Field(None, max_length=100)
    is_active: bool = True
    roles: List[UserRole] = Field(default=[UserRole.VIEWER])

    @validator('email')
    def validate_email_domain(cls, v):
        """Basic email domain validation"""
        if '@' not in v:
            raise ValueError('Invalid email format')
        return v.lower()


class UserCreate(UserBase):
    """User creation model"""
    password: constr(min_length=MIN_PASSWORD_LENGTH, max_length=128)
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Ensure password meets security requirements"""
        errors = []
        
        if len(v) < MIN_PASSWORD_LENGTH:
            errors.append(f'Password must be at least {MIN_PASSWORD_LENGTH} characters long')
        
        if REQUIRE_UPPERCASE and not any(c.isupper() for c in v):
            errors.append('Password must contain at least one uppercase letter')
        
        if REQUIRE_LOWERCASE and not any(c.islower() for c in v):
            errors.append('Password must contain at least one lowercase letter')
        
        if REQUIRE_DIGITS and not any(c.isdigit() for c in v):
            errors.append('Password must contain at least one digit')
        
        if REQUIRE_SPECIAL_CHARS and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in v):
            errors.append('Password must contain at least one special character')
        
        # Check for common weak passwords
        weak_passwords = [
            'password', '12345678', 'qwertyui', 'admin123', 'letmein',
            'welcome', 'monkey', 'dragon', 'password1'
        ]
        if v.lower() in weak_passwords:
            errors.append('Password is too common')
        
        if errors:
            raise ValueError('; '.join(errors))
        
        return v


class UserInDB(UserBase):
    """Database user model"""
    id: str
    hashed_password: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    account_locked_until: Optional[datetime] = None
    mfa_enabled: bool = False

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class Token(BaseModel):
    """Token response model"""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    scope: Optional[str] = None


class APIKeyCreate(BaseModel):
    """API key creation model"""
    name: str = Field(..., min_length=1, max_length=100)
    expires_days: Optional[int] = Field(30, ge=1, le=365)
    scopes: List[str] = Field(default_factory=list)
    description: Optional[str] = Field(None, max_length=500)


class APIKeyInDB(APIKeyCreate):
    """Database API key model"""
    id: str
    key_hash: str
    owner_id: str
    created_at: datetime
    last_used: Optional[datetime] = None
    is_active: bool = True
    revoked_at: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# Utility functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hash"""
    try:
        # Pre-process password for bcrypt if it's too long
        password_bytes = plain_password.encode('utf-8')
        if len(password_bytes) > 72:
            # Pre-hash with SHA-256 to handle long passwords
            password_bytes = hashlib.sha256(password_bytes).digest()
        return pwd_context.verify(password_bytes, hashed_password)
    except Exception:
        # Always return False on any error to prevent timing attacks
        pwd_context.dummy_verify()
        return False


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
    data: dict, 
    expires_delta: Optional[timedelta] = None,
    jti: Optional[str] = None
) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    now = datetime.utcnow()
    
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": TokenType.ACCESS,
        "jti": jti or os.urandom(16).hex()
    })
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict, jti: Optional[str] = None) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": TokenType.REFRESH,
        "jti": jti or os.urandom(16).hex()
    })
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[TokenPayload]:
    """Decode and validate JWT token"""
    try:
        # Verify token signature and claims
        payload = jwt.decode(
            token, 
            SECRET_KEY, 
            algorithms=[ALGORITHM],
            options={
                "require": ["exp", "iat", "sub", "type"],
                "verify_exp": True,
                "verify_iat": True,
            }
        )
        
        # Convert timestamps to datetime objects
        if "exp" in payload:
            payload["exp"] = datetime.fromtimestamp(payload["exp"])
        if "iat" in payload:
            payload["iat"] = datetime.fromtimestamp(payload["iat"])
        
        return TokenPayload(**payload)
    except jwt.ExpiredSignatureError:
        # Token has expired
        return None
    except jwt.InvalidTokenError:
        # Invalid token
        return None
    except Exception:
        # Any other error
        return None


def generate_api_key() -> str:
    """Generate a secure API key"""
    import secrets
    import base64
    
    # Generate 32 bytes of randomness
    key_bytes = secrets.token_bytes(32)
    
    # Encode in URL-safe base64 without padding
    key = base64.urlsafe_b64encode(key_bytes).decode('utf-8').rstrip('=')
    
    # Format with prefix for easy identification
    return f"arf_{key}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key for secure storage"""
    # Use a different pepper for API keys if desired
    api_key_with_pepper = api_key + SECRET_KEY[:16]
    return hashlib.sha256(api_key_with_pepper.encode('utf-8')).hexdigest()


def verify_api_key(plain_key: str, hashed_key: str) -> bool:
    """Verify an API key against its hash"""
    try:
        api_key_with_pepper = plain_key + SECRET_KEY[:16]
        computed_hash = hashlib.sha256(api_key_with_pepper.encode('utf-8')).hexdigest()
        return secrets.compare_digest(computed_hash, hashed_key)
    except Exception:
        return False

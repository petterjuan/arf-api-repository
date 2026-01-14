"""
Authentication models and utilities for ARF API.
Psychology: Separation of concerns - authentication logic isolated from business logic.
Intention: Provide flexible auth supporting both human users (JWT) and machine clients (API keys).
"""
import hashlib
import os
import secrets
import base64
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, EmailStr, validator, constr, root_validator
import jwt
from passlib.context import CryptContext

# Password hashing context - production secure configuration
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__ident="2b",  # Use modern bcrypt version
    bcrypt__rounds=14,   # Production secure (increased from 12 for better security)
)

# Load environment variables with proper fallbacks
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", os.getenv("JWT_SECRET", "arf-super-secret-key-change-in-production"))
if len(JWT_SECRET_KEY) < 32:
    raise ValueError("JWT_SECRET_KEY must be at least 32 characters long for production")

ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Password policy from environment
MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "12"))  # Increased for production
REQUIRE_UPPERCASE = os.getenv("REQUIRE_UPPERCASE", "true").lower() == "true"
REQUIRE_LOWERCASE = os.getenv("REQUIRE_LOWERCASE", "true").lower() == "true"
REQUIRE_DIGITS = os.getenv("REQUIRE_DIGITS", "true").lower() == "true"
REQUIRE_SPECIAL_CHARS = os.getenv("REQUIRE_SPECIAL_CHARS", "true").lower() == "true"


class TokenType(str, Enum):
    """Token type enumeration for clear intent"""
    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"
    RESET_PASSWORD = "reset_password"
    VERIFY_EMAIL = "verify_email"


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
    nbf: Optional[datetime] = None  # Not before
    type: TokenType
    roles: List[UserRole] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    jti: str  # JWT ID for token revocation
    iss: Optional[str] = "arf-api"  # Issuer
    aud: Optional[str] = "arf-client"  # Audience

    class Config:
        json_encoders = {
            datetime: lambda v: int(v.timestamp())
        }


class UserBase(BaseModel):
    """Base user model"""
    email: EmailStr
    username: str = Field(
        ..., 
        min_length=3, 
        max_length=50, 
        regex=r'^[a-zA-Z0-9_.-]+$',
        description="Username can contain letters, numbers, dots, dashes, and underscores"
    )
    full_name: Optional[str] = Field(None, max_length=100)
    is_active: bool = True
    roles: List[UserRole] = Field(default=[UserRole.VIEWER])
    email_verified: bool = False

    @validator('email')
    def validate_email_domain(cls, v):
        """Basic email domain validation"""
        if '@' not in v:
            raise ValueError('Invalid email format')
        # Convert to lowercase for consistency
        return v.lower().strip()


class UserCreate(UserBase):
    """User creation model"""
    password: constr(min_length=MIN_PASSWORD_LENGTH, max_length=128)
    password_confirm: str
    
    @validator('password_confirm')
    def passwords_match(cls, v, values, **kwargs):
        """Validate that password and confirmation match"""
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Ensure password meets security requirements"""
        errors = []
        
        # Check length
        if len(v) < MIN_PASSWORD_LENGTH:
            errors.append(f'Password must be at least {MIN_PASSWORD_LENGTH} characters long')
        
        # Check character composition
        if REQUIRE_UPPERCASE and not any(c.isupper() for c in v):
            errors.append('Password must contain at least one uppercase letter')
        
        if REQUIRE_LOWERCASE and not any(c.islower() for c in v):
            errors.append('Password must contain at least one lowercase letter')
        
        if REQUIRE_DIGITS and not any(c.isdigit() for c in v):
            errors.append('Password must contain at least one digit')
        
        if REQUIRE_SPECIAL_CHARS:
            special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?`~'
            if not any(c in special_chars for c in v):
                errors.append(f'Password must contain at least one special character: {special_chars}')
        
        # Check for common weak passwords
        common_passwords = [
            'password', '12345678', 'qwertyui', 'admin123', 'letmein',
            'welcome', 'monkey', 'dragon', 'password1', '1234567890',
            '123123123', '11111111', 'sunshine', 'iloveyou', 'football'
        ]
        if v.lower() in common_passwords:
            errors.append('Password is too common and easily guessable')
        
        # Check for sequential characters
        if any(str(i) * 3 in v for i in range(10)):
            errors.append('Password contains sequential numbers')
        
        if any(c * 3 in v.lower() for c in 'abcdefghijklmnopqrstuvwxyz'):
            errors.append('Password contains sequential letters')
        
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
    mfa_secret: Optional[str] = None
    last_password_change: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class UserResponse(UserBase):
    """User response model (excludes sensitive data)"""
    id: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class Token(BaseModel):
    """Token response model"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    scope: str = "read write"
    id_token: Optional[str] = None  # For OIDC compatibility


class APIKeyCreate(BaseModel):
    """API key creation model"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    expires_days: Optional[int] = Field(90, ge=1, le=365)  # Default 90 days for production
    scopes: List[str] = Field(default_factory=lambda: ["read"])
    ip_restrictions: Optional[List[str]] = Field(None, description="Allowed IP addresses")
    user_agent_restrictions: Optional[List[str]] = Field(None, description="Allowed user agents")


class APIKeyInDB(APIKeyCreate):
    """Database API key model"""
    id: str
    key_hash: str
    key_prefix: str  # First 8 chars for identification
    owner_id: str
    created_at: datetime
    last_used: Optional[datetime] = None
    last_ip: Optional[str] = None
    last_user_agent: Optional[str] = None
    usage_count: int = 0
    is_active: bool = True
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    revoked_reason: Optional[str] = None

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class APIKeyResponse(BaseModel):
    """API key response model (includes full key only once)"""
    id: str
    name: str
    key: str  # Only returned on creation
    key_prefix: str
    description: Optional[str]
    scopes: List[str]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    is_active: bool

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# Utility functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hash.
    
    Uses constant-time comparison to prevent timing attacks.
    """
    try:
        # Pre-process password for bcrypt if it's too long
        password_bytes = plain_password.encode('utf-8')
        if len(password_bytes) > 72:
            # Pre-hash with SHA-256 to handle long passwords
            # This is safe because bcrypt only accepts 72 bytes max
            password_bytes = hashlib.sha256(password_bytes).digest()
        
        # Use constant-time verification
        return pwd_context.verify(password_bytes, hashed_password)
    except Exception:
        # Always return False on any error to prevent timing attacks
        # Use dummy verify to maintain constant time
        pwd_context.dummy_verify()
        return False


def get_password_hash(password: str) -> str:
    """
    Generate password hash with bcrypt handling long passwords.
    
    For passwords longer than 72 bytes, we pre-hash with SHA-256
    to ensure compatibility with bcrypt's limitations.
    """
    # Convert to bytes
    password_bytes = password.encode('utf-8')
    
    # If password is too long for bcrypt (72 bytes), pre-hash with SHA-256
    if len(password_bytes) > 72:
        # Pre-hash with SHA-256 to handle long passwords
        # Note: This is secure because SHA-256 is collision-resistant
        password_bytes = hashlib.sha256(password_bytes).digest()
    
    # Hash with bcrypt with production-appropriate work factor
    return pwd_context.hash(password_bytes)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
    jti: Optional[str] = None,
    issuer: Optional[str] = None,
    audience: Optional[str] = None
) -> str:
    """Create JWT access token with production security features."""
    to_encode = data.copy()
    now = datetime.utcnow()
    
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Generate JTI (JWT ID) for token revocation if not provided
    token_jti = jti or secrets.token_urlsafe(32)
    
    to_encode.update({
        "exp": expire,
        "iat": now,
        "nbf": now,  # Not before
        "type": TokenType.ACCESS.value,
        "jti": token_jti,
        "iss": issuer or "arf-api",
        "aud": audience or "arf-client",
    })
    
    # Ensure subject is present
    if "sub" not in to_encode:
        raise ValueError("Token must have a subject (sub)")
    
    # Create token with algorithm specified
    return jwt.encode(
        to_encode, 
        JWT_SECRET_KEY, 
        algorithm=ALGORITHM,
        headers={
            "typ": "JWT",
            "alg": ALGORITHM,
            "kid": "arf-1"  # Key ID for key rotation
        }
    )


def create_refresh_token(
    data: Dict[str, Any],
    jti: Optional[str] = None,
    issuer: Optional[str] = None,
    audience: Optional[str] = None
) -> str:
    """Create JWT refresh token with production security features."""
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    # Generate JTI (JWT ID) for token revocation if not provided
    token_jti = jti or secrets.token_urlsafe(32)
    
    to_encode.update({
        "exp": expire,
        "iat": now,
        "nbf": now,
        "type": TokenType.REFRESH.value,
        "jti": token_jti,
        "iss": issuer or "arf-api",
        "aud": audience or "arf-client",
    })
    
    # Ensure subject is present
    if "sub" not in to_encode:
        raise ValueError("Refresh token must have a subject (sub)")
    
    return jwt.encode(
        to_encode, 
        JWT_SECRET_KEY, 
        algorithm=ALGORITHM,
        headers={
            "typ": "JWT",
            "alg": ALGORITHM,
            "kid": "arf-1"
        }
    )


def decode_token(token: str, verify: bool = True) -> Optional[TokenPayload]:
    """
    Decode and validate JWT token with production-grade validation.
    
    Args:
        token: JWT token string
        verify: Whether to verify the token signature and claims
        
    Returns:
        TokenPayload if valid, None otherwise
    """
    try:
        if verify:
            # Verify token signature and claims
            payload = jwt.decode(
                token, 
                JWT_SECRET_KEY, 
                algorithms=[ALGORITHM],
                options={
                    "require": ["exp", "iat", "sub", "type", "jti"],
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": False,  # nbf is optional
                },
                issuer="arf-api",
                audience="arf-client",
                leeway=30,  # 30 seconds leeway for clock skew
            )
        else:
            # Decode without verification (for debugging only)
            payload = jwt.decode(token, options={"verify_signature": False})
        
        # Convert timestamps to datetime objects
        if "exp" in payload:
            payload["exp"] = datetime.fromtimestamp(payload["exp"])
        if "iat" in payload:
            payload["iat"] = datetime.fromtimestamp(payload["iat"])
        if "nbf" in payload:
            payload["nbf"] = datetime.fromtimestamp(payload["nbf"])
        
        return TokenPayload(**payload)
    except jwt.ExpiredSignatureError:
        # Token has expired
        return None
    except jwt.InvalidTokenError as e:
        # Invalid token (signature, claims, etc.)
        return None
    except Exception:
        # Any other error
        return None


def generate_api_key() -> str:
    """Generate a secure API key for production use."""
    # Generate 32 bytes of cryptographically secure randomness
    key_bytes = secrets.token_bytes(32)
    
    # Encode in URL-safe base64 without padding
    key = base64.urlsafe_b64encode(key_bytes).decode('utf-8').rstrip('=')
    
    # Format with prefix for easy identification
    return f"arf_{key}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key for secure storage using SHA-256."""
    # Use a pepper from the secret key for additional security
    pepper = JWT_SECRET_KEY[:16] if JWT_SECRET_KEY else "arf-api-pepper"
    api_key_with_pepper = api_key + pepper
    
    # Hash with SHA-256
    return hashlib.sha256(api_key_with_pepper.encode('utf-8')).hexdigest()


def verify_api_key(plain_key: str, hashed_key: str) -> bool:
    """Verify an API key against its hash using constant-time comparison."""
    try:
        # Recreate the pepper
        pepper = JWT_SECRET_KEY[:16] if JWT_SECRET_KEY else "arf-api-pepper"
        api_key_with_pepper = plain_key + pepper
        
        # Compute hash
        computed_hash = hashlib.sha256(api_key_with_pepper.encode('utf-8')).hexdigest()
        
        # Use constant-time comparison
        return secrets.compare_digest(computed_hash, hashed_key)
    except Exception:
        # Always return False on any error
        return False


def get_api_key_prefix(api_key: str) -> str:
    """Get the prefix of an API key for display purposes."""
    if api_key.startswith("arf_"):
        # Return first 8 chars after prefix
        return api_key[:12]  # arf_ + 8 chars
    else:
        # Return first 8 chars
        return api_key[:8]


def create_password_reset_token(user_id: str, expires_minutes: int = 15) -> str:
    """Create a password reset token."""
    now = datetime.utcnow()
    expire = now + timedelta(minutes=expires_minutes)
    
    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": now,
        "type": TokenType.RESET_PASSWORD.value,
        "jti": secrets.token_urlsafe(32),
        "iss": "arf-api",
        "aud": "arf-client",
    }
    
    return jwt.encode(
        payload, 
        JWT_SECRET_KEY, 
        algorithm=ALGORITHM,
        headers={
            "typ": "JWT",
            "alg": ALGORITHM,
            "kid": "arf-reset"
        }
    )


def create_email_verification_token(user_id: str, email: str, expires_hours: int = 24) -> str:
    """Create an email verification token."""
    now = datetime.utcnow()
    expire = now + timedelta(hours=expires_hours)
    
    payload = {
        "sub": user_id,
        "email": email,
        "exp": expire,
        "iat": now,
        "type": TokenType.VERIFY_EMAIL.value,
        "jti": secrets.token_urlsafe(32),
        "iss": "arf-api",
        "aud": "arf-client",
    }
    
    return jwt.encode(
        payload, 
        JWT_SECRET_KEY, 
        algorithm=ALGORITHM,
        headers={
            "typ": "JWT",
            "alg": ALGORITHM,
            "kid": "arf-verify"
        }
    )

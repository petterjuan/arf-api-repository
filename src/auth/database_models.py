"""
Authentication database models.
Psychology: Extensible design allowing for future OAuth, SSO integrations.
Intention: Clear separation between authentication data and business data.
"""
from sqlalchemy import Column, String, Boolean, DateTime, JSON, Index
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID, ENUM
import uuid
from src.database import Base

# Create ENUM types in database
from sqlalchemy.dialects.postgresql import ENUM as PGEnum

class UserDB(Base):
    """User database model"""
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255))
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # JSON array of roles stored as text for simplicity
    # In production, consider a separate roles table
    roles = Column(JSON, default=["viewer"])
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Audit fields
    created_by = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)
    
    # Indexes
    __table_args__ = (
        Index('ix_users_email_active', 'email', 'is_active'),
        Index('ix_users_created_at', 'created_at'),
    )

class APIKeyDB(Base):
    """API key database model"""
    __tablename__ = "api_keys"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False, index=True)
    owner_id = Column(String, nullable=False, index=True)
    
    # Metadata
    scopes = Column(JSON, default=[])
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used = Column(DateTime(timezone=True), nullable=True)
    
    # Usage tracking
    usage_count = Column(JSON, default={})  # {"endpoint": count}
    
    # Indexes
    __table_args__ = (
        Index('ix_api_keys_owner_active', 'owner_id', 'is_active'),
        Index('ix_api_keys_expires_at', 'expires_at'),
    )

class RefreshTokenDB(Base):
    """Refresh token database model for token revocation"""
    __tablename__ = "refresh_tokens"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    token_hash = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(String, nullable=False, index=True)
    
    # Metadata
    is_revoked = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('ix_refresh_tokens_user_expires', 'user_id', 'expires_at'),
    )

# File: backend/app/models/user.py
"""
User management models for authentication and authorization.

This module defines models for:
- User accounts with comprehensive authentication features
- User sessions and JWT token management
- User invitations for team management
- OAuth provider integrations
- API key management for developers
"""

from datetime import datetime
from typing import Optional, List, TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    String,
    Boolean,
    DateTime,
    Text,
    Integer,
    ForeignKey,
    CheckConstraint,
    Index,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID, JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.auth import AuthAuditLog


class User(Base):
    """
    User model with comprehensive authentication and authorization features.
    
    Supports multi-tenant organizations, OAuth integration, 2FA, and
    comprehensive security features including account lockout and audit logging.
    
    Attributes:
        id: Unique user identifier
        organization_id: Reference to user's organization
        email: User's email address (unique)
        password_hash: Hashed password
        first_name: User's first name
        last_name: User's last name
        avatar_url: URL to user's avatar image
        phone: User's phone number
        timezone: User's timezone preference
        locale: User's locale/language preference
        role: User's role within organization
        permissions: JSON object with granular permissions
        account status and verification fields
        security and tracking fields
        social authentication fields
        audit and metadata fields
    """
    
    __tablename__ = "users"
    
    # Primary identifier
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        comment="Unique user identifier"
    )
    
    # Organization relationship (multi-tenant)
    organization_id: Mapped[Optional[UUID]] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Reference to user's organization"
    )
    
    # Basic user information
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="User's email address"
    )
    
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Hashed password using bcrypt"
    )
    
    first_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="User's first name"
    )
    
    last_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="User's last name"
    )
    
    avatar_url: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="URL to user's avatar image"
    )
    
    phone: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
        comment="User's phone number"
    )
    
    timezone: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="UTC",
        comment="User's timezone preference"
    )
    
    locale: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="en",
        comment="User's locale/language preference"
    )
    
    # Role and permissions
    role: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="member",
        comment="User's role: owner, admin, member, viewer, developer"
    )
    
    permissions: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Granular permissions JSON object"
    )
    
    # Account status and verification
    is_email_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether email is verified"
    )
    
    is_phone_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether phone is verified"
    )
    
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Whether user account is active"
    )
    
    account_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="active",
        comment="Account status: active, suspended, pending, deactivated"
    )
    
    # Email verification
    email_verification_token: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        unique=True,
        comment="Token for email verification"
    )
    
    email_verification_expires: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Email verification token expiration"
    )
    
    # Phone verification
    phone_verification_token: Mapped[Optional[str]] = mapped_column(
        String(6),
        nullable=True,
        comment="SMS OTP for phone verification"
    )
    
    phone_verification_expires: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Phone verification token expiration"
    )
    
    # Password reset
    password_reset_token: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        unique=True,
        comment="Token for password reset"
    )
    
    password_reset_expires: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Password reset token expiration"
    )
    
    password_reset_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of password reset attempts"
    )
    
    # Security and tracking
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last successful login timestamp"
    )
    
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of consecutive failed login attempts"
    )
    
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Account locked until this timestamp"
    )
    
    force_password_reset: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether user must reset password on next login"
    )
    
    # Two-factor authentication
    two_factor_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether 2FA is enabled"
    )
    
    two_factor_secret: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Encrypted 2FA secret key"
    )
    
    backup_codes: Mapped[Optional[List[str]]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Encrypted backup codes for 2FA"
    )
    
    # Social authentication
    google_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        unique=True,
        comment="Google OAuth user ID"
    )
    
    microsoft_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        unique=True,
        comment="Microsoft OAuth user ID"
    )
    
    github_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        unique=True,
        comment="GitHub OAuth user ID"
    )
    
    # Audit and metadata
    last_password_change: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        comment="Last password change timestamp"
    )
    
    terms_accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Terms of service acceptance timestamp"
    )
    
    privacy_policy_accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Privacy policy acceptance timestamp"
    )
    
    marketing_consent: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether user consented to marketing communications"
    )
    
    onboarding_completed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether user completed onboarding"
    )
    
    preferences: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="User preferences (theme, notifications, etc.)"
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        comment="User creation timestamp"
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        onupdate=datetime.utcnow,
        comment="Last modification timestamp"
    )
    
    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship(
        "Organization",
        back_populates="users"
    )
    
    sessions: Mapped[List["UserSession"]] = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    
    oauth_providers: Mapped[List["OAuthProvider"]] = relationship(
        "OAuthProvider",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    
    api_keys: Mapped[List["APIKey"]] = relationship(
        "APIKey",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    
    auth_audit_logs: Mapped[List["AuthAuditLog"]] = relationship(
        "AuthAuditLog",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    
    sent_invitations: Mapped[List["UserInvitation"]] = relationship(
        "UserInvitation",
        back_populates="invited_by_user",
        foreign_keys="UserInvitation.invited_by",
        lazy="dynamic"
    )
    
    # Table constraints
    __table_args__ = (
        CheckConstraint(
            "role IN ('owner', 'admin', 'member', 'viewer', 'developer')",
            name="ck_users_role"
        ),
        CheckConstraint(
            "account_status IN ('active', 'suspended', 'pending', 'deactivated')",
            name="ck_users_account_status"
        ),
        CheckConstraint(
            "failed_login_attempts >= 0",
            name="ck_users_failed_login_attempts_non_negative"
        ),
        CheckConstraint(
            "password_reset_attempts >= 0",
            name="ck_users_password_reset_attempts_non_negative"
        ),
        CheckConstraint(
            "char_length(first_name) >= 1",
            name="ck_users_first_name_not_empty"
        ),
        CheckConstraint(
            "char_length(last_name) >= 1",
            name="ck_users_last_name_not_empty"
        ),
        # Indexes for performance
        Index("ix_users_organization_role", "organization_id", "role"),
        Index("ix_users_active", "is_active", "is_email_verified"),
        Index("ix_users_last_login", "last_login"),
        Index("ix_users_locked", "locked_until"),
    )
    
    def __repr__(self) -> str:
        """String representation of the user."""
        return f"<User(id={self.id}, email='{self.email}', role='{self.role}')>"
    
    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"{self.first_name} {self.last_name} ({self.email})"
    
    # Business logic methods
    
    @property
    def full_name(self) -> str:
        """Get user's full name."""
        return f"{self.first_name} {self.last_name}"
    
    def is_account_locked(self) -> bool:
        """Check if the account is currently locked."""
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until
    
    def can_login(self) -> bool:
        """Check if user can log in."""
        return (
            self.is_active and
            self.is_email_verified and
            self.account_status == "active" and
            not self.is_account_locked()
        )
    
    def has_permission(self, permission: str) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            permission: Permission to check
            
        Returns:
            bool: True if user has permission
        """
        if not self.permissions:
            return False
        return self.permissions.get(permission, False)
    
    def grant_permission(self, permission: str) -> None:
        """
        Grant a permission to the user.
        
        Args:
            permission: Permission to grant
        """
        if self.permissions is None:
            self.permissions = {}
        self.permissions[permission] = True
    
    def revoke_permission(self, permission: str) -> None:
        """
        Revoke a permission from the user.
        
        Args:
            permission: Permission to revoke
        """
        if self.permissions and permission in self.permissions:
            del self.permissions[permission]
    
    def is_organization_owner(self) -> bool:
        """Check if user is the organization owner."""
        return self.role == "owner"
    
    def is_organization_admin(self) -> bool:
        """Check if user is an organization admin or owner."""
        return self.role in ("owner", "admin")
    
    def can_manage_users(self) -> bool:
        """Check if user can manage other users."""
        return self.is_organization_admin() or self.has_permission("manage_users")
    
    def get_preference(self, preference_name: str, default=None):
        """
        Get a user preference.
        
        Args:
            preference_name: Name of the preference
            default: Default value if preference not found
            
        Returns:
            Preference value or default
        """
        if self.preferences is None:
            return default
        return self.preferences.get(preference_name, default)
    
    def set_preference(self, preference_name: str, preference_value) -> None:
        """
        Set a user preference.
        
        Args:
            preference_name: Name of the preference
            preference_value: Value to set
        """
        if self.preferences is None:
            self.preferences = {}
        self.preferences[preference_name] = preference_value


class UserSession(Base):
    """
    User session model for JWT token tracking and management.
    
    Tracks active user sessions with device information, IP addresses,
    and JWT token identifiers for security and session management.
    """
    
    __tablename__ = "user_sessions"
    
    # Primary identifier
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        comment="Unique session identifier"
    )
    
    # User relationship
    user_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Reference to user"
    )
    
    # JWT token tracking
    access_token_jti: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        comment="JWT ID for access token"
    )
    
    refresh_token_jti: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        comment="JWT ID for refresh token"
    )
    
    # Device and location information
    device_info: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Device fingerprint and browser info"
    )
    
    ip_address: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
        comment="Client IP address"
    )
    
    user_agent: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="User agent string"
    )
    
    location: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Geo location information"
    )
    
    # Session status and lifecycle
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether session is active"
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        comment="Session creation timestamp"
    )
    
    last_used: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        comment="Last session activity timestamp"
    )
    
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Session expiration timestamp"
    )
    
    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="sessions"
    )
    
    # Table constraints
    __table_args__ = (
        Index("ix_user_sessions_user_active", "user_id", "is_active"),
        Index("ix_user_sessions_expires", "expires_at"),
        Index("ix_user_sessions_last_used", "last_used"),
        Index("ix_user_sessions_jti", "access_token_jti", "refresh_token_jti"),
    )
    
    def __repr__(self) -> str:
        """String representation of the session."""
        return f"<UserSession(id={self.id}, user_id={self.user_id}, active={self.is_active})>"
    
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if the session is valid and active."""
        return self.is_active and not self.is_expired()


class UserInvitation(Base):
    """
    User invitation model for team management.
    
    Manages invitations sent to new users to join an organization
    with specific roles and permissions.
    """
    
    __tablename__ = "user_invitations"
    
    # Primary identifier
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        comment="Unique invitation identifier"
    )
    
    # Organization and user relationships
    organization_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Reference to organization"
    )
    
    invited_by: Mapped[Optional[UUID]] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User who sent the invitation"
    )
    
    # Invitation details
    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Email address of invited user"
    )
    
    role: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Role to assign to invited user"
    )
    
    permissions: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Permissions to assign to invited user"
    )
    
    invitation_token: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        comment="Unique invitation token"
    )
    
    # Status and lifecycle
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Invitation expiration timestamp"
    )
    
    accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Invitation acceptance timestamp"
    )
    
    is_used: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether invitation has been used"
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        comment="Invitation creation timestamp"
    )
    
    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization"
    )
    
    invited_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="sent_invitations",
        foreign_keys=[invited_by]
    )
    
    # Table constraints
    __table_args__ = (
        CheckConstraint(
            "role IN ('owner', 'admin', 'member', 'viewer', 'developer')",
            name="ck_user_invitations_role"
        ),
        Index("ix_user_invitations_email", "email", "is_used"),
        Index("ix_user_invitations_token", "invitation_token"),
        Index("ix_user_invitations_org", "organization_id", "is_used"),
        Index("ix_user_invitations_expires", "expires_at"),
    )
    
    def __repr__(self) -> str:
        """String representation of the invitation."""
        return f"<UserInvitation(id={self.id}, email='{self.email}', role='{self.role}')>"
    
    def is_expired(self) -> bool:
        """Check if the invitation has expired."""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if the invitation is valid and can be accepted."""
        return not self.is_used and not self.is_expired()


class OAuthProvider(Base):
    """
    OAuth provider model for social authentication.
    
    Stores OAuth provider connections for users including
    encrypted tokens and provider-specific data.
    """
    
    __tablename__ = "oauth_providers"
    
    # Primary identifier
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        comment="Unique OAuth provider record identifier"
    )
    
    # User relationship
    user_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Reference to user"
    )
    
    # Provider information
    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="OAuth provider name (google, microsoft, github)"
    )
    
    provider_user_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="User ID from OAuth provider"
    )
    
    provider_email: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Email from OAuth provider"
    )
    
    provider_data: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Additional provider data"
    )
    
    # Token storage (encrypted)
    access_token_encrypted: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Encrypted OAuth access token"
    )
    
    refresh_token_encrypted: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Encrypted OAuth refresh token"
    )
    
    token_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="OAuth token expiration timestamp"
    )
    
    # Status and metadata
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether OAuth connection is active"
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        comment="OAuth connection creation timestamp"
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        onupdate=datetime.utcnow,
        comment="Last modification timestamp"
    )
    
    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="oauth_providers"
    )
    
    # Table constraints
    __table_args__ = (
        UniqueConstraint(
            "provider", "provider_user_id",
            name="uq_oauth_providers_provider_user"
        ),
        CheckConstraint(
            "provider IN ('google', 'microsoft', 'github')",
            name="ck_oauth_providers_provider"
        ),
        Index("ix_oauth_providers_user", "user_id", "provider"),
        Index("ix_oauth_providers_provider_id", "provider", "provider_user_id"),
    )
    
    def __repr__(self) -> str:
        """String representation of the OAuth provider."""
        return f"<OAuthProvider(id={self.id}, provider='{self.provider}', user_id={self.user_id})>"


class APIKey(Base):
    """
    API key model for developer access and integrations.
    
    Manages API keys for programmatic access to the platform
    with specific permissions and rate limiting.
    """
    
    __tablename__ = "api_keys"
    
    # Primary identifier
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        comment="Unique API key identifier"
    )
    
    # User and organization relationships
    user_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Reference to user who created the API key"
    )
    
    organization_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Reference to organization"
    )
    
    # API key details
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable name for the API key"
    )
    
    key_hash: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        comment="Hashed API key for secure storage"
    )
    
    key_prefix: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="First few characters for identification"
    )
    
    # Permissions and limits
    permissions: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="API-specific permissions"
    )
    
    rate_limit_per_minute: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1000,
        comment="Rate limit per minute"
    )
    
    # Status and usage
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether API key is active"
    )
    
    last_used: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last usage timestamp"
    )
    
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="API key expiration timestamp"
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        comment="API key creation timestamp"
    )
    
    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="api_keys"
    )
    
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="api_keys"
    )
    
    # Table constraints
    __table_args__ = (
        CheckConstraint(
            "rate_limit_per_minute > 0",
            name="ck_api_keys_rate_limit_positive"
        ),
        Index("ix_api_keys_user_active", "user_id", "is_active"),
        Index("ix_api_keys_org_active", "organization_id", "is_active"),
        Index("ix_api_keys_hash", "key_hash"),
        Index("ix_api_keys_expires", "expires_at"),
    )
    
    def __repr__(self) -> str:
        """String representation of the API key."""
        return f"<APIKey(id={self.id}, name='{self.name}', prefix='{self.key_prefix}')>"
    
    def is_expired(self) -> bool:
        """Check if the API key has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if the API key is valid and active."""
        return self.is_active and not self.is_expired()
    
    def has_permission(self, permission: str) -> bool:
        """
        Check if API key has a specific permission.
        
        Args:
            permission: Permission to check
            
        Returns:
            bool: True if API key has permission
        """
        if not self.permissions:
            return False
        return self.permissions.get(permission, False)
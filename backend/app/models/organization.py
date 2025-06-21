# File: backend/app/models/organization.py
"""
Organization model for multi-tenant architecture.

This module defines the Organization model which provides:
- Multi-tenant data isolation
- Subscription and billing management
- Organization-wide settings and configurations
- Credit system and usage tracking
"""

from datetime import datetime
from decimal import Decimal
from typing import Optional, List, TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    String, 
    Boolean, 
    DateTime, 
    Text,
    Numeric,
    CheckConstraint,
    Index,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User, APIKey
    from app.models.auth import AuthAuditLog, SecuritySettings


class Organization(Base):
    """
    Organization model for multi-tenant architecture.
    
    Each organization represents a separate tenant with isolated data,
    subscription management, and billing. This enables the platform to
    serve multiple businesses while maintaining data separation.
    
    Attributes:
        id: Unique organization identifier
        name: Organization display name
        slug: URL-friendly organization identifier
        domain: Company domain for SSO (optional)
        subscription_tier: Subscription plan level
        subscription_status: Current subscription status
        trial_ends_at: Trial expiration date
        billing_email: Email for billing notifications
        settings: JSON configuration for organization preferences
        credit_balance: Current credit balance for usage-based billing
        usage_limits: JSON configuration for usage limits per plan
        is_active: Whether the organization is active
        created_at: Organization creation timestamp
        updated_at: Last modification timestamp
    """
    
    __tablename__ = "organizations"
    
    # Primary identifier
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        comment="Unique organization identifier"
    )
    
    # Basic organization information
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Organization display name"
    )
    
    slug: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="URL-friendly organization identifier"
    )
    
    domain: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        unique=True,
        index=True,
        comment="Company domain for SSO integration"
    )
    
    # Subscription management
    subscription_tier: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="free",
        comment="Subscription plan: free, pro, enterprise, developer, agency"
    )
    
    subscription_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="active",
        comment="Subscription status: active, cancelled, suspended, trial"
    )
    
    trial_ends_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Trial expiration date"
    )
    
    billing_email: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Email address for billing notifications"
    )
    
    # Configuration and settings
    settings: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Organization-specific settings and preferences"
    )
    
    # Credit system for usage-based billing
    credit_balance: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False,
        default=Decimal("0.00"),
        comment="Current credit balance"
    )
    
    usage_limits: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Usage limits configuration per subscription plan"
    )
    
    # Status and metadata
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Whether the organization is active"
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        comment="Organization creation timestamp"
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        onupdate=datetime.utcnow,
        comment="Last modification timestamp"
    )
    
    # Relationships (will be uncommented as we add more models)
    users: Mapped[List["User"]] = relationship(
        "User",
        back_populates="organization",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    
    # agents: Mapped[List["Agent"]] = relationship(
    #     "Agent",
    #     back_populates="organization", 
    #     cascade="all, delete-orphan",
    #     lazy="dynamic"
    # )
    
    api_keys: Mapped[List["APIKey"]] = relationship(
        "APIKey",
        back_populates="organization",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    
    auth_audit_logs: Mapped[List["AuthAuditLog"]] = relationship(
        "AuthAuditLog",
        back_populates="organization",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    
    security_settings: Mapped[Optional["SecuritySettings"]] = relationship(
        "SecuritySettings",
        back_populates="organization",
        uselist=False,
        cascade="all, delete-orphan"
    )
    
    # Table constraints
    __table_args__ = (
        CheckConstraint(
            "subscription_tier IN ('free', 'pro', 'enterprise', 'developer', 'agency')",
            name="ck_organizations_subscription_tier"
        ),
        CheckConstraint(
            "subscription_status IN ('active', 'cancelled', 'suspended', 'trial')",
            name="ck_organizations_subscription_status"
        ),
        CheckConstraint(
            "credit_balance >= 0",
            name="ck_organizations_credit_balance_non_negative"
        ),
        CheckConstraint(
            "char_length(name) >= 1",
            name="ck_organizations_name_not_empty"
        ),
        CheckConstraint(
            "char_length(slug) >= 1",
            name="ck_organizations_slug_not_empty"
        ),
        # Indexes for performance
        Index("ix_organizations_subscription", "subscription_tier", "subscription_status"),
        Index("ix_organizations_active", "is_active", "created_at"),
        Index("ix_organizations_trial", "trial_ends_at"),
    )
    
    def __repr__(self) -> str:
        """String representation of the organization."""
        return f"<Organization(id={self.id}, name='{self.name}', slug='{self.slug}')>"
    
    def __str__(self) -> str:
        """Human-readable string representation."""
        return self.name
    
    # Business logic methods
    
    def is_trial_expired(self) -> bool:
        """
        Check if the organization's trial period has expired.
        
        Returns:
            bool: True if trial has expired, False otherwise
        """
        if not self.trial_ends_at:
            return False
        return datetime.utcnow() > self.trial_ends_at
    
    def is_subscription_active(self) -> bool:
        """
        Check if the organization has an active subscription.
        
        Returns:
            bool: True if subscription is active, False otherwise
        """
        return (
            self.subscription_status == "active" and
            self.is_active and
            not self.is_trial_expired()
        )
    
    def has_sufficient_credits(self, required_credits: Decimal) -> bool:
        """
        Check if the organization has sufficient credits for an operation.
        
        Args:
            required_credits: Number of credits required
            
        Returns:
            bool: True if sufficient credits available, False otherwise
        """
        return self.credit_balance >= required_credits
    
    def deduct_credits(self, amount: Decimal) -> bool:
        """
        Deduct credits from the organization's balance.
        
        Args:
            amount: Amount of credits to deduct
            
        Returns:
            bool: True if deduction successful, False if insufficient credits
        """
        if not self.has_sufficient_credits(amount):
            return False
        
        self.credit_balance -= amount
        return True
    
    def add_credits(self, amount: Decimal) -> None:
        """
        Add credits to the organization's balance.
        
        Args:
            amount: Amount of credits to add
        """
        self.credit_balance += amount
    
    def get_usage_limit(self, limit_type: str) -> Optional[int]:
        """
        Get a specific usage limit for the organization.
        
        Args:
            limit_type: Type of limit to retrieve
            
        Returns:
            int: Limit value or None if not set
        """
        return self.usage_limits.get(limit_type)
    
    def set_usage_limit(self, limit_type: str, limit_value: int) -> None:
        """
        Set a usage limit for the organization.
        
        Args:
            limit_type: Type of limit to set
            limit_value: Limit value to set
        """
        if self.usage_limits is None:
            self.usage_limits = {}
        self.usage_limits[limit_type] = limit_value
    
    def get_setting(self, setting_name: str, default=None):
        """
        Get an organization setting.
        
        Args:
            setting_name: Name of the setting
            default: Default value if setting not found
            
        Returns:
            Setting value or default
        """
        if self.settings is None:
            return default
        return self.settings.get(setting_name, default)
    
    def set_setting(self, setting_name: str, setting_value) -> None:
        """
        Set an organization setting.
        
        Args:
            setting_name: Name of the setting
            setting_value: Value to set
        """
        if self.settings is None:
            self.settings = {}
        self.settings[setting_name] = setting_value
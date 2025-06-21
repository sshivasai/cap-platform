# File: backend/app/models/auth.py
"""
Authentication and security models.

This module defines models for:
- Authentication audit logging
- Security settings and policies
- Session tracking and management
"""

from datetime import datetime
from typing import Optional, TYPE_CHECKING
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
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID, JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.organization import Organization


class AuthAuditLog(Base):
    """
    Authentication audit log for security tracking and compliance.
    
    Logs all authentication-related events including successful logins,
    failed attempts, password changes, and security events for audit
    and security monitoring purposes.
    
    Attributes:
        id: Unique audit log entry identifier
        user_id: Reference to user (nullable for failed attempts)
        organization_id: Reference to organization
        event_type: Type of authentication event
        event_details: JSON object with event-specific details
        ip_address: Client IP address
        user_agent: User agent string
        success: Whether the event was successful
        error_message: Error message for failed events
        risk_score: Security risk assessment score
        created_at: Event timestamp
    """
    
    __tablename__ = "auth_audit_log"
    
    # Primary identifier
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        comment="Unique audit log entry identifier"
    )
    
    # User and organization relationships (nullable for failed attempts)
    user_id: Mapped[Optional[UUID]] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Reference to user (null for failed attempts)"
    )
    
    organization_id: Mapped[Optional[UUID]] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Reference to organization"
    )
    
    # Event information
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Type of authentication event"
    )
    
    event_details: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Event-specific details and metadata"
    )
    
    # Request information
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
    
    # Event outcome
    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether the event was successful"
    )
    
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Error message for failed events"
    )
    
    # Security assessment
    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Security risk assessment score (0-100)"
    )
    
    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        index=True,
        comment="Event timestamp"
    )
    
    # Relationships
    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="auth_audit_logs"
    )
    
    organization: Mapped[Optional["Organization"]] = relationship(
        "Organization",
        back_populates="auth_audit_logs"
    )
    
    # Table constraints
    __table_args__ = (
        CheckConstraint(
            "event_type IN ("
            "'login', 'logout', 'failed_login', 'password_reset', "
            "'password_change', 'email_verification', 'phone_verification', "
            "'account_locked', 'account_unlocked', 'account_created', "
            "'account_deactivated', 'oauth_login', 'oauth_link', "
            "'oauth_unlink', 'api_key_created', 'api_key_used', "
            "'api_key_revoked', 'two_factor_enabled', 'two_factor_disabled', "
            "'two_factor_verified', 'permission_changed', 'role_changed', "
            "'suspicious_activity', 'security_alert'"
            ")",
            name="ck_auth_audit_log_event_type"
        ),
        CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name="ck_auth_audit_log_risk_score_range"
        ),
        # Indexes for performance
        Index("ix_auth_audit_user_time", "user_id", "created_at"),
        Index("ix_auth_audit_org_time", "organization_id", "created_at"),
        Index("ix_auth_audit_event_time", "event_type", "created_at"),
        Index("ix_auth_audit_success_time", "success", "created_at"),
        Index("ix_auth_audit_risk_time", "risk_score", "created_at"),
        Index("ix_auth_audit_ip", "ip_address", "created_at"),
    )
    
    def __repr__(self) -> str:
        """String representation of the audit log entry."""
        return (
            f"<AuthAuditLog(id={self.id}, event_type='{self.event_type}', "
            f"success={self.success}, risk_score={self.risk_score})>"
        )
    
    def __str__(self) -> str:
        """Human-readable string representation."""
        status = "SUCCESS" if self.success else "FAILED"
        return f"{self.event_type.upper()} - {status} (Risk: {self.risk_score})"
    
    # Business logic methods
    
    def is_high_risk(self) -> bool:
        """Check if this event is considered high risk."""
        return self.risk_score >= 70
    
    def is_security_event(self) -> bool:
        """Check if this is a security-related event."""
        security_events = {
            "failed_login", "account_locked", "suspicious_activity", 
            "security_alert", "oauth_unlink", "permission_changed"
        }
        return self.event_type in security_events
    
    def get_event_detail(self, key: str, default=None):
        """
        Get a specific detail from the event details.
        
        Args:
            key: Detail key to retrieve
            default: Default value if key not found
            
        Returns:
            Detail value or default
        """
        if not self.event_details:
            return default
        return self.event_details.get(key, default)
    
    def add_event_detail(self, key: str, value) -> None:
        """
        Add a detail to the event details.
        
        Args:
            key: Detail key
            value: Detail value
        """
        if self.event_details is None:
            self.event_details = {}
        self.event_details[key] = value
    
    @classmethod
    def create_login_event(
        cls,
        user_id: Optional[UUID] = None,
        organization_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        details: Optional[dict] = None
    ) -> "AuthAuditLog":
        """
        Create a login audit log entry.
        
        Args:
            user_id: User identifier
            organization_id: Organization identifier
            ip_address: Client IP address
            user_agent: User agent string
            success: Whether login was successful
            error_message: Error message for failed logins
            details: Additional event details
            
        Returns:
            AuthAuditLog: Created audit log entry
        """
        risk_score = 0
        if not success:
            risk_score = 30  # Failed login has moderate risk
        
        return cls(
            user_id=user_id,
            organization_id=organization_id,
            event_type="login" if success else "failed_login",
            event_details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            error_message=error_message,
            risk_score=risk_score
        )
    
    @classmethod
    def create_security_event(
        cls,
        event_type: str,
        user_id: Optional[UUID] = None,
        organization_id: Optional[UUID] = None,
        risk_score: int = 50,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> "AuthAuditLog":
        """
        Create a security audit log entry.
        
        Args:
            event_type: Type of security event
            user_id: User identifier
            organization_id: Organization identifier
            risk_score: Security risk score (0-100)
            details: Additional event details
            ip_address: Client IP address
            user_agent: User agent string
            
        Returns:
            AuthAuditLog: Created audit log entry
        """
        return cls(
            user_id=user_id,
            organization_id=organization_id,
            event_type=event_type,
            event_details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,  # Security events are logged as "successful" logs
            risk_score=risk_score
        )


class SecuritySettings(Base):
    """
    Security settings and policies for organizations.
    
    Defines organization-level security policies including password
    requirements, session settings, IP restrictions, and security
    configurations that apply to all users in the organization.
    
    Attributes:
        id: Unique security settings identifier
        organization_id: Reference to organization
        password_policy: JSON object with password requirements
        session_settings: JSON object with session configurations
        ip_whitelist: JSON array of allowed IP ranges
        security_questions_required: Whether security questions are required
        created_at: Settings creation timestamp
        updated_at: Last modification timestamp
    """
    
    __tablename__ = "security_settings"
    
    # Primary identifier
    id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        comment="Unique security settings identifier"
    )
    
    # Organization relationship (one-to-one)
    organization_id: Mapped[UUID] = mapped_column(
        PostgresUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        comment="Reference to organization"
    )
    
    # Password policy configuration
    password_policy: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: {
            "min_length": 8,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special_chars": True,
            "max_age_days": 90,
            "prevent_reuse_count": 5,
            "complexity_score_min": 50
        },
        comment="Password policy configuration"
    )
    
    # Session security settings
    session_settings: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: {
            "max_session_duration_hours": 24,
            "idle_timeout_minutes": 30,
            "require_2fa": False,
            "allow_concurrent_sessions": True,
            "max_concurrent_sessions": 5,
            "require_fresh_login_for_sensitive": True,
            "session_rotation_interval_hours": 6
        },
        comment="Session security configuration"
    )
    
    # IP access control
    ip_whitelist: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="Array of allowed IP ranges (CIDR notation)"
    )
    
    # Additional security features
    security_questions_required: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether security questions are required"
    )
    
    # Audit and compliance settings
    audit_settings: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: {
            "log_all_actions": True,
            "log_retention_days": 365,
            "alert_on_suspicious_activity": True,
            "alert_on_failed_logins": 5,
            "alert_on_new_device": True
        },
        comment="Audit and compliance configuration"
    )
    
    # API security settings
    api_security: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: {
            "require_api_key_rotation": False,
            "api_key_max_age_days": 365,
            "rate_limiting_enabled": True,
            "rate_limit_per_minute": 1000,
            "require_https": True
        },
        comment="API security configuration"
    )
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        comment="Settings creation timestamp"
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        onupdate=datetime.utcnow,
        comment="Last modification timestamp"
    )
    
    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="security_settings"
    )
    
    # Table constraints
    __table_args__ = (
        Index("ix_security_settings_org", "organization_id"),
    )
    
    def __repr__(self) -> str:
        """String representation of the security settings."""
        return f"<SecuritySettings(id={self.id}, organization_id={self.organization_id})>"
    
    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"Security Settings for Organization {self.organization_id}"
    
    # Business logic methods
    
    def get_password_requirement(self, requirement: str, default=None):
        """
        Get a specific password requirement.
        
        Args:
            requirement: Requirement name
            default: Default value if requirement not found
            
        Returns:
            Requirement value or default
        """
        if not self.password_policy:
            return default
        return self.password_policy.get(requirement, default)
    
    def set_password_requirement(self, requirement: str, value) -> None:
        """
        Set a password requirement.
        
        Args:
            requirement: Requirement name
            value: Requirement value
        """
        if self.password_policy is None:
            self.password_policy = {}
        self.password_policy[requirement] = value
    
    def get_session_setting(self, setting: str, default=None):
        """
        Get a specific session setting.
        
        Args:
            setting: Setting name
            default: Default value if setting not found
            
        Returns:
            Setting value or default
        """
        if not self.session_settings:
            return default
        return self.session_settings.get(setting, default)
    
    def set_session_setting(self, setting: str, value) -> None:
        """
        Set a session setting.
        
        Args:
            setting: Setting name
            value: Setting value
        """
        if self.session_settings is None:
            self.session_settings = {}
        self.session_settings[setting] = value
    
    def is_ip_allowed(self, ip_address: str) -> bool:
        """
        Check if an IP address is allowed based on whitelist.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            bool: True if IP is allowed (or no whitelist configured)
        """
        # If no whitelist is configured, allow all IPs
        if not self.ip_whitelist:
            return True
        
        # Import here to avoid circular imports
        import ipaddress
        
        try:
            ip = ipaddress.ip_address(ip_address)
            for allowed_range in self.ip_whitelist:
                if ip in ipaddress.ip_network(allowed_range, strict=False):
                    return True
            return False
        except (ipaddress.AddressValueError, ValueError):
            # If IP parsing fails, deny access
            return False
    
    def add_ip_to_whitelist(self, ip_range: str) -> None:
        """
        Add an IP range to the whitelist.
        
        Args:
            ip_range: IP range in CIDR notation
        """
        if self.ip_whitelist is None:
            self.ip_whitelist = []
        
        # Validate IP range format
        import ipaddress
        try:
            ipaddress.ip_network(ip_range, strict=False)
            if ip_range not in self.ip_whitelist:
                self.ip_whitelist.append(ip_range)
        except (ipaddress.AddressValueError, ValueError) as e:
            raise ValueError(f"Invalid IP range format: {ip_range}") from e
    
    def remove_ip_from_whitelist(self, ip_range: str) -> None:
        """
        Remove an IP range from the whitelist.
        
        Args:
            ip_range: IP range to remove
        """
        if self.ip_whitelist and ip_range in self.ip_whitelist:
            self.ip_whitelist.remove(ip_range)
    
    def requires_2fa(self) -> bool:
        """Check if 2FA is required for the organization."""
        return self.get_session_setting("require_2fa", False)
    
    def get_max_concurrent_sessions(self) -> int:
        """Get the maximum number of concurrent sessions allowed."""
        return self.get_session_setting("max_concurrent_sessions", 5)
    
    def get_session_timeout_minutes(self) -> int:
        """Get the session idle timeout in minutes."""
        return self.get_session_setting("idle_timeout_minutes", 30)
    
    def get_password_min_length(self) -> int:
        """Get the minimum password length requirement."""
        return self.get_password_requirement("min_length", 8)
    
    def validate_password_policy(self, password: str) -> tuple[bool, list[str]]:
        """
        Validate a password against the organization's policy.
        
        Args:
            password: Password to validate
            
        Returns:
            tuple: (is_valid, list_of_errors)
        """
        errors = []
        
        # Check minimum length
        min_length = self.get_password_min_length()
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters long")
        
        # Check character requirements
        if self.get_password_requirement("require_uppercase", True):
            if not any(c.isupper() for c in password):
                errors.append("Password must contain at least one uppercase letter")
        
        if self.get_password_requirement("require_lowercase", True):
            if not any(c.islower() for c in password):
                errors.append("Password must contain at least one lowercase letter")
        
        if self.get_password_requirement("require_numbers", True):
            if not any(c.isdigit() for c in password):
                errors.append("Password must contain at least one number")
        
        if self.get_password_requirement("require_special_chars", True):
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
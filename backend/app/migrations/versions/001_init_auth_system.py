# File: backend/app/migrations/versions/001_init_auth_system.py
"""Initial authentication system setup

Revision ID: 001_init_auth_system
Revises: None
Create Date: 2025-06-20 00:00:00.000000

This migration creates the initial authentication system for CAP Platform including:
- Organizations table for multi-tenant architecture
- Users table with comprehensive authentication features
- User sessions for JWT token management
- User invitations for team management
- OAuth providers for social authentication
- API keys for developer access
- Authentication audit logging
- Security settings for organizations

Migration Type: Initial
Tables Affected: organizations, users, user_sessions, user_invitations, oauth_providers, api_keys, auth_audit_log, security_settings
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_init_auth_system'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Upgrade database schema.
    
    Creates all tables for the authentication system with proper constraints,
    indexes, and relationships for production use.
    """
    # Migration safety check
    print("Applying migration: Initial authentication system setup")
    
    # Enable UUID extension if not already enabled
    op.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
    op.execute("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"")
    
    # Create organizations table (multi-tenant architecture)
    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False, comment='Unique organization identifier'),
        sa.Column('name', sa.String(length=255), nullable=False, comment='Organization display name'),
        sa.Column('slug', sa.String(length=100), nullable=False, comment='URL-friendly organization identifier'),
        sa.Column('domain', sa.String(length=255), nullable=True, comment='Company domain for SSO integration'),
        sa.Column('subscription_tier', sa.String(length=50), nullable=False, server_default='free', comment='Subscription plan: free, pro, enterprise, developer, agency'),
        sa.Column('subscription_status', sa.String(length=50), nullable=False, server_default='active', comment='Subscription status: active, cancelled, suspended, trial'),
        sa.Column('trial_ends_at', sa.DateTime(timezone=True), nullable=True, comment='Trial expiration date'),
        sa.Column('billing_email', sa.String(length=255), nullable=True, comment='Email address for billing notifications'),
        sa.Column('settings', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}', comment='Organization-specific settings and preferences'),
        sa.Column('credit_balance', sa.Numeric(precision=10, scale=2), nullable=False, server_default='0.00', comment='Current credit balance'),
        sa.Column('usage_limits', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}', comment='Usage limits configuration per subscription plan'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true', comment='Whether the organization is active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Organization creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Last modification timestamp'),
        sa.CheckConstraint("subscription_tier IN ('free', 'pro', 'enterprise', 'developer', 'agency')", name='ck_organizations_subscription_tier'),
        sa.CheckConstraint("subscription_status IN ('active', 'cancelled', 'suspended', 'trial')", name='ck_organizations_subscription_status'),
        sa.CheckConstraint('credit_balance >= 0', name='ck_organizations_credit_balance_non_negative'),
        sa.CheckConstraint('char_length(name) >= 1', name='ck_organizations_name_not_empty'),
        sa.CheckConstraint('char_length(slug) >= 1', name='ck_organizations_slug_not_empty'),
        sa.PrimaryKeyConstraint('id', name='pk_organizations'),
        sa.UniqueConstraint('slug', name='uq_organizations_slug'),
        sa.UniqueConstraint('domain', name='uq_organizations_domain'),
        comment='Organizations for multi-tenant architecture'
    )
    
    # Create indexes for organizations
    op.create_index('ix_organizations_slug', 'organizations', ['slug'])
    op.create_index('ix_organizations_subscription', 'organizations', ['subscription_tier', 'subscription_status'])
    op.create_index('ix_organizations_active', 'organizations', ['is_active', 'created_at'])
    op.create_index('ix_organizations_trial', 'organizations', ['trial_ends_at'])
    op.create_index('ix_organizations_domain', 'organizations', ['domain'])
    
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False, comment='Unique user identifier'),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=True, comment='Reference to user\'s organization'),
        sa.Column('email', sa.String(length=255), nullable=False, comment='User\'s email address'),
        sa.Column('password_hash', sa.String(length=255), nullable=False, comment='Hashed password using bcrypt'),
        sa.Column('first_name', sa.String(length=100), nullable=False, comment='User\'s first name'),
        sa.Column('last_name', sa.String(length=100), nullable=False, comment='User\'s last name'),
        sa.Column('avatar_url', sa.Text(), nullable=True, comment='URL to user\'s avatar image'),
        sa.Column('phone', sa.String(length=20), nullable=True, comment='User\'s phone number'),
        sa.Column('timezone', sa.String(length=50), nullable=False, server_default='UTC', comment='User\'s timezone preference'),
        sa.Column('locale', sa.String(length=10), nullable=False, server_default='en', comment='User\'s locale/language preference'),
        sa.Column('role', sa.String(length=50), nullable=False, server_default='member', comment='User\'s role: owner, admin, member, viewer, developer'),
        sa.Column('permissions', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}', comment='Granular permissions JSON object'),
        sa.Column('is_email_verified', sa.Boolean(), nullable=False, server_default='false', comment='Whether email is verified'),
        sa.Column('is_phone_verified', sa.Boolean(), nullable=False, server_default='false', comment='Whether phone is verified'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true', comment='Whether user account is active'),
        sa.Column('account_status', sa.String(length=50), nullable=False, server_default='active', comment='Account status: active, suspended, pending, deactivated'),
        sa.Column('email_verification_token', sa.String(length=255), nullable=True, comment='Token for email verification'),
        sa.Column('email_verification_expires', sa.DateTime(timezone=True), nullable=True, comment='Email verification token expiration'),
        sa.Column('phone_verification_token', sa.String(length=6), nullable=True, comment='SMS OTP for phone verification'),
        sa.Column('phone_verification_expires', sa.DateTime(timezone=True), nullable=True, comment='Phone verification token expiration'),
        sa.Column('password_reset_token', sa.String(length=255), nullable=True, comment='Token for password reset'),
        sa.Column('password_reset_expires', sa.DateTime(timezone=True), nullable=True, comment='Password reset token expiration'),
        sa.Column('password_reset_attempts', sa.Integer(), nullable=False, server_default='0', comment='Number of password reset attempts'),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True, comment='Last successful login timestamp'),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0', comment='Number of consecutive failed login attempts'),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True, comment='Account locked until this timestamp'),
        sa.Column('force_password_reset', sa.Boolean(), nullable=False, server_default='false', comment='Whether user must reset password on next login'),
        sa.Column('two_factor_enabled', sa.Boolean(), nullable=False, server_default='false', comment='Whether 2FA is enabled'),
        sa.Column('two_factor_secret', sa.String(length=255), nullable=True, comment='Encrypted 2FA secret key'),
        sa.Column('backup_codes', postgresql.JSONB(astext_type=sa.Text()), nullable=True, comment='Encrypted backup codes for 2FA'),
        sa.Column('google_id', sa.String(length=255), nullable=True, comment='Google OAuth user ID'),
        sa.Column('microsoft_id', sa.String(length=255), nullable=True, comment='Microsoft OAuth user ID'),
        sa.Column('github_id', sa.String(length=255), nullable=True, comment='GitHub OAuth user ID'),
        sa.Column('last_password_change', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Last password change timestamp'),
        sa.Column('terms_accepted_at', sa.DateTime(timezone=True), nullable=True, comment='Terms of service acceptance timestamp'),
        sa.Column('privacy_policy_accepted_at', sa.DateTime(timezone=True), nullable=True, comment='Privacy policy acceptance timestamp'),
        sa.Column('marketing_consent', sa.Boolean(), nullable=False, server_default='false', comment='Whether user consented to marketing communications'),
        sa.Column('onboarding_completed', sa.Boolean(), nullable=False, server_default='false', comment='Whether user completed onboarding'),
        sa.Column('preferences', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}', comment='User preferences (theme, notifications, etc.)'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='User creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Last modification timestamp'),
        sa.CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer', 'developer')", name='ck_users_role'),
        sa.CheckConstraint("account_status IN ('active', 'suspended', 'pending', 'deactivated')", name='ck_users_account_status'),
        sa.CheckConstraint('failed_login_attempts >= 0', name='ck_users_failed_login_attempts_non_negative'),
        sa.CheckConstraint('password_reset_attempts >= 0', name='ck_users_password_reset_attempts_non_negative'),
        sa.CheckConstraint('char_length(first_name) >= 1', name='ck_users_first_name_not_empty'),
        sa.CheckConstraint('char_length(last_name) >= 1', name='ck_users_last_name_not_empty'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE', name='fk_users_organization_id_organizations'),
        sa.PrimaryKeyConstraint('id', name='pk_users'),
        sa.UniqueConstraint('email', name='uq_users_email'),
        sa.UniqueConstraint('email_verification_token', name='uq_users_email_verification_token'),
        sa.UniqueConstraint('password_reset_token', name='uq_users_password_reset_token'),
        sa.UniqueConstraint('google_id', name='uq_users_google_id'),
        sa.UniqueConstraint('microsoft_id', name='uq_users_microsoft_id'),
        sa.UniqueConstraint('github_id', name='uq_users_github_id'),
        comment='Users with comprehensive authentication features'
    )
    
    # Create indexes for users
    op.create_index('ix_users_email', 'users', ['email'])
    op.create_index('ix_users_organization', 'users', ['organization_id'])
    op.create_index('ix_users_organization_role', 'users', ['organization_id', 'role'])
    op.create_index('ix_users_active', 'users', ['is_active', 'is_email_verified'])
    op.create_index('ix_users_last_login', 'users', ['last_login'])
    op.create_index('ix_users_locked', 'users', ['locked_until'])
    
    # Create user_sessions table
    op.create_table(
        'user_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False, comment='Unique session identifier'),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Reference to user'),
        sa.Column('access_token_jti', sa.String(length=255), nullable=False, comment='JWT ID for access token'),
        sa.Column('refresh_token_jti', sa.String(length=255), nullable=False, comment='JWT ID for refresh token'),
        sa.Column('device_info', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}', comment='Device fingerprint and browser info'),
        sa.Column('ip_address', postgresql.INET(), nullable=True, comment='Client IP address'),
        sa.Column('user_agent', sa.Text(), nullable=True, comment='User agent string'),
        sa.Column('location', postgresql.JSONB(astext_type=sa.Text()), nullable=True, comment='Geo location information'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true', comment='Whether session is active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Session creation timestamp'),
        sa.Column('last_used', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Last session activity timestamp'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False, comment='Session expiration timestamp'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE', name='fk_user_sessions_user_id_users'),
        sa.PrimaryKeyConstraint('id', name='pk_user_sessions'),
        sa.UniqueConstraint('access_token_jti', name='uq_user_sessions_access_token_jti'),
        sa.UniqueConstraint('refresh_token_jti', name='uq_user_sessions_refresh_token_jti'),
        comment='User sessions for JWT token tracking'
    )
    
    # Create indexes for user_sessions
    op.create_index('ix_user_sessions_user_id', 'user_sessions', ['user_id'])
    op.create_index('ix_user_sessions_user_active', 'user_sessions', ['user_id', 'is_active'])
    op.create_index('ix_user_sessions_expires', 'user_sessions', ['expires_at'])
    op.create_index('ix_user_sessions_last_used', 'user_sessions', ['last_used'])
    op.create_index('ix_user_sessions_jti', 'user_sessions', ['access_token_jti', 'refresh_token_jti'])
    
    # Create user_invitations table
    op.create_table(
        'user_invitations',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False, comment='Unique invitation identifier'),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Reference to organization'),
        sa.Column('invited_by', postgresql.UUID(as_uuid=True), nullable=True, comment='User who sent the invitation'),
        sa.Column('email', sa.String(length=255), nullable=False, comment='Email address of invited user'),
        sa.Column('role', sa.String(length=50), nullable=False, comment='Role to assign to invited user'),
        sa.Column('permissions', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}', comment='Permissions to assign to invited user'),
        sa.Column('invitation_token', sa.String(length=255), nullable=False, comment='Unique invitation token'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False, comment='Invitation expiration timestamp'),
        sa.Column('accepted_at', sa.DateTime(timezone=True), nullable=True, comment='Invitation acceptance timestamp'),
        sa.Column('is_used', sa.Boolean(), nullable=False, server_default='false', comment='Whether invitation has been used'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Invitation creation timestamp'),
        sa.CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer', 'developer')", name='ck_user_invitations_role'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE', name='fk_user_invitations_organization_id_organizations'),
        sa.ForeignKeyConstraint(['invited_by'], ['users.id'], ondelete='SET NULL', name='fk_user_invitations_invited_by_users'),
        sa.PrimaryKeyConstraint('id', name='pk_user_invitations'),
        sa.UniqueConstraint('invitation_token', name='uq_user_invitations_invitation_token'),
        comment='User invitations for team management'
    )
    
    # Create indexes for user_invitations
    op.create_index('ix_user_invitations_email', 'user_invitations', ['email', 'is_used'])
    op.create_index('ix_user_invitations_token', 'user_invitations', ['invitation_token'])
    op.create_index('ix_user_invitations_org', 'user_invitations', ['organization_id', 'is_used'])
    op.create_index('ix_user_invitations_expires', 'user_invitations', ['expires_at'])
    
    # Create oauth_providers table
    op.create_table(
        'oauth_providers',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False, comment='Unique OAuth provider record identifier'),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Reference to user'),
        sa.Column('provider', sa.String(length=50), nullable=False, comment='OAuth provider name (google, microsoft, github)'),
        sa.Column('provider_user_id', sa.String(length=255), nullable=False, comment='User ID from OAuth provider'),
        sa.Column('provider_email', sa.String(length=255), nullable=True, comment='Email from OAuth provider'),
        sa.Column('provider_data', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}', comment='Additional provider data'),
        sa.Column('access_token_encrypted', sa.Text(), nullable=True, comment='Encrypted OAuth access token'),
        sa.Column('refresh_token_encrypted', sa.Text(), nullable=True, comment='Encrypted OAuth refresh token'),
        sa.Column('token_expires_at', sa.DateTime(timezone=True), nullable=True, comment='OAuth token expiration timestamp'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true', comment='Whether OAuth connection is active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='OAuth connection creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Last modification timestamp'),
        sa.CheckConstraint("provider IN ('google', 'microsoft', 'github')", name='ck_oauth_providers_provider'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE', name='fk_oauth_providers_user_id_users'),
        sa.PrimaryKeyConstraint('id', name='pk_oauth_providers'),
        sa.UniqueConstraint('provider', 'provider_user_id', name='uq_oauth_providers_provider_user'),
        comment='OAuth provider connections for social authentication'
    )
    
    # Create indexes for oauth_providers
    op.create_index('ix_oauth_providers_user', 'oauth_providers', ['user_id', 'provider'])
    op.create_index('ix_oauth_providers_provider_id', 'oauth_providers', ['provider', 'provider_user_id'])
    
    # Create api_keys table
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False, comment='Unique API key identifier'),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Reference to user who created the API key'),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Reference to organization'),
        sa.Column('name', sa.String(length=255), nullable=False, comment='Human-readable name for the API key'),
        sa.Column('key_hash', sa.String(length=255), nullable=False, comment='Hashed API key for secure storage'),
        sa.Column('key_prefix', sa.String(length=20), nullable=False, comment='First few characters for identification'),
        sa.Column('permissions', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}', comment='API-specific permissions'),
        sa.Column('rate_limit_per_minute', sa.Integer(), nullable=False, server_default='1000', comment='Rate limit per minute'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true', comment='Whether API key is active'),
        sa.Column('last_used', sa.DateTime(timezone=True), nullable=True, comment='Last usage timestamp'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True, comment='API key expiration timestamp'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='API key creation timestamp'),
        sa.CheckConstraint('rate_limit_per_minute > 0', name='ck_api_keys_rate_limit_positive'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE', name='fk_api_keys_user_id_users'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE', name='fk_api_keys_organization_id_organizations'),
        sa.PrimaryKeyConstraint('id', name='pk_api_keys'),
        sa.UniqueConstraint('key_hash', name='uq_api_keys_key_hash'),
        comment='API keys for developer access and integrations'
    )
    
    # Create indexes for api_keys
    op.create_index('ix_api_keys_user_active', 'api_keys', ['user_id', 'is_active'])
    op.create_index('ix_api_keys_org_active', 'api_keys', ['organization_id', 'is_active'])
    op.create_index('ix_api_keys_hash', 'api_keys', ['key_hash'])
    op.create_index('ix_api_keys_expires', 'api_keys', ['expires_at'])
    
    # Create auth_audit_log table
    op.create_table(
        'auth_audit_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False, comment='Unique audit log entry identifier'),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True, comment='Reference to user (null for failed attempts)'),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=True, comment='Reference to organization'),
        sa.Column('event_type', sa.String(length=50), nullable=False, comment='Type of authentication event'),
        sa.Column('event_details', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}', comment='Event-specific details and metadata'),
        sa.Column('ip_address', postgresql.INET(), nullable=True, comment='Client IP address'),
        sa.Column('user_agent', sa.Text(), nullable=True, comment='User agent string'),
        sa.Column('success', sa.Boolean(), nullable=False, server_default='true', comment='Whether the event was successful'),
        sa.Column('error_message', sa.Text(), nullable=True, comment='Error message for failed events'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0', comment='Security risk assessment score (0-100)'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Event timestamp'),
        sa.CheckConstraint(
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
            name='ck_auth_audit_log_event_type'
        ),
        sa.CheckConstraint('risk_score >= 0 AND risk_score <= 100', name='ck_auth_audit_log_risk_score_range'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL', name='fk_auth_audit_log_user_id_users'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE', name='fk_auth_audit_log_organization_id_organizations'),
        sa.PrimaryKeyConstraint('id', name='pk_auth_audit_log'),
        comment='Authentication audit log for security tracking'
    )
    
    # Create indexes for auth_audit_log
    op.create_index('ix_auth_audit_log_created_at', 'auth_audit_log', ['created_at'])
    op.create_index('ix_auth_audit_user_time', 'auth_audit_log', ['user_id', 'created_at'])
    op.create_index('ix_auth_audit_org_time', 'auth_audit_log', ['organization_id', 'created_at'])
    op.create_index('ix_auth_audit_event_time', 'auth_audit_log', ['event_type', 'created_at'])
    op.create_index('ix_auth_audit_success_time', 'auth_audit_log', ['success', 'created_at'])
    op.create_index('ix_auth_audit_risk_time', 'auth_audit_log', ['risk_score', 'created_at'])
    op.create_index('ix_auth_audit_ip', 'auth_audit_log', ['ip_address', 'created_at'])
    
    # Create security_settings table
    op.create_table(
        'security_settings',
        sa.Column('id', postgresql.UUID(as_uuid=True), server_default=sa.text('uuid_generate_v4()'), nullable=False, comment='Unique security settings identifier'),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False, comment='Reference to organization'),
        sa.Column('password_policy', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{"min_length": 8, "require_uppercase": true, "require_lowercase": true, "require_numbers": true, "require_special_chars": true, "max_age_days": 90, "prevent_reuse_count": 5, "complexity_score_min": 50}', comment='Password policy configuration'),
        sa.Column('session_settings', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{"max_session_duration_hours": 24, "idle_timeout_minutes": 30, "require_2fa": false, "allow_concurrent_sessions": true, "max_concurrent_sessions": 5, "require_fresh_login_for_sensitive": true, "session_rotation_interval_hours": 6}', comment='Session security configuration'),
        sa.Column('ip_whitelist', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]', comment='Array of allowed IP ranges (CIDR notation)'),
        sa.Column('security_questions_required', sa.Boolean(), nullable=False, server_default='false', comment='Whether security questions are required'),
        sa.Column('audit_settings', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{"log_all_actions": true, "log_retention_days": 365, "alert_on_suspicious_activity": true, "alert_on_failed_logins": 5, "alert_on_new_device": true}', comment='Audit and compliance configuration'),
        sa.Column('api_security', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{"require_api_key_rotation": false, "api_key_max_age_days": 365, "rate_limiting_enabled": true, "rate_limit_per_minute": 1000, "require_https": true}', comment='API security configuration'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Settings creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=False, comment='Last modification timestamp'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE', name='fk_security_settings_organization_id_organizations'),
        sa.PrimaryKeyConstraint('id', name='pk_security_settings'),
        sa.UniqueConstraint('organization_id', name='uq_security_settings_organization_id'),
        comment='Security settings and policies for organizations'
    )
    
    # Create indexes for security_settings
    op.create_index('ix_security_settings_org', 'security_settings', ['organization_id'])
    
    # Create trigger function for updating updated_at columns
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ language 'plpgsql';
    """)
    
    # Create triggers for updated_at columns
    op.execute("CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();")
    op.execute("CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();")
    op.execute("CREATE TRIGGER update_oauth_providers_updated_at BEFORE UPDATE ON oauth_providers FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();")
    op.execute("CREATE TRIGGER update_security_settings_updated_at BEFORE UPDATE ON security_settings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();")
    
    # Insert default organization for development
    op.execute("""
        INSERT INTO organizations (name, slug, subscription_tier, settings, usage_limits) 
        VALUES (
            'Default Organization', 
            'default', 
            'pro',
            '{"theme": "light", "timezone": "UTC", "language": "en"}',
            '{"max_users": 100, "max_agents": 50, "max_conversations_per_month": 10000}'
        )
        ON CONFLICT (slug) DO NOTHING;
    """)
    
    print("✅  Initial authentication system migration completed successfully")


def downgrade() -> None:
    """
    Downgrade database schema.
    
    Removes all authentication system tables and related objects.
    """
    # Migration safety check
    print("Reversing migration: Initial authentication system setup")
    
    # Drop triggers first
    op.execute("DROP TRIGGER IF EXISTS update_security_settings_updated_at ON security_settings;")
    op.execute("DROP TRIGGER IF EXISTS update_oauth_providers_updated_at ON oauth_providers;")
    op.execute("DROP TRIGGER IF EXISTS update_users_updated_at ON users;")
    op.execute("DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;")
    
    # Drop trigger function
    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column();")
    
    # Drop tables in reverse order (respecting foreign key dependencies)
    op.drop_table('security_settings')
    op.drop_table('auth_audit_log')
    op.drop_table('api_keys')
    op.drop_table('oauth_providers')
    op.drop_table('user_invitations')
    op.drop_table('user_sessions')
    op.drop_table('users')
    op.drop_table('organizations')
    
    print("✅  Initial authentication system migration reversed successfully")
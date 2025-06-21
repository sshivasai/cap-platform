"""
Core configuration module for CAP Platform.

This module handles all application configuration including database connections,
Redis, Celery, security settings, and external service integrations.
Designed for production scalability with environment-based configuration.

Compatible with Pydantic v2.
"""

import os
import secrets
from typing import Any, Dict, List, Optional, Union
from functools import lru_cache

from pydantic import Field, field_validator, computed_field
from pydantic.networks import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings with environment variable support.
    
    All settings can be overridden via environment variables.
    Supports multiple environments: development, staging, production.
    """
    
    # Pydantic v2 configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"  # Allow extra fields from environment variables
    )
    
    # ================================
    # Core Application Settings
    # ================================
    
    APP_NAME: str = Field(default="CAP Platform", description="Application name")
    APP_VERSION: str = Field(default="1.0.0", description="Application version") 
    APP_DESCRIPTION: str = Field(default="Conversational AI Platform", description="Application description")
    ENVIRONMENT: str = Field(default="development", description="Environment: development, staging, production")
    DEBUG: bool = Field(default=True, description="Debug mode for development")
    
    # API Configuration
    API_V1_STR: str = Field(default="/api/v1", description="API version 1 prefix")
    PROJECT_NAME: str = Field(default="CAP Platform API", description="Project name for documentation")
    
    # Security and CORS
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32), description="Application secret key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, description="Access token expiration in minutes")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, description="Refresh token expiration in days")
    ALGORITHM: str = Field(default="HS256", description="JWT algorithm")
    
    # CORS Settings - Handle both list and string formats
    BACKEND_CORS_ORIGINS: Union[str, List[str]] = Field(
    default=["http://localhost:3000", "http://localhost:8000"],
    description="Allowed CORS origins"
    )

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                return json.loads(v)
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, list):
            return v
        return ["http://localhost:3000", "http://localhost:8000"]
    
    # ================================
    # Database Configuration
    # ================================
    
    # PostgreSQL (Primary Database)
    POSTGRES_SERVER: str = Field(default="localhost", description="PostgreSQL server host")
    POSTGRES_PORT: int = Field(default=5432, description="PostgreSQL server port")
    POSTGRES_USER: str = Field(default="cap_user", description="PostgreSQL username")
    POSTGRES_PASSWORD: str = Field(default="cap_password", description="PostgreSQL password")
    POSTGRES_DB: str = Field(default="cap_platform", description="PostgreSQL database name")
    
    # MongoDB (Document Storage)
    MONGODB_URL: str = Field(
        default="mongodb://cap_user:cap_password@localhost:27017/cap_platform",
        description="MongoDB connection URL"
    )
    MONGODB_DB_NAME: str = Field(default="cap_platform", description="MongoDB database name")
    
    # Additional MongoDB settings for backward compatibility
    MONGODB_SERVER: Optional[str] = Field(default=None, description="MongoDB server host (legacy)")
    MONGODB_PORT: Optional[str] = Field(default=None, description="MongoDB port (legacy)")
    MONGODB_USER: Optional[str] = Field(default=None, description="MongoDB user (legacy)")
    MONGODB_PASSWORD: Optional[str] = Field(default=None, description="MongoDB password (legacy)")
    MONGODB_DB: Optional[str] = Field(default=None, description="MongoDB database (legacy)")
    
    # Qdrant (Vector Database)
    QDRANT_HOST: str = Field(default="localhost", description="Qdrant server host")
    QDRANT_PORT: int = Field(default=6333, description="Qdrant server port")
    QDRANT_API_KEY: Optional[str] = Field(default=None, description="Qdrant API key for authentication")
    QDRANT_SERVER: Optional[str] = Field(default=None, description="Qdrant server host (legacy)")
    
    @computed_field
    @property
    def postgres_url(self) -> str:
        """Construct PostgreSQL connection URL."""
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
    
    @computed_field
    @property
    def postgres_sync_url(self) -> str:
        """Construct synchronous PostgreSQL connection URL for Alembic."""
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
    
    # ================================
    # Redis Configuration
    # ================================
    
    REDIS_HOST: str = Field(default="localhost", description="Redis server host")
    REDIS_PORT: int = Field(default=6379, description="Redis server port")
    REDIS_PASSWORD: Optional[str] = Field(default=None, description="Redis password")
    REDIS_DB: int = Field(default=0, description="Redis database number")
    REDIS_POOL_SIZE: int = Field(default=20, description="Redis connection pool size")
    REDIS_SERVER: Optional[str] = Field(default=None, description="Redis server host (legacy)")
    
    # Redis Key Prefixes for different data types
    REDIS_SESSION_PREFIX: str = Field(default="cap:session:", description="Redis session key prefix")
    REDIS_CACHE_PREFIX: str = Field(default="cap:cache:", description="Redis cache key prefix")
    REDIS_RATE_LIMIT_PREFIX: str = Field(default="cap:rate_limit:", description="Redis rate limit key prefix")
    REDIS_LOCK_PREFIX: str = Field(default="cap:lock:", description="Redis lock key prefix")
    
    @computed_field
    @property
    def redis_url(self) -> str:
        """Construct Redis connection URL."""
        password_part = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{password_part}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
    
    # ================================
    # RabbitMQ Configuration (Legacy Support)
    # ================================
    
    RABBITMQ_HOST: Optional[str] = Field(default=None, description="RabbitMQ server host")
    RABBITMQ_PORT: Optional[str] = Field(default=None, description="RabbitMQ server port")
    RABBITMQ_USER: Optional[str] = Field(default=None, description="RabbitMQ username")
    RABBITMQ_PASSWORD: Optional[str] = Field(default=None, description="RabbitMQ password")
    RABBITMQ_VHOST: Optional[str] = Field(default=None, description="RabbitMQ virtual host")
    RABBITMQ_SERVER: Optional[str] = Field(default=None, description="RabbitMQ server (legacy)")
    
    # ================================
    # Celery Configuration
    # ================================
    
    # Message Broker (Redis for simplicity, can switch to RabbitMQ)
    CELERY_BROKER_URL: str = Field(
        default="redis://localhost:6379/1",
        description="Celery message broker URL"
    )
    CELERY_RESULT_BACKEND: str = Field(
        default="redis://localhost:6379/2",
        description="Celery result backend URL"
    )
    
    # Celery Task Configuration
    CELERY_TASK_SERIALIZER: str = Field(default="json", description="Celery task serialization format")
    CELERY_RESULT_SERIALIZER: str = Field(default="json", description="Celery result serialization format")
    CELERY_ACCEPT_CONTENT: List[str] = Field(default=["json"], description="Accepted content types")
    CELERY_TIMEZONE: str = Field(default="UTC", description="Celery timezone")
    CELERY_ENABLE_UTC: bool = Field(default=True, description="Enable UTC in Celery")
    
    # Task Routing and Queues
    CELERY_TASK_ROUTES: Dict[str, Dict[str, str]] = Field(
        default={
            "app.tasks.notifications.*": {"queue": "notifications"},
            "app.tasks.document_processing.*": {"queue": "document_processing"},
            "app.tasks.analytics.*": {"queue": "analytics"},
            "app.tasks.auth.*": {"queue": "auth"},
        },
        description="Celery task routing configuration"
    )
    
    # Worker Configuration
    CELERY_WORKER_PREFETCH_MULTIPLIER: int = Field(default=1, description="Worker prefetch multiplier")
    CELERY_WORKER_MAX_TASKS_PER_CHILD: int = Field(default=1000, description="Max tasks per worker child")
    CELERY_WORKER_CONCURRENCY: int = Field(default=4, description="Worker concurrency level")
    
    # ================================
    # Email Configuration
    # ================================
    
    # SMTP Settings
    SMTP_TLS: bool = Field(default=True, description="Use TLS for SMTP")
    SMTP_PORT: Optional[int] = Field(default=587, description="SMTP server port")
    SMTP_HOST: Optional[str] = Field(default=None, description="SMTP server host")
    SMTP_USER: Optional[str] = Field(default=None, description="SMTP username")
    SMTP_PASSWORD: Optional[str] = Field(default=None, description="SMTP password")
    
    # Email Settings
    EMAILS_FROM_EMAIL: Optional[str] = Field(default=None, description="Default from email address")
    EMAILS_FROM_NAME: Optional[str] = Field(default="CAP Platform", description="Default from name")
    EMAIL_RESET_TOKEN_EXPIRE_HOURS: int = Field(default=1, description="Password reset token expiration hours")
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = Field(default=24, description="Email verification token expiration hours")
    
    # Email Templates
    EMAIL_TEMPLATES_DIR: str = Field(default="app/templates", description="Email templates directory")
    
    # ================================
    # SMS/Phone Configuration
    # ================================
    
    # Twilio Configuration
    TWILIO_ACCOUNT_SID: Optional[str] = Field(default=None, description="Twilio Account SID")
    TWILIO_AUTH_TOKEN: Optional[str] = Field(default=None, description="Twilio Auth Token")
    TWILIO_PHONE_NUMBER: Optional[str] = Field(default=None, description="Twilio phone number")
    
    # SMS Settings
    SMS_VERIFICATION_CODE_EXPIRE_MINUTES: int = Field(default=5, description="SMS verification code expiration minutes")
    SMS_VERIFICATION_CODE_LENGTH: int = Field(default=6, description="SMS verification code length")
    
    # ================================
    # AI/LLM Configuration
    # ================================
    
    # OpenAI
    OPENAI_API_KEY: Optional[str] = Field(default=None, description="OpenAI API key")
    OPENAI_ORGANIZATION: Optional[str] = Field(default=None, description="OpenAI organization ID")
    
    # Anthropic
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None, description="Anthropic API key")
    
    # Default LLM Settings
    DEFAULT_LLM_PROVIDER: str = Field(default="openai", description="Default LLM provider")
    DEFAULT_LLM_MODEL: str = Field(default="gpt-3.5-turbo", description="Default LLM model")
    DEFAULT_CHAT_MODEL: str = Field(default="gpt-3.5-turbo", description="Default chat model")
    DEFAULT_EMBEDDING_MODEL: str = Field(default="text-embedding-ada-002", description="Default embedding model")
    
    # ================================
    # File Processing Configuration
    # ================================
    
    UPLOAD_DIR: str = Field(default="uploads", description="File upload directory")
    TEMP_DIR: str = Field(default="/tmp", description="Temporary files directory")
    MAX_FILE_SIZE_MB: int = Field(default=50, description="Maximum file size in MB")
    ALLOWED_FILE_TYPES: Union[str, List[str]] = Field(
        default=["pdf", "docx", "txt", "csv", "json", "html"],
        description="Allowed file types for upload"
    )
    
    # Document Processing Settings
    CHUNK_SIZE: int = Field(default=1000, description="Document chunk size for processing")
    CHUNK_OVERLAP: int = Field(default=200, description="Overlap between document chunks")
    
    # ================================
    # Vector Database Configuration
    # ================================
    
    VECTOR_DIMENSION: int = Field(default=1536, description="Vector embedding dimension")
    SIMILARITY_THRESHOLD: float = Field(default=0.7, description="Similarity threshold for vector search")
    
    # ================================
    # Rate Limiting Configuration
    # ================================
    
    # Authentication Rate Limits
    RATE_LIMIT_LOGIN_ATTEMPTS: int = Field(default=5, description="Max login attempts per IP per hour")
    RATE_LIMIT_REGISTRATION_ATTEMPTS: int = Field(default=3, description="Max registration attempts per IP per hour")
    RATE_LIMIT_PASSWORD_RESET_ATTEMPTS: int = Field(default=3, description="Max password reset attempts per IP per hour")
    
    # API Rate Limits
    RATE_LIMIT_API_CALLS_PER_MINUTE: int = Field(default=100, description="API calls per minute per user")
    RATE_LIMIT_BULK_OPERATIONS_PER_HOUR: int = Field(default=10, description="Bulk operations per hour per user")
    
    # ================================
    # Security Configuration
    # ================================
    
    # Password Policy
    PASSWORD_MIN_LENGTH: int = Field(default=8, description="Minimum password length")
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True, description="Require uppercase in password")
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True, description="Require lowercase in password")
    PASSWORD_REQUIRE_NUMBERS: bool = Field(default=True, description="Require numbers in password")
    PASSWORD_REQUIRE_SPECIAL_CHARS: bool = Field(default=True, description="Require special characters in password")
    
    # Account Security
    ACCOUNT_LOCKOUT_ATTEMPTS: int = Field(default=5, description="Failed login attempts before lockout")
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = Field(default=30, description="Account lockout duration in minutes")
    
    # Session Security
    SESSION_COOKIE_SECURE: bool = Field(default=True, description="Secure session cookies")
    SESSION_COOKIE_HTTPONLY: bool = Field(default=True, description="HTTP-only session cookies")
    SESSION_COOKIE_SAMESITE: str = Field(default="lax", description="SameSite cookie attribute")
    
    # ================================
    # Credit System Configuration
    # ================================
    
    # Default Credit Allocations
    DEFAULT_FREE_CREDITS: int = Field(default=1000, description="Default credits for free tier")
    CREDIT_COST_PER_1K_TOKENS: float = Field(default=0.01, description="Credit cost per 1K tokens")
    CREDIT_COST_PER_MINUTE_VOICE: float = Field(default=0.1, description="Credit cost per minute of voice")
    CREDIT_COST_PER_PHONE_MINUTE: float = Field(default=0.05, description="Credit cost per minute of phone call")
    
    # Credit Alerts
    LOW_CREDIT_THRESHOLD_PERCENT: int = Field(default=20, description="Low credit alert threshold percentage")
    CREDIT_USAGE_ALERT_THRESHOLD: int = Field(default=100, description="Credit usage alert threshold")
    
    # ================================
    # Monitoring and Logging
    # ================================
    
    # Logging Configuration
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string"
    )
    LOG_FILE_PATH: str = Field(default="logs/app.log", description="Log file path")
    LOG_MAX_SIZE_MB: int = Field(default=100, description="Maximum log file size in MB")
    LOG_BACKUP_COUNT: int = Field(default=5, description="Number of log backup files")
    
    # Metrics and Monitoring
    ENABLE_METRICS: bool = Field(default=True, description="Enable metrics collection")
    METRICS_PORT: int = Field(default=8001, description="Metrics server port")
    
    # Sentry Integration
    SENTRY_DSN: Optional[str] = Field(default=None, description="Sentry DSN for error tracking")
    
    # ================================
    # Testing Configuration
    # ================================
    
    TESTING: bool = Field(default=False, description="Testing mode flag")
    TEST_DATABASE_URL: Optional[str] = Field(default=None, description="Test database URL")
    
    # ================================
    # Legacy Fields (for backward compatibility)
    # ================================
    
    VERSION: Optional[str] = Field(default=None, description="Legacy version field")
    DESCRIPTION: Optional[str] = Field(default=None, description="Legacy description field")
    CORS_ORIGINS: Optional[str] = Field(default=None, description="Legacy CORS origins field")
    
    # ================================
    # Field Validators
    # ================================
    
    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        """Validate environment setting."""
        allowed_environments = ["development", "staging", "production", "testing"]
        if v not in allowed_environments:
            raise ValueError(f"Environment must be one of: {allowed_environments}")
        return v
    
    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level setting."""
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"Log level must be one of: {allowed_levels}")
        return v.upper()
    
    @field_validator("CELERY_ACCEPT_CONTENT", mode="before")
    @classmethod
    def validate_celery_accept_content(cls, v: Union[str, List[str]]) -> List[str]:
        """Validate and parse Celery accept content."""
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except json.JSONDecodeError:
                    pass
            return [v.strip()]
        return v or ["json"]
    
    # ================================
    # Utility Methods
    # ================================
    
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.ENVIRONMENT == "production"
    
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.ENVIRONMENT == "development"
    
    def is_testing(self) -> bool:
        """Check if running in testing environment."""
        return self.TESTING or self.ENVIRONMENT == "testing"


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Uses LRU cache to ensure settings are loaded only once and reused
    throughout the application lifecycle.
    
    Returns:
        Settings: Cached settings instance
    """
    return Settings()


# ================================
# Environment-specific Overrides
# ================================

def configure_for_testing():
    """Configure settings for testing environment."""
    # Create new instance for testing
    os.environ["TESTING"] = "true"
    os.environ["DEBUG"] = "true"
    os.environ["LOG_LEVEL"] = "DEBUG"
    
    # Get current settings to check test database
    current_settings = get_settings()
    
    # Use test database
    if current_settings.TEST_DATABASE_URL:
        os.environ["POSTGRES_DB"] = current_settings.TEST_DATABASE_URL
    else:
        os.environ["POSTGRES_DB"] = f"{current_settings.POSTGRES_DB}_test"
    
    # Disable external services in testing
    os.environ["EMAILS_FROM_EMAIL"] = "test@example.com"
    os.environ["SMTP_HOST"] = ""
    
    # Clear cache to reload with new env vars
    get_settings.cache_clear()


def configure_for_production():
    """Configure settings for production environment."""
    os.environ["DEBUG"] = "false"
    os.environ["TESTING"] = "false"
    os.environ["LOG_LEVEL"] = "INFO"
    
    # Get current settings to validate
    current_settings = get_settings()
    
    # Ensure required production settings
    required_production_settings = [
        "SECRET_KEY",
        "POSTGRES_PASSWORD",
        "EMAILS_FROM_EMAIL",
        "SMTP_HOST",
        "SMTP_USER",
        "SMTP_PASSWORD"
    ]
    
    missing_settings = []
    for setting in required_production_settings:
        if not getattr(current_settings, setting):
            missing_settings.append(setting)
    
    if missing_settings:
        raise ValueError(
            f"Missing required production settings: {', '.join(missing_settings)}"
        )


# ================================
# Global Settings Instance
# ================================

# Initialize settings and configure based on environment
_initial_settings = get_settings()

# Configure based on environment
if _initial_settings.is_testing():
    configure_for_testing()
elif _initial_settings.is_production():
    configure_for_production()

# Get final configured settings
settings = get_settings()


# ================================
# Additional Utility Functions
# ================================

def update_settings(**kwargs):
    """
    Update settings at runtime (primarily for testing).
    
    Args:
        **kwargs: Settings to update
    """
    for key, value in kwargs.items():
        os.environ[key] = str(value)
    
    # Clear cache and reload settings
    get_settings.cache_clear()
    return get_settings()


def get_database_urls() -> Dict[str, str]:
    """
    Get all database connection URLs.
    
    Returns:
        Dict containing all database URLs
    """
    return {
        "postgres_async": settings.postgres_url,
        "postgres_sync": settings.postgres_sync_url,
        "mongodb": settings.MONGODB_URL,
        "redis": settings.redis_url,
        "qdrant": f"http://{settings.QDRANT_HOST}:{settings.QDRANT_PORT}"
    }


def validate_settings() -> List[str]:
    """
    Validate all settings and return list of issues.
    
    Returns:
        List of validation error messages
    """
    errors = []
    
    # Check required settings
    if not settings.SECRET_KEY or len(settings.SECRET_KEY) < 32:
        errors.append("SECRET_KEY must be at least 32 characters")
    
    if settings.is_production():
        prod_required = ["POSTGRES_PASSWORD", "SMTP_HOST", "EMAILS_FROM_EMAIL"]
        for field in prod_required:
            if not getattr(settings, field):
                errors.append(f"{field} is required in production")
    
    return errors
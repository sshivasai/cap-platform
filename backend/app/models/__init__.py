# File: backend/app/models/__init__.py
"""
Database models for CAP Platform.

This module contains all SQLAlchemy models for the platform including:
- User management and authentication
- Organization and multi-tenancy
- AI agents and configurations
- Knowledge base and document management
- Conversations and analytics
- System audit and security

All models inherit from the Base class defined in database.py
"""

from app.core.database import Base

# Import all models to ensure they're registered with SQLAlchemy
from app.models.organization import Organization  # noqa
from app.models.user import (  # noqa
    User,
    UserSession,
    UserInvitation,
    OAuthProvider,
    APIKey,
)
from app.models.auth import (  # noqa
    AuthAuditLog,
    SecuritySettings,
)

# Models will be added as we implement other features
# from app.models.agent import Agent, AgentConfiguration  # noqa
# from app.models.knowledge_base import KnowledgeBase, Document  # noqa
# from app.models.conversation import Conversation, Message  # noqa
# from app.models.analytics import UsageAnalytics, ConversationMetrics  # noqa

__all__ = [
    "Base",
    # Organization models
    "Organization",
    # User models  
    "Auth",
    "User",
    "UserSession",
    "UserInvitation",
    "OAuthProvider", 
    "APIKey",
    # Auth models
    "AuthAuditLog",
    "SecuritySettings",
]
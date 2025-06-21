"""
Security utilities and configuration for CAP Platform.

This module provides:
- JWT token generation, validation, and management
- Password hashing and verification with bcrypt
- API key generation and validation
- Security middleware and decorators
- CSRF protection utilities
- Rate limiting integration
- Security headers and CORS configuration

Designed for enterprise-grade security with proper token rotation,
secure random generation, and comprehensive audit logging.
"""

import secrets
import hashlib
import hmac
import base64
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union, Tuple
from uuid import uuid4

import bcrypt
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core.config import settings
from app.utils.logging import get_logger

logger = get_logger(__name__)


# ================================
# Password Hashing Configuration
# ================================

class PasswordManager:
    """
    Secure password hashing and verification using bcrypt.
    
    Provides enterprise-grade password security with configurable
    cost factors and comprehensive validation.
    """
    
    def __init__(self):
        # Configure password context with bcrypt
        self.pwd_context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__min_rounds=12,  # Minimum 12 rounds for security
            bcrypt__max_rounds=16,  # Maximum 16 rounds to prevent DoS
            bcrypt__default_rounds=12  # Default rounds
        )
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt with salt.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password string
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Hash the password
        hashed = self.pwd_context.hash(password)
        logger.debug("Password hashed successfully")
        return hashed
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            plain_password: Plain text password to verify
            hashed_password: Stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        if not plain_password or not hashed_password:
            return False
        
        try:
            result = self.pwd_context.verify(plain_password, hashed_password)
            logger.debug(f"Password verification: {'success' if result else 'failed'}")
            return result
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password strength based on configured policy.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check minimum length
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            errors.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
        
        # Check for uppercase letter
        if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Check for lowercase letter
        if settings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Check for numbers
        if settings.PASSWORD_REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")
        
        # Check for special characters
        if settings.PASSWORD_REQUIRE_SPECIAL_CHARS:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                errors.append("Password must contain at least one special character")
        
        # Check for common weak passwords
        weak_passwords = [
            "password", "123456", "qwerty", "admin", "letmein",
            "welcome", "monkey", "1234567890", "password123"
        ]
        if password.lower() in weak_passwords:
            errors.append("Password is too common and easily guessable")
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if password hash needs to be updated.
        
        Args:
            hashed_password: Stored password hash
            
        Returns:
            True if hash needs updating
        """
        return self.pwd_context.needs_update(hashed_password)


# ================================
# JWT Token Management
# ================================

class JWTManager:
    """
    JWT token generation, validation, and management.
    
    Provides secure token handling with rotation, blacklisting,
    and comprehensive validation.
    """
    
    def __init__(self):
        self.algorithm = "HS256"
        self.secret_key = settings.SECRET_KEY
        
        # Ensure secret key is strong enough
        if len(self.secret_key) < 32:
            logger.warning("JWT secret key is shorter than recommended 32 characters")
    
    def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token.
        
        Args:
            data: Data to encode in token
            expires_delta: Custom expiration time
            
        Returns:
            JWT token string
        """
        to_encode = data.copy()
        
        # Set expiration
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        # Add standard claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access",
            "jti": str(uuid4())  # Unique token ID for blacklisting
        })
        
        # Create token
        token = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        logger.debug(f"Created access token with JTI: {to_encode['jti']}")
        return token
    
    def create_refresh_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT refresh token.
        
        Args:
            data: Data to encode in token
            expires_delta: Custom expiration time
            
        Returns:
            JWT refresh token string
        """
        to_encode = data.copy()
        
        # Set expiration
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            )
        
        # Add standard claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "refresh",
            "jti": str(uuid4())  # Unique token ID for blacklisting
        })
        
        # Create token
        token = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        logger.debug(f"Created refresh token with JTI: {to_encode['jti']}")
        return token
    
    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token to verify
            token_type: Expected token type ('access' or 'refresh')
            
        Returns:
            Decoded token data or None if invalid
        """
        try:
            # Decode token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": True}
            )
            
            # Verify token type
            if payload.get("type") != token_type:
                logger.warning(f"Token type mismatch: expected {token_type}, got {payload.get('type')}")
                return None
            
            logger.debug(f"Successfully verified {token_type} token with JTI: {payload.get('jti')}")
            return payload
            
        except ExpiredSignatureError:
            logger.debug(f"Token expired: {token_type}")
            return None
        except InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None
    
    def extract_jti(self, token: str) -> Optional[str]:
        """
        Extract JTI (JWT ID) from token without full verification.
        
        Args:
            token: JWT token
            
        Returns:
            JTI string or None
        """
        try:
            # Decode without verification to get JTI
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": False, "verify_signature": False}
            )
            return payload.get("jti")
        except Exception as e:
            logger.error(f"Failed to extract JTI: {e}")
            return None
    
    def create_token_pair(self, user_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Create access and refresh token pair.
        
        Args:
            user_data: User data to encode
            
        Returns:
            Dict with access_token and refresh_token
        """
        access_token = self.create_access_token(user_data)
        refresh_token = self.create_refresh_token(user_data)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }


# ================================
# API Key Management
# ================================

class APIKeyManager:
    """
    API key generation and validation for developer access.
    """
    
    def __init__(self):
        self.key_prefix = "cap_"
        self.key_length = 32
    
    def generate_api_key(self) -> Tuple[str, str]:
        """
        Generate new API key pair.
        
        Returns:
            Tuple of (api_key, key_hash) - store hash in database
        """
        # Generate random key
        random_part = secrets.token_urlsafe(self.key_length)
        api_key = f"{self.key_prefix}{random_part}"
        
        # Create hash for storage
        key_hash = self._hash_api_key(api_key)
        
        logger.debug("Generated new API key")
        return api_key, key_hash
    
    def _hash_api_key(self, api_key: str) -> str:
        """Hash API key for secure storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def verify_api_key(self, api_key: str, stored_hash: str) -> bool:
        """
        Verify API key against stored hash.
        
        Args:
            api_key: API key to verify
            stored_hash: Stored hash from database
            
        Returns:
            True if key is valid
        """
        if not api_key or not stored_hash:
            return False
        
        computed_hash = self._hash_api_key(api_key)
        return hmac.compare_digest(computed_hash, stored_hash)
    
    def extract_key_prefix(self, api_key: str) -> str:
        """
        Extract displayable prefix from API key.
        
        Args:
            api_key: Full API key
            
        Returns:
            First 8 characters for display
        """
        return api_key[:8] if len(api_key) >= 8 else api_key


# ================================
# Data Encryption
# ================================

class DataEncryption:
    """
    Symmetric encryption for sensitive data storage.
    """
    
    def __init__(self):
        # Derive encryption key from application secret
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"cap_platform_salt",  # In production, use proper random salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(settings.SECRET_KEY.encode()))
        self.cipher = Fernet(key)
    
    def encrypt(self, data: str) -> str:
        """
        Encrypt string data.
        
        Args:
            data: String to encrypt
            
        Returns:
            Encrypted data as base64 string
        """
        if not data:
            return ""
        
        encrypted = self.cipher.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt string data.
        
        Args:
            encrypted_data: Base64 encrypted data
            
        Returns:
            Decrypted string
        """
        if not encrypted_data:
            return ""
        
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise ValueError("Failed to decrypt data")


# ================================
# Security Token Generation
# ================================

class SecurityTokenGenerator:
    """
    Generate secure tokens for various purposes (email verification, password reset, etc.).
    """
    
    @staticmethod
    def generate_verification_token() -> str:
        """Generate secure token for email verification."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_reset_token() -> str:
        """Generate secure token for password reset."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_otp(length: int = 6) -> str:
        """
        Generate numeric OTP.
        
        Args:
            length: Length of OTP
            
        Returns:
            Numeric OTP string
        """
        return ''.join(secrets.choice('0123456789') for _ in range(length))
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> List[str]:
        """
        Generate backup codes for 2FA.
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes
        """
        return [secrets.token_hex(4).upper() for _ in range(count)]


# ================================
# CSRF Protection
# ================================

class CSRFProtection:
    """
    CSRF token generation and validation.
    """
    
    def __init__(self):
        self.secret_key = settings.SECRET_KEY.encode()
    
    def generate_csrf_token(self, session_id: str) -> str:
        """
        Generate CSRF token for session.
        
        Args:
            session_id: User session ID
            
        Returns:
            CSRF token
        """
        # Create token with timestamp
        timestamp = str(int(datetime.now(timezone.utc).timestamp()))
        message = f"{session_id}:{timestamp}"
        
        # Create HMAC signature
        signature = hmac.new(
            self.secret_key,
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Combine timestamp and signature
        token = base64.urlsafe_b64encode(f"{timestamp}:{signature}".encode()).decode()
        return token
    
    def verify_csrf_token(self, token: str, session_id: str, max_age: int = 3600) -> bool:
        """
        Verify CSRF token.
        
        Args:
            token: CSRF token to verify
            session_id: User session ID
            max_age: Maximum token age in seconds
            
        Returns:
            True if token is valid
        """
        try:
            # Decode token
            decoded = base64.urlsafe_b64decode(token.encode()).decode()
            timestamp_str, signature = decoded.split(':', 1)
            
            # Check token age
            token_time = int(timestamp_str)
            current_time = int(datetime.now(timezone.utc).timestamp())
            
            if current_time - token_time > max_age:
                logger.debug("CSRF token expired")
                return False
            
            # Verify signature
            message = f"{session_id}:{timestamp_str}"
            expected_signature = hmac.new(
                self.secret_key,
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            is_valid = hmac.compare_digest(signature, expected_signature)
            logger.debug(f"CSRF token validation: {'success' if is_valid else 'failed'}")
            return is_valid
            
        except (ValueError, TypeError) as e:
            logger.warning(f"CSRF token validation error: {e}")
            return False


# ================================
# Security Headers
# ================================

class SecurityHeaders:
    """
    Security headers configuration for HTTP responses.
    """
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """
        Get recommended security headers.
        
        Returns:
            Dict of security headers
        """
        headers = {
            # Prevent XSS attacks
            "X-XSS-Protection": "1; mode=block",
            
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Control framing (prevent clickjacking)
            "X-Frame-Options": "DENY",
            
            # Referrer policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Permissions policy
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        }
        
        # Add HSTS in production
        if settings.is_production():
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        # Content Security Policy
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",  # Adjust as needed
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self' https:",
            "connect-src 'self' wss: https:",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ]
        headers["Content-Security-Policy"] = "; ".join(csp_directives)
        
        return headers


# ================================
# Input Validation and Sanitization
# ================================

class InputValidator:
    """
    Input validation and sanitization utilities.
    """
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email format.
        
        Args:
            email: Email address to validate
            
        Returns:
            True if email is valid
        """
        import re
        
        if not email or len(email) > 254:
            return False
        
        # RFC 5322 compliant regex (simplified)
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """
        Validate phone number format.
        
        Args:
            phone: Phone number to validate
            
        Returns:
            True if phone is valid
        """
        import re
        
        if not phone:
            return False
        
        # Remove all non-digit characters
        digits_only = re.sub(r'\D', '', phone)
        
        # Check length (7-15 digits for international numbers)
        return 7 <= len(digits_only) <= 15
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """
        Sanitize string input.
        
        Args:
            value: String to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not value:
            return ""
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
        
        # Truncate to max length
        return sanitized[:max_length].strip()
    
    @staticmethod
    def validate_uuid(uuid_string: str) -> bool:
        """
        Validate UUID format.
        
        Args:
            uuid_string: UUID string to validate
            
        Returns:
            True if UUID is valid
        """
        import uuid
        
        try:
            uuid.UUID(uuid_string)
            return True
        except (ValueError, TypeError):
            return False


# ================================
# Security Audit Logging
# ================================

class SecurityAuditor:
    """
    Security event logging and monitoring.
    """
    
    def __init__(self):
        self.logger = get_logger("security")
    
    def log_authentication_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log authentication-related security events.
        
        Args:
            event_type: Type of event (login, logout, failed_login, etc.)
            user_id: User ID involved
            ip_address: Client IP address
            user_agent: Client user agent
            success: Whether the event was successful
            details: Additional event details
        """
        log_data = {
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": success,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {}
        }
        
        log_level = "INFO" if success else "WARNING"
        self.logger.log(
            getattr(self.logger, log_level.lower()),
            f"Security event: {event_type}",
            extra={"security_event": log_data}
        )
    
    def log_suspicious_activity(
        self,
        activity_type: str,
        risk_score: int,
        ip_address: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log suspicious security activities.
        
        Args:
            activity_type: Type of suspicious activity
            risk_score: Risk score (1-100)
            ip_address: Client IP address
            user_id: User ID if known
            details: Additional details
        """
        log_data = {
            "activity_type": activity_type,
            "risk_score": risk_score,
            "ip_address": ip_address,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {}
        }
        
        log_level = "ERROR" if risk_score >= 70 else "WARNING"
        self.logger.log(
            getattr(self.logger, log_level.lower()),
            f"Suspicious activity: {activity_type} (risk: {risk_score})",
            extra={"security_event": log_data}
        )


# ================================
# Global Security Instances
# ================================

# Global security managers
password_manager = PasswordManager()
jwt_manager = JWTManager()
api_key_manager = APIKeyManager()
data_encryption = DataEncryption()
token_generator = SecurityTokenGenerator()
csrf_protection = CSRFProtection()
input_validator = InputValidator()
security_auditor = SecurityAuditor()


# ================================
# Security Decorators
# ================================

def require_auth(func):
    """
    Decorator to require authentication for endpoints.
    
    Usage:
        @require_auth
        async def protected_endpoint():
            pass
    """
    from functools import wraps
    
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # This will be implemented with FastAPI dependencies
        # For now, it's a placeholder
        return await func(*args, **kwargs)
    
    return wrapper


def require_permissions(*required_permissions):
    """
    Decorator to require specific permissions.
    
    Args:
        required_permissions: List of required permission strings
        
    Usage:
        @require_permissions("user:read", "user:write")
        async def user_endpoint():
            pass
    """
    def decorator(func):
        from functools import wraps
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Permission checking logic will be implemented
            # with FastAPI dependencies
            return await func(*args, **kwargs)
        
        wrapper._required_permissions = required_permissions
        return wrapper
    
    return decorator


def rate_limit(requests: int, window: int, key_func=None):
    """
    Decorator for rate limiting endpoints.
    
    Args:
        requests: Number of requests allowed
        window: Time window in seconds
        key_func: Function to generate rate limit key
        
    Usage:
        @rate_limit(requests=10, window=60)
        async def api_endpoint():
            pass
    """
    def decorator(func):
        from functools import wraps
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Rate limiting logic will be implemented
            # with FastAPI dependencies
            return await func(*args, **kwargs)
        
        wrapper._rate_limit = {"requests": requests, "window": window, "key_func": key_func}
        return wrapper
    
    return decorator


# ================================
# Security Utilities
# ================================

def generate_secure_filename(filename: str) -> str:
    """
    Generate secure filename for uploads.
    
    Args:
        filename: Original filename
        
    Returns:
        Secure filename
    """
    import os
    import re
    
    # Get file extension
    name, ext = os.path.splitext(filename)
    
    # Sanitize filename
    secure_name = re.sub(r'[^a-zA-Z0-9._-]', '_', name)
    secure_name = secure_name[:50]  # Limit length
    
    # Add timestamp to prevent conflicts
    timestamp = int(datetime.now(timezone.utc).timestamp())
    
    return f"{secure_name}_{timestamp}{ext}"


def calculate_password_strength(password: str) -> int:
    """
    Calculate password strength score.
    
    Args:
        password: Password to analyze
        
    Returns:
        Strength score (0-100)
    """
    if not password:
        return 0
    
    score = 0
    
    # Length scoring
    length = len(password)
    if length >= 8:
        score += 20
    if length >= 12:
        score += 15
    if length >= 16:
        score += 15
    
    # Character variety scoring
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    variety_score = sum([has_lower, has_upper, has_digit, has_special]) * 10
    score += variety_score
    
    # Complexity bonus
    unique_chars = len(set(password))
    if unique_chars > length * 0.7:
        score += 10
    
    # Pattern penalties
    import re
    
    # Sequential characters penalty
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        score -= 10
    
    # Repeated characters penalty
    if re.search(r'(.)\1{2,}', password):
        score -= 10
    
    # Common patterns penalty
    common_patterns = ['password', 'admin', 'user', 'login', '1234', 'qwer']
    for pattern in common_patterns:
        if pattern.lower() in password.lower():
            score -= 20
            break
    
    return max(0, min(100, score))


def mask_sensitive_data(data: str, show_chars: int = 4) -> str:
    """
    Mask sensitive data for logging.
    
    Args:
        data: Sensitive data to mask
        show_chars: Number of characters to show at the end
        
    Returns:
        Masked data string
    """
    if not data or len(data) <= show_chars:
        return "*" * len(data) if data else ""
    
    mask_length = len(data) - show_chars
    return "*" * mask_length + data[-show_chars:]


# ================================
# Security Configuration Functions
# ================================

def get_cors_config() -> Dict[str, Any]:
    """
    Get CORS configuration for FastAPI.
    
    Returns:
        CORS configuration dict
    """
    return {
        "allow_origins": [str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        "allow_credentials": True,
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        "allow_headers": [
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "X-CSRF-Token",
            "X-API-Key"
        ],
        "expose_headers": [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset"
        ]
    }


def validate_security_configuration():
    """
    Validate security configuration on startup.
    
    Raises:
        ValueError: If security configuration is invalid
    """
    errors = []
    
    # Check secret key strength
    if len(settings.SECRET_KEY) < 32:
        errors.append("SECRET_KEY must be at least 32 characters long")
    
    # Check token expiration times
    if settings.ACCESS_TOKEN_EXPIRE_MINUTES < 5:
        errors.append("ACCESS_TOKEN_EXPIRE_MINUTES should be at least 5 minutes")
    
    if settings.REFRESH_TOKEN_EXPIRE_DAYS < 1:
        errors.append("REFRESH_TOKEN_EXPIRE_DAYS should be at least 1 day")
    
    # Check password policy
    if settings.PASSWORD_MIN_LENGTH < 8:
        errors.append("PASSWORD_MIN_LENGTH should be at least 8 characters")
    
    # Check production-specific requirements
    if settings.is_production():
        production_errors = []
        
        if not settings.SESSION_COOKIE_SECURE:
            production_errors.append("SESSION_COOKIE_SECURE must be True in production")
        
        if not settings.SESSION_COOKIE_HTTPONLY:
            production_errors.append("SESSION_COOKIE_HTTPONLY must be True in production")
        
        if not all([
            settings.SMTP_HOST,
            settings.SMTP_USER,
            settings.SMTP_PASSWORD,
            settings.EMAILS_FROM_EMAIL
        ]):
            production_errors.append("SMTP configuration is required in production")
        
        errors.extend(production_errors)
    
    if errors:
        error_message = "Security configuration errors:\n" + "\n".join(f"- {error}" for error in errors)
        logger.error(error_message)
        raise ValueError(error_message)
    
    logger.info("Security configuration validation passed")


# ================================
# Security Initialization
# ================================

def init_security():
    """Initialize security components."""
    logger.info("Initializing security components...")
    
    # Validate configuration
    validate_security_configuration()
    
    # Log security configuration (without sensitive data)
    security_config = {
        "password_min_length": settings.PASSWORD_MIN_LENGTH,
        "access_token_expire_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        "refresh_token_expire_days": settings.REFRESH_TOKEN_EXPIRE_DAYS,
        "account_lockout_attempts": settings.ACCOUNT_LOCKOUT_ATTEMPTS,
        "environment": settings.ENVIRONMENT
    }
    
    logger.info(f"Security configuration: {security_config}")
    logger.info("Security components initialized successfully")


# ================================
# Cleanup Function
# ================================

def cleanup_security():
    """Cleanup security components."""
    logger.info("Cleaning up security components...")
    # Any cleanup needed for security components
    logger.info("Security cleanup completed")
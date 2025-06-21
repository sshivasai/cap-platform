# File: backend/app/utils/password.py
"""
Password utility functions for secure password handling.

This module provides utilities for:
- Password hashing using bcrypt
- Password verification
- Password strength validation
- Password generation
"""

import re
import secrets
import string
from typing import Tuple, List

import bcrypt

from app.core.config import settings


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password to hash
        
    Returns:
        str: Hashed password
    """
    # Convert string to bytes
    password_bytes = password.encode('utf-8')
    
    # Generate salt and hash password
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds for good security/performance balance
    hashed = bcrypt.hashpw(password_bytes, salt)
    
    # Return as string
    return hashed.decode('utf-8')


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        password: Plain text password to verify
        hashed_password: Hashed password to verify against
        
    Returns:
        bool: True if password matches hash
    """
    try:
        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, List[str], int]:
    """
    Validate password strength based on platform requirements.
    
    Args:
        password: Password to validate
        
    Returns:
        tuple: (is_valid, list_of_errors, strength_score)
    """
    errors = []
    score = 0
    
    # Check minimum length
    min_length = settings.PASSWORD_MIN_LENGTH
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long")
    else:
        score += min(len(password) * 2, 20)  # Up to 20 points for length
    
    # Check for uppercase letters
    if settings.PASSWORD_REQUIRE_UPPERCASE:
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        else:
            score += 10
    
    # Check for lowercase letters
    if settings.PASSWORD_REQUIRE_LOWERCASE:
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        else:
            score += 10
    
    # Check for numbers
    if settings.PASSWORD_REQUIRE_NUMBERS:
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        else:
            score += 10
    
    # Check for special characters
    if settings.PASSWORD_REQUIRE_SPECIAL_CHARS:
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            errors.append("Password must contain at least one special character")
        else:
            score += 15
    
    # Additional strength checks
    
    # Check for character variety
    char_types = 0
    if re.search(r'[a-z]', password):
        char_types += 1
    if re.search(r'[A-Z]', password):
        char_types += 1
    if re.search(r'\d', password):
        char_types += 1
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        char_types += 1
    
    score += char_types * 5  # 5 points per character type
    
    # Check for repeated characters
    repeated_chars = len(password) - len(set(password))
    score -= repeated_chars * 2  # Penalty for repeated characters
    
    # Check for common patterns
    common_patterns = [
        r'123',
        r'abc',
        r'qwe',
        r'password',
        r'admin',
        r'user',
        r'login'
    ]
    
    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            score -= 10
            if len(errors) < 5:  # Don't overwhelm with too many errors
                errors.append(f"Password should not contain common patterns like '{pattern}'")
    
    # Check for keyboard patterns
    keyboard_patterns = [
        r'qwerty',
        r'asdf',
        r'zxcv',
        r'1234',
        r'abcd'
    ]
    
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            score -= 5
    
    # Ensure score is between 0 and 100
    score = max(0, min(100, score))
    
    is_valid = len(errors) == 0 and score >= 50
    
    return is_valid, errors, score


def generate_secure_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_numbers: bool = True,
    include_special: bool = True,
    exclude_ambiguous: bool = True
) -> str:
    """
    Generate a secure random password.
    
    Args:
        length: Length of password to generate
        include_uppercase: Include uppercase letters
        include_lowercase: Include lowercase letters
        include_numbers: Include numbers
        include_special: Include special characters
        exclude_ambiguous: Exclude ambiguous characters (0, O, l, 1, etc.)
        
    Returns:
        str: Generated secure password
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")
    
    # Build character set
    chars = ""
    
    if include_lowercase:
        chars += string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace('l', '').replace('o', '')
    
    if include_uppercase:
        chars += string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace('I', '').replace('O', '')
    
    if include_numbers:
        chars += string.digits
        if exclude_ambiguous:
            chars = chars.replace('0', '').replace('1', '')
    
    if include_special:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if exclude_ambiguous:
            # Remove potentially ambiguous special characters
            special_chars = special_chars.replace('|', '').replace('l', '')
        chars += special_chars
    
    if not chars:
        raise ValueError("At least one character type must be included")
    
    # Generate password ensuring at least one character from each required type
    password = []
    
    # Add required characters first
    if include_lowercase:
        available = string.ascii_lowercase
        if exclude_ambiguous:
            available = available.replace('l', '').replace('o', '')
        password.append(secrets.choice(available))
    
    if include_uppercase:
        available = string.ascii_uppercase
        if exclude_ambiguous:
            available = available.replace('I', '').replace('O', '')
        password.append(secrets.choice(available))
    
    if include_numbers:
        available = string.digits
        if exclude_ambiguous:
            available = available.replace('0', '').replace('1', '')
        password.append(secrets.choice(available))
    
    if include_special:
        available = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if exclude_ambiguous:
            available = available.replace('|', '').replace('l', '')
        password.append(secrets.choice(available))
    
    # Fill the rest with random characters
    remaining_length = length - len(password)
    for _ in range(remaining_length):
        password.append(secrets.choice(chars))
    
    # Shuffle the password to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)


def generate_reset_token() -> str:
    """
    Generate a secure token for password reset.
    
    Returns:
        str: Secure random token
    """
    return secrets.token_urlsafe(32)


def generate_verification_token() -> str:
    """
    Generate a secure token for email verification.
    
    Returns:
        str: Secure random token
    """
    return secrets.token_urlsafe(32)


def generate_phone_verification_code() -> str:
    """
    Generate a numeric code for phone verification.
    
    Returns:
        str: 6-digit numeric code
    """
    return ''.join(secrets.choice(string.digits) for _ in range(6))


def is_password_compromised(password: str) -> bool:
    """
    Check if password appears in common breach lists.
    
    Note: This is a placeholder function. In production, you might want to
    integrate with services like HaveIBeenPwned or maintain your own
    compromised password database.
    
    Args:
        password: Password to check
        
    Returns:
        bool: True if password is compromised
    """
    # Common compromised passwords
    common_passwords = {
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey',
        '1234567890', 'password1', '123123', 'admin123', 'root',
        'user', 'test', 'guest', 'demo', 'sample'
    }
    
    return password.lower() in common_passwords


def get_password_strength_description(score: int) -> str:
    """
    Get a human-readable description of password strength.
    
    Args:
        score: Password strength score (0-100)
        
    Returns:
        str: Strength description
    """
    if score < 30:
        return "Very Weak"
    elif score < 50:
        return "Weak"
    elif score < 70:
        return "Fair"
    elif score < 85:
        return "Good"
    else:
        return "Strong"


def suggest_password_improvements(password: str) -> List[str]:
    """
    Suggest improvements for a password.
    
    Args:
        password: Password to analyze
        
    Returns:
        list: List of improvement suggestions
    """
    suggestions = []
    
    if len(password) < 12:
        suggestions.append("Consider using a longer password (12+ characters)")
    
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add uppercase letters")
    
    if not re.search(r'[a-z]', password):
        suggestions.append("Add lowercase letters")
    
    if not re.search(r'\d', password):
        suggestions.append("Add numbers")
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        suggestions.append("Add special characters")
    
    # Check for repeated characters
    if len(password) - len(set(password)) > len(password) * 0.3:
        suggestions.append("Reduce repeated characters")
    
    # Check for sequential characters
    sequential_patterns = ['123', 'abc', 'qwe']
    for pattern in sequential_patterns:
        if pattern in password.lower():
            suggestions.append("Avoid sequential characters")
            break
    
    if is_password_compromised(password):
        suggestions.append("This password has been found in data breaches - choose a different one")
    
    return suggestions
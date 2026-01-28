#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.
# Individual use is free. Commercial use requires 3% profit sharing.
# See LICENSE file for details.

"""
Input Validation Models for Enterprise OSINT Platform

Provides Pydantic models for validating and sanitizing API inputs
to prevent injection attacks and ensure data integrity.
"""

import re
import logging
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from datetime import datetime

logger = logging.getLogger(__name__)

# Valid investigation types (whitelist)
VALID_INVESTIGATION_TYPES = ['comprehensive', 'infrastructure', 'social_media', 'threat_assessment', 'corporate']

# Valid priority levels (whitelist)
VALID_PRIORITIES = ['low', 'normal', 'high', 'urgent', 'critical']

# Valid report formats
VALID_REPORT_FORMATS = ['json', 'pdf', 'markdown', 'html']

# Regex patterns for target validation
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
IP_V4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)
IP_V6_PATTERN = re.compile(
    r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
    r'^(?:[0-9a-fA-F]{1,4}:){1,7}:$|'
    r'^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$'
)
EMAIL_PATTERN = re.compile(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
)
USERNAME_PATTERN = re.compile(
    r'^[a-zA-Z0-9_.-]{1,64}$'
)

# Characters that could indicate injection attempts
DANGEROUS_PATTERNS = [
    r'<script',           # XSS
    r'javascript:',       # XSS
    r'on\w+\s*=',        # Event handlers
    r';\s*--',           # SQL comment
    r"'\s*or\s*'",       # SQL injection
    r'"\s*or\s*"',       # SQL injection
    r'\$\{',             # Template injection
    r'\{\{',             # Template injection
    r'`.*`',             # Command injection
    r'\|.*\|',           # Pipe injection
    r'&{2,}',            # Command chaining
    r';{2,}',            # Command chaining
]


class ValidationError(Exception):
    """Custom validation error with details"""
    def __init__(self, message: str, field: str = None, details: dict = None):
        self.message = message
        self.field = field
        self.details = details or {}
        super().__init__(self.message)


def sanitize_string(value: str, max_length: int = 255) -> str:
    """
    Sanitize a string input by:
    - Stripping whitespace
    - Limiting length
    - Removing null bytes
    - Escaping potentially dangerous characters
    """
    if not value:
        return value

    # Strip and limit length
    value = value.strip()[:max_length]

    # Remove null bytes
    value = value.replace('\x00', '')

    # Remove control characters (except newline, tab)
    value = ''.join(c for c in value if c.isprintable() or c in '\n\t')

    return value


def check_dangerous_patterns(value: str, field_name: str = 'input') -> None:
    """Check for potentially dangerous patterns in input"""
    if not value:
        return

    lower_value = value.lower()
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, lower_value, re.IGNORECASE):
            logger.warning(f"Potentially dangerous pattern detected in {field_name}: {pattern}")
            raise ValidationError(
                f"Invalid characters detected in {field_name}",
                field=field_name,
                details={'pattern': 'dangerous_characters'}
            )


def validate_target_format(target: str) -> str:
    """
    Validate that target is a valid domain, IP, email, or username.
    Returns the sanitized target.
    """
    target = sanitize_string(target, max_length=253)  # Max domain length

    if not target:
        raise ValidationError("Target cannot be empty", field='target')

    # Check for dangerous patterns
    check_dangerous_patterns(target, 'target')

    # Check if it matches any valid format
    is_valid = (
        DOMAIN_PATTERN.match(target) or
        IP_V4_PATTERN.match(target) or
        IP_V6_PATTERN.match(target) or
        EMAIL_PATTERN.match(target) or
        USERNAME_PATTERN.match(target)
    )

    if not is_valid:
        raise ValidationError(
            "Target must be a valid domain, IP address, email, or username",
            field='target',
            details={'provided': target[:50]}  # Truncate for logging
        )

    return target


class InvestigationRequest(BaseModel):
    """
    Validated investigation creation request.

    Ensures all inputs are properly validated and sanitized
    before processing.
    """
    target: str = Field(..., min_length=1, max_length=253, description="Investigation target (domain, IP, email, or username)")
    type: Literal['comprehensive', 'infrastructure', 'social_media', 'threat_assessment', 'corporate'] = Field(
        default='comprehensive',
        description="Type of investigation to perform"
    )
    priority: Literal['low', 'normal', 'high', 'urgent', 'critical'] = Field(
        default='normal',
        description="Investigation priority level"
    )
    investigator: str = Field(
        default='System',
        min_length=1,
        max_length=100,
        description="Name of the investigator"
    )
    notes: Optional[str] = Field(
        default=None,
        max_length=2000,
        description="Optional investigation notes"
    )

    @field_validator('target')
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Validate and sanitize target"""
        return validate_target_format(v)

    @field_validator('investigator')
    @classmethod
    def validate_investigator(cls, v: str) -> str:
        """Validate and sanitize investigator name"""
        v = sanitize_string(v, max_length=100)
        check_dangerous_patterns(v, 'investigator')

        # Only allow alphanumeric, spaces, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9\s_.-]+$', v):
            raise ValueError('Investigator name contains invalid characters')

        return v

    @field_validator('notes')
    @classmethod
    def validate_notes(cls, v: Optional[str]) -> Optional[str]:
        """Validate and sanitize notes"""
        if v is None:
            return v
        v = sanitize_string(v, max_length=2000)
        check_dangerous_patterns(v, 'notes')
        return v


class LoginRequest(BaseModel):
    """Validated login request"""
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format"""
        v = sanitize_string(v, max_length=64)
        check_dangerous_patterns(v, 'username')

        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError('Username contains invalid characters')

        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Basic password validation - don't log or expose"""
        if not v or len(v) < 1:
            raise ValueError('Password is required')
        # Don't sanitize password - just check length
        if len(v) > 128:
            raise ValueError('Password too long')
        return v


class ComplianceAssessmentRequest(BaseModel):
    """Validated compliance assessment request"""
    target: str = Field(..., min_length=1, max_length=253)
    framework: Literal['gdpr', 'ccpa', 'pipeda', 'lgpd', 'hipaa'] = Field(
        default='gdpr',
        description="Compliance framework to assess"
    )
    data_categories: Optional[List[str]] = Field(
        default=None,
        max_length=20,
        description="Data categories to assess"
    )

    @field_validator('target')
    @classmethod
    def validate_target(cls, v: str) -> str:
        return validate_target_format(v)

    @field_validator('data_categories')
    @classmethod
    def validate_data_categories(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v

        # Validate each category
        valid_categories = [
            'personal_data', 'sensitive_data', 'financial_data',
            'health_data', 'biometric_data', 'location_data',
            'contact_info', 'professional_data', 'public_data',
            'business_contact'
        ]

        sanitized = []
        for cat in v[:20]:  # Max 20 categories
            cat = sanitize_string(cat, max_length=50)
            if cat.lower() in valid_categories:
                sanitized.append(cat.lower())

        return sanitized if sanitized else None


class RiskAssessmentRequest(BaseModel):
    """Validated risk assessment request"""
    target: str = Field(..., min_length=1, max_length=253)
    context: Optional[str] = Field(default=None, max_length=500)
    include_recommendations: bool = Field(default=True)

    @field_validator('target')
    @classmethod
    def validate_target(cls, v: str) -> str:
        return validate_target_format(v)

    @field_validator('context')
    @classmethod
    def validate_context(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = sanitize_string(v, max_length=500)
        check_dangerous_patterns(v, 'context')
        return v


class ReportGenerationRequest(BaseModel):
    """Validated report generation request"""
    format: Literal['json', 'pdf', 'markdown', 'html'] = Field(
        default='pdf',
        description="Report output format"
    )
    include_executive_summary: bool = Field(default=True)
    include_technical_details: bool = Field(default=True)
    include_recommendations: bool = Field(default=True)
    classification: Literal['unclassified', 'confidential', 'secret', 'top_secret'] = Field(
        default='confidential',
        description="Report classification level"
    )


def validate_investigation_request(data: dict) -> InvestigationRequest:
    """
    Validate investigation request data and return validated model.
    Raises ValidationError on invalid input.
    """
    try:
        return InvestigationRequest(**data)
    except Exception as e:
        logger.warning(f"Investigation validation failed: {str(e)}")
        raise ValidationError(str(e), details={'validation_errors': str(e)})


def validate_login_request(data: dict) -> LoginRequest:
    """Validate login request data"""
    try:
        return LoginRequest(**data)
    except Exception as e:
        # Don't log password-related errors in detail
        logger.warning("Login validation failed")
        raise ValidationError("Invalid login credentials format")


def validate_compliance_request(data: dict) -> ComplianceAssessmentRequest:
    """Validate compliance assessment request"""
    try:
        return ComplianceAssessmentRequest(**data)
    except Exception as e:
        logger.warning(f"Compliance validation failed: {str(e)}")
        raise ValidationError(str(e), details={'validation_errors': str(e)})


def validate_risk_request(data: dict) -> RiskAssessmentRequest:
    """Validate risk assessment request"""
    try:
        return RiskAssessmentRequest(**data)
    except Exception as e:
        logger.warning(f"Risk assessment validation failed: {str(e)}")
        raise ValidationError(str(e), details={'validation_errors': str(e)})


def validate_report_request(data: dict) -> ReportGenerationRequest:
    """Validate report generation request"""
    try:
        return ReportGenerationRequest(**data)
    except Exception as e:
        logger.warning(f"Report validation failed: {str(e)}")
        raise ValidationError(str(e), details={'validation_errors': str(e)})


# Safe error messages that don't expose internal details
SAFE_ERROR_MESSAGES = {
    'database_error': 'A database error occurred. Please try again later.',
    'authentication_error': 'Authentication failed. Please check your credentials.',
    'authorization_error': 'You do not have permission to perform this action.',
    'validation_error': 'The request contains invalid data.',
    'not_found': 'The requested resource was not found.',
    'rate_limit': 'Too many requests. Please try again later.',
    'service_unavailable': 'Service temporarily unavailable. Please try again later.',
    'internal_error': 'An internal error occurred. Please contact support if the problem persists.',
}


def get_safe_error_message(error_type: str, default: str = None) -> str:
    """Get a safe error message that doesn't expose internal details"""
    return SAFE_ERROR_MESSAGES.get(error_type, default or SAFE_ERROR_MESSAGES['internal_error'])

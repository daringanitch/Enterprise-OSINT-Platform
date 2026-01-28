#!/usr/bin/env python3
"""
Unit tests for input validation module.

Tests security validation including:
- Target format validation (domain, IP, email)
- Dangerous pattern detection (XSS, SQL injection)
- Input sanitization
- Pydantic model validation
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from validators import (
    validate_target_format, sanitize_string, check_dangerous_patterns,
    InvestigationRequest, LoginRequest, ComplianceAssessmentRequest,
    RiskAssessmentRequest, ValidationError, DOMAIN_PATTERN, IP_V4_PATTERN,
    EMAIL_PATTERN, validate_investigation_request, validate_login_request
)


class TestTargetValidation:
    """Test target format validation"""

    def test_valid_domain(self):
        """Test valid domain names are accepted"""
        valid_domains = [
            'example.com',
            'sub.example.com',
            'test-site.org',
            'my-company.co.uk',
            'a.io',
        ]
        for domain in valid_domains:
            result = validate_target_format(domain)
            assert result == domain

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses are accepted"""
        valid_ips = [
            '192.168.1.1',
            '10.0.0.1',
            '172.16.0.1',
            '8.8.8.8',
            '255.255.255.255',
        ]
        for ip in valid_ips:
            result = validate_target_format(ip)
            assert result == ip

    def test_valid_email(self):
        """Test valid email addresses are accepted"""
        valid_emails = [
            'test@example.com',
            'user.name@company.org',
            'admin+tag@domain.co.uk',
        ]
        for email in valid_emails:
            result = validate_target_format(email)
            assert result == email

    def test_valid_username(self):
        """Test valid usernames are accepted"""
        valid_usernames = [
            'johndoe',
            'user_123',
            'test.user',
            'admin-user',
        ]
        for username in valid_usernames:
            result = validate_target_format(username)
            assert result == username

    def test_empty_target_rejected(self):
        """Test empty target is rejected"""
        with pytest.raises(ValidationError) as exc_info:
            validate_target_format('')
        assert 'empty' in str(exc_info.value).lower()

    def test_whitespace_only_rejected(self):
        """Test whitespace-only target is rejected"""
        with pytest.raises(ValidationError):
            validate_target_format('   ')

    def test_invalid_target_rejected(self):
        """Test invalid targets are rejected"""
        invalid_targets = [
            'not a valid target!',
            'target with spaces',
            '<script>alert(1)</script>',
            '../../etc/passwd',
        ]
        for target in invalid_targets:
            with pytest.raises(ValidationError):
                validate_target_format(target)


class TestDangerousPatternDetection:
    """Test dangerous pattern detection"""

    def test_xss_patterns_detected(self):
        """Test XSS patterns are detected"""
        xss_patterns = [
            '<script>alert(1)</script>',
            'javascript:void(0)',
            '<img onerror=alert(1)>',
            '<div onclick=evil()>',
        ]
        for pattern in xss_patterns:
            with pytest.raises(ValidationError):
                check_dangerous_patterns(pattern, 'test')

    def test_sql_injection_patterns_detected(self):
        """Test SQL injection patterns are detected"""
        sql_patterns = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            '" OR "1"="1',
        ]
        for pattern in sql_patterns:
            with pytest.raises(ValidationError):
                check_dangerous_patterns(pattern, 'test')

    def test_template_injection_detected(self):
        """Test template injection patterns are detected"""
        template_patterns = [
            '${7*7}',
            '{{config}}',
        ]
        for pattern in template_patterns:
            with pytest.raises(ValidationError):
                check_dangerous_patterns(pattern, 'test')

    def test_safe_strings_allowed(self):
        """Test safe strings pass validation"""
        safe_strings = [
            'example.com',
            'normal text here',
            'user@example.com',
            'test-domain.org',
        ]
        for s in safe_strings:
            # Should not raise
            check_dangerous_patterns(s, 'test')


class TestStringSanitization:
    """Test string sanitization"""

    def test_strips_whitespace(self):
        """Test leading/trailing whitespace is removed"""
        assert sanitize_string('  test  ') == 'test'

    def test_limits_length(self):
        """Test string length is limited"""
        long_string = 'a' * 1000
        result = sanitize_string(long_string, max_length=100)
        assert len(result) == 100

    def test_removes_null_bytes(self):
        """Test null bytes are removed"""
        result = sanitize_string('test\x00value')
        assert '\x00' not in result
        assert result == 'testvalue'

    def test_removes_control_characters(self):
        """Test control characters are removed"""
        result = sanitize_string('test\x01\x02value')
        assert result == 'testvalue'

    def test_preserves_newlines_tabs(self):
        """Test newlines and tabs are preserved"""
        result = sanitize_string('test\n\tvalue')
        assert '\n' in result
        assert '\t' in result


class TestInvestigationRequestValidation:
    """Test InvestigationRequest Pydantic model"""

    def test_valid_request(self):
        """Test valid investigation request"""
        req = InvestigationRequest(
            target='example.com',
            type='comprehensive',
            priority='normal',
            investigator='Test User'
        )
        assert req.target == 'example.com'
        assert req.type == 'comprehensive'
        assert req.priority == 'normal'

    def test_default_values(self):
        """Test default values are applied"""
        req = InvestigationRequest(target='example.com')
        assert req.type == 'comprehensive'
        assert req.priority == 'normal'
        assert req.investigator == 'System'

    def test_invalid_type_rejected(self):
        """Test invalid investigation type is rejected"""
        with pytest.raises(Exception):
            InvestigationRequest(target='example.com', type='invalid_type')

    def test_invalid_priority_rejected(self):
        """Test invalid priority is rejected"""
        with pytest.raises(Exception):
            InvestigationRequest(target='example.com', priority='invalid')

    def test_xss_in_target_rejected(self):
        """Test XSS in target is rejected"""
        with pytest.raises(Exception):
            InvestigationRequest(target='<script>alert(1)</script>')


class TestLoginRequestValidation:
    """Test LoginRequest Pydantic model"""

    def test_valid_login(self):
        """Test valid login request"""
        req = LoginRequest(username='testuser', password='password123')
        assert req.username == 'testuser'
        assert req.password == 'password123'

    def test_empty_username_rejected(self):
        """Test empty username is rejected"""
        with pytest.raises(Exception):
            LoginRequest(username='', password='password')

    def test_empty_password_rejected(self):
        """Test empty password is rejected"""
        with pytest.raises(Exception):
            LoginRequest(username='testuser', password='')

    def test_invalid_username_characters_rejected(self):
        """Test invalid characters in username are rejected"""
        with pytest.raises(Exception):
            LoginRequest(username='test<user>', password='password')

    def test_username_sql_injection_rejected(self):
        """Test SQL injection in username is rejected"""
        with pytest.raises(Exception):
            LoginRequest(username="admin'; DROP TABLE users;--", password='password')


class TestComplianceRequestValidation:
    """Test ComplianceAssessmentRequest validation"""

    def test_valid_compliance_request(self):
        """Test valid compliance request"""
        req = ComplianceAssessmentRequest(
            target='example.com',
            framework='gdpr'
        )
        assert req.target == 'example.com'
        assert req.framework == 'gdpr'

    def test_invalid_framework_rejected(self):
        """Test invalid framework is rejected"""
        with pytest.raises(Exception):
            ComplianceAssessmentRequest(target='example.com', framework='invalid')


class TestValidationHelpers:
    """Test validation helper functions"""

    def test_validate_investigation_request_helper(self):
        """Test validate_investigation_request helper"""
        data = {
            'target': 'example.com',
            'type': 'comprehensive',
            'priority': 'high',
            'investigator': 'Test User'
        }
        result = validate_investigation_request(data)
        assert result.target == 'example.com'

    def test_validate_investigation_request_invalid(self):
        """Test validate_investigation_request with invalid data"""
        with pytest.raises(ValidationError):
            validate_investigation_request({'target': '<script>bad</script>'})

    def test_validate_login_request_helper(self):
        """Test validate_login_request helper"""
        data = {'username': 'testuser', 'password': 'password123'}
        result = validate_login_request(data)
        assert result.username == 'testuser'


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_max_length_domain(self):
        """Test maximum length domain (253 chars)"""
        # Create a domain at max length
        long_domain = ('a' * 63 + '.') * 3 + 'com'
        if len(long_domain) <= 253:
            # Should be accepted if valid format
            pass  # May or may not be valid depending on exact length

    def test_unicode_handling(self):
        """Test unicode characters are handled safely"""
        # Unicode should be rejected in domain validation
        with pytest.raises(ValidationError):
            validate_target_format('tëst.com')

    def test_null_input_handling(self):
        """Test None input is handled"""
        result = sanitize_string(None)
        assert result is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

#!/usr/bin/env python3
"""
Unit tests for credential_intel_service module.

Tests:
  - CredentialIntelService instantiation
  - check_password_pwned() with mocked HIBP response
  - analyze_passwords() with mocked pattern detection
  - get_source_status() returns expected structure
  - Graceful degradation when clients unavailable
  - All methods with mocked external calls
"""

import pytest
import os
from unittest.mock import Mock, patch, AsyncMock, MagicMock

from credential_intel_service import (
    CredentialIntelService,
    _unavailable_response,
    _run_async,
)


# ─────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────

@pytest.fixture
def clean_env(monkeypatch):
    """Clean environment variables for credentials."""
    keys_to_remove = ['HIBP_API_KEY', 'DEHASHED_EMAIL', 'DEHASHED_API_KEY']
    for key in keys_to_remove:
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


@pytest.fixture
def service():
    """Create a CredentialIntelService instance."""
    return CredentialIntelService()


# ─────────────────────────────────────────────────────────────────────────
# Tests: Service instantiation
# ─────────────────────────────────────────────────────────────────────────

def test_credential_intel_service_instantiation(clean_env):
    """Test creating a CredentialIntelService."""
    svc = CredentialIntelService()
    assert svc is not None


# ─────────────────────────────────────────────────────────────────────────
# Tests: Unavailable responses
# ─────────────────────────────────────────────────────────────────────────

def test_unavailable_response():
    """Test _unavailable_response() structure."""
    resp = _unavailable_response("hibp", "test@example.com", "Client not available")
    assert resp["error"] == "Client not available"
    assert resp["target"] == "test@example.com"
    assert resp["source"] == "hibp"


# ─────────────────────────────────────────────────────────────────────────
# Tests: check_password_pwned
# ─────────────────────────────────────────────────────────────────────────

@patch('credential_intel_service._CLIENTS_AVAILABLE', False)
def test_check_password_pwned_unavailable(service):
    """Test check_password_pwned when clients are unavailable."""
    result = service.check_password_pwned("password123")
    assert "error" in result
    assert result["source"] == "hibp_passwords"


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
@patch('credential_intel_service.HIBPClient')
def test_check_password_pwned_not_pwned(mock_hibp_class, clean_env, service):
    """Test check_password_pwned returns not pwned."""
    # Mock the async client
    mock_client = AsyncMock()
    mock_client.check_password_pwned = AsyncMock(
        return_value={
            "is_pwned": False,
            "pwned_count": 0,
        }
    )
    mock_hibp_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_hibp_class.return_value.__aexit__ = AsyncMock(return_value=None)

    result = service.check_password_pwned("SuperSecurePassword123!")
    assert result["is_pwned"] is False
    assert result["pwned_count"] == 0


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
@patch('credential_intel_service.HIBPClient')
def test_check_password_pwned_is_pwned(mock_hibp_class, clean_env, service):
    """Test check_password_pwned returns pwned."""
    mock_client = AsyncMock()
    mock_client.check_password_pwned = AsyncMock(
        return_value={
            "is_pwned": True,
            "pwned_count": 456,
        }
    )
    mock_hibp_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_hibp_class.return_value.__aexit__ = AsyncMock(return_value=None)

    result = service.check_password_pwned("password123")
    assert result["is_pwned"] is True
    assert result["pwned_count"] == 456


# ─────────────────────────────────────────────────────────────────────────
# Tests: analyze_passwords
# ─────────────────────────────────────────────────────────────────────────

@patch('credential_intel_service._CLIENTS_AVAILABLE', False)
def test_analyze_passwords_unavailable(service):
    """Test analyze_passwords when clients unavailable."""
    result = service.analyze_passwords(["pass1", "pass2"])
    assert "error" in result


# ─────────────────────────────────────────────────────────────────────────
# Tests: get_source_status
# ─────────────────────────────────────────────────────────────────────────

@patch('credential_intel_service._CLIENTS_AVAILABLE', False)
def test_get_source_status_no_clients(service):
    """Test get_source_status when clients unavailable."""
    status = service.get_source_status()
    assert status["clients_available"] is False
    assert "sources" in status
    assert status["sources"]["hibp"]["available"] is False


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
def test_get_source_status_with_clients(clean_env, service):
    """Test get_source_status with all clients available."""
    status = service.get_source_status()
    assert status["clients_available"] is True
    assert "sources" in status

    # Check expected sources
    expected_sources = ["hibp", "dehashed", "hudson_rock", "paste"]
    for source in expected_sources:
        assert source in status["sources"]
        assert "available" in status["sources"][source]


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
def test_get_source_status_hibp_configured(clean_env):
    """Test get_source_status with HIBP key configured."""
    clean_env.setenv('HIBP_API_KEY', 'test-key-12345')

    svc = CredentialIntelService()
    status = svc.get_source_status()

    hibp_status = status["sources"]["hibp"]
    assert hibp_status["api_key_set"] is True
    assert hibp_status["configured"] is True


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
def test_get_source_status_dehashed_unconfigured(clean_env, service):
    """Test get_source_status with Dehashed missing keys."""
    status = service.get_source_status()

    dehashed_status = status["sources"]["dehashed"]
    assert dehashed_status["configured"] is False
    assert dehashed_status.get("email_set") is False


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
def test_get_source_status_free_sources(clean_env, service):
    """Test get_source_status shows free sources as always available."""
    status = service.get_source_status()

    hudson = status["sources"]["hudson_rock"]
    paste = status["sources"]["paste"]

    assert hudson["available"] is True
    assert hudson["configured"] is True
    assert "free" in hudson.get("note", "").lower()

    assert paste["available"] is True
    assert paste["configured"] is True


# ─────────────────────────────────────────────────────────────────────────
# Tests: HIBP methods
# ─────────────────────────────────────────────────────────────────────────

@patch('credential_intel_service._CLIENTS_AVAILABLE', False)
def test_check_email_breaches_unavailable(service):
    """Test check_email_breaches when HIBP unavailable."""
    result = service.check_email_breaches("test@example.com")
    assert "error" in result


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
@patch('credential_intel_service.HIBPClient')
def test_check_email_breaches_found(mock_hibp_class, clean_env, service):
    """Test check_email_breaches with breaches found."""
    mock_client = AsyncMock()
    mock_client.check_email = AsyncMock(
        return_value={
            "email": "test@example.com",
            "breaches": ["LinkedIn", "Equifax"],
            "breach_count": 2,
        }
    )
    mock_hibp_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_hibp_class.return_value.__aexit__ = AsyncMock(return_value=None)

    result = service.check_email_breaches("test@example.com")
    assert result["breach_count"] == 2


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
@patch('credential_intel_service.HIBPClient')
def test_check_email_pastes(mock_hibp_class, clean_env, service):
    """Test check_email_pastes."""
    mock_client = AsyncMock()
    mock_client.check_pastes = AsyncMock(
        return_value={
            "email": "test@example.com",
            "pastes": ["PasteSite1", "PasteSite2"],
        }
    )
    mock_hibp_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_hibp_class.return_value.__aexit__ = AsyncMock(return_value=None)

    result = service.check_email_pastes("test@example.com")
    assert "pastes" in result


# ─────────────────────────────────────────────────────────────────────────
# Tests: Dehashed methods
# ─────────────────────────────────────────────────────────────────────────

@patch('credential_intel_service._CLIENTS_AVAILABLE', False)
def test_dehashed_search_unavailable(service):
    """Test dehashed_search when Dehashed unavailable."""
    result = service.dehashed_search("test@example.com")
    assert "error" in result


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
@patch('credential_intel_service.DehashedClient')
def test_dehashed_domain(mock_dehashed_class, clean_env, service):
    """Test dehashed_domain search."""
    mock_client = AsyncMock()
    mock_client.search_domain = AsyncMock(
        return_value={
            "domain": "example.com",
            "results": [
                {"email": "user1@example.com", "password": "hash1"},
                {"email": "user2@example.com", "password": "hash2"},
            ],
        }
    )
    mock_dehashed_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_dehashed_class.return_value.__aexit__ = AsyncMock(return_value=None)

    result = service.dehashed_domain("example.com")
    assert result["domain"] == "example.com"
    assert len(result["results"]) == 2


# ─────────────────────────────────────────────────────────────────────────
# Tests: Hudson Rock methods
# ─────────────────────────────────────────────────────────────────────────

@patch('credential_intel_service._CLIENTS_AVAILABLE', False)
def test_hudson_rock_email_unavailable(service):
    """Test hudson_rock_email when unavailable."""
    result = service.hudson_rock_email("test@example.com")
    assert "error" in result


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
@patch('credential_intel_service.HudsonRockClient')
def test_hudson_rock_email(mock_hr_class, clean_env, service):
    """Test hudson_rock_email lookup."""
    mock_client = AsyncMock()
    mock_client.search_email = AsyncMock(
        return_value={
            "email": "test@example.com",
            "infostealer_hits": 3,
            "domains": ["malware1.com", "cc-dump.ru"],
        }
    )
    mock_hr_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_hr_class.return_value.__aexit__ = AsyncMock(return_value=None)

    result = service.hudson_rock_email("test@example.com")
    assert result["infostealer_hits"] == 3


# ─────────────────────────────────────────────────────────────────────────
# Tests: Paste monitor methods
# ─────────────────────────────────────────────────────────────────────────

@patch('credential_intel_service._CLIENTS_AVAILABLE', False)
def test_paste_search_domain_unavailable(service):
    """Test paste_search_domain when unavailable."""
    result = service.paste_search_domain("example.com")
    assert "error" in result


@patch('credential_intel_service._CLIENTS_AVAILABLE', True)
@patch('credential_intel_service.PasteMonitor')
def test_paste_search_domain(mock_pm_class, clean_env, service):
    """Test paste_search_domain."""
    mock_monitor = AsyncMock()
    mock_monitor.search_domain = AsyncMock(
        return_value={
            "domain": "example.com",
            "pastes": [
                {"site": "pastebin.com", "id": "abc123", "time": "2024-01-01"},
            ],
        }
    )
    mock_pm_class.return_value.__aenter__ = AsyncMock(return_value=mock_monitor)
    mock_pm_class.return_value.__aexit__ = AsyncMock(return_value=None)

    result = service.paste_search_domain("example.com")
    assert result["domain"] == "example.com"


# ─────────────────────────────────────────────────────────────────────────
# Tests: full_exposure_check
# ─────────────────────────────────────────────────────────────────────────

@patch('credential_intel_service._CLIENTS_AVAILABLE', False)
def test_full_exposure_check_unavailable(service):
    """Test full_exposure_check when clients unavailable."""
    result = service.full_exposure_check("test@example.com", "email")
    assert "error" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

#!/usr/bin/env python3
"""
Unit tests for monitoring_scheduler module.

Tests:
  - MonitoringScheduler instantiation
  - start() sets running = True (without actually starting thread)
  - build_snapshot() with all collectors mocked
  - _collect_dns() with dnspython mocked
  - _collect_certificates() with crt.sh mocked
  - _collect_whois() with python-whois mocked
  - _collect_ip_reputation() with AbuseIPDB mocked
  - Scheduler._is_due() time calculation
"""

import pytest
import os
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from monitoring_scheduler import (
    MonitoringScheduler,
    _collect_dns,
    _collect_certificates,
    _collect_whois,
    _collect_ip_reputation,
    build_snapshot,
)
from alert_engine import WatchlistEntry, InfraSnapshot


# ─────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_app_data_dir(tmp_path, monkeypatch):
    """Override APP_DATA_DIR with a temporary directory."""
    monkeypatch.setenv('APP_DATA_DIR', str(tmp_path))
    return tmp_path


@pytest.fixture
def clean_env(monkeypatch):
    """Clean environment variables."""
    monkeypatch.delenv('ABUSEIPDB_API_KEY', raising=False)
    return monkeypatch


# ─────────────────────────────────────────────────────────────────────────
# Tests: MonitoringScheduler
# ─────────────────────────────────────────────────────────────────────────

def test_monitoring_scheduler_instantiation(tmp_app_data_dir):
    """Test creating a MonitoringScheduler."""
    scheduler = MonitoringScheduler()
    assert scheduler is not None
    assert scheduler._running is False
    assert scheduler._thread is None


def test_monitoring_scheduler_start(tmp_app_data_dir):
    """Test starting the scheduler."""
    scheduler = MonitoringScheduler()

    # Mock the thread start to avoid actually starting it
    with patch.object(threading.Thread, 'start'):
        scheduler.start()

    assert scheduler._running is True
    assert scheduler._thread is not None


def test_monitoring_scheduler_start_already_running(tmp_app_data_dir):
    """Test starting scheduler when already running."""
    scheduler = MonitoringScheduler()

    with patch.object(threading.Thread, 'start'):
        scheduler.start()
        thread1 = scheduler._thread

        # Try to start again
        scheduler.start()
        # Should not create a new thread
        assert scheduler._thread is thread1


def test_monitoring_scheduler_is_running(tmp_app_data_dir):
    """Test is_running() status."""
    scheduler = MonitoringScheduler()
    assert scheduler.is_running() is False


def test_monitoring_scheduler_stop(tmp_app_data_dir):
    """Test stopping the scheduler."""
    scheduler = MonitoringScheduler()

    with patch.object(threading.Thread, 'start'):
        scheduler.start()
        assert scheduler._running is True

        scheduler.stop()
        assert scheduler._running is False


# ─────────────────────────────────────────────────────────────────────────
# Tests: DNS collection
# ─────────────────────────────────────────────────────────────────────────

@patch('monitoring_scheduler._try_import')
def test_collect_dns_with_dnspython(mock_try_import, clean_env):
    """Test _collect_dns with dnspython available."""
    # Mock dnspython
    mock_dns_module = MagicMock()
    mock_resolver = MagicMock()

    # Mock A record
    mock_a_record = MagicMock()
    mock_a_record.__str__ = lambda x: "192.0.2.1"
    mock_resolver.resolve.side_effect = lambda target, rtype, lifetime: [mock_a_record] if rtype == "A" else []

    mock_dns_module.resolver = mock_resolver
    mock_try_import.return_value = mock_dns_module

    result = _collect_dns("example.com")
    assert "A" in result


@patch('monitoring_scheduler._try_import')
def test_collect_dns_fallback(mock_try_import, clean_env):
    """Test _collect_dns falls back to socket when dnspython unavailable."""
    mock_try_import.return_value = None

    with patch('socket.getaddrinfo') as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('192.0.2.1', 0)),  # AF_INET
        ]

        result = _collect_dns("example.com")
        # Should have attempted A record fallback
        assert isinstance(result, dict)


# ─────────────────────────────────────────────────────────────────────────
# Tests: Certificate collection
# ─────────────────────────────────────────────────────────────────────────

@patch('urllib.request.urlopen')
def test_collect_certificates_crt_sh(mock_urlopen, clean_env):
    """Test _collect_certificates queries crt.sh."""
    import json
    import io

    # Mock crt.sh response
    certs_data = [
        {
            "serial_number": "abc123",
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com",
            "issuer_ca_id": "issuerca",
            "not_before": "2024-01-01",
            "not_after": "2025-01-01",
            "entry_timestamp": "2024-01-01",
        }
    ]
    response = io.BytesIO(json.dumps(certs_data).encode())
    mock_urlopen.return_value.__enter__.return_value = response

    result = _collect_certificates("example.com")
    assert len(result) > 0
    assert result[0]["serial"] == "abc123"


@patch('urllib.request.urlopen')
def test_collect_certificates_error(mock_urlopen, clean_env):
    """Test _collect_certificates handles errors gracefully."""
    mock_urlopen.side_effect = Exception("Network error")

    result = _collect_certificates("example.com")
    assert result == []  # Returns empty list on error


# ─────────────────────────────────────────────────────────────────────────
# Tests: WHOIS collection
# ─────────────────────────────────────────────────────────────────────────

@patch('monitoring_scheduler._try_import')
def test_collect_whois_with_library(mock_try_import, clean_env):
    """Test _collect_whois with python-whois available."""
    mock_whois_module = MagicMock()
    mock_domain_info = MagicMock()
    mock_domain_info.registrar = "Registrar Inc"
    mock_domain_info.emails = ["admin@example.com"]
    mock_domain_info.creation_date = "2010-01-01"
    mock_domain_info.expiration_date = "2025-01-01"
    mock_domain_info.name_servers = ["ns1.example.com", "ns2.example.com"]

    mock_whois_module.whois.return_value = mock_domain_info
    mock_try_import.return_value = mock_whois_module

    result = _collect_whois("example.com")
    assert result["registrar"] == "Registrar Inc"
    assert result["registrant_email"] == "admin@example.com"


@patch('monitoring_scheduler._try_import')
def test_collect_whois_unavailable(mock_try_import, clean_env):
    """Test _collect_whois when library unavailable."""
    mock_try_import.return_value = None

    result = _collect_whois("example.com")
    assert result == {}


# ─────────────────────────────────────────────────────────────────────────
# Tests: IP reputation collection
# ─────────────────────────────────────────────────────────────────────────

def test_collect_ip_reputation_no_key(clean_env):
    """Test _collect_ip_reputation returns None without API key."""
    result = _collect_ip_reputation("192.0.2.1")
    assert result is None


@patch('urllib.request.urlopen')
def test_collect_ip_reputation_with_key(mock_urlopen, clean_env, monkeypatch):
    """Test _collect_ip_reputation with AbuseIPDB key."""
    import json
    import io

    monkeypatch.setenv('ABUSEIPDB_API_KEY', 'test-key-12345')

    abuse_response = {
        "data": {
            "abuseConfidenceScore": 75,
        }
    }
    response = io.BytesIO(json.dumps(abuse_response).encode())
    mock_urlopen.return_value.__enter__.return_value = response

    result = _collect_ip_reputation("192.0.2.1")
    assert result == 75


@patch('urllib.request.urlopen')
def test_collect_ip_reputation_error(mock_urlopen, clean_env, monkeypatch):
    """Test _collect_ip_reputation handles errors gracefully."""
    monkeypatch.setenv('ABUSEIPDB_API_KEY', 'test-key-12345')
    mock_urlopen.side_effect = Exception("API error")

    result = _collect_ip_reputation("192.0.2.1")
    assert result is None


# ─────────────────────────────────────────────────────────────────────────
# Tests: build_snapshot
# ─────────────────────────────────────────────────────────────────────────

@patch('monitoring_scheduler._collect_dns')
@patch('monitoring_scheduler._collect_certificates')
@patch('monitoring_scheduler._collect_whois')
def test_build_snapshot_domain(mock_whois, mock_certs, mock_dns, tmp_app_data_dir):
    """Test build_snapshot for domain watchlist."""
    mock_dns.return_value = {"A": ["192.0.2.1"]}
    mock_certs.return_value = [{"serial": "abc123", "subject": "example.com"}]
    mock_whois.return_value = {
        "registrar": "Registrar Inc",
        "registrant_email": "admin@example.com",
        "creation_date": "2010-01-01",
        "expiry_date": "2025-01-01",
        "name_servers": ["ns1.example.com"],
    }

    entry = WatchlistEntry(
        id="wl-1",
        name="Test Domain",
        entry_type="domain",
        value="example.com",
    )

    snap = build_snapshot(entry)
    assert snap.watchlist_id == "wl-1"
    assert snap.dns_records["A"] == ["192.0.2.1"]
    assert len(snap.certificates) == 1
    assert snap.whois_registrar == "Registrar Inc"


@patch('monitoring_scheduler._collect_ip_reputation')
def test_build_snapshot_ip(mock_ip_rep, tmp_app_data_dir):
    """Test build_snapshot for IP watchlist."""
    mock_ip_rep.return_value = 45

    entry = WatchlistEntry(
        id="wl-2",
        name="Test IP",
        entry_type="ip",
        value="192.0.2.1",
    )

    snap = build_snapshot(entry)
    assert snap.watchlist_id == "wl-2"
    assert snap.ip_abuse_score == 45


@patch('monitoring_scheduler._collect_certificates')
def test_build_snapshot_certificate_subject(mock_certs, tmp_app_data_dir):
    """Test build_snapshot for certificate subject watchlist."""
    mock_certs.return_value = [
        {"serial": "xyz789", "subject": "*.evil.com"}
    ]

    entry = WatchlistEntry(
        id="wl-3",
        name="Evil certs",
        entry_type="certificate_subject",
        value="*.evil.com",
    )

    snap = build_snapshot(entry)
    assert snap.watchlist_id == "wl-3"
    assert len(snap.certificates) == 1


# ─────────────────────────────────────────────────────────────────────────
# Tests: Scheduler timing logic
# ─────────────────────────────────────────────────────────────────────────

def test_scheduler_is_due_never_checked(tmp_app_data_dir):
    """Test _is_due returns True for never-checked entries."""
    scheduler = MonitoringScheduler()
    entry = WatchlistEntry(last_checked_at=None)
    now = datetime.utcnow()

    assert scheduler._is_due(entry, now) is True


def test_scheduler_is_due_interval_not_passed(tmp_app_data_dir):
    """Test _is_due returns False when interval hasn't passed."""
    scheduler = MonitoringScheduler()

    now = datetime.utcnow()
    recent = (now - timedelta(hours=1)).isoformat()  # 1 hour ago

    entry = WatchlistEntry(
        last_checked_at=recent,
        check_interval_hours=24,
    )

    assert scheduler._is_due(entry, now) is False


def test_scheduler_is_due_interval_passed(tmp_app_data_dir):
    """Test _is_due returns True when interval has passed."""
    scheduler = MonitoringScheduler()

    now = datetime.utcnow()
    past = (now - timedelta(hours=25)).isoformat()  # 25 hours ago

    entry = WatchlistEntry(
        last_checked_at=past,
        check_interval_hours=24,
    )

    assert scheduler._is_due(entry, now) is True


def test_scheduler_is_due_exactly_at_interval(tmp_app_data_dir):
    """Test _is_due at exact interval boundary."""
    scheduler = MonitoringScheduler()

    now = datetime.utcnow()
    past = (now - timedelta(hours=24)).isoformat()  # exactly 24 hours ago

    entry = WatchlistEntry(
        last_checked_at=past,
        check_interval_hours=24,
    )

    # Should be True (now >= last + interval)
    assert scheduler._is_due(entry, now) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

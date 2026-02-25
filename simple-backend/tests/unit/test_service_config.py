#!/usr/bin/env python3
"""
Unit tests for service_config module.

Tests:
  - SERVICE_CATALOG structure and validation
  - ServiceConfigManager enable/disable
  - API key management (save, delete, preview)
  - get_all_services_status()
  - Persistence across instances
  - Summary statistics
"""

import pytest
import json
import os
from pathlib import Path

from service_config import (
    SERVICE_CATALOG,
    ServiceDefinition,
    ServiceConfigManager,
)


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
    """Clean environment variables for API keys."""
    keys_to_remove = [
        'VIRUSTOTAL_API_KEY', 'ABUSEIPDB_API_KEY', 'ALIENVAULT_API_KEY',
        'GREYNOISE_API_KEY', 'HIBP_API_KEY', 'SHODAN_API_KEY',
        'CENSYS_API_ID', 'GITHUB_TOKEN', 'OPENAI_API_KEY',
        'TWITTER_BEARER_TOKEN', 'DEHASHED_API_KEY', 'DEHASHED_EMAIL',
    ]
    for key in keys_to_remove:
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


# ─────────────────────────────────────────────────────────────────────────
# Tests: SERVICE_CATALOG
# ─────────────────────────────────────────────────────────────────────────

def test_service_catalog_not_empty():
    """Test SERVICE_CATALOG is not empty."""
    assert len(SERVICE_CATALOG) > 0


def test_service_catalog_all_fields_present():
    """Test all SERVICE_CATALOG entries have required fields."""
    required_fields = {
        'id', 'name', 'description', 'category', 'tier',
        'tier_note', 'works_without_key', 'enabled_by_default'
    }
    for svc in SERVICE_CATALOG:
        for field in required_fields:
            assert hasattr(svc, field), f"Missing {field} in {svc.id}"
        assert svc.id  # non-empty
        assert svc.name  # non-empty


def test_service_catalog_valid_tiers():
    """Test all SERVICE_CATALOG entries have valid tier values."""
    valid_tiers = {'free', 'freemium', 'paid'}
    for svc in SERVICE_CATALOG:
        assert svc.tier in valid_tiers, f"Invalid tier '{svc.tier}' for {svc.id}"


def test_service_catalog_valid_categories():
    """Test all SERVICE_CATALOG entries have reasonable categories."""
    valid_categories = {'threat', 'network', 'social', 'ai', 'breach'}
    for svc in SERVICE_CATALOG:
        assert svc.category in valid_categories, f"Invalid category '{svc.category}' for {svc.id}"


def test_service_catalog_unique_ids():
    """Test all SERVICE_CATALOG entries have unique IDs."""
    ids = [svc.id for svc in SERVICE_CATALOG]
    assert len(ids) == len(set(ids)), "Duplicate IDs in SERVICE_CATALOG"


def test_service_catalog_free_services_work_without_key():
    """Test that most free services work without keys."""
    free_svcs = [s for s in SERVICE_CATALOG if s.tier == 'free']
    assert len(free_svcs) > 0
    for svc in free_svcs:
        # Most free services should work without key
        # Some exceptions (VirusTotal) are freemium
        assert svc.works_without_key is True


def test_service_catalog_paid_services():
    """Test that paid services are in catalog."""
    paid_svcs = [s for s in SERVICE_CATALOG if s.tier == 'paid']
    assert len(paid_svcs) > 0
    for svc in paid_svcs:
        assert svc.works_without_key is False


# ─────────────────────────────────────────────────────────────────────────
# Tests: ServiceConfigManager
# ─────────────────────────────────────────────────────────────────────────

def test_service_config_manager_creation(tmp_app_data_dir, clean_env):
    """Test ServiceConfigManager initializes correctly."""
    mgr = ServiceConfigManager()
    assert mgr.config_path == tmp_app_data_dir / 'service_config.json'


def test_service_config_manager_get_all_services(tmp_app_data_dir, clean_env):
    """Test get_all_services_status returns all services."""
    mgr = ServiceConfigManager()
    all_svcs = mgr.get_all_services_status()

    assert len(all_svcs) == len(SERVICE_CATALOG)
    for svc in all_svcs:
        assert 'id' in svc
        assert 'name' in svc
        assert 'enabled' in svc
        assert 'operational' in svc


def test_service_config_manager_enable_disable(tmp_app_data_dir, clean_env):
    """Test enabling/disabling services."""
    mgr = ServiceConfigManager()

    # Find a service ID
    svc_id = SERVICE_CATALOG[0].id

    # Disable it
    success = mgr.set_service_enabled(svc_id, False)
    assert success is True
    assert mgr.is_service_enabled(svc_id) is False

    # Enable it
    success = mgr.set_service_enabled(svc_id, True)
    assert success is True
    assert mgr.is_service_enabled(svc_id) is True


def test_service_config_manager_enable_nonexistent(tmp_app_data_dir, clean_env):
    """Test enabling a non-existent service fails."""
    mgr = ServiceConfigManager()
    success = mgr.set_service_enabled("nonexistent-service", True)
    assert success is False


def test_service_config_manager_save_api_key(tmp_app_data_dir, clean_env):
    """Test saving an API key."""
    mgr = ServiceConfigManager()

    success = mgr.save_api_key("TEST_API_KEY", "sk-12345abcde")
    assert success is True
    assert mgr.has_api_key("TEST_API_KEY") is True
    assert os.environ.get("TEST_API_KEY") == "sk-12345abcde"


def test_service_config_manager_delete_api_key(tmp_app_data_dir, clean_env):
    """Test deleting an API key."""
    mgr = ServiceConfigManager()

    mgr.save_api_key("TEST_KEY", "test-value")
    assert mgr.has_api_key("TEST_KEY") is True

    success = mgr.delete_api_key("TEST_KEY")
    assert success is True
    assert mgr.has_api_key("TEST_KEY") is False
    assert os.environ.get("TEST_KEY") is None


def test_service_config_manager_key_preview(tmp_app_data_dir, clean_env):
    """Test API key preview masking."""
    mgr = ServiceConfigManager()

    mgr.save_api_key("TEST_KEY", "sk-1234abcdefghijklmnop")
    preview = mgr.key_preview("TEST_KEY")

    assert preview is not None
    assert preview.startswith("sk-1")
    assert preview.endswith("mnop")
    assert "•" in preview  # Should have masked middle


def test_service_config_manager_key_preview_short_key(tmp_app_data_dir, clean_env):
    """Test API key preview for short keys."""
    mgr = ServiceConfigManager()

    mgr.save_api_key("SHORT_KEY", "abc")
    preview = mgr.key_preview("SHORT_KEY")

    # Short keys should be fully masked
    assert preview is not None
    assert len(preview) == 3


def test_service_config_manager_key_preview_missing(tmp_app_data_dir, clean_env):
    """Test API key preview for non-existent key."""
    mgr = ServiceConfigManager()
    preview = mgr.key_preview("NONEXISTENT_KEY")
    assert preview is None


def test_service_config_manager_persistence(tmp_app_data_dir, clean_env):
    """Test service configuration persists across instances."""
    mgr1 = ServiceConfigManager()
    svc_id = SERVICE_CATALOG[0].id

    mgr1.set_service_enabled(svc_id, False)
    mgr1.save_api_key("PERSIST_KEY", "secret123")

    # Create new instance
    mgr2 = ServiceConfigManager()
    assert mgr2.is_service_enabled(svc_id) is False
    assert mgr2.has_api_key("PERSIST_KEY") is True


def test_service_config_manager_summary(tmp_app_data_dir, clean_env):
    """Test summary() returns correct statistics."""
    mgr = ServiceConfigManager()

    # Enable a few services and add a key
    svc_id = SERVICE_CATALOG[0].id
    mgr.set_service_enabled(svc_id, True)

    summary = mgr.summary()
    assert "total" in summary
    assert "enabled" in summary
    assert "operational" in summary
    assert summary["total"] == len(SERVICE_CATALOG)


def test_service_config_manager_get_service_status(tmp_app_data_dir, clean_env):
    """Test getting status of individual service."""
    mgr = ServiceConfigManager()

    svc = mgr.get_service_status("dns")
    assert svc is not None
    assert svc["id"] == "dns"
    assert svc["name"]
    assert "enabled" in svc
    assert "operational" in svc


def test_service_config_manager_get_nonexistent_service(tmp_app_data_dir, clean_env):
    """Test getting status of non-existent service."""
    mgr = ServiceConfigManager()
    svc = mgr.get_service_status("nonexistent")
    assert svc is None


def test_service_config_manager_works_without_key_status(tmp_app_data_dir, clean_env):
    """Test services that work without key show correct status."""
    mgr = ServiceConfigManager()

    # DNS is a free service with no key required
    dns = mgr.get_service_status("dns")
    assert dns is not None
    assert dns["key_status"] == "not_required"
    assert dns["operational"] is True  # Even without enabling


def test_service_config_manager_key_required_status(tmp_app_data_dir, clean_env):
    """Test services that require a key show correct status."""
    mgr = ServiceConfigManager()

    # VirusTotal requires a key
    vt = mgr.get_service_status("virustotal")
    assert vt is not None
    assert vt["works_without_key"] is False
    assert vt["key_status"] == "missing"
    assert vt["operational"] is False

    # Add key
    mgr.save_api_key("VIRUSTOTAL_API_KEY", "test-key")
    vt2 = mgr.get_service_status("virustotal")
    assert vt2["key_status"] == "configured"


def test_service_config_save_invalid_key(tmp_app_data_dir, clean_env):
    """Test saving invalid API keys."""
    mgr = ServiceConfigManager()

    # Empty key
    success = mgr.save_api_key("TEST_KEY", "")
    assert success is False

    # Whitespace only
    success = mgr.save_api_key("TEST_KEY", "   ")
    assert success is False

    # None/empty env_var
    success = mgr.save_api_key("", "valid-key")
    assert success is False


def test_service_config_json_structure(tmp_app_data_dir, clean_env):
    """Test that service_config.json has correct structure."""
    mgr = ServiceConfigManager()

    mgr.set_service_enabled("dns", False)
    mgr.save_api_key("TEST_KEY", "test-value")

    # Read and verify structure
    with open(mgr.config_path) as f:
        data = json.load(f)

    assert "services" in data
    assert "api_keys" in data
    assert "updated_at" in data
    assert "dns" in data["services"]
    assert "TEST_KEY" in data["api_keys"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

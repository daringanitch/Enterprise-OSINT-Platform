#!/usr/bin/env python3
"""
Unit tests for alert_engine module.

Tests:
  - WatchlistEntry creation and defaults
  - InfraSnapshot creation and serialization
  - MonitorAlert creation and status field
  - diff_snapshots() with various scenarios (DNS, certificates, ports, WHOIS, IP reputation)
  - AlertStore persistence (load/save round-trip)
"""

import pytest
import json
import os
from datetime import datetime
from pathlib import Path

from alert_engine import (
    WatchlistEntry,
    InfraSnapshot,
    MonitorAlert,
    diff_snapshots,
    AlertStore,
)


# ─────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_app_data_dir(tmp_path, monkeypatch):
    """Override APP_DATA_DIR with a temporary directory."""
    monkeypatch.setenv('APP_DATA_DIR', str(tmp_path))
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────
# Tests: WatchlistEntry
# ─────────────────────────────────────────────────────────────────────────

def test_watchlist_entry_creation():
    """Test creating a WatchlistEntry."""
    entry = WatchlistEntry(
        name="Corporate Domain",
        entry_type="domain",
        value="example.com",
    )
    assert entry.name == "Corporate Domain"
    assert entry.entry_type == "domain"
    assert entry.value == "example.com"
    assert entry.id  # Should have UUID


def test_watchlist_entry_defaults():
    """Test WatchlistEntry defaults."""
    entry = WatchlistEntry()
    assert entry.enabled is True
    assert entry.check_interval_hours == 24
    assert entry.last_checked_at is None
    assert entry.next_check_at is None
    assert entry.total_checks == 0
    assert entry.total_alerts == 0
    assert entry.ip_reputation_threshold == 50
    assert entry.alert_on_any_cert is True


def test_watchlist_entry_alert_on_list():
    """Test WatchlistEntry alert_on field."""
    entry = WatchlistEntry(
        alert_on=["new_dns_record", "new_certificate"],
    )
    assert len(entry.alert_on) == 2
    assert "new_dns_record" in entry.alert_on


def test_watchlist_entry_tags():
    """Test WatchlistEntry tags field."""
    entry = WatchlistEntry(tags=["critical", "client-a"])
    assert entry.tags == ["critical", "client-a"]


# ─────────────────────────────────────────────────────────────────────────
# Tests: InfraSnapshot
# ─────────────────────────────────────────────────────────────────────────

def test_infra_snapshot_creation():
    """Test creating an InfraSnapshot."""
    snap = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["192.0.2.1"], "MX": ["mail.example.com"]},
    )
    assert snap.watchlist_id == "wl-1"
    assert snap.dns_records["A"] == ["192.0.2.1"]
    assert snap.dns_records["MX"] == ["mail.example.com"]
    assert snap.id


def test_infra_snapshot_defaults():
    """Test InfraSnapshot defaults."""
    snap = InfraSnapshot()
    assert snap.dns_records == {}
    assert snap.certificates == []
    assert snap.open_ports == []
    assert snap.services == []
    assert snap.whois_name_servers == []
    assert snap.ip_abuse_score is None
    assert snap.vt_malicious_count is None
    assert snap.captured_at  # ISO timestamp


def test_infra_snapshot_asdict_serialization():
    """Test InfraSnapshot can be serialized with asdict."""
    from dataclasses import asdict

    snap = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["1.2.3.4"]},
        certificates=[{"serial": "123", "subject": "example.com"}],
        open_ports=[80, 443],
        ip_abuse_score=75,
    )
    snap_dict = asdict(snap)

    assert snap_dict["watchlist_id"] == "wl-1"
    assert snap_dict["dns_records"]["A"] == ["1.2.3.4"]
    assert snap_dict["certificates"][0]["serial"] == "123"
    assert snap_dict["open_ports"] == [80, 443]
    assert snap_dict["ip_abuse_score"] == 75


# ─────────────────────────────────────────────────────────────────────────
# Tests: MonitorAlert
# ─────────────────────────────────────────────────────────────────────────

def test_monitor_alert_creation():
    """Test creating a MonitorAlert."""
    alert = MonitorAlert(
        watchlist_id="wl-1",
        watchlist_name="example.com",
        alert_type="new_dns_record",
        severity="medium",
        title="New A record",
        description="New A record added",
    )
    assert alert.watchlist_id == "wl-1"
    assert alert.alert_type == "new_dns_record"
    assert alert.severity == "medium"
    assert alert.id


def test_monitor_alert_status_field():
    """Test MonitorAlert status field."""
    alert = MonitorAlert(status="new")
    assert alert.status == "new"
    assert alert.acknowledged_at is None

    # Note: acknowledged_at is only set when using AlertStore.update_alert_status()
    # Direct assignment doesn't auto-set the timestamp
    alert2 = MonitorAlert(status="acknowledged", acknowledged_by="analyst", acknowledged_at="2024-01-01T00:00:00")
    assert alert2.status == "acknowledged"
    assert alert2.acknowledged_by == "analyst"
    assert alert2.acknowledged_at is not None


def test_monitor_alert_defaults():
    """Test MonitorAlert defaults."""
    alert = MonitorAlert()
    assert alert.severity == "medium"
    assert alert.status == "new"
    assert alert.false_positive is False
    assert alert.old_value is None
    assert alert.new_value is None
    assert alert.triggered_at  # ISO timestamp


def test_monitor_alert_false_positive():
    """Test MonitorAlert false_positive field."""
    alert = MonitorAlert(false_positive=True)
    assert alert.false_positive is True


# ─────────────────────────────────────────────────────────────────────────
# Tests: diff_snapshots
# ─────────────────────────────────────────────────────────────────────────

def test_diff_snapshots_identical():
    """Test diff_snapshots returns empty list for identical snapshots."""
    snap1 = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["192.0.2.1"]},
    )
    snap2 = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["192.0.2.1"]},
    )
    alerts = diff_snapshots(snap1, snap2)
    assert len(alerts) == 0


def test_diff_snapshots_new_dns_record():
    """Test diff_snapshots detects new DNS records."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["192.0.2.1"]},
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["192.0.2.1", "192.0.2.2"]},
    )
    alerts = diff_snapshots(old, new)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "new_dns_record"
    assert alerts[0].new_value == "192.0.2.2"
    assert "new" in alerts[0].title.lower()


def test_diff_snapshots_removed_dns_record():
    """Test diff_snapshots detects removed DNS records."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["192.0.2.1", "192.0.2.2"]},
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["192.0.2.1"]},
    )
    alerts = diff_snapshots(old, new)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "dns_record_removed"
    assert alerts[0].old_value == "192.0.2.2"
    assert "removed" in alerts[0].title.lower()


def test_diff_snapshots_multiple_record_types():
    """Test diff_snapshots with multiple DNS record types."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["1.2.3.4"], "MX": ["mail.example.com"]},
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["1.2.3.4"], "MX": ["mail2.example.com"]},
    )
    alerts = diff_snapshots(old, new)

    assert len(alerts) == 2  # One removed MX, one new MX
    types = {a.alert_type for a in alerts}
    assert "new_dns_record" in types
    assert "dns_record_removed" in types


def test_diff_snapshots_new_certificate():
    """Test diff_snapshots detects new certificates."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        certificates=[{"serial": "abc123", "subject": "example.com"}],
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        certificates=[
            {"serial": "abc123", "subject": "example.com"},
            {"serial": "xyz789", "subject": "www.example.com", "san_list": ["www.example.com"]},
        ],
    )
    alerts = diff_snapshots(old, new)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "new_certificate"
    assert "xyz789" in alerts[0].details.get("serial", "")


def test_diff_snapshots_new_open_port():
    """Test diff_snapshots detects new open ports."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        open_ports=[80, 443],
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        open_ports=[80, 443, 22],
    )
    alerts = diff_snapshots(old, new)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "shodan_port_change"
    assert alerts[0].new_value == "22"
    assert "new open port: 22" in alerts[0].title.lower()


def test_diff_snapshots_critical_port_high_severity():
    """Test new critical ports get high severity."""
    old = InfraSnapshot(watchlist_id="wl-1", open_ports=[])
    new = InfraSnapshot(watchlist_id="wl-1", open_ports=[22])  # SSH

    alerts = diff_snapshots(old, new)
    assert len(alerts) == 1
    assert alerts[0].severity == "high"

    # Test RDP port
    old2 = InfraSnapshot(watchlist_id="wl-1", open_ports=[])
    new2 = InfraSnapshot(watchlist_id="wl-1", open_ports=[3389])
    alerts2 = diff_snapshots(old2, new2)
    assert alerts2[0].severity == "high"

    # Test non-critical port
    old3 = InfraSnapshot(watchlist_id="wl-1", open_ports=[])
    new3 = InfraSnapshot(watchlist_id="wl-1", open_ports=[8080])
    alerts3 = diff_snapshots(old3, new3)
    assert alerts3[0].severity == "medium"


def test_diff_snapshots_port_closed():
    """Test diff_snapshots detects closed ports."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        open_ports=[80, 443, 22],
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        open_ports=[80, 443],
    )
    alerts = diff_snapshots(old, new)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "shodan_port_change"
    assert alerts[0].old_value == "22"
    assert alerts[0].severity == "info"


def test_diff_snapshots_whois_registrar_changed():
    """Test diff_snapshots detects WHOIS registrar changes."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        whois_registrar="Registrar A",
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        whois_registrar="Registrar B",
    )
    alerts = diff_snapshots(old, new)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "whois_change"
    assert "registrar changed" in alerts[0].title.lower()


def test_diff_snapshots_whois_registrant_email_changed():
    """Test diff_snapshots detects WHOIS registrant email changes."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        whois_registrant_email="old@example.com",
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        whois_registrant_email="new@example.com",
    )
    alerts = diff_snapshots(old, new)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "whois_change"
    assert "registrant email changed" in alerts[0].title.lower()


def test_diff_snapshots_ip_reputation_spike():
    """Test diff_snapshots detects IP reputation spikes."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        ip_abuse_score=30,
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        ip_abuse_score=50,  # Jumped > 10 points
    )
    alerts = diff_snapshots(old, new)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "ip_reputation_change"
    assert alerts[0].old_value == "30"
    assert alerts[0].new_value == "50"


def test_diff_snapshots_ip_reputation_spike_high_severity():
    """Test IP reputation spike severity based on score."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        ip_abuse_score=65,
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        ip_abuse_score=80,  # > 10 point increase and >= 75
    )
    alerts = diff_snapshots(old, new)

    assert len(alerts) == 1
    assert alerts[0].severity == "high"  # Score >= 75 = high


def test_diff_snapshots_ip_reputation_small_increase():
    """Test IP reputation small increases don't alert."""
    old = InfraSnapshot(
        watchlist_id="wl-1",
        ip_abuse_score=30,
    )
    new = InfraSnapshot(
        watchlist_id="wl-1",
        ip_abuse_score=35,  # Only 5 point increase
    )
    alerts = diff_snapshots(old, new)

    # No alert if increase <= 10
    assert len(alerts) == 0


# ─────────────────────────────────────────────────────────────────────────
# Tests: AlertStore
# ─────────────────────────────────────────────────────────────────────────

def test_alert_store_creation(tmp_app_data_dir):
    """Test AlertStore initializes correctly."""
    store = AlertStore()
    assert store.path == tmp_app_data_dir / 'alert_store.json'


def test_alert_store_save_and_load_entry(tmp_app_data_dir):
    """Test saving and loading a watchlist entry."""
    store = AlertStore()

    entry = WatchlistEntry(
        name="Test Domain",
        entry_type="domain",
        value="example.com",
    )
    saved = store.save_entry(entry)
    assert saved.id == entry.id

    loaded = store.get_entry(entry.id)
    assert loaded is not None
    assert loaded.name == "Test Domain"
    assert loaded.value == "example.com"


def test_alert_store_get_all_entries(tmp_app_data_dir):
    """Test retrieving all entries."""
    store = AlertStore()

    entry1 = WatchlistEntry(name="E1", value="example1.com")
    entry2 = WatchlistEntry(name="E2", value="example2.com", enabled=False)

    store.save_entry(entry1)
    store.save_entry(entry2)

    all_entries = store.get_all_entries()
    assert len(all_entries) == 2

    enabled_entries = store.get_all_entries(enabled_only=True)
    assert len(enabled_entries) == 1
    assert enabled_entries[0].name == "E1"


def test_alert_store_delete_entry(tmp_app_data_dir):
    """Test deleting an entry."""
    store = AlertStore()

    entry = WatchlistEntry(name="To Delete", value="example.com")
    store.save_entry(entry)
    assert store.get_entry(entry.id) is not None

    success = store.delete_entry(entry.id)
    assert success is True
    assert store.get_entry(entry.id) is None

    # Delete non-existent
    success = store.delete_entry("nonexistent")
    assert success is False


def test_alert_store_save_and_load_snapshot(tmp_app_data_dir):
    """Test saving and loading snapshots."""
    store = AlertStore()

    snap = InfraSnapshot(
        watchlist_id="wl-1",
        dns_records={"A": ["1.2.3.4"]},
        open_ports=[80, 443],
    )
    saved = store.save_snapshot(snap)
    assert saved.id == snap.id

    loaded = store.get_latest_snapshot("wl-1")
    assert loaded is not None
    assert loaded.dns_records["A"] == ["1.2.3.4"]


def test_alert_store_get_latest_snapshot(tmp_app_data_dir):
    """Test getting the latest snapshot."""
    store = AlertStore()

    snap1 = InfraSnapshot(watchlist_id="wl-1", dns_records={"A": ["1.2.3.4"]})
    snap2 = InfraSnapshot(watchlist_id="wl-1", dns_records={"A": ["5.6.7.8"]})

    store.save_snapshot(snap1)
    store.save_snapshot(snap2)

    latest = store.get_latest_snapshot("wl-1")
    assert latest.dns_records["A"] == ["5.6.7.8"]


def test_alert_store_save_and_load_alert(tmp_app_data_dir):
    """Test saving and loading alerts."""
    store = AlertStore()

    alert = MonitorAlert(
        watchlist_id="wl-1",
        alert_type="new_dns_record",
        title="Test alert",
    )
    saved = store.save_alert(alert)
    assert saved.id == alert.id

    loaded = store.get_alert(alert.id)
    assert loaded is not None
    assert loaded.alert_type == "new_dns_record"


def test_alert_store_save_multiple_alerts(tmp_app_data_dir):
    """Test saving multiple alerts at once."""
    store = AlertStore()

    alerts = [
        MonitorAlert(watchlist_id="wl-1", alert_type="new_dns_record"),
        MonitorAlert(watchlist_id="wl-1", alert_type="new_certificate"),
    ]
    saved = store.save_alerts(alerts)
    assert len(saved) == 2


def test_alert_store_get_alerts_by_watchlist(tmp_app_data_dir):
    """Test filtering alerts by watchlist."""
    store = AlertStore()

    a1 = MonitorAlert(watchlist_id="wl-1", alert_type="new_dns_record")
    a2 = MonitorAlert(watchlist_id="wl-1", alert_type="new_certificate")
    a3 = MonitorAlert(watchlist_id="wl-2", alert_type="new_dns_record")

    store.save_alert(a1)
    store.save_alert(a2)
    store.save_alert(a3)

    wl1_alerts = store.get_alerts(watchlist_id="wl-1")
    assert len(wl1_alerts) == 2


def test_alert_store_get_alerts_by_status(tmp_app_data_dir):
    """Test filtering alerts by status."""
    store = AlertStore()

    a1 = MonitorAlert(watchlist_id="wl-1", status="new")
    a2 = MonitorAlert(watchlist_id="wl-1", status="acknowledged")
    a3 = MonitorAlert(watchlist_id="wl-1", status="new")

    store.save_alert(a1)
    store.save_alert(a2)
    store.save_alert(a3)

    new_alerts = store.get_alerts(status="new")
    assert len(new_alerts) == 2

    ack_alerts = store.get_alerts(status="acknowledged")
    assert len(ack_alerts) == 1


def test_alert_store_get_alerts_by_severity(tmp_app_data_dir):
    """Test filtering alerts by severity."""
    store = AlertStore()

    a1 = MonitorAlert(watchlist_id="wl-1", severity="high")
    a2 = MonitorAlert(watchlist_id="wl-1", severity="low")

    store.save_alert(a1)
    store.save_alert(a2)

    high_alerts = store.get_alerts(severity="high")
    assert len(high_alerts) == 1


def test_alert_store_update_alert_status(tmp_app_data_dir):
    """Test updating alert status."""
    store = AlertStore()

    alert = MonitorAlert(watchlist_id="wl-1", status="new")
    store.save_alert(alert)

    updated = store.update_alert_status(alert.id, "acknowledged", by="analyst")
    assert updated is not None
    assert updated.status == "acknowledged"
    assert updated.acknowledged_by == "analyst"
    assert updated.acknowledged_at is not None


def test_alert_store_update_alert_resolved(tmp_app_data_dir):
    """Test resolving an alert."""
    store = AlertStore()

    alert = MonitorAlert(watchlist_id="wl-1", status="new")
    store.save_alert(alert)

    updated = store.update_alert_status(
        alert.id,
        "resolved",
        by="analyst",
        notes="False positive",
    )
    assert updated.status == "resolved"
    assert updated.resolved_by == "analyst"
    assert updated.resolution_notes == "False positive"


def test_alert_store_summary(tmp_app_data_dir):
    """Test AlertStore.summary()."""
    store = AlertStore()

    # Create some entries and alerts
    entry1 = WatchlistEntry(name="E1", enabled=True)
    entry2 = WatchlistEntry(name="E2", enabled=False)
    store.save_entry(entry1)
    store.save_entry(entry2)

    a1 = MonitorAlert(watchlist_id="wl-1", status="new", severity="high")
    a2 = MonitorAlert(watchlist_id="wl-1", status="new", severity="low")
    a3 = MonitorAlert(watchlist_id="wl-1", status="acknowledged")
    store.save_alert(a1)
    store.save_alert(a2)
    store.save_alert(a3)

    summary = store.summary()
    assert summary["watchlist_entries"] == 2
    assert summary["enabled_entries"] == 1
    assert summary["total_alerts"] == 3
    assert summary["new_alerts"] == 2
    assert "high" in summary["by_severity"]


def test_alert_store_roundtrip_persistence(tmp_app_data_dir):
    """Test data persists across AlertStore instances."""
    store1 = AlertStore()

    entry = WatchlistEntry(name="Persistent", value="example.com")
    store1.save_entry(entry)

    alert = MonitorAlert(watchlist_id="wl-1", title="Persistent alert")
    store1.save_alert(alert)

    # Create new store instance
    store2 = AlertStore()
    loaded_entry = store2.get_entry(entry.id)
    loaded_alert = store2.get_alert(alert.id)

    assert loaded_entry is not None
    assert loaded_entry.name == "Persistent"
    assert loaded_alert is not None
    assert loaded_alert.title == "Persistent alert"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

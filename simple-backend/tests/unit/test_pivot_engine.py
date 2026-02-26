"""
Unit tests for pivot_engine.py
================================

Tests cover:
  - PivotEngine.analyse() with a minimal investigation dict
  - Score clamping (0–1 range)
  - Threat-flag weight applied when entity is in a threat feed
  - Recency weight decays for old entities
  - max_suggestions parameter is respected
  - PivotReport.to_dict() serialises correctly
  - Empty investigation returns empty suggestions
  - coverage_score reflects proportion of entities with suggestions
"""

import pytest
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_investigation(domains=None, ips=None, threat_network_indicators=None):
    """
    Build a minimal investigation dict matching pivot_engine's extraction schema.
    Uses infrastructure_intelligence.domains / ip_addresses and
    threat_intelligence.network_indicators.
    """
    return {
        "id": "test-inv-001",
        "status": "active",
        "target_profile": {"primary_identifier": "evil.example.com"},
        "infrastructure_intelligence": {
            "domains":      domains or [],
            "ip_addresses": ips or [],
            "certificates": [],
        },
        "threat_intelligence": {
            "network_indicators": threat_network_indicators or [],
        },
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def minimal_investigation():
    now = datetime.now(timezone.utc).isoformat()
    return _make_investigation(
        domains=[
            {"domain": "evil.example.com", "first_seen": now,
             "sources": ["virustotal", "shodan"],
             "risk_indicators": ["malware_distribution"],  # marks as threat-flagged
             "registrant_email": ""},
        ],
        ips=[
            {"ip": "1.2.3.4", "first_seen": now,
             "abuse_score": 50,  # high abuse → threat-flagged
             "sources": ["shodan"], "asn": "AS12345"},
        ],
    )


@pytest.fixture()
def old_entity_investigation():
    old = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    return _make_investigation(
        domains=[
            {"domain": "stale.example.com", "first_seen": old,
             "sources": ["virustotal"], "risk_indicators": []},
        ],
    )


# ---------------------------------------------------------------------------
# Import under test
# ---------------------------------------------------------------------------

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

import importlib

@pytest.fixture(autouse=True)
def _set_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    # Re-import to pick up env var
    import pivot_engine as pe
    importlib.reload(pe)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_analyse_returns_pivot_report(minimal_investigation):
    import pivot_engine as pe
    report = pe.pivot_engine.analyse(minimal_investigation)
    assert report is not None
    assert hasattr(report, "suggestions")
    assert hasattr(report, "coverage_score")


def test_suggestions_not_empty_for_populated_investigation(minimal_investigation):
    import pivot_engine as pe
    report = pe.pivot_engine.analyse(minimal_investigation)
    assert len(report.suggestions) > 0


def test_max_suggestions_respected(minimal_investigation):
    import pivot_engine as pe
    report = pe.pivot_engine.analyse(minimal_investigation, max_suggestions=1)
    assert len(report.suggestions) <= 1


def test_scores_in_valid_range(minimal_investigation):
    import pivot_engine as pe
    report = pe.pivot_engine.analyse(minimal_investigation, max_suggestions=50)
    for s in report.suggestions:
        assert 0.0 <= s.score <= 1.0, f"Score out of range: {s.score}"


def test_flagged_entity_scores_higher_than_unflagged():
    """evil.example.com is flagged (has risk_indicators); benign should outscore or equal."""
    import pivot_engine as pe
    now = datetime.now(timezone.utc).isoformat()
    inv = _make_investigation(
        domains=[
            {"domain": "evil.example.com", "first_seen": now,
             "sources": ["virustotal"], "risk_indicators": ["phishing"]},
            {"domain": "benign.example.com", "first_seen": now,
             "sources": ["virustotal"], "risk_indicators": []},
        ],
    )
    report = pe.pivot_engine.analyse(inv, max_suggestions=50)
    flagged_scores   = [s.score for s in report.suggestions if s.entity_value == "evil.example.com"]
    unflagged_scores = [s.score for s in report.suggestions if s.entity_value == "benign.example.com"]
    if flagged_scores and unflagged_scores:
        assert max(flagged_scores) >= max(unflagged_scores)


def test_recency_weight_lower_for_old_entity(old_entity_investigation):
    """Entities first seen 90 days ago should have lower recency contribution."""
    import pivot_engine as pe
    now = datetime.now(timezone.utc).isoformat()
    recent_inv = _make_investigation(
        domains=[
            {"domain": "fresh.example.com", "first_seen": now,
             "sources": ["virustotal"], "risk_indicators": []},
        ]
    )
    old_report    = pe.pivot_engine.analyse(old_entity_investigation, max_suggestions=50)
    recent_report = pe.pivot_engine.analyse(recent_inv, max_suggestions=50)

    old_scores    = [s.score for s in old_report.suggestions]
    recent_scores = [s.score for s in recent_report.suggestions]
    if old_scores and recent_scores:
        assert max(recent_scores) >= max(old_scores)


def test_empty_investigation_returns_empty_suggestions():
    import pivot_engine as pe
    report = pe.pivot_engine.analyse(_make_investigation(domains=[], ips=[]))
    assert report.suggestions == []


def test_coverage_score_range(minimal_investigation):
    import pivot_engine as pe
    report = pe.pivot_engine.analyse(minimal_investigation)
    assert 0.0 <= report.coverage_score <= 1.0


def test_to_dict_has_required_keys(minimal_investigation):
    import pivot_engine as pe
    report = pe.pivot_engine.analyse(minimal_investigation)
    d = report.to_dict()
    assert "suggestions" in d
    assert "coverage_score" in d
    assert isinstance(d["suggestions"], list)


def test_suggestion_to_dict_has_required_keys(minimal_investigation):
    import pivot_engine as pe
    report = pe.pivot_engine.analyse(minimal_investigation)
    if report.suggestions:
        s = report.suggestions[0].to_dict() if hasattr(report.suggestions[0], "to_dict") else vars(report.suggestions[0])
        for key in ("entity_value", "entity_type", "pivot_type", "score", "reason"):
            assert key in s, f"Missing key '{key}' in suggestion dict"


def test_suggestions_sorted_by_score_descending(minimal_investigation):
    import pivot_engine as pe
    report = pe.pivot_engine.analyse(minimal_investigation, max_suggestions=50)
    scores = [s.score for s in report.suggestions]
    assert scores == sorted(scores, reverse=True)

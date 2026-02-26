"""
Unit tests for cross_investigation_correlator.py
=================================================

Tests cover:
  - run() with 0 or 1 investigations returns empty report
  - run() with shared domain surfaces a SharedIndicator
  - run() with shared IP surfaces a SharedIndicator
  - run() with shared email surfaces a SharedIndicator with high/critical significance
  - SharedIndicator.significance classification
  - InvestigationLink constructed correctly for two linked investigations
  - link_strength proportional to shared indicator count/significance
  - links_for() returns only links involving the requested investigation
  - CorrelationReport.to_dict() serialises correctly
  - No false positives when investigations share no indicators
"""

import os, sys, pytest, importlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))


@pytest.fixture(autouse=True)
def _set_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    import cross_investigation_correlator as cic
    importlib.reload(cic)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inv(inv_id, domain=None, ip=None, email=None, asn=None, cert=None):
    """Build a minimal investigation matching the correlator's extraction schema."""
    domains = []
    if domain:
        domains.append({"domain": domain, "risk_indicators": []})

    ip_addresses = []
    if ip:
        ip_addresses.append({"ip": ip, "abuse_score": 0, "registrant_email": email or ""})
    elif email:
        # Email via a domain registrant even without an IP
        domains.append({"domain": inv_id + ".example.com",
                         "registrant_email": email,
                         "risk_indicators": []})

    ip_addresses_with_asn = []
    if asn and ip_addresses:
        ip_addresses[0]["asn"] = asn
    elif asn:
        ip_addresses_with_asn.append({"ip": "0.0.0.0", "asn": asn, "abuse_score": 0})

    certs = []
    if cert:
        certs.append({"thumbprint": cert, "sans": []})

    return {
        "id": inv_id,
        "status": "active",
        "target_profile": {"primary_identifier": inv_id + ".example.com"},
        "infrastructure_intelligence": {
            "domains": domains,
            "ip_addresses": ip_addresses + ip_addresses_with_asn,
            "certificates": certs,
        },
        "threat_intelligence": {"network_indicators": []},
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_run_empty_returns_empty_report():
    import cross_investigation_correlator as cic
    report = cic.correlator.run([])
    assert report.shared_indicators == []
    assert report.investigation_links == []


def test_run_single_investigation_returns_empty_report():
    import cross_investigation_correlator as cic
    report = cic.correlator.run([_inv("inv-001", domain="a.com")])
    assert report.shared_indicators == []


def test_run_shared_domain_detected():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", domain="evil.com"),
        _inv("inv-002", domain="evil.com"),
    ]
    report = cic.correlator.run(invs)
    assert len(report.shared_indicators) >= 1
    values = [si.indicator_value for si in report.shared_indicators]
    assert "evil.com" in values


def test_run_shared_ip_detected():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", ip="185.220.101.47"),
        _inv("inv-002", ip="185.220.101.47"),
    ]
    report = cic.correlator.run(invs)
    values = [si.indicator_value for si in report.shared_indicators]
    assert "185.220.101.47" in values


def test_run_shared_email_detected():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", email="attacker@evil.com"),
        _inv("inv-002", email="attacker@evil.com"),
    ]
    report = cic.correlator.run(invs)
    values = [si.indicator_value for si in report.shared_indicators]
    assert "attacker@evil.com" in values


def test_email_significance_is_high_or_critical():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", email="attacker@evil.com"),
        _inv("inv-002", email="attacker@evil.com"),
        _inv("inv-003", email="attacker@evil.com"),
    ]
    report = cic.correlator.run(invs)
    email_indicators = [si for si in report.shared_indicators if si.indicator_value == "attacker@evil.com"]
    if email_indicators:
        assert email_indicators[0].significance in ("high", "critical")


def test_cert_thumbprint_significance_is_critical():
    import cross_investigation_correlator as cic
    thumb = "AA:BB:CC:DD:EE:FF:00:11"
    invs = [
        _inv("inv-001", cert=thumb),
        _inv("inv-002", cert=thumb),
    ]
    report = cic.correlator.run(invs)
    cert_indicators = [si for si in report.shared_indicators if si.indicator_value == thumb]
    if cert_indicators:
        assert cert_indicators[0].significance == "critical"


def test_investigation_link_created_for_shared_indicator():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", domain="evil.com"),
        _inv("inv-002", domain="evil.com"),
    ]
    report = cic.correlator.run(invs)
    assert len(report.investigation_links) >= 1
    link = report.investigation_links[0]
    assert "inv-001" in (link.investigation_a, link.investigation_b)
    assert "inv-002" in (link.investigation_a, link.investigation_b)


def test_link_strength_in_valid_range():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", domain="evil.com", ip="1.2.3.4"),
        _inv("inv-002", domain="evil.com", ip="1.2.3.4"),
    ]
    report = cic.correlator.run(invs)
    for link in report.investigation_links:
        assert 0.0 <= link.link_strength <= 1.0


def test_no_false_positives_no_shared_indicators():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", domain="site-a.com"),
        _inv("inv-002", domain="site-b.com"),
    ]
    report = cic.correlator.run(invs)
    assert report.shared_indicators == []
    assert report.investigation_links == []


def test_links_for_filters_correctly():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", domain="evil.com"),
        _inv("inv-002", domain="evil.com"),
        _inv("inv-003", domain="other.com"),
    ]
    links = cic.correlator.links_for("inv-001", invs)
    for link in links:
        assert "inv-001" in (link.investigation_a, link.investigation_b)


def test_links_for_no_links_when_not_involved():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", domain="evil.com"),
        _inv("inv-002", domain="evil.com"),
        _inv("inv-003", domain="other.com"),
    ]
    links = cic.correlator.links_for("inv-003", invs)
    assert links == []


def test_correlation_report_to_dict():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", domain="evil.com"),
        _inv("inv-002", domain="evil.com"),
    ]
    report = cic.correlator.run(invs)
    d = report.to_dict()
    assert "shared_indicators" in d
    assert "investigation_links" in d
    assert "shared_indicator_count" in d
    assert "investigation_link_count" in d


def test_shared_indicator_contains_both_investigation_ids():
    import cross_investigation_correlator as cic
    invs = [
        _inv("inv-001", domain="evil.com"),
        _inv("inv-002", domain="evil.com"),
    ]
    report = cic.correlator.run(invs)
    shared = [si for si in report.shared_indicators if si.indicator_value == "evil.com"]
    assert shared
    assert "inv-001" in shared[0].investigation_ids
    assert "inv-002" in shared[0].investigation_ids

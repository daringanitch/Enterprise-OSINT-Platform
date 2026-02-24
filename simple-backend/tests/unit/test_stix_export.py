"""
Unit tests for simple-backend/stix_export.py

Tests cover STIXExporter and MISPClient with all external I/O mocked.
"""
import json
import sys
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure simple-backend is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from stix_export import STIXExporter, MISPClient, _STIX2_AVAILABLE


# ---------------------------------------------------------------------------
# Skip all STIX object tests when stix2 is not installed
# ---------------------------------------------------------------------------

pytestmark_stix = pytest.mark.skipif(
    not _STIX2_AVAILABLE, reason="stix2 library not installed"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def exporter():
    return STIXExporter()


def _make_investigation(inv_id="inv-001", name="Test Investigation"):
    return {"id": inv_id, "name": name, "summary": "Test summary", "notes": ""}


def _make_correlation(entity_type="domain", entity_value="evil.com"):
    """Build a minimal correlation-like dict."""
    entity = MagicMock()
    entity.entity_type = MagicMock()
    entity.entity_type.value = entity_type
    entity.value = entity_value

    return MagicMock(
        entities={"e1": entity},
        relationships=[],
        mitre_techniques=[],
    )


# ---------------------------------------------------------------------------
# Bundle structure
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_bundle_has_required_keys(exporter):
    bundle = exporter.export_investigation(_make_investigation())
    bundle_dict = json.loads(exporter.to_json(bundle))

    assert bundle_dict.get("type") == "bundle"
    assert "id" in bundle_dict
    assert "objects" in bundle_dict
    assert isinstance(bundle_dict["objects"], list)
    assert len(bundle_dict["objects"]) > 0


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_bundle_contains_identity(exporter):
    bundle = exporter.export_investigation(_make_investigation())
    bundle_dict = json.loads(exporter.to_json(bundle))

    types = [o["type"] for o in bundle_dict["objects"]]
    assert "identity" in types


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_bundle_contains_report(exporter):
    bundle = exporter.export_investigation(_make_investigation())
    bundle_dict = json.loads(exporter.to_json(bundle))

    types = [o["type"] for o in bundle_dict["objects"]]
    assert "report" in types


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_bundle_serializes_to_valid_json(exporter):
    bundle = exporter.export_investigation(_make_investigation())
    json_str = exporter.to_json(bundle)

    parsed = json.loads(json_str)
    assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Entity type mappings
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_domain_entity_maps_to_stix_domain_name(exporter):
    entity = MagicMock()
    entity.entity_type = MagicMock()
    entity.entity_type.value = "domain"
    entity.value = "evil.example.com"

    stix_obj = exporter._entity_to_stix(entity)
    assert stix_obj is not None
    assert stix_obj.type == "domain-name"
    assert stix_obj.value == "evil.example.com"


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_ip_entity_maps_to_ipv4_addr(exporter):
    entity = MagicMock()
    entity.entity_type = MagicMock()
    entity.entity_type.value = "ip_address"
    entity.value = "192.168.1.100"

    stix_obj = exporter._entity_to_stix(entity)
    assert stix_obj is not None
    assert stix_obj.type == "ipv4-addr"


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_cve_entity_maps_to_vulnerability(exporter):
    entity = MagicMock()
    entity.entity_type = MagicMock()
    entity.entity_type.value = "cve"
    entity.value = "CVE-2021-44228"

    stix_obj = exporter._entity_to_stix(entity)
    assert stix_obj is not None
    assert stix_obj.type == "vulnerability"


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_threat_actor_maps_to_stix_threat_actor(exporter):
    entity = MagicMock()
    entity.entity_type = MagicMock()
    entity.entity_type.value = "threat_actor"
    entity.value = "APT28"

    stix_obj = exporter._entity_to_stix(entity)
    assert stix_obj is not None
    assert stix_obj.type == "threat-actor"
    assert stix_obj.name == "APT28"


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_url_entity_maps_to_stix_url(exporter):
    entity = MagicMock()
    entity.entity_type = MagicMock()
    entity.entity_type.value = "url"
    entity.value = "https://malicious.example.com/payload"

    stix_obj = exporter._entity_to_stix(entity)
    assert stix_obj is not None
    assert stix_obj.type == "url"


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_unknown_entity_type_returns_none(exporter):
    entity = MagicMock()
    entity.entity_type = MagicMock()
    entity.entity_type.value = "totally_unknown_type_xyz"
    entity.value = "something"

    stix_obj = exporter._entity_to_stix(entity)
    assert stix_obj is None


# ---------------------------------------------------------------------------
# MITRE technique mapping
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_mitre_technique_maps_to_attack_pattern(exporter):
    result = exporter._mitre_techniques_to_stix(["T1566.002"])

    assert len(result) == 1
    ap = result[0]
    assert ap.type == "attack-pattern"
    # External reference should include the technique ID
    ext_refs = [
        ref.external_id
        for ref in (ap.get("external_references") or [])
        if hasattr(ref, "external_id")
    ]
    assert "T1566.002" in ext_refs


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_mitre_multiple_techniques(exporter):
    result = exporter._mitre_techniques_to_stix(["T1566.002", "T1059", "T1071"])
    assert len(result) == 3


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_mitre_empty_list_returns_empty(exporter):
    result = exporter._mitre_techniques_to_stix([])
    assert result == []


# ---------------------------------------------------------------------------
# Relationship mapping
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_relationship_attribution_maps_correctly(exporter):
    """resolves_to should map to 'resolves-to' STIX relationship."""
    import stix2

    # Create two STIX objects to reference
    domain = stix2.DomainName(value="evil.example.com")
    ip = stix2.IPv4Address(value="1.2.3.4")

    id_map = {"src-entity": domain.id, "tgt-entity": ip.id}

    # Use a plain dict so the extraction logic receives a string, not a MagicMock
    rel = {
        "source_id": "src-entity",
        "target_id": "tgt-entity",
        "relationship_type": "resolves_to",
    }

    stix_rel = exporter._relationship_to_stix(rel, id_map)
    assert stix_rel is not None
    assert stix_rel.type == "relationship"
    assert stix_rel.relationship_type == "resolves-to"


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_relationship_missing_entity_returns_none(exporter):
    """Relationship with missing entity id should gracefully return None."""
    rel = MagicMock()
    rel.source_id = "missing-src"
    rel.target_id = "missing-tgt"
    rel.relationship_type = MagicMock()
    rel.relationship_type.value = "resolves_to"

    stix_rel = exporter._relationship_to_stix(rel, id_map={})
    assert stix_rel is None


# ---------------------------------------------------------------------------
# IOC bundle
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_export_iocs_bundle_type(exporter):
    corr = _make_correlation("domain", "malicious.example.com")
    bundle = exporter.export_iocs(corr)
    bundle_dict = json.loads(exporter.to_json(bundle))

    assert bundle_dict["type"] == "bundle"


@pytest.mark.skipif(not _STIX2_AVAILABLE, reason="stix2 not installed")
def test_export_iocs_contains_indicator(exporter):
    corr = _make_correlation("domain", "malicious.example.com")
    bundle = exporter.export_iocs(corr)
    bundle_dict = json.loads(exporter.to_json(bundle))

    types = [o["type"] for o in bundle_dict["objects"]]
    assert "indicator" in types


# ---------------------------------------------------------------------------
# stix2 unavailable — graceful degradation
# ---------------------------------------------------------------------------


def test_export_investigation_stix2_unavailable():
    """When stix2 is not available, export returns an error dict."""
    with patch("stix_export._STIX2_AVAILABLE", False):
        exp = STIXExporter.__new__(STIXExporter)
        exp._identity = None
        bundle = exp.export_investigation({"id": "x", "name": "y"})

    assert isinstance(bundle, dict)
    assert "error" in bundle


def test_export_iocs_stix2_unavailable():
    with patch("stix_export._STIX2_AVAILABLE", False):
        exp = STIXExporter.__new__(STIXExporter)
        exp._identity = None
        bundle = exp.export_iocs({})

    assert isinstance(bundle, dict)
    assert "error" in bundle


# ---------------------------------------------------------------------------
# MISPClient — unconfigured
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_client_unconfigured_health_check():
    async with MISPClient("", "") as client:
        result = await client.health_check()

    assert result["healthy"] is False
    assert "not configured" in result["error"].lower()


@pytest.mark.asyncio
async def test_misp_client_unconfigured_push_returns_error():
    async with MISPClient("", "") as client:
        result = await client.push_stix_bundle("{}")

    assert result["success"] is False


@pytest.mark.asyncio
async def test_misp_client_unconfigured_pull_returns_empty():
    async with MISPClient("", "") as client:
        result = await client.pull_events()

    assert result == []


# ---------------------------------------------------------------------------
# MISPClient — HTTP error responses
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_client_401_returns_error():
    """A 401 response from MISP health check should return healthy=False."""
    resp = AsyncMock()
    resp.status = 401
    resp.text = AsyncMock(return_value="Unauthorized")
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.get = MagicMock(return_value=resp)
    session.close = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)

    with patch("aiohttp.ClientSession", return_value=session):
        async with MISPClient("https://misp.example.com", "bad-key") as client:
            result = await client.health_check()

    assert result["healthy"] is False
    assert "401" in str(result.get("error", ""))


@pytest.mark.asyncio
async def test_misp_client_connection_error_graceful():
    """A connection error should not raise — return error dict."""
    import aiohttp

    resp = AsyncMock()
    resp.__aenter__ = AsyncMock(side_effect=aiohttp.ClientError("refused"))
    resp.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.get = MagicMock(return_value=resp)
    session.close = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)

    with patch("aiohttp.ClientSession", return_value=session):
        async with MISPClient("https://unreachable.example.com", "key") as client:
            result = await client.health_check()

    assert result["healthy"] is False
    assert result["error"] is not None

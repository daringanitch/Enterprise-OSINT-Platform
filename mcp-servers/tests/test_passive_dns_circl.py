"""
Unit tests for mcp-servers/infrastructure-advanced/passive_dns_circl.py

All HTTP I/O is mocked so the tests run completely offline.
"""
import json
import sys
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Make the infrastructure-advanced package importable
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "infrastructure-advanced"),
)

from passive_dns_circl import CIRCLPassiveDNS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ndjson(*records: dict) -> str:
    """Build a newline-delimited JSON string from a sequence of dicts."""
    return "\n".join(json.dumps(r) for r in records)


def _sample_records():
    """Return two sample CIRCL pDNS records (one A, one CNAME)."""
    return [
        {
            "rrname": "example.com.",
            "rdata": "93.184.216.34",
            "rrtype": "A",
            "time_first": 1_600_000_000,
            "time_last": 1_700_000_000,
            "count": 42,
        },
        {
            "rrname": "www.example.com.",
            "rdata": "example.com.",
            "rrtype": "CNAME",
            "time_first": 1_610_000_000,
            "time_last": 1_710_000_000,
            "count": 7,
        },
    ]


def _build_mock_session(text: str, status: int = 200):
    """Build a minimal aiohttp session mock that returns *text* on GET."""
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=text)
    # aiohttp uses an async context manager for resp
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.get = MagicMock(return_value=resp)
    session.close = AsyncMock()
    # session itself is used as async context manager
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


# ---------------------------------------------------------------------------
# Tests — query()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_returns_normalised_records():
    """query() parses ndjson and returns normalised records."""
    ndjson = _make_ndjson(*_sample_records())
    mock_session = _build_mock_session(ndjson)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with CIRCLPassiveDNS() as client:
            result = await client.query("example.com")

    assert result["query"] == "example.com"
    assert result["record_count"] == 2
    assert result["source"] == "circl_pdns"
    # A record's IP should appear in unique_ips
    assert "93.184.216.34" in result["unique_ips"]
    # CNAME rdata should appear in unique_domains
    assert "example.com" in result["unique_domains"]


@pytest.mark.asyncio
async def test_query_unique_ip_deduplication():
    """Duplicate IPs across records should be deduplicated."""
    records = [
        {"rrname": "a.example.com.", "rdata": "1.2.3.4", "rrtype": "A",
         "time_first": 1_600_000_000, "time_last": 1_700_000_000, "count": 1},
        {"rrname": "b.example.com.", "rdata": "1.2.3.4", "rrtype": "A",
         "time_first": 1_610_000_000, "time_last": 1_710_000_000, "count": 1},
    ]
    mock_session = _build_mock_session(_make_ndjson(*records))

    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with CIRCLPassiveDNS() as client:
            result = await client.query("example.com")

    assert result["unique_ips"] == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_query_404_returns_empty():
    """A 404 response should return an empty result (not an error dict)."""
    mock_session = _build_mock_session("", status=404)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with CIRCLPassiveDNS() as client:
            result = await client.query("nonexistent.example.com")

    assert result["record_count"] == 0
    assert result["records"] == []
    assert result["unique_ips"] == []


@pytest.mark.asyncio
async def test_query_non_200_returns_empty():
    """A non-200/non-404 response should also return an empty result."""
    mock_session = _build_mock_session("Server Error", status=500)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with CIRCLPassiveDNS() as client:
            result = await client.query("example.com")

    assert result["record_count"] == 0


@pytest.mark.asyncio
async def test_query_skips_malformed_lines():
    """Malformed JSON lines should be silently skipped."""
    ndjson = _make_ndjson(_sample_records()[0]) + "\nNOT_JSON\n{also bad"
    mock_session = _build_mock_session(ndjson)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with CIRCLPassiveDNS() as client:
            result = await client.query("example.com")

    # Only the one valid record
    assert result["record_count"] == 1


@pytest.mark.asyncio
async def test_query_empty_response_returns_empty():
    """Completely empty response body should return empty result."""
    mock_session = _build_mock_session("")

    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with CIRCLPassiveDNS() as client:
            result = await client.query("example.com")

    assert result["record_count"] == 0


@pytest.mark.asyncio
async def test_query_timestamps_are_iso8601():
    """Epoch timestamps should be converted to ISO-8601 strings."""
    records = _sample_records()
    mock_session = _build_mock_session(_make_ndjson(*records))

    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with CIRCLPassiveDNS() as client:
            result = await client.query("example.com")

    for rec in result["records"]:
        # ISO-8601 UTC string ends with +00:00 or Z
        assert "T" in rec["time_first"]
        assert "T" in rec["time_last"]


# ---------------------------------------------------------------------------
# Tests — build_timeline()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_build_timeline_sorted_chronologically():
    """build_timeline() must return IP entries sorted by first_seen ascending."""
    records = [
        {"rrname": "example.com.", "rdata": "10.0.0.2", "rrtype": "A",
         "time_first": 1_700_000_000, "time_last": 1_710_000_000, "count": 2},
        {"rrname": "example.com.", "rdata": "10.0.0.1", "rrtype": "A",
         "time_first": 1_600_000_000, "time_last": 1_610_000_000, "count": 5},
    ]
    mock_session = _build_mock_session(_make_ndjson(*records))

    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with CIRCLPassiveDNS() as client:
            timeline = await client.build_timeline("example.com")

    assert len(timeline) == 2
    # Older record (10.0.0.1) must come first
    assert timeline[0]["ip"] == "10.0.0.1"
    assert timeline[1]["ip"] == "10.0.0.2"


@pytest.mark.asyncio
async def test_build_timeline_excludes_non_a_records():
    """build_timeline() should only include A/AAAA records."""
    records = [
        {"rrname": "example.com.", "rdata": "10.0.0.1", "rrtype": "A",
         "time_first": 1_600_000_000, "time_last": 1_700_000_000, "count": 1},
        {"rrname": "example.com.", "rdata": "mail.example.com.", "rrtype": "MX",
         "time_first": 1_600_000_000, "time_last": 1_700_000_000, "count": 1},
    ]
    mock_session = _build_mock_session(_make_ndjson(*records))

    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with CIRCLPassiveDNS() as client:
            timeline = await client.build_timeline("example.com")

    assert len(timeline) == 1
    assert timeline[0]["ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_build_timeline_empty_on_no_a_records():
    """build_timeline() returns empty list when there are no A/AAAA records."""
    records = [
        {"rrname": "example.com.", "rdata": "mail.example.com.", "rrtype": "MX",
         "time_first": 1_600_000_000, "time_last": 1_700_000_000, "count": 1},
    ]
    mock_session = _build_mock_session(_make_ndjson(*records))

    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with CIRCLPassiveDNS() as client:
            timeline = await client.build_timeline("example.com")

    assert timeline == []


# ---------------------------------------------------------------------------
# Tests — static helpers
# ---------------------------------------------------------------------------


def test_parse_ndjson_valid():
    text = '{"a": 1}\n{"b": 2}\n'
    result = CIRCLPassiveDNS._parse_ndjson(text)
    assert result == [{"a": 1}, {"b": 2}]


def test_parse_ndjson_skips_blank_lines():
    text = '{"a": 1}\n\n{"b": 2}\n'
    result = CIRCLPassiveDNS._parse_ndjson(text)
    assert len(result) == 2


def test_parse_ndjson_skips_malformed():
    text = '{"ok": true}\nNOT_JSON\n{"also": "ok"}'
    result = CIRCLPassiveDNS._parse_ndjson(text)
    assert len(result) == 2


def test_epoch_to_iso_conversion():
    iso = CIRCLPassiveDNS._epoch_to_iso(0)
    assert "1970-01-01" in iso


def test_epoch_to_iso_invalid_returns_string():
    iso = CIRCLPassiveDNS._epoch_to_iso("not-a-number")
    assert iso == "not-a-number"

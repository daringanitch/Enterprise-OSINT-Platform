#!/usr/bin/env python3
"""
Tests for geolocation collection and its merge into infrastructure intelligence.

Covers the path that was broken end to end: the infrastructure MCP exposes
`geolocation` via /execute, mcp_clients collects it, and the orchestrator
merges the coordinates onto the matching ip_addresses entry so they travel
with the IP they belong to.
"""

from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from models import IntelligenceResult


# ---------------------------------------------------------------------------
# Orchestrator merge
# ---------------------------------------------------------------------------

from utils.geographical_scope import merge_geolocation


def _geo(ip="93.184.216.34", **overrides):
    geo = {
        "ip": ip,
        "countryCode": "DE",
        "country": "Germany",
        "city": "Frankfurt am Main",
        "region": "Hesse",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "accuracy_radius_km": 20,
        "data_source": "maxmind-geolite2-local",
    }
    geo.update(overrides)
    return geo


class TestGeolocationMerge:
    """merge_geolocation() is what the orchestrator calls on a geolocation result."""

    def test_coordinates_land_on_the_matching_ip_entry(self):
        ip_addresses = [{"ip": "93.184.216.34", "source": "dns_resolution_enhanced",
                         "record_type": "A"}]

        merge_geolocation(ip_addresses, _geo())

        entry = ip_addresses[0]
        assert entry["countryCode"] == "DE"
        assert entry["latitude"] == 50.1109
        assert entry["longitude"] == 8.6821
        assert entry["geo_source"] == "maxmind-geolite2-local"

    def test_dns_provenance_is_preserved(self):
        """The merge must not clobber how the IP was discovered."""
        ip_addresses = [{"ip": "93.184.216.34", "source": "dns_resolution_enhanced",
                         "record_type": "A"}]

        merge_geolocation(ip_addresses, _geo())

        assert ip_addresses[0]["source"] == "dns_resolution_enhanced"
        assert ip_addresses[0]["record_type"] == "A"

    def test_only_the_matching_entry_is_touched(self):
        ip_addresses = [
            {"ip": "1.1.1.1", "source": "dns"},
            {"ip": "93.184.216.34", "source": "dns"},
        ]

        merge_geolocation(ip_addresses, _geo())

        assert "latitude" not in ip_addresses[0]
        assert ip_addresses[1]["latitude"] == 50.1109

    def test_unmatched_ip_is_appended(self):
        """Geolocation can arrive for an address DNS never surfaced."""
        ip_addresses = [{"ip": "1.1.1.1", "source": "dns"}]

        merge_geolocation(ip_addresses, _geo(ip="8.8.8.8"))

        assert len(ip_addresses) == 2
        assert ip_addresses[1]["ip"] == "8.8.8.8"
        assert ip_addresses[1]["source"] == "geolocation"

    def test_empty_values_do_not_blank_existing_data(self):
        """A partial result must not erase a value another source supplied."""
        ip_addresses = [{"ip": "8.8.8.8", "country": "United States",
                         "countryCode": "US"}]

        merge_geolocation(ip_addresses, {"ip": "8.8.8.8", "latitude": 37.7,
                                         "countryCode": None})

        assert ip_addresses[0]["countryCode"] == "US"
        assert ip_addresses[0]["latitude"] == 37.7

    def test_merged_country_feeds_compliance_scope(self):
        """The whole point: jurisdiction becomes derivable from a geolocated IP."""
        from models import InfrastructureIntelligence
        from utils.geographical_scope import derive_geographical_scope

        ip_addresses = [{"ip": "93.184.216.34", "source": "dns"}]
        merge_geolocation(ip_addresses, _geo())

        infra = InfrastructureIntelligence(ip_addresses=ip_addresses)
        assert derive_geographical_scope(infra) == ["DE"]

    @pytest.mark.parametrize("bad", [None, "string", 42, []])
    def test_malformed_input_is_ignored(self, bad):
        ip_addresses = [{"ip": "1.1.1.1"}]
        merge_geolocation(ip_addresses, bad)
        assert ip_addresses == [{"ip": "1.1.1.1"}]

    def test_geo_without_ip_is_ignored(self):
        ip_addresses = [{"ip": "1.1.1.1"}]
        merge_geolocation(ip_addresses, {"countryCode": "DE"})
        assert ip_addresses == [{"ip": "1.1.1.1"}]


# ---------------------------------------------------------------------------
# mcp_clients collection
# ---------------------------------------------------------------------------

class TestGeolocationCollection:
    @pytest.mark.asyncio
    async def test_unavailable_geolocation_is_not_collected(self):
        """available=False (private IP, or no database) yields no result."""
        from mcp_clients import InfrastructureMCPClient

        client = InfrastructureMCPClient.__new__(InfrastructureMCPClient)

        class _Resp:
            status = 200

            async def json(self):
                return {
                    "success": True,
                    "result": {"ip": "192.168.1.1", "available": False,
                               "error": "private or reserved address"},
                }

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        class _Session:
            def post(self, *a, **k):
                return _Resp()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        with patch("mcp_clients.aiohttp.ClientSession", return_value=_Session()):
            result = await client._gather_geolocation_intelligence("192.168.1.1")

        assert result is None

    @pytest.mark.asyncio
    async def test_available_geolocation_is_normalized(self):
        from mcp_clients import InfrastructureMCPClient

        client = InfrastructureMCPClient.__new__(InfrastructureMCPClient)

        class _Resp:
            status = 200

            async def json(self):
                return {
                    "success": True,
                    "result": {
                        "ip": "93.184.216.34",
                        "available": True,
                        "countryCode": "DE",
                        "country": "Germany",
                        "city": "Frankfurt am Main",
                        "latitude": 50.1109,
                        "longitude": 8.6821,
                        "source": "maxmind-geolite2-local",
                    },
                    "metadata": {"processing_time_ms": 1.2},
                }

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        class _Session:
            def post(self, *a, **k):
                return _Resp()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        with patch("mcp_clients.aiohttp.ClientSession", return_value=_Session()):
            result = await client._gather_geolocation_intelligence("93.184.216.34")

        assert result is not None
        assert result.source == "geolocation"
        assert result.processed_data["countryCode"] == "DE"
        assert result.processed_data["latitude"] == 50.1109
        assert result.processed_data["data_source"] == "maxmind-geolite2-local"

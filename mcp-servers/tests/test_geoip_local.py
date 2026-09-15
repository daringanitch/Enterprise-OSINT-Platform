"""
Tests for local GeoIP resolution (infrastructure-advanced/geoip_local.py).

The module answers lookups from a MaxMind GeoLite2 .mmdb file in-process.
These tests never touch the network — which is the whole point of the module,
since it replaced a plaintext `http://ip-api.com` call that disclosed every
investigation target IP to a third party.

The .mmdb file is not redistributable and is absent in CI, so the tests that
need a real database are skipped when it is missing. The behaviour that
matters most — degrading to "unavailable" instead of falling back to the
network — is tested without one.
"""

import importlib.util
import os
import sys
from unittest.mock import patch

import pytest

_SERVER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "infrastructure-advanced")
)

_spec = importlib.util.spec_from_file_location(
    "infrastructure_geoip_local",
    os.path.join(_SERVER_DIR, "geoip_local.py"),
)
geoip_local = importlib.util.module_from_spec(_spec)
sys.modules["infrastructure_geoip_local"] = geoip_local
_spec.loader.exec_module(geoip_local)

_DB_PATH = os.getenv("GEOIP_DB_PATH", geoip_local.DEFAULT_DB_PATH)
_HAS_DB = os.path.exists(_DB_PATH) and geoip_local._GEOIP2_AVAILABLE

requires_db = pytest.mark.skipif(
    not _HAS_DB,
    reason=f"GeoLite2 database not present at {_DB_PATH}",
)


# ---------------------------------------------------------------------------
# Degradation: no database must never mean "fall back to the network"
# ---------------------------------------------------------------------------

def test_missing_database_reports_unavailable():
    client = geoip_local.LocalGeoIP(db_path="/nonexistent/GeoLite2-City.mmdb")
    result = client.lookup("8.8.8.8")

    assert result["available"] is False
    assert "not found" in result["error"]
    assert result["source"] == "maxmind-geolite2-local"


def test_missing_database_makes_no_network_call():
    """The regression that matters: degradation must not restore egress."""
    client = geoip_local.LocalGeoIP(db_path="/nonexistent/GeoLite2-City.mmdb")

    # Any attempt to reach the network through the usual suspects should fail
    # the test rather than silently succeed.
    import socket as _socket

    with patch.object(_socket.socket, "connect", side_effect=AssertionError(
        "geoip_local attempted a network connection"
    )):
        result = client.lookup("8.8.8.8")

    assert result["available"] is False


def test_available_property_false_without_database():
    client = geoip_local.LocalGeoIP(db_path="/nonexistent/GeoLite2-City.mmdb")
    assert client.available is False


def test_unavailable_reason_is_cached_not_retried(tmp_path):
    """A missing database is checked once, not on every lookup."""
    client = geoip_local.LocalGeoIP(db_path=str(tmp_path / "absent.mmdb"))
    client.lookup("8.8.8.8")

    with patch("os.path.exists", side_effect=AssertionError("re-checked disk")):
        result = client.lookup("1.1.1.1")

    assert result["available"] is False


# ---------------------------------------------------------------------------
# Input handling — these need no database at all
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["not-an-ip", "", "999.999.999.999", "example.com"])
def test_invalid_ip_rejected(value):
    client = geoip_local.LocalGeoIP(db_path="/nonexistent/db.mmdb")
    result = client.lookup(value)

    assert result["available"] is False
    assert result["error"] == "not a valid IP address"


@pytest.mark.parametrize("value", [
    "10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1",
])
def test_private_and_loopback_addresses_short_circuit(value):
    """Private ranges are absent from GeoLite2; that is normal, not an error."""
    client = geoip_local.LocalGeoIP(db_path="/nonexistent/db.mmdb")
    result = client.lookup(value)

    assert result["available"] is False
    assert result["error"] == "private or reserved address"


def test_private_address_checked_before_database():
    """Private IPs are rejected without ever opening the database."""
    client = geoip_local.LocalGeoIP(db_path="/nonexistent/db.mmdb")

    with patch.object(client, "_get_reader", side_effect=AssertionError("opened db")):
        result = client.lookup("192.168.1.1")

    assert result["error"] == "private or reserved address"


def test_result_always_carries_ip_and_available_flag():
    client = geoip_local.LocalGeoIP(db_path="/nonexistent/db.mmdb")
    for value in ["8.8.8.8", "192.168.1.1", "garbage"]:
        result = client.lookup(value)
        assert result["ip"] == value
        assert "available" in result


# ---------------------------------------------------------------------------
# Real lookups — skipped without a database
# ---------------------------------------------------------------------------

@requires_db
def test_public_ip_resolves_with_expected_fields():
    client = geoip_local.LocalGeoIP()
    result = client.lookup("8.8.8.8")

    assert result["available"] is True
    # 'countryCode' is the key the backend's compliance scope derivation
    # reads — it must stay stable.
    assert result["countryCode"]
    assert len(result["countryCode"]) == 2
    assert isinstance(result["latitude"], float)
    assert isinstance(result["longitude"], float)
    assert -90 <= result["latitude"] <= 90
    assert -180 <= result["longitude"] <= 180


@requires_db
def test_shared_client_is_reused():
    assert geoip_local.get_client() is geoip_local.get_client()


# ---------------------------------------------------------------------------
# Field mapping — covers the happy path without needing a real database
# ---------------------------------------------------------------------------

def _fake_response():
    """Mirrors the shape geoip2.database.Reader.city() returns."""
    from types import SimpleNamespace as NS

    return NS(
        country=NS(iso_code="DE", name="Germany"),
        city=NS(name="Frankfurt am Main"),
        subdivisions=NS(most_specific=NS(name="Hesse", iso_code="HE")),
        postal=NS(code="60313"),
        location=NS(
            latitude=50.1109,
            longitude=8.6821,
            accuracy_radius=20,
            time_zone="Europe/Berlin",
        ),
    )


def test_field_mapping_from_geoip2_response():
    """Guards against a typo in the geoip2 attribute paths."""
    client = geoip_local.LocalGeoIP(db_path="/nonexistent/db.mmdb")

    class _FakeReader:
        def city(self, ip):
            return _fake_response()

    with patch.object(client, "_get_reader", return_value=_FakeReader()):
        result = client.lookup("85.10.0.1")

    assert result["available"] is True
    assert result["countryCode"] == "DE"
    assert result["country"] == "Germany"
    assert result["city"] == "Frankfurt am Main"
    assert result["region"] == "Hesse"
    assert result["regionCode"] == "HE"
    assert result["postalCode"] == "60313"
    assert result["latitude"] == 50.1109
    assert result["longitude"] == 8.6821
    assert result["accuracyRadiusKm"] == 20
    assert result["timezone"] == "Europe/Berlin"
    assert result["source"] == "maxmind-geolite2-local"


def test_address_not_in_database_is_not_an_error_state():
    client = geoip_local.LocalGeoIP(db_path="/nonexistent/db.mmdb")

    class _FakeReader:
        def city(self, ip):
            raise geoip_local.geoip2.errors.AddressNotFoundError("nope")

    with patch.object(client, "_get_reader", return_value=_FakeReader()):
        result = client.lookup("8.8.8.8")

    assert result["available"] is False
    assert result["error"] == "address not present in database"

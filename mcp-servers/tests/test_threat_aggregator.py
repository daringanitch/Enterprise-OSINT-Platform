"""
Smoke tests for the Threat Aggregator MCP Server.

Tests verify the server class and its HTTP contract without requiring any
real API keys (VirusTotal, AbuseIPDB, Shodan, OTX, etc. are never called).

Strategy
--------
Like infrastructure-advanced, the FastAPI app lives inside __main__, so we
import ThreatAggregatorMCPServer directly and build our own test app around it.
"""

import importlib.util
import os
import sys
import pytest

# ---------------------------------------------------------------------------
# Dependency guards
# ---------------------------------------------------------------------------
pytest.importorskip("fastapi", reason="fastapi not installed — skipping threat-aggregator smoke tests")
pytest.importorskip("httpx", reason="httpx not installed — skipping threat-aggregator smoke tests")

_SERVER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "threat-aggregator")
)

# Use importlib to give this module a unique name in sys.modules,
# preventing collisions with other server test files.
try:
    _spec = importlib.util.spec_from_file_location(
        "threat_aggregator_app",
        os.path.join(_SERVER_DIR, "app.py"),
    )
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules["threat_aggregator_app"] = _mod
    _spec.loader.exec_module(_mod)
    ThreatAggregatorMCPServer = _mod.ThreatAggregatorMCPServer
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient
except (ImportError, AttributeError) as exc:
    pytest.skip(
        f"threat-aggregator server dependencies not available: {exc}",
        allow_module_level=True,
    )

# ---------------------------------------------------------------------------
# Minimal test app
# ---------------------------------------------------------------------------
_mcp_server = ThreatAggregatorMCPServer()
_app = FastAPI(title="Threat Aggregator MCP Server (test)")


@_app.get("/health")
async def _health():
    return {"status": "healthy", "service": "threat-aggregator-mcp"}


@_app.get("/capabilities")
async def _capabilities():
    return await _mcp_server.get_capabilities()


@_app.post("/mcp")
async def _mcp(request: dict):
    try:
        return await _mcp_server.handle_request(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@pytest.fixture(scope="module")
def client():
    return TestClient(_app)


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------
class TestHealthEndpoint:
    def test_returns_200(self, client):
        assert client.get("/health").status_code == 200

    def test_status_is_healthy(self, client):
        assert client.get("/health").json().get("status") == "healthy"

    def test_service_field_present(self, client):
        assert "service" in client.get("/health").json()


# ---------------------------------------------------------------------------
# Capabilities endpoint
# ---------------------------------------------------------------------------
class TestCapabilitiesEndpoint:
    def test_returns_200(self, client):
        assert client.get("/capabilities").status_code == 200

    def test_has_required_fields(self, client):
        data = client.get("/capabilities").json()
        for field in ("name", "version", "methods"):
            assert field in data, f"capabilities missing '{field}'"

    def test_name_matches_expected(self, client):
        data = client.get("/capabilities").json()
        assert data["name"] == "Threat Intelligence Aggregator"

    def test_methods_is_non_empty_list(self, client):
        methods = client.get("/capabilities").json()["methods"]
        assert isinstance(methods, list)
        assert len(methods) > 0

    def test_each_method_has_name_field(self, client):
        for entry in client.get("/capabilities").json()["methods"]:
            assert "name" in entry, f"Method entry missing 'name': {entry}"

    def test_core_threat_methods_advertised(self, client):
        """All four core threat intel methods must be present."""
        method_names = {
            m["name"] for m in client.get("/capabilities").json()["methods"]
        }
        expected = {
            "threat/check_ip",
            "threat/check_domain",
            "threat/check_hash",
            "threat/hunt",
        }
        assert expected.issubset(method_names), (
            f"Missing expected methods: {expected - method_names}"
        )


# ---------------------------------------------------------------------------
# MCP request endpoint
# ---------------------------------------------------------------------------
class TestMcpEndpoint:
    def test_unknown_method_returns_200(self, client):
        resp = client.post("/mcp", json={"method": "threat/nonexistent", "params": {}})
        assert resp.status_code == 200

    def test_unknown_method_success_false(self, client):
        data = client.post(
            "/mcp", json={"method": "threat/nonexistent", "params": {}}
        ).json()
        assert data.get("success") is False

    def test_unknown_method_has_error_field(self, client):
        data = client.post(
            "/mcp", json={"method": "threat/nonexistent", "params": {}}
        ).json()
        assert "error" in data
        assert "nonexistent" in data["error"] or "Unknown" in data["error"]

    def test_empty_body_returns_failure(self, client):
        data = client.post("/mcp", json={}).json()
        assert data.get("success") is False

    def test_no_method_field_returns_failure(self, client):
        data = client.post("/mcp", json={"params": {"ip": "8.8.8.8"}}).json()
        assert data.get("success") is False

    def test_response_schema_is_consistent(self, client):
        """Every MCP response must carry a 'success' boolean."""
        payloads = [
            {"method": "threat/unknown_a", "params": {}},
            {"method": "threat/unknown_b", "params": {}},
            {},
        ]
        for payload in payloads:
            resp = client.post("/mcp", json=payload)
            assert resp.status_code == 200
            assert "success" in resp.json(), (
                f"'success' missing in response for payload {payload}"
            )

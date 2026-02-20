"""
Smoke tests for the Infrastructure Advanced MCP Server.

Tests verify the server class and its HTTP contract without requiring any
real API keys (no external network calls are made during these tests).

Strategy
--------
Because the FastAPI app is defined inside ``if __name__ == '__main__':`` in
app.py, we cannot import it directly.  Instead, we import the server *class*
(InfrastructureAdvancedMCPServer) — which is defined at module level — and
build a minimal test FastAPI app that mirrors the __main__ routes exactly.
"""

import importlib.util
import os
import sys
import pytest

# ---------------------------------------------------------------------------
# Dependency guards — skip gracefully if server deps are not installed
# ---------------------------------------------------------------------------
pytest.importorskip("fastapi", reason="fastapi not installed — skipping infrastructure-advanced smoke tests")
pytest.importorskip("httpx", reason="httpx not installed — skipping infrastructure-advanced smoke tests")

_SERVER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "infrastructure-advanced")
)

# Use importlib so this module gets a unique name in sys.modules,
# avoiding collisions when multiple server test files run in the same session.
try:
    _spec = importlib.util.spec_from_file_location(
        "infrastructure_advanced_app",
        os.path.join(_SERVER_DIR, "app.py"),
    )
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules["infrastructure_advanced_app"] = _mod
    _spec.loader.exec_module(_mod)
    InfrastructureAdvancedMCPServer = _mod.InfrastructureAdvancedMCPServer
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient
except (ImportError, AttributeError) as exc:
    pytest.skip(
        f"infrastructure-advanced server dependencies not available: {exc}",
        allow_module_level=True,
    )

# ---------------------------------------------------------------------------
# Minimal test app — mirrors the server's __main__ block
# ---------------------------------------------------------------------------
_mcp_server = InfrastructureAdvancedMCPServer()
_app = FastAPI(title="Infrastructure Advanced MCP Server (test)")


@_app.get("/health")
async def _health():
    return {"status": "healthy", "service": "infrastructure-advanced-mcp"}


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
    """Synchronous TestClient wrapping the test FastAPI app."""
    return TestClient(_app)


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------
class TestHealthEndpoint:
    def test_returns_200(self, client):
        assert client.get("/health").status_code == 200

    def test_status_is_healthy(self, client):
        data = client.get("/health").json()
        assert data.get("status") == "healthy"

    def test_service_field_present(self, client):
        data = client.get("/health").json()
        assert "service" in data


# ---------------------------------------------------------------------------
# Capabilities endpoint
# ---------------------------------------------------------------------------
class TestCapabilitiesEndpoint:
    def test_returns_200(self, client):
        assert client.get("/capabilities").status_code == 200

    def test_has_name_field(self, client):
        assert "name" in client.get("/capabilities").json()

    def test_has_version_field(self, client):
        assert "version" in client.get("/capabilities").json()

    def test_has_methods_list(self, client):
        data = client.get("/capabilities").json()
        assert "methods" in data
        assert isinstance(data["methods"], list)
        assert len(data["methods"]) > 0

    def test_each_method_entry_has_name(self, client):
        methods = client.get("/capabilities").json()["methods"]
        for entry in methods:
            assert "name" in entry, f"Method entry missing 'name': {entry}"

    def test_expected_methods_advertised(self, client):
        method_names = {
            m["name"] for m in client.get("/capabilities").json()["methods"]
        }
        expected = {
            "infrastructure/certificate_transparency",
            "infrastructure/comprehensive_recon",
            "infrastructure/asn_lookup",
        }
        assert expected.issubset(method_names), (
            f"Missing expected methods: {expected - method_names}"
        )


# ---------------------------------------------------------------------------
# MCP request endpoint
# ---------------------------------------------------------------------------
class TestMcpEndpoint:
    def test_unknown_method_returns_200(self, client):
        resp = client.post("/mcp", json={"method": "unknown/method", "params": {}})
        assert resp.status_code == 200

    def test_unknown_method_has_success_false(self, client):
        data = client.post(
            "/mcp", json={"method": "unknown/method", "params": {}}
        ).json()
        assert data.get("success") is False

    def test_unknown_method_has_error_field(self, client):
        data = client.post(
            "/mcp", json={"method": "unknown/method", "params": {}}
        ).json()
        assert "error" in data

    def test_missing_method_field_returns_failure(self, client):
        data = client.post("/mcp", json={"params": {}}).json()
        assert data.get("success") is False

    def test_all_responses_have_success_field(self, client):
        payloads = [
            {"method": "unknown/a", "params": {}},
            {"method": "unknown/b", "params": {}},
            {"params": {}},
        ]
        for payload in payloads:
            resp = client.post("/mcp", json=payload)
            assert resp.status_code == 200
            assert "success" in resp.json(), (
                f"Response missing 'success' field for payload {payload}"
            )

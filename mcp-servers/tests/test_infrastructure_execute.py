"""
Contract tests for the infrastructure MCP's /execute endpoint.

The backend (simple-backend/mcp_clients.py) posts to /execute with
{"tool", "parameters"} and reads {"success", "result", "metadata"}. This
server previously exposed only /mcp (method/params -> data) and REST-style
/infrastructure/<tool> routes, so every infrastructure call from the backend
failed and the orchestrator silently fell back to simulated data.

These tests pin the wire contract — tool names, request keys, response
envelope — so it cannot drift apart again. The underlying lookups are mocked;
nothing here touches the network.
"""

import importlib.util
import os
import sys
from unittest.mock import AsyncMock, patch

import pytest

_SERVER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "infrastructure-advanced")
)

# app.py imports its siblings (passive_dns_circl, cert_chain, geoip_local) by
# bare name, so the server directory has to be importable.
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

try:
    _spec = importlib.util.spec_from_file_location(
        "infrastructure_execute_app",
        os.path.join(_SERVER_DIR, "app.py"),
    )
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules["infrastructure_execute_app"] = _mod
    _spec.loader.exec_module(_mod)
    InfrastructureAdvancedMCPServer = _mod.InfrastructureAdvancedMCPServer
except (ImportError, AttributeError) as exc:
    pytest.skip(
        f"infrastructure-advanced server dependencies not available: {exc}",
        allow_module_level=True,
    )


@pytest.fixture
def server():
    return InfrastructureAdvancedMCPServer()


def _patch_intel(**methods):
    """Patch AdvancedInfrastructureIntel so no real lookup runs.

    The dispatcher builds its whole handler dict up front, so every tool
    method must exist on the fake — not just the one under test. Unspecified
    methods get a generic AsyncMock.
    """
    class _FakeIntel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def __getattr__(self, name):
            return AsyncMock(return_value={"unstubbed": name})

    for name, value in methods.items():
        setattr(_FakeIntel, name, AsyncMock(return_value=value))

    return patch.object(_mod, "AdvancedInfrastructureIntel", _FakeIntel)


# ---------------------------------------------------------------------------
# The three tools the backend actually calls
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_whois_lookup_tool_is_reachable(server):
    """Regression: 'whois_lookup' previously existed under no route at all."""
    with _patch_intel(whois_lookup={"domain": "example.com", "registrar": "X"}):
        payload, status = await server.execute_tool(
            {"tool": "whois_lookup", "parameters": {"domain": "example.com"}}
        )

    assert status == 200
    assert payload["success"] is True
    assert payload["result"]["domain"] == "example.com"


@pytest.mark.asyncio
async def test_dns_records_tool_is_reachable(server):
    with _patch_intel(dns_records={"domain": "example.com", "a_records": ["1.2.3.4"]}):
        payload, status = await server.execute_tool(
            {"tool": "dns_records", "parameters": {"domain": "example.com"}}
        )

    assert status == 200
    assert payload["result"]["a_records"] == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_ssl_certificate_info_tool_is_reachable(server):
    with _patch_intel(ssl_certificate_info={"domain": "example.com", "is_valid": True}):
        payload, status = await server.execute_tool(
            {"tool": "ssl_certificate_info",
             "parameters": {"domain": "example.com", "port": 443}}
        )

    assert status == 200
    assert payload["result"]["is_valid"] is True


@pytest.mark.asyncio
async def test_geolocation_tool_is_reachable(server):
    with _patch_intel(geoip_lookup={"ip": "8.8.8.8", "available": True,
                                    "countryCode": "US"}):
        payload, status = await server.execute_tool(
            {"tool": "geolocation", "parameters": {"ip": "8.8.8.8"}}
        )

    assert status == 200
    assert payload["result"]["countryCode"] == "US"


# ---------------------------------------------------------------------------
# Response envelope — what mcp_clients.py reads
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_response_envelope_matches_house_contract(server):
    """social-media-enhanced and financial-enhanced return this exact shape."""
    with _patch_intel(whois_lookup={"domain": "example.com"}):
        payload, status = await server.execute_tool(
            {"tool": "whois_lookup", "parameters": {"domain": "example.com"}}
        )

    assert status == 200
    for key in ("tool", "parameters", "result", "success", "timestamp", "metadata"):
        assert key in payload, f"missing envelope key: {key}"

    for key in ("processing_time_ms", "cache_used", "intelligence_type",
                "data_freshness"):
        assert key in payload["metadata"], f"missing metadata key: {key}"

    assert payload["metadata"]["intelligence_type"] == "REAL"


@pytest.mark.asyncio
async def test_result_is_under_result_not_data(server):
    """The /mcp route returns 'data'; the backend reads 'result'."""
    with _patch_intel(whois_lookup={"domain": "example.com"}):
        payload, _ = await server.execute_tool(
            {"tool": "whois_lookup", "parameters": {"domain": "example.com"}}
        )

    assert "result" in payload
    assert "data" not in payload


@pytest.mark.asyncio
async def test_tool_error_reported_as_unsuccessful_not_raised(server):
    """A lookup that returns {'error': ...} is a 200 with success=False."""
    with _patch_intel(whois_lookup={"error": "no such domain"}):
        payload, status = await server.execute_tool(
            {"tool": "whois_lookup", "parameters": {"domain": "nope.invalid"}}
        )

    assert status == 200
    assert payload["success"] is False
    assert payload["metadata"]["data_freshness"] == "Error"


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_tool_rejected(server):
    payload, status = await server.execute_tool(
        {"tool": "does_not_exist", "parameters": {}}
    )

    assert status == 400
    assert payload["success"] is False
    assert "Unknown tool" in payload["error"]


@pytest.mark.asyncio
async def test_missing_tool_rejected(server):
    payload, status = await server.execute_tool({"parameters": {}})

    assert status == 400
    assert payload["success"] is False


@pytest.mark.asyncio
async def test_wrong_parameters_reported_as_client_error(server):
    """A bad parameter name is the caller's fault, not a 500.

    Uses a real function rather than an AsyncMock, because a mock accepts
    any keyword and would never raise the TypeError being tested.
    """
    class _FakeIntel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def __getattr__(self, name):
            return AsyncMock(return_value={})

        async def whois_lookup(self, domain):
            return {"domain": domain}

    with patch.object(_mod, "AdvancedInfrastructureIntel", _FakeIntel):
        payload, status = await server.execute_tool(
            {"tool": "whois_lookup", "parameters": {"wrong_kwarg": "x"}}
        )

    assert status == 400
    assert "Invalid parameters" in payload["error"]


@pytest.mark.asyncio
async def test_handler_exception_becomes_500_not_a_crash(server):
    class _FakeIntel:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def __getattr__(self, name):
            return AsyncMock(return_value={})

        async def whois_lookup(self, domain):
            raise RuntimeError("resolver exploded")

    with patch.object(_mod, "AdvancedInfrastructureIntel", _FakeIntel):
        payload, status = await server.execute_tool(
            {"tool": "whois_lookup", "parameters": {"domain": "example.com"}}
        )

    assert status == 500
    assert payload["success"] is False
    assert "resolver exploded" in payload["error"]


# ---------------------------------------------------------------------------
# The existing routes must keep working
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mcp_dispatcher_still_uses_its_own_shape(server):
    """/execute is additive — /mcp's method/params -> data contract is untouched."""
    with _patch_intel(asn_lookup={"asn": "AS15169"}):
        result = await server.handle_request(
            {"method": "infrastructure/asn_lookup", "params": {"ip": "8.8.8.8"}}
        )

    assert result["success"] is True
    assert "data" in result

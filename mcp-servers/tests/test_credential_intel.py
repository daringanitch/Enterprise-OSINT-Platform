"""
Smoke tests for the Credential Intelligence MCP Server.

Tests verify the server contract (health, capabilities, MCP dispatch) and
the four client modules WITHOUT making any real external API calls.

Strategy
--------
The FastAPI app lives inside __main__, so we import the server class and
module-level classes directly using importlib, then build a minimal test
FastAPI app around them.
"""

import importlib.util
import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Dependency guards
# ---------------------------------------------------------------------------
pytest.importorskip("fastapi", reason="fastapi not installed")
pytest.importorskip("httpx", reason="httpx not installed")
pytest.importorskip("aiohttp", reason="aiohttp not installed")

_CRED_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "credential-intel")
)

try:
    _spec = importlib.util.spec_from_file_location(
        "credential_intel_app",
        os.path.join(_CRED_DIR, "app.py"),
    )
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules["credential_intel_app"] = _mod
    _spec.loader.exec_module(_mod)

    CredentialIntelMCPServer = _mod.CredentialIntelMCPServer
    CredentialIntelligence = _mod.CredentialIntelligence

    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient
except (ImportError, AttributeError) as exc:
    pytest.skip(
        f"credential-intel server dependencies not available: {exc}",
        allow_module_level=True,
    )

# ---------------------------------------------------------------------------
# Minimal test app
# ---------------------------------------------------------------------------

_mcp_server = CredentialIntelMCPServer()
_app = FastAPI(title="Credential Intel MCP Server (test)")


@_app.get("/health")
async def _health():
    return {"status": "healthy", "service": "credential-intel-mcp"}


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
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_status_field(self, client):
        data = client.get("/health").json()
        assert data.get("status") == "healthy"

    def test_health_service_field(self, client):
        data = client.get("/health").json()
        assert "credential" in data.get("service", "").lower()


# ---------------------------------------------------------------------------
# Capabilities endpoint
# ---------------------------------------------------------------------------


class TestCapabilitiesEndpoint:
    def test_capabilities_returns_200(self, client):
        assert client.get("/capabilities").status_code == 200

    def test_capabilities_has_name(self, client):
        data = client.get("/capabilities").json()
        assert "name" in data
        assert "credential" in data["name"].lower()

    def test_capabilities_has_version(self, client):
        data = client.get("/capabilities").json()
        assert "version" in data

    def test_capabilities_has_methods(self, client):
        data = client.get("/capabilities").json()
        assert isinstance(data.get("methods"), list)
        assert len(data["methods"]) >= 15

    def test_capabilities_method_names_prefixed_credentials(self, client):
        data = client.get("/capabilities").json()
        for method in data["methods"]:
            assert method["name"].startswith("credentials/"), \
                f"Method {method['name']} does not start with 'credentials/'"

    def test_capabilities_all_methods_have_params(self, client):
        data = client.get("/capabilities").json()
        for method in data["methods"]:
            assert "params" in method, f"Method {method['name']} missing 'params'"

    def test_capabilities_required_keys_listed(self, client):
        data = client.get("/capabilities").json()
        assert "required_api_keys" in data

    def test_capabilities_free_sources_listed(self, client):
        data = client.get("/capabilities").json()
        assert "free_sources" in data
        assert len(data["free_sources"]) >= 2

    def test_capabilities_has_all_expected_methods(self, client):
        data = client.get("/capabilities").json()
        method_names = {m["name"] for m in data["methods"]}
        expected = {
            "credentials/hibp_email",
            "credentials/hibp_domain",
            "credentials/hibp_pastes",
            "credentials/hibp_password_pwned",
            "credentials/dehashed_email",
            "credentials/dehashed_domain",
            "credentials/hudson_rock_email",
            "credentials/hudson_rock_domain",
            "credentials/paste_domain",
            "credentials/paste_email",
            "credentials/analyze_passwords",
            "credentials/full_exposure_check",
        }
        assert expected.issubset(method_names), \
            f"Missing methods: {expected - method_names}"


# ---------------------------------------------------------------------------
# MCP endpoint — unknown method
# ---------------------------------------------------------------------------


class TestMcpEndpoint:
    def test_mcp_unknown_method_returns_success_false(self, client):
        resp = client.post("/mcp", json={"method": "totally/unknown", "params": {}})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is False
        assert "error" in data

    def test_mcp_missing_method_returns_error(self, client):
        resp = client.post("/mcp", json={"params": {}})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is False

    def test_mcp_analyze_passwords_no_external_call(self, client):
        """analyze_passwords is synchronous + local — should always work."""
        resp = client.post(
            "/mcp",
            json={
                "method": "credentials/analyze_passwords",
                "params": {"passwords": ["Dragon2019!", "Dragon2018!", "dragon!123"]},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        # analyze_passwords is local — no API key needed
        assert data.get("success") is True
        result = data.get("data", {})
        assert result.get("password_count") == 3

    def test_mcp_response_schema_success(self, client):
        """Success responses must have 'success' and 'data' keys."""
        resp = client.post(
            "/mcp",
            json={
                "method": "credentials/analyze_passwords",
                "params": {"passwords": ["test123"]},
            },
        )
        data = resp.json()
        assert "success" in data
        assert "data" in data

    def test_mcp_response_schema_failure(self, client):
        """Failure responses must have 'success' and 'error' keys."""
        resp = client.post("/mcp", json={"method": "credentials/nonexistent"})
        data = resp.json()
        assert "success" in data
        assert data["success"] is False
        assert "error" in data


# ---------------------------------------------------------------------------
# CredentialIntelligence — password pattern analysis (no external calls)
# ---------------------------------------------------------------------------


class TestPasswordPatternAnalysis:
    @pytest.fixture(scope="class")
    def ci(self):
        return CredentialIntelligence()

    def test_empty_list_returns_zero_count(self, ci):
        result = ci.analyze_passwords([])
        assert result["password_count"] == 0
        assert result["patterns"] == []

    def test_single_password_analysed(self, ci):
        result = ci.analyze_passwords(["Dragon2019!"])
        assert result["password_count"] == 1
        pattern = result["patterns"][0]
        assert pattern["password"] == "Dragon2019!"
        assert pattern["base_word"] == "dragon"
        assert pattern["year"] == "2019"
        assert pattern["has_special_char"] is True

    def test_year_extraction(self, ci):
        result = ci.analyze_passwords(["Summer2022"])
        assert result["patterns"][0]["year"] == "2022"

    def test_no_year_is_none(self, ci):
        result = ci.analyze_passwords(["password"])
        assert result["patterns"][0]["year"] is None

    def test_leet_speak_detection(self, ci):
        result = ci.analyze_passwords(["P@ssw0rd"])
        # 0→o substitution → leet speak detected
        assert result["patterns"][0]["has_leet_speak"] is True

    def test_base_word_extraction_with_numbers(self, ci):
        result = ci.analyze_passwords(["dragon123"])
        assert result["patterns"][0]["base_word"] == "dragon"

    def test_fingerprint_masks_alpha_and_digits(self, ci):
        result = ci.analyze_passwords(["abc123!"])
        fp = result["patterns"][0]["fingerprint"]
        assert "a" not in fp  # letters replaced
        assert "b" not in fp
        assert "1" not in fp  # digits replaced
        assert "!" in fp  # special chars preserved

    def test_reuse_indicators_same_base_word(self, ci):
        passwords = ["Dragon2019!", "Dragon2020!", "Dragon2021!", "SomethingElse"]
        result = ci.analyze_passwords(passwords)
        dragon_group = next(
            (ri for ri in result["reuse_indicators"] if ri["base_word"] == "dragon"),
            None
        )
        assert dragon_group is not None
        assert dragon_group["reuse_likely"] is True
        assert len(dragon_group["passwords"]) == 3

    def test_high_confidence_reuse_with_3_variants(self, ci):
        passwords = ["base2019!", "base2020!", "base2021!"]
        result = ci.analyze_passwords(passwords)
        assert result["high_confidence_reuse"] is True

    def test_no_reuse_with_unique_passwords(self, ci):
        passwords = ["alpha1!", "beta2@", "gamma3#"]
        result = ci.analyze_passwords(passwords)
        assert result["high_confidence_reuse"] is False

    def test_most_common_year_returned(self, ci):
        passwords = ["pass2021a", "pass2021b", "pass2022"]
        result = ci.analyze_passwords(passwords)
        assert result["most_common_year"] == "2021"

    def test_most_common_base_word_returned(self, ci):
        passwords = ["dog2019!", "dog2020!", "cat2019!"]
        result = ci.analyze_passwords(passwords)
        assert result["most_common_base_word"] == "dog"

    def test_complexity_score_higher_for_complex_password(self, ci):
        simple = ci.analyze_passwords(["password"])["patterns"][0]
        complex_pwd = ci.analyze_passwords(["P@$$w0rd_2024!"])["patterns"][0]
        assert complex_pwd["complexity_score"] >= simple["complexity_score"]

    def test_char_classes_counting(self, ci):
        result = ci.analyze_passwords(["aA1!"])
        pattern = result["patterns"][0]
        assert pattern["char_classes"] == 4  # lower + upper + digit + special

    def test_char_classes_lower_only(self, ci):
        result = ci.analyze_passwords(["abcdef"])
        assert result["patterns"][0]["char_classes"] == 1  # lowercase only


# ---------------------------------------------------------------------------
# CredentialIntelligence — risk scoring
# ---------------------------------------------------------------------------


class TestRiskScoring:
    @pytest.fixture(scope="class")
    def ci(self):
        return CredentialIntelligence()

    def test_no_findings_risk_is_none(self, ci):
        summary = {
            "total_breach_count": 0,
            "total_paste_count": 0,
            "infostealer_found": False,
            "dehashed_entries": 0,
            "has_plaintext_passwords": False,
        }
        score, level = ci._compute_risk(summary)
        assert score == 0.0
        assert level == "none"

    def test_many_breaches_is_high_risk(self, ci):
        summary = {
            "total_breach_count": 10,
            "total_paste_count": 0,
            "infostealer_found": False,
            "dehashed_entries": 0,
            "has_plaintext_passwords": False,
        }
        score, level = ci._compute_risk(summary)
        assert level in ("high", "critical")

    def test_infostealer_adds_30_points(self, ci):
        summary_no_stealer = {
            "total_breach_count": 0, "total_paste_count": 0,
            "infostealer_found": False, "dehashed_entries": 0,
            "has_plaintext_passwords": False,
        }
        summary_stealer = dict(summary_no_stealer, infostealer_found=True)

        score_no, _ = ci._compute_risk(summary_no_stealer)
        score_yes, _ = ci._compute_risk(summary_stealer)
        assert score_yes - score_no == 30.0

    def test_max_risk_capped_at_100(self, ci):
        summary = {
            "total_breach_count": 100,
            "total_paste_count": 100,
            "infostealer_found": True,
            "dehashed_entries": 1000,
            "has_plaintext_passwords": True,
        }
        score, _ = ci._compute_risk(summary)
        assert score == 100.0

    def test_critical_threshold_at_70(self, ci):
        summary = {
            "total_breach_count": 10,
            "total_paste_count": 0,
            "infostealer_found": True,
            "dehashed_entries": 0,
            "has_plaintext_passwords": True,
        }
        # 50 (breaches) + 30 (stealer) + 10 (plaintext) > 70
        _, level = ci._compute_risk(summary)
        assert level == "critical"


# ---------------------------------------------------------------------------
# Module-level imports — HIBP, Dehashed, Hudson Rock, Paste
# ---------------------------------------------------------------------------


class TestClientModuleImports:
    """Verify that all four client modules import cleanly."""

    def test_hibp_client_importable(self):
        spec = importlib.util.spec_from_file_location(
            "hibp_client_test",
            os.path.join(_CRED_DIR, "hibp_client.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "HIBPClient")

    def test_dehashed_client_importable(self):
        spec = importlib.util.spec_from_file_location(
            "dehashed_client_test",
            os.path.join(_CRED_DIR, "dehashed_client.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "DehashedClient")

    def test_hudson_rock_client_importable(self):
        spec = importlib.util.spec_from_file_location(
            "hudson_rock_client_test",
            os.path.join(_CRED_DIR, "hudson_rock_client.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "HudsonRockClient")

    def test_paste_monitor_importable(self):
        spec = importlib.util.spec_from_file_location(
            "paste_monitor_test",
            os.path.join(_CRED_DIR, "paste_monitor.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "PasteMonitor")

    def test_hibp_client_unconfigured_when_no_key(self):
        import importlib.util as ilu
        spec = ilu.spec_from_file_location(
            "hibp_t2", os.path.join(_CRED_DIR, "hibp_client.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        client = mod.HIBPClient(api_key="")
        assert client.configured is False

    def test_dehashed_client_unconfigured_when_no_creds(self):
        spec = importlib.util.spec_from_file_location(
            "dh_t2", os.path.join(_CRED_DIR, "dehashed_client.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        client = mod.DehashedClient(email="", api_key="")
        assert client.configured is False

    def test_hudson_rock_always_configured(self):
        spec = importlib.util.spec_from_file_location(
            "hr_t2", os.path.join(_CRED_DIR, "hudson_rock_client.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Hudson Rock has no configuration — it's always available
        client = mod.HudsonRockClient()
        assert hasattr(client, "_session")

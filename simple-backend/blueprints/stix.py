"""
STIX 2.1 Export + MISP Integration Blueprint
=============================================

Endpoints
---------
GET  /api/investigations/<inv_id>/export/stix
    Export a full STIX 2.1 bundle for the investigation.
    Optional query param: ?iocs_only=true  — returns indicator-only bundle.

GET  /api/investigations/<inv_id>/export/stix/indicators
    Export an IOC-only indicator bundle.

POST /api/misp/push/<inv_id>
    Push the investigation bundle to a MISP instance.
    Body: {"misp_url": str, "api_key": str, "verify_ssl": bool (opt)}
    Falls back to MISP_URL / MISP_API_KEY env vars.

POST /api/misp/pull
    Pull recent events from a MISP instance.
    Body: {"misp_url": str, "api_key": str, "since": ISO date (opt)}

GET  /api/misp/status
    Check MISP connectivity with the env-var configured instance.
    Returns {"configured": bool, "healthy": bool|null, "version": str|null}
"""

import asyncio
import logging
import os

from flask import Blueprint, Response, jsonify, request

from blueprints.auth import require_auth
from stix_export import MISPClient, STIXExporter, _STIX2_AVAILABLE

logger = logging.getLogger(__name__)
bp = Blueprint("stix", __name__)

# Singleton exporter — identity SDO created once at startup
_exporter = STIXExporter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_investigation_and_correlation(inv_id: str):
    """
    Fetch investigation + correlation result from the services singleton.

    Returns (investigation, correlation) where either may be None on error.
    """
    from shared import services  # local import to avoid circular deps

    investigation = None
    correlation = None

    try:
        investigation = services.get_investigation(inv_id)
    except Exception:
        pass

    if investigation is not None:
        try:
            from intelligence_correlation import IntelligenceCorrelator

            correlator = IntelligenceCorrelator()
            inv_dict = (
                investigation.__dict__
                if not isinstance(investigation, dict)
                else investigation
            )
            correlation = correlator.correlate(inv_dict)
        except Exception:
            pass

    return investigation, correlation


def _misp_creds_from_request(body: dict) -> tuple[str, str, bool]:
    """
    Extract MISP URL, API key, and verify_ssl from request body,
    falling back to environment variables.
    """
    url = body.get("misp_url") or os.getenv("MISP_URL", "")
    key = body.get("api_key") or os.getenv("MISP_API_KEY", "")
    verify_ssl = body.get("verify_ssl", True)
    return url, key, bool(verify_ssl)


def _run_async(coro):
    """Run an async coroutine from a synchronous Flask route."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=30)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@bp.route("/api/investigations/<inv_id>/export/stix", methods=["GET"])
@require_auth
def export_stix(inv_id: str):
    """
    Export a STIX 2.1 bundle for an investigation.

    Query parameters
    ----------------
    iocs_only : bool (default false)
        Return an indicator-only bundle instead of the full bundle.
    """
    if not _STIX2_AVAILABLE:
        return jsonify({"error": "stix2 package not installed"}), 503

    iocs_only = request.args.get("iocs_only", "false").lower() == "true"

    investigation, correlation = _get_investigation_and_correlation(inv_id)
    if investigation is None:
        return jsonify({"error": f"Investigation '{inv_id}' not found"}), 404

    if iocs_only:
        bundle = _exporter.export_iocs(correlation)
    else:
        bundle = _exporter.export_investigation(investigation, correlation)

    if isinstance(bundle, dict) and "error" in bundle:
        return jsonify(bundle), 500

    json_str = _exporter.to_json(bundle)
    return Response(
        json_str,
        mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="investigation-{inv_id}.stix2.json"'
        },
    )


@bp.route("/api/investigations/<inv_id>/export/stix/indicators", methods=["GET"])
@require_auth
def export_stix_indicators(inv_id: str):
    """Export an IOC-only STIX indicator bundle."""
    if not _STIX2_AVAILABLE:
        return jsonify({"error": "stix2 package not installed"}), 503

    investigation, correlation = _get_investigation_and_correlation(inv_id)
    if investigation is None:
        return jsonify({"error": f"Investigation '{inv_id}' not found"}), 404

    bundle = _exporter.export_iocs(correlation)
    if isinstance(bundle, dict) and "error" in bundle:
        return jsonify(bundle), 500

    json_str = _exporter.to_json(bundle)
    return Response(
        json_str,
        mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="investigation-{inv_id}-indicators.stix2.json"'
        },
    )


@bp.route("/api/misp/push/<inv_id>", methods=["POST"])
@require_auth
def push_to_misp(inv_id: str):
    """
    Push investigation as a STIX bundle to a MISP instance.

    Request body::

        {
            "misp_url": "https://misp.example.com",  // or MISP_URL env var
            "api_key": "abc123...",                  // or MISP_API_KEY env var
            "verify_ssl": true                       // optional, default true
        }
    """
    if not _STIX2_AVAILABLE:
        return jsonify({"error": "stix2 package not installed"}), 503

    body = request.get_json(silent=True) or {}
    misp_url, misp_key, verify_ssl = _misp_creds_from_request(body)

    if not misp_url or not misp_key:
        return jsonify({
            "error": "MISP credentials required (body or MISP_URL/MISP_API_KEY env vars)"
        }), 400

    investigation, correlation = _get_investigation_and_correlation(inv_id)
    if investigation is None:
        return jsonify({"error": f"Investigation '{inv_id}' not found"}), 404

    bundle = _exporter.export_investigation(investigation, correlation)
    if isinstance(bundle, dict) and "error" in bundle:
        return jsonify(bundle), 500

    bundle_json = _exporter.to_json(bundle)

    async def _push():
        async with MISPClient(misp_url, misp_key, verify_ssl) as client:
            return await client.push_stix_bundle(bundle_json)

    result = _run_async(_push())
    status = 200 if result.get("success") else 502
    return jsonify(result), status


@bp.route("/api/misp/pull", methods=["POST"])
@require_auth
def pull_from_misp():
    """
    Pull recent events from a MISP instance.

    Request body::

        {
            "misp_url": "https://misp.example.com",
            "api_key": "abc123...",
            "since": "2024-01-01"   // optional ISO date
        }

    Returns::

        {"events": [...], "count": int}
    """
    body = request.get_json(silent=True) or {}
    misp_url, misp_key, verify_ssl = _misp_creds_from_request(body)

    if not misp_url or not misp_key:
        return jsonify({
            "error": "MISP credentials required (body or MISP_URL/MISP_API_KEY env vars)"
        }), 400

    since = None
    since_raw = body.get("since")
    if since_raw:
        try:
            from datetime import datetime, timezone

            since = datetime.fromisoformat(since_raw).replace(tzinfo=timezone.utc)
        except ValueError:
            return jsonify({"error": f"Invalid 'since' date: {since_raw}"}), 400

    async def _pull():
        async with MISPClient(misp_url, misp_key, verify_ssl) as client:
            return await client.pull_events(since=since)

    events = _run_async(_pull())
    return jsonify({"events": events, "count": len(events)})


@bp.route("/api/misp/status", methods=["GET"])
@require_auth
def misp_status():
    """
    Check MISP connectivity using env-var configured instance.

    Returns::

        {
            "configured": bool,
            "healthy": bool | null,   // null when not configured
            "version": str | null
        }
    """
    misp_url = os.getenv("MISP_URL", "")
    misp_key = os.getenv("MISP_API_KEY", "")
    configured = bool(misp_url and misp_key)

    if not configured:
        return jsonify({"configured": False, "healthy": None, "version": None})

    async def _check():
        async with MISPClient(misp_url, misp_key) as client:
            return await client.health_check()

    health = _run_async(_check())
    return jsonify({
        "configured": True,
        "healthy": health.get("healthy"),
        "version": health.get("version"),
        "error": health.get("error"),
    })

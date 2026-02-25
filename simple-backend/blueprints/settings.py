#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Settings Blueprint
==================

REST endpoints for platform configuration.  Allows the frontend to:

  GET  /api/settings/services            – Full service catalog with status
  GET  /api/settings/services/<id>       – Single service status
  POST /api/settings/services/<id>/enable  – Enable a service
  POST /api/settings/services/<id>/disable – Disable a service
  POST /api/settings/services/<id>/key   – Save an API key
  DELETE /api/settings/services/<id>/key – Remove an API key
  POST /api/settings/services/<id>/test  – Test an API key (live check)
  GET  /api/settings/summary             – Quick stats (enabled/operational counts)
  GET  /api/settings/mode                – Get demo/live mode
  POST /api/settings/mode                – Switch mode
"""

import logging
import os
import asyncio
import aiohttp
from flask import Blueprint, jsonify, request
from service_config import service_config, SERVICE_CATALOG
from mode_manager import mode_manager
from blueprints.auth import require_auth

logger = logging.getLogger(__name__)

bp = Blueprint("settings", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_catalog_entry(service_id: str):
    """Return the ServiceDefinition for a service id, or None."""
    for svc in SERVICE_CATALOG:
        if svc.id == service_id:
            return svc
    return None


async def _live_test_key(service_id: str, api_key: str) -> dict:
    """
    Attempt a cheap, real API call to validate the key.
    Returns {ok: bool, message: str}.
    """
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:

            if service_id == "virustotal":
                url = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
                async with session.get(url, headers={"x-apikey": api_key}) as r:
                    if r.status == 200:
                        return {"ok": True, "message": "VirusTotal key is valid ✓"}
                    elif r.status == 401:
                        return {"ok": False, "message": "Invalid API key (401 Unauthorized)"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            elif service_id == "abuseipdb":
                url = "https://api.abuseipdb.com/api/v2/check"
                params = {"ipAddress": "8.8.8.8", "maxAgeInDays": "90"}
                async with session.get(url, headers={"Key": api_key, "Accept": "application/json"}, params=params) as r:
                    if r.status == 200:
                        return {"ok": True, "message": "AbuseIPDB key is valid ✓"}
                    elif r.status == 401:
                        return {"ok": False, "message": "Invalid API key (401 Unauthorized)"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            elif service_id == "alienvault_otx":
                url = "https://otx.alienvault.com/api/v1/user/me"
                async with session.get(url, headers={"X-OTX-API-KEY": api_key}) as r:
                    if r.status == 200:
                        data = await r.json()
                        username = data.get("username", "unknown")
                        return {"ok": True, "message": f"AlienVault OTX key valid – logged in as {username} ✓"}
                    elif r.status == 403:
                        return {"ok": False, "message": "Invalid API key (403 Forbidden)"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            elif service_id == "greynoise":
                url = "https://api.greynoise.io/v3/community/8.8.8.8"
                async with session.get(url, headers={"key": api_key}) as r:
                    if r.status in (200, 404):  # 404 means IP not in noise db – key still valid
                        return {"ok": True, "message": "GreyNoise key is valid ✓"}
                    elif r.status == 401:
                        return {"ok": False, "message": "Invalid API key (401 Unauthorized)"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            elif service_id in ("shodan", "shodan_premium"):
                url = f"https://api.shodan.io/api-info?key={api_key}"
                async with session.get(url) as r:
                    if r.status == 200:
                        data = await r.json()
                        credits = data.get("query_credits", "?")
                        return {"ok": True, "message": f"Shodan key valid – {credits} query credits remaining ✓"}
                    elif r.status == 401:
                        return {"ok": False, "message": "Invalid API key (401 Unauthorized)"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            elif service_id == "openai":
                url = "https://api.openai.com/v1/models"
                async with session.get(url, headers={"Authorization": f"Bearer {api_key}"}) as r:
                    if r.status == 200:
                        return {"ok": True, "message": "OpenAI key is valid ✓"}
                    elif r.status == 401:
                        return {"ok": False, "message": "Invalid API key (401 Unauthorized)"}
                    elif r.status == 429:
                        return {"ok": True, "message": "OpenAI key valid but rate-limited (quota may be low)"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            elif service_id == "github":
                url = "https://api.github.com/user"
                async with session.get(url, headers={"Authorization": f"token {api_key}", "Accept": "application/vnd.github.v3+json"}) as r:
                    if r.status == 200:
                        data = await r.json()
                        login = data.get("login", "unknown")
                        return {"ok": True, "message": f"GitHub token valid – authenticated as {login} ✓"}
                    elif r.status == 401:
                        return {"ok": False, "message": "Invalid token (401 Unauthorized)"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            elif service_id == "urlscan":
                url = "https://urlscan.io/api/v1/user/quotas/"
                async with session.get(url, headers={"API-Key": api_key}) as r:
                    if r.status == 200:
                        return {"ok": True, "message": "URLScan key is valid ✓"}
                    elif r.status == 400:
                        return {"ok": False, "message": "Invalid API key"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            elif service_id == "hibp":
                # HIBP test: look up a known-breached domain
                url = "https://haveibeenpwned.com/api/v3/breacheddomain/adobe.com"
                async with session.get(url, headers={"hibp-api-key": api_key, "User-Agent": "OSINT-Platform-Test"}) as r:
                    if r.status in (200, 404):
                        return {"ok": True, "message": "HIBP key is valid ✓"}
                    elif r.status == 401:
                        return {"ok": False, "message": "Invalid API key (401 Unauthorized)"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            elif service_id == "censys":
                # Censys uses basic auth: API_ID as user, API_SECRET as password
                # We store just the API ID in env; secret could be a second field
                url = "https://search.censys.io/api/v2/account"
                api_secret = os.environ.get("CENSYS_API_SECRET", "")
                async with session.get(url, auth=aiohttp.BasicAuth(api_key, api_secret)) as r:
                    if r.status == 200:
                        return {"ok": True, "message": "Censys credentials are valid ✓"}
                    elif r.status == 401:
                        return {"ok": False, "message": "Invalid credentials (401 Unauthorized)"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            elif service_id == "twitter":
                url = "https://api.twitter.com/2/users/me"
                async with session.get(url, headers={"Authorization": f"Bearer {api_key}"}) as r:
                    if r.status == 200:
                        return {"ok": True, "message": "Twitter Bearer Token is valid ✓"}
                    elif r.status == 401:
                        return {"ok": False, "message": "Invalid Bearer Token (401 Unauthorized)"}
                    else:
                        return {"ok": False, "message": f"Unexpected response: HTTP {r.status}"}

            else:
                # Generic length/format check for unimplemented testers
                if len(api_key) >= 8:
                    return {"ok": True, "message": f"Key saved (format looks valid – no live test implemented for {service_id})"}
                else:
                    return {"ok": False, "message": "Key appears too short – please check it"}

    except aiohttp.ClientConnectorError:
        return {"ok": False, "message": "Network error – could not reach the service API"}
    except asyncio.TimeoutError:
        return {"ok": False, "message": "Request timed out after 10s"}
    except Exception as e:
        logger.exception(f"Error testing API key for {service_id}")
        return {"ok": False, "message": f"Test failed: {str(e)}"}


def _run_async(coro):
    """Run an async coroutine in a sync Flask context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
        return loop.run_until_complete(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bp.route("/api/settings/services", methods=["GET"])
@require_auth
def list_services():
    """Return full service catalog with live status."""
    return jsonify({
        "services": service_config.get_all_services_status(),
        "summary": service_config.summary(),
    })


@bp.route("/api/settings/services/<service_id>", methods=["GET"])
@require_auth
def get_service(service_id: str):
    status = service_config.get_service_status(service_id)
    if not status:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    return jsonify(status)


@bp.route("/api/settings/services/<service_id>/enable", methods=["POST"])
@require_auth
def enable_service(service_id: str):
    if not _get_catalog_entry(service_id):
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    service_config.set_service_enabled(service_id, True)
    return jsonify({"ok": True, "service": service_id, "enabled": True})


@bp.route("/api/settings/services/<service_id>/disable", methods=["POST"])
@require_auth
def disable_service(service_id: str):
    if not _get_catalog_entry(service_id):
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    service_config.set_service_enabled(service_id, False)
    return jsonify({"ok": True, "service": service_id, "enabled": False})


@bp.route("/api/settings/services/<service_id>/key", methods=["POST"])
@require_auth
def save_service_key(service_id: str):
    """Save (or update) an API key for a service."""
    svc = _get_catalog_entry(service_id)
    if not svc:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    if not svc.env_var:
        return jsonify({"error": "This service does not use an API key"}), 400

    data = request.get_json(silent=True) or {}
    key_value = (data.get("api_key") or "").strip()
    if not key_value:
        return jsonify({"error": "api_key field is required and must not be empty"}), 400

    ok = service_config.save_api_key(svc.env_var, key_value)
    if not ok:
        return jsonify({"error": "Failed to save API key"}), 500

    # Auto-enable the service when a key is provided
    service_config.set_service_enabled(service_id, True)

    return jsonify({
        "ok": True,
        "service": service_id,
        "env_var": svc.env_var,
        "key_preview": service_config.key_preview(svc.env_var),
        "enabled": True,
    })


@bp.route("/api/settings/services/<service_id>/key", methods=["DELETE"])
@require_auth
def delete_service_key(service_id: str):
    """Remove an API key for a service."""
    svc = _get_catalog_entry(service_id)
    if not svc:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    if not svc.env_var:
        return jsonify({"error": "This service does not use an API key"}), 400

    service_config.delete_api_key(svc.env_var)
    # If the service requires a key to be useful, disable it automatically
    if not svc.works_without_key:
        service_config.set_service_enabled(service_id, False)

    return jsonify({
        "ok": True,
        "service": service_id,
        "key_removed": True,
        "auto_disabled": not svc.works_without_key,
    })


@bp.route("/api/settings/services/<service_id>/test", methods=["POST"])
@require_auth
def test_service_key(service_id: str):
    """Live-test an API key.  Key can be the stored one, or passed in the body."""
    svc = _get_catalog_entry(service_id)
    if not svc:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404

    # Accept an explicit key in the body (for testing before saving)
    data = request.get_json(silent=True) or {}
    api_key = (data.get("api_key") or "").strip()

    if not api_key:
        # Use stored key
        if not svc.env_var:
            return jsonify({"ok": True, "message": "No key required – service is always available ✓"})
        api_key = os.environ.get(svc.env_var, "")
        if not api_key:
            return jsonify({"ok": False, "message": "No API key configured for this service"}), 400

    result = _run_async(_live_test_key(service_id, api_key))
    return jsonify(result)


@bp.route("/api/settings/summary", methods=["GET"])
@require_auth
def get_summary():
    """Quick stats: how many services are enabled/operational."""
    return jsonify({
        "services": service_config.summary(),
        "mode": mode_manager.get_current_mode(),
    })


@bp.route("/api/settings/mode", methods=["GET"])
@require_auth
def get_mode():
    return jsonify(mode_manager.get_mode_status())


@bp.route("/api/settings/mode", methods=["POST"])
@require_auth
def set_mode():
    data = request.get_json(silent=True) or {}
    new_mode = data.get("mode")
    if new_mode not in ("demo", "live", "production"):
        return jsonify({"error": "mode must be 'demo' or 'live'"}), 400
    # Normalise "live" → "production" for internal compatibility
    internal_mode = "production" if new_mode == "live" else "demo"
    ok, message = mode_manager.set_mode(internal_mode, user_initiated=True)
    return jsonify({"ok": ok, "message": message, "mode": mode_manager.get_current_mode()})

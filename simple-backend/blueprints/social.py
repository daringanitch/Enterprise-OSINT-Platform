"""
Social Intelligence Blueprint
==============================

REST endpoints backed by the social-media-enhanced MCP server (:8010).

Endpoints
---------
POST /api/social/username-search
    Search 400+ social-media sites for a username via the Sherlock tool
    and return the claimed accounts.

    Request body::

        {"username": "john_doe"}

    Returns::

        {
            "username": str,
            "count": int,
            "accounts": [{"site": str, "url": str}, ...],
            "scan_duration_seconds": float
        }
"""

import asyncio
import logging

import aiohttp
from flask import Blueprint, jsonify, request

from blueprints.auth import require_auth
from config import Config

logger = logging.getLogger(__name__)
bp = Blueprint("social", __name__)

# Sherlock scans up to ~400 sites; the MCP server caps its own scan at 120s.
# Give the HTTP call a little more headroom than the tool's internal timeout.
_SEARCH_TIMEOUT_SECONDS = 130


async def _call_sherlock(username: str) -> dict:
    """POST to the social MCP /execute endpoint and return its `result` block."""
    url = f"{Config.MCP_SOCIAL_URL}/execute"
    payload = {"tool": "sherlock_username_search", "parameters": {"username": username}}
    timeout = aiohttp.ClientTimeout(total=_SEARCH_TIMEOUT_SECONDS)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=payload) as resp:
            data = await resp.json()
            if resp.status != 200 or "error" in data:
                raise RuntimeError(data.get("error", f"MCP returned HTTP {resp.status}"))
            return data.get("result", {})


@bp.route("/api/social/username-search", methods=["POST"])
@require_auth
def username_search():
    """Search social-media sites for a username via Sherlock."""
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()

    if not username:
        return jsonify({"error": "'username' is required"}), 400

    logger.info("Username search (sherlock): username=%s", username)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(_call_sherlock(username))
    except asyncio.TimeoutError:
        logger.warning("Username search timed out for %r", username)
        return jsonify({"error": f"Search timed out after {_SEARCH_TIMEOUT_SECONDS}s"}), 504
    except Exception as exc:  # noqa: BLE001 - surface MCP/network errors to the client
        logger.error("Username search failed for %r: %s", username, exc)
        return jsonify({"error": str(exc)[:200]}), 502
    finally:
        loop.close()

    accounts = result.get("accounts", [])
    return jsonify({
        "username": result.get("username", username),
        "count": result.get("found_count", len(accounts)),
        "accounts": accounts,
        "scan_duration_seconds": result.get("scan_duration_seconds"),
    })

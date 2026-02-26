"""
Pivots Blueprint
================

REST endpoints exposing pivot suggestions for investigations.

Endpoints
---------
GET  /api/investigations/<inv_id>/pivots
    Return ranked pivot suggestions for a completed investigation.
    Query params:
      max  (int, default 10) — maximum suggestions to return

POST /api/investigations/<inv_id>/pivots/dismiss
    Mark a specific pivot suggestion as dismissed (stored per-session).

GET  /api/pivots/explain
    Return documentation on pivot types and scoring logic.
"""

import logging
from flask import Blueprint, jsonify, request
from blueprints.auth import require_auth
from pivot_engine import pivot_engine

logger = logging.getLogger(__name__)
bp = Blueprint("pivots", __name__)

_PIVOT_TYPE_DOCS = {
    "expand_infrastructure": "Enumerate DNS records, passive DNS history, and Shodan data for this entity.",
    "check_reputation":      "Query VirusTotal, AbuseIPDB, and OTX for malicious activity reports.",
    "check_credentials":     "Search HIBP, Dehashed, and Hudson Rock for breach exposure.",
    "lookup_registration":   "Retrieve WHOIS registration history and registrant details.",
    "enumerate_subdomains":  "Run subdomain enumeration via DNS brute-force and crt.sh.",
    "cert_transparency":     "Query Certificate Transparency logs for related certificates and SANs.",
    "social_footprint":      "Search social platforms and paste sites for mentions of this entity.",
}


@bp.route("/api/investigations/<inv_id>/pivots", methods=["GET"])
@require_auth
def get_pivots(inv_id: str):
    """Return ranked pivot suggestions for an investigation."""
    from shared import services

    max_suggestions = min(int(request.args.get("max", 10)), 50)

    investigation = None
    try:
        inv_obj = services.get_investigation(inv_id)
        if inv_obj is not None:
            investigation = inv_obj if isinstance(inv_obj, dict) else inv_obj.to_dict()
    except Exception as exc:
        logger.warning("Could not load investigation %s: %s", inv_id, exc)

    if investigation is None:
        return jsonify({"error": f"Investigation '{inv_id}' not found"}), 404

    report = pivot_engine.analyse(investigation, max_suggestions=max_suggestions)
    return jsonify(report.to_dict())


@bp.route("/api/investigations/<inv_id>/pivots/dismiss", methods=["POST"])
@require_auth
def dismiss_pivot(inv_id: str):
    """Acknowledge/dismiss a pivot suggestion (no-op store for now)."""
    body = request.get_json(silent=True) or {}
    entity_value = body.get("entity_value", "")
    if not entity_value:
        return jsonify({"error": "'entity_value' is required"}), 400
    # Future: persist dismissals per analyst/investigation
    return jsonify({"status": "dismissed", "entity_value": entity_value})


@bp.route("/api/pivots/explain", methods=["GET"])
@require_auth
def explain_pivots():
    """Return documentation on pivot types and scoring weights."""
    return jsonify({
        "pivot_types": _PIVOT_TYPE_DOCS,
        "scoring": {
            "threat_flag":   "0.35 — entity flagged by at least one threat feed",
            "corroboration": "0.25 — entity appears across multiple intelligence sources",
            "centrality":    "0.20 — entity has many resolved neighbours in the graph",
            "recency":       "0.10 — entity observed recently (decays over 30 days)",
            "unresolved":    "0.10 — flat bonus for entities with no full investigation yet",
        },
    })

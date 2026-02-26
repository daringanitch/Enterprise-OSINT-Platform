"""
Cross-Investigation Correlations Blueprint
==========================================

REST endpoints for cross-investigation correlation.

Endpoints
---------
GET  /api/correlations
    Scan all investigations and return the full correlation report.

GET  /api/investigations/<inv_id>/correlations
    Return only the links involving a specific investigation.

GET  /api/correlations/indicators/<indicator_value>
    Find all investigations containing a specific indicator value.
"""

import logging
from flask import Blueprint, jsonify, request
from blueprints.auth import require_auth
from cross_investigation_correlator import correlator

logger = logging.getLogger(__name__)
bp = Blueprint("correlations", __name__)


def _load_all_investigations():
    """Load all investigations from the orchestrator."""
    from shared import services
    try:
        invs = services.orchestrator.get_active_investigations()
        return [
            inv if isinstance(inv, dict) else inv.to_dict()
            for inv in invs
            if inv is not None
        ]
    except Exception as exc:
        logger.warning("Could not load investigations: %s", exc)
        return []


@bp.route("/api/correlations", methods=["GET"])
@require_auth
def get_correlations():
    """Scan all investigations and return cross-investigation correlation report."""
    investigations = _load_all_investigations()
    if len(investigations) < 2:
        return jsonify({
            "investigations_scanned": len(investigations),
            "shared_indicator_count": 0,
            "investigation_link_count": 0,
            "shared_indicators": [],
            "investigation_links": [],
            "note": "At least 2 investigations are needed for cross-investigation correlation.",
        })
    report = correlator.run(investigations)
    return jsonify(report.to_dict())


@bp.route("/api/investigations/<inv_id>/correlations", methods=["GET"])
@require_auth
def get_investigation_correlations(inv_id: str):
    """Return correlation links involving a specific investigation."""
    from shared import services

    # Verify investigation exists
    try:
        inv_obj = services.get_investigation(inv_id)
        if inv_obj is None:
            return jsonify({"error": f"Investigation '{inv_id}' not found"}), 404
    except Exception:
        return jsonify({"error": f"Investigation '{inv_id}' not found"}), 404

    investigations = _load_all_investigations()
    links = correlator.links_for(inv_id, investigations)
    return jsonify({
        "investigation_id": inv_id,
        "links": [link.to_dict() for link in links],
        "total": len(links),
    })


@bp.route("/api/correlations/indicators/<path:indicator_value>", methods=["GET"])
@require_auth
def find_indicator(indicator_value: str):
    """Find all investigations containing a specific indicator."""
    investigations = _load_all_investigations()
    matches = []
    val_lower = indicator_value.lower()
    for inv in investigations:
        inv_dict = inv if isinstance(inv, dict) else {}
        inv_str = str(inv_dict).lower()
        if val_lower in inv_str:
            tp = (inv_dict.get("target_profile") or {})
            matches.append({
                "investigation_id": inv_dict.get("id", ""),
                "target": tp.get("primary_identifier", ""),
                "status": inv_dict.get("status", ""),
                "created_at": inv_dict.get("created_at", ""),
            })
    return jsonify({
        "indicator": indicator_value,
        "found_in": matches,
        "total": len(matches),
    })

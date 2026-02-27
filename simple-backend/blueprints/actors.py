"""
Threat Actor Dossiers Blueprint
================================

REST endpoints for the threat actor library.

Endpoints
---------
GET  /api/actors
    List all actors (summary form). Supports ?type=, ?sector=, ?country= filters.

GET  /api/actors/<actor_id>
    Full dossier for a specific actor by ID or name.

POST /api/actors/match
    Match a set of MITRE ATT&CK techniques against the library and return ranked actors.

GET  /api/actors/search
    Full-text search. Query param: q=

GET  /api/investigations/<inv_id>/actors
    Automatically match the investigation's observed TTPs against the library
    and return ranked attribution candidates.
"""

import logging
from flask import Blueprint, jsonify, request
from blueprints.auth import require_auth
from threat_actor_library import actor_library

logger = logging.getLogger(__name__)
bp = Blueprint("actors", __name__)


@bp.route("/api/actors", methods=["GET"])
@require_auth
def list_actors():
    actor_type   = request.args.get("type", "").lower()
    sector       = request.args.get("sector", "")
    country      = request.args.get("country", "").upper()
    status       = request.args.get("status", "").lower()

    actors = actor_library.all()

    if actor_type:
        actors = [a for a in actors if actor_type in a.actor_type.lower()]
    if sector:
        actors = [a for a in actors if a.matches_sector(sector)]
    if country:
        actors = [a for a in actors if country in a.origin_country.upper()]
    if status:
        actors = [a for a in actors if status in a.activity_status.lower()]

    return jsonify({
        "actors": [a.to_dict() for a in actors],
        "total": len(actors),
    })


@bp.route("/api/actors/<actor_id>", methods=["GET"])
@require_auth
def get_actor(actor_id: str):
    actor = actor_library.get_by_id(actor_id) or actor_library.get(actor_id)
    if actor is None:
        return jsonify({"error": f"Actor '{actor_id}' not found"}), 404
    return jsonify(actor.to_dict())


@bp.route("/api/actors/match", methods=["POST"])
@require_auth
def match_actors():
    body = request.get_json(silent=True) or {}
    techniques = body.get("techniques", [])
    min_match  = int(body.get("min_match", 1))

    if not isinstance(techniques, list) or not techniques:
        return jsonify({"error": "'techniques' must be a non-empty list"}), 400

    results = actor_library.match_ttps(techniques, min_match=min_match)
    return jsonify({
        "query_techniques": techniques,
        "matches": [r.to_dict() for r in results],
        "total": len(results),
    })


@bp.route("/api/actors/search", methods=["GET"])
@require_auth
def search_actors():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "'q' query parameter is required"}), 400
    results = actor_library.search(q)
    return jsonify({
        "query": q,
        "results": [a.to_dict() for a in results],
        "total": len(results),
    })


@bp.route("/api/investigations/<inv_id>/actors", methods=["GET"])
@require_auth
def match_investigation_actors(inv_id: str):
    """Auto-match investigation TTPs → library actors."""
    from shared import services

    investigation = None
    try:
        inv_obj = services.get_investigation(inv_id)
        if inv_obj is not None:
            investigation = inv_obj if isinstance(inv_obj, dict) else inv_obj.to_dict()
    except Exception as exc:
        logger.warning("Could not load investigation %s: %s", inv_id, exc)

    if investigation is None:
        return jsonify({"error": f"Investigation '{inv_id}' not found"}), 404

    threat = investigation.get("threat_intelligence") or {}
    techniques = threat.get("mitre_techniques", [])

    if not techniques:
        return jsonify({
            "investigation_id": inv_id,
            "matches": [],
            "note": "No MITRE techniques found in this investigation.",
        })

    results = actor_library.match_ttps(techniques, min_match=1)
    return jsonify({
        "investigation_id": inv_id,
        "observed_techniques": techniques,
        "matches": [r.to_dict() for r in results[:10]],
        "total_matches": len(results),
    })

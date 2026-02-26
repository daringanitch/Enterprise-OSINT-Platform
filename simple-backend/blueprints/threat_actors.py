"""
Threat Actor Dossiers Blueprint
================================

REST endpoints for the curated threat actor library.

Endpoints
---------
GET  /api/threat-actors
    List all actors (compact summary).
    Query params: q (search), sector, technique, type, motivation

GET  /api/threat-actors/<actor_id>
    Full dossier for one actor.

POST /api/threat-actors/match
    Find actors matching a set of observed TTPs (ranked by overlap).
    Body: {"techniques": ["T1566.001", "T1071.001"], "top_n": 5}

POST /api/threat-actors/fingerprint
    Given an investigation ID, score all actors against its observed TTPs
    and infrastructure fingerprints and return ranked attribution candidates.
    Body: {"investigation_id": "..."}
"""

import logging
from flask import Blueprint, jsonify, request
from blueprints.auth import require_auth
from threat_actor_library import actor_library

logger = logging.getLogger(__name__)
bp = Blueprint("threat_actors", __name__)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bp.route("/api/threat-actors", methods=["GET"])
@require_auth
def list_actors():
    """
    Return compact list of all threat actors.

    Optional query parameters
    -------------------------
    q         Full-text search across name, aliases, tools, sectors
    sector    Filter to actors targeting this sector (case-insensitive substring)
    technique Filter to actors using this MITRE technique ID
    type      nation-state | criminal | hacktivist | unknown
    motivation espionage | financial | disruption | ideological
    """
    q          = request.args.get("q", "").strip()
    sector     = request.args.get("sector", "").strip()
    technique  = request.args.get("technique", "").strip()
    actor_type = request.args.get("type", "").strip()
    motivation = request.args.get("motivation", "").strip()

    actors = actor_library.summary_list()

    # Apply filters
    if q:
        hits = {a.actor_id for a in actor_library.search(q)}
        actors = [a for a in actors if a["actor_id"] in hits]

    if sector:
        sector_l = sector.lower()
        actors = [
            a for a in actors
            if any(sector_l in s.lower() for s in a.get("targeted_sectors", []))
        ]

    if technique:
        hits = {a.actor_id for a in actor_library.find_by_technique(technique)}
        actors = [a for a in actors if a["actor_id"] in hits]

    if actor_type:
        actors = [a for a in actors if a.get("actor_type", "").lower() == actor_type.lower()]

    if motivation:
        actors = [a for a in actors if a.get("motivation", "").lower() == motivation.lower()]

    return jsonify({
        "actors": actors,
        "total": len(actors),
        "filters_applied": {
            k: v for k, v in {
                "q": q, "sector": sector, "technique": technique,
                "type": actor_type, "motivation": motivation,
            }.items() if v
        },
    })


@bp.route("/api/threat-actors/<actor_id>", methods=["GET"])
@require_auth
def get_actor(actor_id: str):
    """Return the full dossier for a single threat actor."""
    dossier = actor_library.get(actor_id)
    if dossier is None:
        # Try searching by name as a fallback
        results = actor_library.search(actor_id)
        if results:
            dossier = results[0]
        else:
            return jsonify({"error": f"Threat actor '{actor_id}' not found"}), 404

    return jsonify(dossier.to_dict())


@bp.route("/api/threat-actors/match", methods=["POST"])
@require_auth
def match_ttps():
    """
    Find threat actors matching a set of observed MITRE techniques.

    Request
    -------
    {
        "techniques": ["T1566.001", "T1071.001", "T1090.003"],
        "top_n": 5
    }

    Response
    --------
    {
        "matches": [
            {
                "actor_id": "cobalt_group",
                "name": "Cobalt Group",
                "overlap_count": 3,
                "overlap_score": 0.75,
                "matched_techniques": ["T1566.001", "T1071.001", "T1090.003"],
                "unmatched_observed": [],
                ...summary fields...
            }
        ],
        "techniques_queried": [...],
        "total_actors_scored": 26
    }
    """
    body = request.get_json(silent=True) or {}
    techniques = body.get("techniques", [])
    top_n = min(int(body.get("top_n", 5)), 20)

    if not isinstance(techniques, list) or not techniques:
        return jsonify({"error": "'techniques' must be a non-empty list of MITRE IDs"}), 400

    matches = actor_library.match_ttps(techniques, top_n=top_n)
    return jsonify({
        "matches": matches,
        "techniques_queried": techniques,
        "total_actors_scored": len(actor_library.summary_list()),
    })


@bp.route("/api/threat-actors/fingerprint", methods=["POST"])
@require_auth
def fingerprint_investigation():
    """
    Score all threat actors against an investigation's observed TTPs and
    infrastructure fingerprints.  Returns ranked attribution candidates.

    Request
    -------
    {"investigation_id": "d3m0-0001-..."}

    Response
    --------
    {
        "investigation_id": "...",
        "target": "secure-docview-portal.net",
        "candidates": [...match objects ranked by score...],
        "techniques_observed": [...],
        "note": "..."
    }
    """
    body = request.get_json(silent=True) or {}
    inv_id = body.get("investigation_id", "").strip()

    if not inv_id:
        return jsonify({"error": "'investigation_id' is required"}), 400

    from shared import services
    inv_obj = None
    try:
        inv_obj = services.get_investigation(inv_id)
    except Exception as exc:
        logger.warning("Could not load investigation %s: %s", inv_id, exc)

    if inv_obj is None:
        return jsonify({"error": f"Investigation '{inv_id}' not found"}), 404

    inv = inv_obj if isinstance(inv_obj, dict) else inv_obj.to_dict()

    # Extract observed techniques from the investigation
    threat_intel = inv.get("threat_intelligence") or {}
    techniques_observed = threat_intel.get("mitre_techniques", [])

    # Also pull from behavioral indicators
    for b in threat_intel.get("behavioral_indicators", []):
        t = b.get("technique", "")
        if t and t not in techniques_observed:
            techniques_observed.append(t)

    target = (inv.get("target_profile") or {}).get("primary_identifier", "")

    if not techniques_observed:
        return jsonify({
            "investigation_id": inv_id,
            "target": target,
            "candidates": [],
            "techniques_observed": [],
            "note": "No MITRE techniques found in this investigation. Run threat intelligence collection first.",
        })

    candidates = actor_library.match_ttps(techniques_observed, top_n=10)

    return jsonify({
        "investigation_id": inv_id,
        "target": target,
        "candidates": candidates,
        "techniques_observed": techniques_observed,
        "total_actors_scored": len(actor_library.summary_list()),
    })

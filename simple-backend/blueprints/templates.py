"""
Investigation Templates Blueprint
==================================

REST endpoints for the investigation template library.

Endpoints
---------
GET  /api/templates
    List all templates (compact summary).
    Query params: category

GET  /api/templates/<template_id>
    Full template detail including watchlist seeds, ACH hypotheses,
    recommended techniques, and analyst guidance.

POST /api/templates/<template_id>/apply
    Apply a template to a new investigation.  Accepts an optional target
    identifier and returns a pre-populated scope dict, watchlist seeds,
    and ACH hypothesis seeds ready for investigation creation.

GET  /api/templates/categories
    List all available template categories.
"""

import logging
from flask import Blueprint, jsonify, request
from blueprints.auth import require_auth
from investigation_templates import template_library

logger = logging.getLogger(__name__)
bp = Blueprint("templates", __name__)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bp.route("/api/templates", methods=["GET"])
@require_auth
def list_templates():
    """
    Return compact list of all investigation templates.

    Optional query parameters
    -------------------------
    category   Filter by category (e.g. 'threat_intel', 'corporate_due_diligence',
               'insider_threat', 'vulnerability_management')
    """
    category = request.args.get("category", "").strip()

    if category:
        templates = template_library.by_category(category)
    else:
        templates = template_library.list_all()

    summaries = []
    for t in templates:
        summaries.append({
            "template_id":   t.template_id,
            "name":          t.name,
            "description":   t.description,
            "category":      t.category,
            "default_depth": t.default_depth,
            "ach_hypotheses_count":  len(t.ach_hypotheses),
            "watchlist_seeds_count": len(t.watchlist_seeds),
            "recommended_techniques": t.recommended_techniques[:5],  # preview
            "compliance_frameworks":  t.compliance_frameworks,
        })

    return jsonify({
        "templates": summaries,
        "total":     len(summaries),
        "filters_applied": {"category": category} if category else {},
    })


@bp.route("/api/templates/categories", methods=["GET"])
@require_auth
def list_categories():
    """Return all available template categories with counts."""
    all_templates = template_library.list_all()
    category_counts: dict = {}
    for t in all_templates:
        category_counts[t.category] = category_counts.get(t.category, 0) + 1

    return jsonify({
        "categories": [
            {"category": cat, "count": cnt}
            for cat, cnt in sorted(category_counts.items())
        ],
        "total_templates": len(all_templates),
    })


@bp.route("/api/templates/<template_id>", methods=["GET"])
@require_auth
def get_template(template_id: str):
    """Return the full template detail for a single investigation template."""
    tmpl = template_library.get(template_id)
    if tmpl is None:
        return jsonify({"error": f"Template '{template_id}' not found"}), 404

    return jsonify(tmpl.to_dict())


@bp.route("/api/templates/<template_id>/apply", methods=["POST"])
@require_auth
def apply_template(template_id: str):
    """
    Apply a template and return pre-populated investigation fields.

    Request body (all optional)
    ---------------------------
    {
        "target":          "evil-domain.example.com",
        "target_type":     "domain",          // domain | ip | email | org | person
        "analyst_notes":   "Initial triage from SOC ticket #1234"
    }

    Response
    --------
    {
        "template_id":   "apt_attribution",
        "name":          "APT Attribution",
        "scope":         { ...pre-populated InvestigationScope fields... },
        "watchlist_seeds": [ ...WatchlistSeed dicts with placeholders resolved... ],
        "ach_hypotheses":  [ ...ACHHypothesisSeed dicts... ],
        "recommended_techniques": [...],
        "key_questions":   [...],
        "analyst_guidance": "...",
        "compliance_frameworks": [...]
    }
    """
    tmpl = template_library.get(template_id)
    if tmpl is None:
        return jsonify({"error": f"Template '{template_id}' not found"}), 404

    body        = request.get_json(silent=True) or {}
    target      = body.get("target", "").strip()
    target_type = body.get("target_type", "").strip()
    analyst_notes = body.get("analyst_notes", "").strip()

    # Build scope dict from template defaults
    scope = tmpl.to_scope_dict()

    # Resolve watchlist seed placeholders if a target was provided
    watchlist_seeds = []
    for seed in tmpl.watchlist_seeds:
        seed_dict = {
            "target":           seed.target_placeholder,
            "target_type":      seed.target_type,
            "description":      seed.description,
            "check_interval_hours": seed.check_interval_hours,
            "tags":             seed.tags,
            "is_placeholder":   True,
        }
        if target and "{target}" in seed.target_placeholder:
            seed_dict["target"]        = target
            seed_dict["is_placeholder"] = False
        watchlist_seeds.append(seed_dict)

    # Build ACH hypothesis list
    ach_hypotheses = [
        {
            "title":           h.title,
            "description":     h.description,
            "hypothesis_type": h.hypothesis_type,
        }
        for h in tmpl.ach_hypotheses
    ]

    # Attach optional analyst notes to the scope
    if analyst_notes:
        scope["analyst_notes"] = analyst_notes
    if target:
        scope["primary_target"] = target
    if target_type:
        scope["target_type"] = target_type

    return jsonify({
        "template_id":            tmpl.template_id,
        "name":                   tmpl.name,
        "scope":                  scope,
        "watchlist_seeds":        watchlist_seeds,
        "ach_hypotheses":         ach_hypotheses,
        "recommended_techniques": tmpl.recommended_techniques,
        "key_questions":          tmpl.key_questions,
        "analyst_guidance":       tmpl.analyst_guidance,
        "compliance_frameworks":  tmpl.compliance_frameworks,
    })

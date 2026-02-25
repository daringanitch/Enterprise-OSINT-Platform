#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Analytic Tradecraft Blueprint
==============================

REST endpoints for structured analytic techniques, source rating, and
IC-standard confidence levels.

Intelligence Items (sourced intelligence with Admiralty ratings)
  GET    /api/tradecraft/investigations/<inv_id>/items
  POST   /api/tradecraft/investigations/<inv_id>/items
  PUT    /api/tradecraft/items/<item_id>
  DELETE /api/tradecraft/items/<item_id>

Hypotheses (for ACH and alternative tracking)
  GET    /api/tradecraft/investigations/<inv_id>/hypotheses
  POST   /api/tradecraft/investigations/<inv_id>/hypotheses
  PUT    /api/tradecraft/hypotheses/<hyp_id>
  DELETE /api/tradecraft/hypotheses/<hyp_id>

ACH Matrix
  GET    /api/tradecraft/investigations/<inv_id>/ach
  POST   /api/tradecraft/ach/cell          — set one cell consistency rating
  GET    /api/tradecraft/investigations/<inv_id>/ach/scores  — computed rankings

Conclusions (with IC confidence language)
  GET    /api/tradecraft/investigations/<inv_id>/conclusions
  POST   /api/tradecraft/investigations/<inv_id>/conclusions
  PUT    /api/tradecraft/conclusions/<cid>
  GET    /api/tradecraft/conclusions/<cid>/completeness

Alternative Explanations
  GET    /api/tradecraft/conclusions/<cid>/alternatives
  POST   /api/tradecraft/conclusions/<cid>/alternatives
  PUT    /api/tradecraft/alternatives/<alt_id>

Devil's Advocacy
  GET    /api/tradecraft/conclusions/<cid>/advocacy
  POST   /api/tradecraft/conclusions/<cid>/advocacy
  PUT    /api/tradecraft/advocacy/<da_id>

Reference data
  GET    /api/tradecraft/reference/admiralty
  GET    /api/tradecraft/reference/confidence
  GET    /api/tradecraft/reference/wep
"""

import logging
from datetime import datetime
from flask import Blueprint, jsonify, request

from blueprints.auth import require_auth
from analytic_tradecraft import (
    tradecraft_store,
    IntelligenceItem,
    Hypothesis,
    ACHCell,
    AnalyticConclusion,
    AlternativeExplanation,
    DevilsAdvocacy,
    compute_ach_scores,
    SOURCE_RELIABILITY_LABELS,
    SOURCE_RELIABILITY_DESCRIPTIONS,
    INFO_CREDIBILITY_LABELS,
    INFO_CREDIBILITY_DESCRIPTIONS,
    CONFIDENCE_LANGUAGE,
    WEP_SCALE,
)

logger = logging.getLogger(__name__)
bp = Blueprint("tradecraft", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize(obj) -> dict:
    from dataclasses import asdict
    return asdict(obj)


# ---------------------------------------------------------------------------
# Reference data (always available, no auth needed is fine, but keep consistent)
# ---------------------------------------------------------------------------

@bp.route("/api/tradecraft/reference/admiralty", methods=["GET"])
@require_auth
def get_admiralty_reference():
    """Return the full NATO/Admiralty scale reference."""
    return jsonify({
        "source_reliability": [
            {
                "grade": grade,
                "label": SOURCE_RELIABILITY_LABELS[grade],
                "description": SOURCE_RELIABILITY_DESCRIPTIONS[grade],
            }
            for grade in ["A", "B", "C", "D", "E", "F"]
        ],
        "information_credibility": [
            {
                "grade": grade,
                "label": INFO_CREDIBILITY_LABELS[grade],
                "description": INFO_CREDIBILITY_DESCRIPTIONS[grade],
            }
            for grade in ["1", "2", "3", "4", "5", "6"]
        ],
    })


@bp.route("/api/tradecraft/reference/confidence", methods=["GET"])
@require_auth
def get_confidence_reference():
    return jsonify({
        "levels": CONFIDENCE_LANGUAGE,
        "note": "Based on ICD 203 analytic standards. Confidence levels reflect quality of information and soundness of reasoning, not certainty.",
    })


@bp.route("/api/tradecraft/reference/wep", methods=["GET"])
@require_auth
def get_wep_reference():
    return jsonify({
        "scale": WEP_SCALE,
        "note": "Words of Estimative Probability (Sherman Kent scale). Use these controlled phrases in assessments to signal probabilistic judgements consistently.",
    })


# ---------------------------------------------------------------------------
# Intelligence Items
# ---------------------------------------------------------------------------

@bp.route("/api/tradecraft/investigations/<inv_id>/items", methods=["GET"])
@require_auth
def list_intel_items(inv_id: str):
    items = tradecraft_store.get_intel_items(inv_id)
    return jsonify({
        "items": [_serialize(i) for i in items],
        "count": len(items),
    })


@bp.route("/api/tradecraft/investigations/<inv_id>/items", methods=["POST"])
@require_auth
def create_intel_item(inv_id: str):
    data = request.get_json(silent=True) or {}
    item = IntelligenceItem(
        investigation_id=inv_id,
        title=data.get("title", ""),
        content=data.get("content", ""),
        source_name=data.get("source_name", ""),
        source_type=data.get("source_type", "osint"),
        source_reliability=data.get("source_reliability", "F"),
        info_credibility=data.get("info_credibility", "6"),
        collection_method=data.get("collection_method", ""),
        tags=data.get("tags", []),
        analyst_notes=data.get("analyst_notes", ""),
        raw_data=data.get("raw_data"),
    )
    tradecraft_store.save_intel_item(item)
    return jsonify(_serialize(item)), 201


@bp.route("/api/tradecraft/items/<item_id>", methods=["PUT"])
@require_auth
def update_intel_item(item_id: str):
    item = tradecraft_store.get_intel_item(item_id)
    if not item:
        return jsonify({"error": "Item not found"}), 404
    data = request.get_json(silent=True) or {}
    for field in ["title", "content", "source_name", "source_type",
                  "source_reliability", "info_credibility", "collection_method",
                  "tags", "analyst_notes"]:
        if field in data:
            setattr(item, field, data[field])
    tradecraft_store.save_intel_item(item)
    return jsonify(_serialize(item))


@bp.route("/api/tradecraft/items/<item_id>", methods=["DELETE"])
@require_auth
def delete_intel_item(item_id: str):
    ok = tradecraft_store.delete_intel_item(item_id)
    if not ok:
        return jsonify({"error": "Item not found"}), 404
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Hypotheses
# ---------------------------------------------------------------------------

@bp.route("/api/tradecraft/investigations/<inv_id>/hypotheses", methods=["GET"])
@require_auth
def list_hypotheses(inv_id: str):
    hyps = tradecraft_store.get_hypotheses(inv_id)
    return jsonify({"hypotheses": [_serialize(h) for h in hyps], "count": len(hyps)})


@bp.route("/api/tradecraft/investigations/<inv_id>/hypotheses", methods=["POST"])
@require_auth
def create_hypothesis(inv_id: str):
    data = request.get_json(silent=True) or {}
    if not data.get("title"):
        return jsonify({"error": "title is required"}), 400
    h = Hypothesis(
        investigation_id=inv_id,
        title=data["title"],
        description=data.get("description", ""),
        hypothesis_type=data.get("hypothesis_type", "primary"),
        notes=data.get("notes", ""),
    )
    tradecraft_store.save_hypothesis(h)
    return jsonify(_serialize(h)), 201


@bp.route("/api/tradecraft/hypotheses/<hyp_id>", methods=["PUT"])
@require_auth
def update_hypothesis(hyp_id: str):
    h = tradecraft_store.get_hypothesis(hyp_id)
    if not h:
        return jsonify({"error": "Hypothesis not found"}), 404
    data = request.get_json(silent=True) or {}

    # Enforce: rejection requires rationale
    new_status = data.get("status", h.status)
    if new_status == "rejected" and not (data.get("rejection_rationale") or h.rejection_rationale):
        return jsonify({"error": "rejection_rationale is required when rejecting a hypothesis"}), 400

    for field in ["title", "description", "hypothesis_type", "status", "rejection_rationale", "notes"]:
        if field in data:
            setattr(h, field, data[field])
    h.updated_at = datetime.utcnow().isoformat()
    tradecraft_store.save_hypothesis(h)
    return jsonify(_serialize(h))


@bp.route("/api/tradecraft/hypotheses/<hyp_id>", methods=["DELETE"])
@require_auth
def delete_hypothesis(hyp_id: str):
    ok = tradecraft_store.delete_hypothesis(hyp_id)
    if not ok:
        return jsonify({"error": "Hypothesis not found"}), 404
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# ACH Matrix
# ---------------------------------------------------------------------------

@bp.route("/api/tradecraft/investigations/<inv_id>/ach", methods=["GET"])
@require_auth
def get_ach_matrix(inv_id: str):
    """Return full ACH matrix: hypotheses × evidence with cell values."""
    hyps = tradecraft_store.get_hypotheses(inv_id)
    items = tradecraft_store.get_intel_items(inv_id)
    cells = tradecraft_store.get_ach_cells(inv_id)

    cell_map = {(c.evidence_id, c.hypothesis_id): _serialize(c) for c in cells}

    matrix = []
    for item in items:
        row = {
            "evidence": _serialize(item),
            "cells": {}
        }
        for hyp in hyps:
            key = (item.id, hyp.id)
            row["cells"][hyp.id] = cell_map.get(key, {
                "evidence_id": item.id,
                "hypothesis_id": hyp.id,
                "consistency": "NA",
                "analyst_rationale": "",
            })
        matrix.append(row)

    return jsonify({
        "investigation_id": inv_id,
        "hypotheses": [_serialize(h) for h in hyps],
        "matrix": matrix,
        "cell_count": len(cells),
    })


@bp.route("/api/tradecraft/ach/cell", methods=["POST"])
@require_auth
def set_ach_cell():
    """Set or update a single ACH cell."""
    data = request.get_json(silent=True) or {}
    required = ["evidence_id", "hypothesis_id", "consistency"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    valid = {"C", "I", "N", "NA"}
    if data["consistency"] not in valid:
        return jsonify({"error": f"consistency must be one of {valid}"}), 400

    cell = ACHCell(
        evidence_id=data["evidence_id"],
        hypothesis_id=data["hypothesis_id"],
        consistency=data["consistency"],
        analyst_rationale=data.get("analyst_rationale", ""),
    )
    tradecraft_store.set_ach_cell(cell)
    return jsonify(_serialize(cell))


@bp.route("/api/tradecraft/investigations/<inv_id>/ach/scores", methods=["GET"])
@require_auth
def get_ach_scores(inv_id: str):
    """Return computed ACH diagnostic scores and hypothesis rankings."""
    hyps = tradecraft_store.get_hypotheses(inv_id)
    items = tradecraft_store.get_intel_items(inv_id)
    cells = tradecraft_store.get_ach_cells(inv_id)
    scores = compute_ach_scores(hyps, items, cells)
    return jsonify({
        "investigation_id": inv_id,
        "scores": scores,
        "interpretation": "Hypothesis with rank 1 has the fewest inconsistencies and is most supported by the evidence. "
                          "Inconsistencies are most diagnostic — evidence consistent with ALL hypotheses does not distinguish between them.",
    })


# ---------------------------------------------------------------------------
# Conclusions
# ---------------------------------------------------------------------------

@bp.route("/api/tradecraft/investigations/<inv_id>/conclusions", methods=["GET"])
@require_auth
def list_conclusions(inv_id: str):
    concs = tradecraft_store.get_conclusions(inv_id)
    return jsonify({"conclusions": [_serialize(c) for c in concs], "count": len(concs)})


@bp.route("/api/tradecraft/investigations/<inv_id>/conclusions", methods=["POST"])
@require_auth
def create_conclusion(inv_id: str):
    data = request.get_json(silent=True) or {}
    if not data.get("title"):
        return jsonify({"error": "title is required"}), 400
    if not data.get("key_judgement"):
        return jsonify({"error": "key_judgement (bottom-line-up-front sentence) is required"}), 400

    c = AnalyticConclusion(
        investigation_id=inv_id,
        title=data["title"],
        assessment_text=data.get("assessment_text", ""),
        confidence_level=data.get("confidence_level", "low"),
        wep_phrase=data.get("wep_phrase", "possibly"),
        key_judgement=data["key_judgement"],
        supporting_evidence_ids=data.get("supporting_evidence_ids", []),
        primary_hypothesis_id=data.get("primary_hypothesis_id"),
        analytic_caveats=data.get("analytic_caveats", []),
        information_gaps=data.get("information_gaps", []),
        collection_gaps=data.get("collection_gaps", []),
        requires_alternative_explanations=data.get("requires_alternative_explanations", True),
        requires_devils_advocacy=data.get("requires_devils_advocacy", False),
    )
    tradecraft_store.save_conclusion(c)
    result = _serialize(c)
    result["ic_statement"] = c.generate_ic_statement()
    return jsonify(result), 201


@bp.route("/api/tradecraft/conclusions/<cid>", methods=["PUT"])
@require_auth
def update_conclusion(cid: str):
    c = tradecraft_store.get_conclusion(cid)
    if not c:
        return jsonify({"error": "Conclusion not found"}), 404
    data = request.get_json(silent=True) or {}

    # Enforce: finalising requires completeness
    new_status = data.get("status", c.status)
    if new_status == "finalised" and c.status != "finalised":
        alts = tradecraft_store.get_alternatives(cid)
        das = tradecraft_store.get_advocacies(cid)
        check = c.completeness_check(alts, das)
        if not check["complete"]:
            return jsonify({
                "error": "Conclusion is not complete",
                "issues": check["issues"],
            }), 422

    for field in ["title", "assessment_text", "confidence_level", "wep_phrase",
                  "key_judgement", "supporting_evidence_ids", "primary_hypothesis_id",
                  "analytic_caveats", "information_gaps", "collection_gaps",
                  "requires_alternative_explanations", "requires_devils_advocacy", "status"]:
        if field in data:
            setattr(c, field, data[field])
    tradecraft_store.save_conclusion(c)
    result = _serialize(c)
    result["ic_statement"] = c.generate_ic_statement()
    return jsonify(result)


@bp.route("/api/tradecraft/conclusions/<cid>/completeness", methods=["GET"])
@require_auth
def check_conclusion_completeness(cid: str):
    c = tradecraft_store.get_conclusion(cid)
    if not c:
        return jsonify({"error": "Conclusion not found"}), 404
    alts = tradecraft_store.get_alternatives(cid)
    das = tradecraft_store.get_advocacies(cid)
    check = c.completeness_check(alts, das)
    check["ic_statement"] = c.generate_ic_statement()
    return jsonify(check)


# ---------------------------------------------------------------------------
# Alternative Explanations
# ---------------------------------------------------------------------------

@bp.route("/api/tradecraft/conclusions/<cid>/alternatives", methods=["GET"])
@require_auth
def list_alternatives(cid: str):
    alts = tradecraft_store.get_alternatives(cid)
    return jsonify({"alternatives": [_serialize(a) for a in alts], "count": len(alts)})


@bp.route("/api/tradecraft/conclusions/<cid>/alternatives", methods=["POST"])
@require_auth
def create_alternative(cid: str):
    if not tradecraft_store.get_conclusion(cid):
        return jsonify({"error": "Conclusion not found"}), 404
    data = request.get_json(silent=True) or {}
    if not data.get("alternative_text"):
        return jsonify({"error": "alternative_text is required"}), 400

    c_obj = tradecraft_store.get_conclusion(cid)
    alt = AlternativeExplanation(
        investigation_id=c_obj.investigation_id if c_obj else "",
        conclusion_id=cid,
        alternative_text=data["alternative_text"],
        why_considered=data.get("why_considered", ""),
        why_rejected=data.get("why_rejected", ""),
        rejection_confidence=data.get("rejection_confidence", "moderate"),
        status="closed" if data.get("why_rejected") else "open",
    )
    tradecraft_store.save_alternative(alt)
    return jsonify(_serialize(alt)), 201


@bp.route("/api/tradecraft/alternatives/<alt_id>", methods=["PUT"])
@require_auth
def update_alternative(alt_id: str):
    alt = tradecraft_store.get_alternative(alt_id)
    if not alt:
        return jsonify({"error": "Alternative not found"}), 404
    data = request.get_json(silent=True) or {}
    for field in ["alternative_text", "why_considered", "why_rejected", "rejection_confidence"]:
        if field in data:
            setattr(alt, field, data[field])
    # Auto-close when rejection rationale is provided
    if alt.why_rejected:
        alt.status = "closed"
    tradecraft_store.save_alternative(alt)
    return jsonify(_serialize(alt))


# ---------------------------------------------------------------------------
# Devil's Advocacy
# ---------------------------------------------------------------------------

@bp.route("/api/tradecraft/conclusions/<cid>/advocacy", methods=["GET"])
@require_auth
def list_advocacy(cid: str):
    das = tradecraft_store.get_advocacies(cid)
    return jsonify({"advocacies": [_serialize(d) for d in das], "count": len(das)})


@bp.route("/api/tradecraft/conclusions/<cid>/advocacy", methods=["POST"])
@require_auth
def create_advocacy(cid: str):
    if not tradecraft_store.get_conclusion(cid):
        return jsonify({"error": "Conclusion not found"}), 404
    data = request.get_json(silent=True) or {}
    if not data.get("challenge_text"):
        return jsonify({"error": "challenge_text is required — state the strongest argument against the conclusion"}), 400

    c_obj = tradecraft_store.get_conclusion(cid)
    da = DevilsAdvocacy(
        investigation_id=c_obj.investigation_id if c_obj else "",
        conclusion_id=cid,
        challenge_text=data["challenge_text"],
        evidence_gaps=data.get("evidence_gaps", []),
        response_text=data.get("response_text", ""),
        status="responded" if data.get("response_text") else "open",
        created_by=data.get("created_by", "devil_advocate"),
    )
    tradecraft_store.save_advocacy(da)
    return jsonify(_serialize(da)), 201


@bp.route("/api/tradecraft/advocacy/<da_id>", methods=["PUT"])
@require_auth
def update_advocacy(da_id: str):
    da = tradecraft_store.get_advocacy(da_id)
    if not da:
        return jsonify({"error": "Advocacy not found"}), 404
    data = request.get_json(silent=True) or {}
    for field in ["challenge_text", "evidence_gaps", "response_text", "status"]:
        if field in data:
            setattr(da, field, data[field])
    if da.response_text and da.status == "open":
        da.status = "responded"
    tradecraft_store.save_advocacy(da)
    return jsonify(_serialize(da))

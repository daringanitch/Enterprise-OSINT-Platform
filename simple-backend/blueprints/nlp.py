"""
NLP Intelligence Blueprint
===========================

Exposes three REST endpoints for extracting structured threat intelligence
from unstructured text using :class:`nlp_pipeline.NLPPipeline`.

Endpoints
---------
POST /api/nlp/analyze
    Analyse a single text snippet.

POST /api/nlp/analyze/batch
    Analyse a list of text snippets in one request.

POST /api/nlp/analyze/investigation/<inv_id>
    Run NLP across all free-text fields of an existing investigation and
    return merged results.  Read-only — does not mutate the investigation.
"""

import logging
from flask import Blueprint, jsonify, request

from blueprints.auth import require_auth
from nlp_pipeline import NLPPipeline, _SPACY_AVAILABLE, _LANGDETECT_AVAILABLE

logger = logging.getLogger(__name__)
bp = Blueprint("nlp", __name__)

# Singleton — regex patterns compiled once at startup
_pipeline = NLPPipeline()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FREE_TEXT_FIELDS = [
    "notes",
    "summary",
    "description",
    "raw_intelligence",
    "findings",
    "context",
    "analyst_notes",
]


def _text_from_investigation(investigation) -> tuple[str, list[str]]:
    """
    Gather all free-text fields from an investigation object into one string.

    Returns (combined_text, list_of_field_names_that_had_content).
    """
    parts: list[str] = []
    fields_used: list[str] = []

    inv_dict = (
        investigation.__dict__
        if not isinstance(investigation, dict)
        else investigation
    )

    for field_name in _FREE_TEXT_FIELDS:
        value = inv_dict.get(field_name, "") or ""
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
            fields_used.append(field_name)

    # Also include target primary identifier
    target = inv_dict.get("target_profile") or {}
    if isinstance(target, dict):
        identifier = target.get("primary_identifier", "")
    else:
        identifier = getattr(target, "primary_identifier", "")
    if identifier:
        parts.append(str(identifier))
        fields_used.append("target_profile.primary_identifier")

    return "\n\n".join(parts), fields_used


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@bp.route("/api/nlp/analyze", methods=["POST"])
@require_auth
def analyze_text():
    """
    Analyse a single text snippet.

    Request body::

        {
            "text": "CVE-2021-44228 exploited by APT28...",
            "source": "paste_site"   // optional, for audit purposes
        }

    Returns a serialised :class:`~nlp_pipeline.NLPResult` plus metadata.
    """
    body = request.get_json(silent=True) or {}
    text = body.get("text", "")

    if not text or not isinstance(text, str):
        return jsonify({"error": "Request body must contain a non-empty 'text' string"}), 400

    source = body.get("source", "api")
    logger.info("NLP analyze request: source=%s, text_length=%d", source, len(text))

    result = _pipeline.analyze(text)
    entities = _pipeline.to_entities(result)

    return jsonify({
        "nlp_result": result.to_dict(),
        "entities": entities,
        "entity_count": len(entities),
        "spacy_available": _SPACY_AVAILABLE,
        "langdetect_available": _LANGDETECT_AVAILABLE,
        "source": source,
    })


@bp.route("/api/nlp/analyze/batch", methods=["POST"])
@require_auth
def analyze_batch():
    """
    Analyse a list of text snippets.

    Request body::

        {
            "texts": ["text one...", "text two..."],
            "source": "feed_ingest"   // optional
        }

    Returns::

        {
            "results": [<NLPResult>, ...],
            "total": int,
            "spacy_available": bool,
            "langdetect_available": bool
        }
    """
    body = request.get_json(silent=True) or {}
    texts = body.get("texts", [])

    if not isinstance(texts, list) or not texts:
        return jsonify({"error": "'texts' must be a non-empty list of strings"}), 400

    if len(texts) > 500:
        return jsonify({"error": "Batch size exceeds maximum of 500 texts"}), 400

    source = body.get("source", "api_batch")
    logger.info(
        "NLP batch analyze request: source=%s, count=%d", source, len(texts)
    )

    results = _pipeline.analyze_batch(texts)
    serialised = [r.to_dict() for r in results]

    return jsonify({
        "results": serialised,
        "total": len(serialised),
        "spacy_available": _SPACY_AVAILABLE,
        "langdetect_available": _LANGDETECT_AVAILABLE,
        "source": source,
    })


@bp.route("/api/nlp/analyze/investigation/<inv_id>", methods=["POST"])
@require_auth
def analyze_investigation(inv_id: str):
    """
    Run NLP over all free-text fields of an existing investigation.

    Read-only — does not mutate the investigation. The caller decides
    whether to write findings back (e.g. via the correlation API).

    Returns::

        {
            "nlp_result": {...},
            "entities": [...],
            "entity_count": int,
            "text_fields_analyzed": [...],
            "investigation_id": str
        }
    """
    from shared import services  # local import to avoid circular deps

    investigation = None
    try:
        investigation = services.get_investigation(inv_id)
    except Exception:
        pass

    if investigation is None:
        return jsonify({"error": f"Investigation '{inv_id}' not found"}), 404

    combined_text, fields_used = _text_from_investigation(investigation)

    if not combined_text.strip():
        return jsonify({
            "nlp_result": NLPPipeline().analyze("").to_dict(),
            "entities": [],
            "entity_count": 0,
            "text_fields_analyzed": [],
            "investigation_id": inv_id,
            "note": "No free-text content found in this investigation",
        })

    logger.info(
        "NLP investigation analyze: id=%s, fields=%s, text_length=%d",
        inv_id,
        fields_used,
        len(combined_text),
    )

    result = _pipeline.analyze(combined_text)
    entities = _pipeline.to_entities(result)

    return jsonify({
        "nlp_result": result.to_dict(),
        "entities": entities,
        "entity_count": len(entities),
        "text_fields_analyzed": fields_used,
        "investigation_id": inv_id,
    })

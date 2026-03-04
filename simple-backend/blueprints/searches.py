#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Saved Searches Blueprint

Provides investigation search and saved-search management endpoints.

Endpoints:
    GET  /api/investigations/search   — filter investigations by query params
    GET  /api/searches                — list saved searches
    POST /api/searches                — create a saved search
    DELETE /api/searches/<id>         — delete a saved search
    GET  /api/searches/<id>/matches   — run a saved search and return matches
"""

import logging
import uuid
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request

from shared import services

logger = logging.getLogger(__name__)

bp = Blueprint('searches', __name__)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_investigations():
    """Return all investigations as a list of serialisable dicts."""
    orchestrator = services.orchestrator
    if orchestrator is None:
        return []

    investigations = []
    if hasattr(orchestrator, 'get_all_investigations'):
        investigations = orchestrator.get_all_investigations() or []
    elif hasattr(orchestrator, 'investigations'):
        investigations = list((orchestrator.investigations or {}).values())
    elif hasattr(orchestrator, 'get_active_investigations'):
        investigations = orchestrator.get_active_investigations() or []

    result = []
    for inv in investigations:
        status = getattr(inv, 'status', 'unknown')
        if hasattr(status, 'value'):
            status = status.value
        inv_type = getattr(inv, 'investigation_type', None) or getattr(inv, 'type', None)
        if inv_type and hasattr(inv_type, 'value'):
            inv_type = inv_type.value
        priority = getattr(inv, 'priority', None)
        if priority and hasattr(priority, 'value'):
            priority = priority.value
        risk_level = getattr(inv, 'risk_level', None)
        if risk_level and hasattr(risk_level, 'value'):
            risk_level = risk_level.value

        result.append({
            'id': str(getattr(inv, 'investigation_id', None) or getattr(inv, 'id', id(inv))),
            'target': str(getattr(inv, 'target', '')),
            'status': str(status),
            'type': str(inv_type) if inv_type else None,
            'priority': str(priority) if priority else None,
            'risk_level': str(risk_level) if risk_level else None,
            'risk_score': getattr(inv, 'risk_score', None),
            'investigator': str(getattr(inv, 'investigator_name', None) or getattr(inv, 'investigator', '') or ''),
            'findings_count': getattr(inv, 'findings_count', 0) or 0,
            'progress': getattr(inv, 'progress', 0) or 0,
            'created_at': _dt_str(getattr(inv, 'created_at', None)),
            'updated_at': _dt_str(getattr(inv, 'updated_at', None)),
        })
    return result


def _dt_str(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _parse_date(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def _matches_query(inv: dict, params: dict) -> bool:
    """Return True if an investigation dict matches all provided query params."""
    # Text search over target + investigator
    q = (params.get('q') or '').strip().lower()
    if q:
        searchable = f"{inv.get('target', '')} {inv.get('investigator', '')}".lower()
        if q not in searchable:
            return False

    # Exact matches
    for field in ('status', 'type', 'priority', 'risk_level'):
        want = params.get(field, '').strip().lower()
        if want:
            got = (inv.get(field) or '').lower()
            if got != want:
                return False

    # Date range
    from_date = _parse_date(params.get('from_date'))
    to_date = _parse_date(params.get('to_date'))
    if from_date or to_date:
        created = _parse_date(inv.get('created_at'))
        if created:
            if from_date and created < from_date:
                return False
            if to_date and created > to_date:
                return False

    return True


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── Investigation search ─────────────────────────────────────────────────────

@bp.route('/api/investigations/search', methods=['GET'])
def search_investigations():
    """
    Filter investigations by query parameters.

    Query params:
        q           Text search over target and investigator fields
        status      Exact status match (e.g. "completed", "analyzing")
        type        Exact type match (e.g. "comprehensive", "corporate")
        priority    Exact priority match (e.g. "high", "critical")
        risk_level  Exact risk level match (e.g. "high", "critical")
        from_date   ISO 8601 — filter by created_at >=
        to_date     ISO 8601 — filter by created_at <=
    """
    params = {
        'q':          request.args.get('q', ''),
        'status':     request.args.get('status', ''),
        'type':       request.args.get('type', ''),
        'priority':   request.args.get('priority', ''),
        'risk_level': request.args.get('risk_level', ''),
        'from_date':  request.args.get('from_date', ''),
        'to_date':    request.args.get('to_date', ''),
    }

    try:
        all_inv = _get_investigations()
        results = [inv for inv in all_inv if _matches_query(inv, params)]
        return jsonify({'results': results, 'total': len(results)})
    except Exception as e:
        logger.error('Investigation search error: %s', e)
        return jsonify({'error': 'Search failed', 'results': [], 'total': 0}), 500


# ─── Saved searches CRUD ──────────────────────────────────────────────────────

@bp.route('/api/searches', methods=['GET'])
def list_saved_searches():
    """Return all saved searches, most recently created first."""
    searches = sorted(
        services.saved_searches.values(),
        key=lambda s: s.get('created_at', ''),
        reverse=True,
    )
    return jsonify({'searches': searches, 'total': len(searches)})


@bp.route('/api/searches', methods=['POST'])
def create_saved_search():
    """
    Save a new search.

    Body:
        name         (required) Display name for the saved search
        description  (optional) Longer description
        query_params (required) Dict of query params (same keys as /api/investigations/search)
    """
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400

    query_params = data.get('query_params')
    if not isinstance(query_params, dict):
        return jsonify({'error': 'query_params must be an object'}), 400

    search_id = str(uuid.uuid4())
    saved = {
        'id': search_id,
        'name': name,
        'description': (data.get('description') or '').strip(),
        'query_params': query_params,
        'created_at': _now_iso(),
        'last_run_at': None,
        'match_count': 0,
    }
    services.saved_searches[search_id] = saved
    logger.info('Saved search created: %s (%s)', name, search_id)
    return jsonify(saved), 201


@bp.route('/api/searches/<search_id>', methods=['DELETE'])
def delete_saved_search(search_id: str):
    """Delete a saved search by ID."""
    if search_id not in services.saved_searches:
        return jsonify({'error': 'Saved search not found'}), 404
    del services.saved_searches[search_id]
    return jsonify({'deleted': True, 'id': search_id})


@bp.route('/api/searches/<search_id>/matches', methods=['GET'])
def run_saved_search(search_id: str):
    """
    Run a saved search and return matching investigations.

    Also updates last_run_at and match_count on the saved search.
    """
    saved = services.saved_searches.get(search_id)
    if not saved:
        return jsonify({'error': 'Saved search not found'}), 404

    try:
        all_inv = _get_investigations()
        params = saved.get('query_params', {})
        matches = [inv for inv in all_inv if _matches_query(inv, params)]

        # Update saved search metadata
        saved['last_run_at'] = _now_iso()
        saved['match_count'] = len(matches)

        return jsonify({
            'search_id': search_id,
            'search_name': saved['name'],
            'results': matches,
            'total': len(matches),
            'last_run_at': saved['last_run_at'],
        })
    except Exception as e:
        logger.error('Run saved search error: %s', e)
        return jsonify({'error': 'Search failed', 'results': [], 'total': 0}), 500

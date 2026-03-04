#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Entity Lookup Blueprint

Provides a lightweight entity lookup endpoint used by the frontend's
EntityHoverCard component. Given an entity value (IP, domain, email, hash, etc.),
scans all in-memory investigations and aggregates intelligence about that entity
across the full platform.

Endpoint:
    GET /api/entities/lookup?value=<value>&type=<type>

Returns 200 in all cases (found: true/false) to avoid error noise on hover.
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from flask import Blueprint, jsonify, request

from shared import services

logger = logging.getLogger(__name__)

bp = Blueprint('entities', __name__)


def _normalize(value: str) -> str:
    """Normalize an entity value for comparison."""
    return value.strip().lower()


def _parse_dt(value) -> Optional[datetime]:
    """Parse a datetime string or datetime object, returning None on failure."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def _dt_to_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _days_since(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = now - dt
    return max(0, delta.days)


@bp.route('/api/entities/lookup', methods=['GET'])
def lookup_entity():
    """
    Look up an entity value across all investigations.

    Query params:
        value (required): The entity value to look up (e.g. "1.2.3.4", "evil.com")
        type  (optional): Entity type hint (ip_address, domain, email, hash, url, etc.)

    Returns:
        200 { found: false }                      — not found in any investigation
        200 { found: true, value, type, ... }     — aggregated entity intel
    """
    value = request.args.get('value', '').strip()
    entity_type = request.args.get('type', '').strip().lower() or None

    if not value:
        return jsonify({'error': 'value parameter is required'}), 400

    normalized = _normalize(value)

    # ── Aggregate data across all investigations ──────────────────────────────

    matched_investigations = []
    all_sources: set = set()
    all_tags: set = set()
    best_confidence: float = 0.0
    earliest_first_seen: Optional[datetime] = None
    latest_last_seen: Optional[datetime] = None
    detected_type: Optional[str] = entity_type

    try:
        orchestrator = services.orchestrator
        if orchestrator is None:
            return jsonify({'found': False, 'reason': 'orchestrator_unavailable'})

        # Try to get all investigations from the orchestrator
        investigations = []
        if hasattr(orchestrator, 'get_all_investigations'):
            investigations = orchestrator.get_all_investigations() or []
        elif hasattr(orchestrator, 'investigations'):
            investigations_dict = orchestrator.investigations or {}
            investigations = list(investigations_dict.values())
        elif hasattr(orchestrator, 'get_active_investigations'):
            investigations = orchestrator.get_active_investigations() or []

        for inv in investigations:
            hit = False

            # ── Check correlation_results.entities ──────────────────────────
            correlation = getattr(inv, 'correlation_results', None)
            if correlation is not None:
                entities = getattr(correlation, 'entities', {}) or {}
                for entity_id, entity in entities.items():
                    entity_value = getattr(entity, 'value', None) or getattr(entity, 'normalized_value', None)
                    if entity_value and _normalize(str(entity_value)) == normalized:
                        hit = True
                        conf = getattr(entity, 'confidence', 0.0) or 0.0
                        best_confidence = max(best_confidence, float(conf))

                        sources = getattr(entity, 'sources', []) or []
                        all_sources.update(sources)

                        tags = getattr(entity, 'tags', []) or []
                        all_tags.update(tags)

                        if not detected_type:
                            etype = getattr(entity, 'entity_type', None) or getattr(entity, 'type', None)
                            if etype:
                                detected_type = str(etype.value if hasattr(etype, 'value') else etype)

                        fs = _parse_dt(getattr(entity, 'first_seen', None))
                        ls = _parse_dt(getattr(entity, 'last_seen', None))
                        if fs and (earliest_first_seen is None or fs < earliest_first_seen):
                            earliest_first_seen = fs
                        if ls and (latest_last_seen is None or ls > latest_last_seen):
                            latest_last_seen = ls

            # ── Check threat_intelligence indicators ────────────────────────
            threat_intel = getattr(inv, 'threat_intelligence', None)
            if threat_intel is not None:
                for indicator_list_attr in ['malware_indicators', 'network_indicators', 'behavioral_indicators']:
                    indicators = getattr(threat_intel, indicator_list_attr, None) or []
                    if isinstance(indicators, list):
                        for ind in indicators:
                            ind_value = None
                            if isinstance(ind, dict):
                                ind_value = ind.get('value') or ind.get('indicator')
                            else:
                                ind_value = getattr(ind, 'value', None)
                            if ind_value and _normalize(str(ind_value)) == normalized:
                                hit = True
                                if isinstance(ind, dict):
                                    all_sources.add(ind.get('source', 'threat-intel'))
                                    conf = float(ind.get('confidence', 0.5))
                                    best_confidence = max(best_confidence, conf)
                                    fs = _parse_dt(ind.get('first_seen'))
                                    ls = _parse_dt(ind.get('last_seen'))
                                else:
                                    all_sources.add(getattr(ind, 'source', 'threat-intel'))
                                    conf = float(getattr(ind, 'confidence', 0.5) or 0.5)
                                    best_confidence = max(best_confidence, conf)
                                    fs = _parse_dt(getattr(ind, 'first_seen', None))
                                    ls = _parse_dt(getattr(ind, 'last_seen', None))
                                if fs and (earliest_first_seen is None or fs < earliest_first_seen):
                                    earliest_first_seen = fs
                                if ls and (latest_last_seen is None or ls > latest_last_seen):
                                    latest_last_seen = ls

            # ── Check target field directly ─────────────────────────────────
            inv_target = getattr(inv, 'target', None)
            if inv_target and _normalize(str(inv_target)) == normalized:
                hit = True
                best_confidence = max(best_confidence, 0.9)

            # ── Record investigation match ───────────────────────────────────
            if hit:
                inv_id = getattr(inv, 'investigation_id', None) or getattr(inv, 'id', None) or str(inv)
                inv_target_str = getattr(inv, 'target', 'Unknown')
                inv_status = getattr(inv, 'status', 'unknown')
                if hasattr(inv_status, 'value'):
                    inv_status = inv_status.value
                inv_risk = getattr(inv, 'risk_level', None)
                if inv_risk and hasattr(inv_risk, 'value'):
                    inv_risk = inv_risk.value

                matched_investigations.append({
                    'id': str(inv_id),
                    'target': str(inv_target_str),
                    'status': str(inv_status),
                    'risk_level': str(inv_risk) if inv_risk else None,
                })

    except Exception as e:
        logger.warning('Entity lookup error: %s', e)
        return jsonify({'found': False, 'reason': 'lookup_error', 'detail': str(e)})

    if not matched_investigations:
        return jsonify({'found': False})

    # ── Build response ────────────────────────────────────────────────────────
    return jsonify({
        'found': True,
        'value': value,
        'type': detected_type or _guess_type(value),
        'confidence': round(best_confidence, 3),
        'first_seen': _dt_to_iso(earliest_first_seen),
        'last_seen': _dt_to_iso(latest_last_seen),
        'days_since_seen': _days_since(latest_last_seen),
        'sources': sorted(all_sources),
        'tags': sorted(all_tags),
        'investigations': matched_investigations,
        'investigation_count': len(matched_investigations),
    })


def _guess_type(value: str) -> str:
    """Heuristic type detection when no explicit type is provided."""
    import re
    value = value.strip()
    # IPv4
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value):
        return 'ip_address'
    # IPv6
    if ':' in value and re.match(r'^[0-9a-fA-F:]+$', value):
        return 'ip_address'
    # Email
    if '@' in value and '.' in value.split('@')[-1]:
        return 'email'
    # Hash (md5/sha1/sha256)
    if re.match(r'^[0-9a-fA-F]{32}$', value):
        return 'hash'
    if re.match(r'^[0-9a-fA-F]{40}$', value):
        return 'hash'
    if re.match(r'^[0-9a-fA-F]{64}$', value):
        return 'hash'
    # URL
    if value.startswith(('http://', 'https://')):
        return 'url'
    # Domain
    if '.' in value and not value.startswith('/'):
        return 'domain'
    return 'unknown'

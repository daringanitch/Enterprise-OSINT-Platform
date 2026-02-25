#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Monitoring Blueprint
=====================

REST endpoints for continuous monitoring and alerting.

Watchlist
  GET    /api/monitoring/watchlist               — all entries
  POST   /api/monitoring/watchlist               — create entry
  GET    /api/monitoring/watchlist/<id>          — single entry + recent alerts
  PUT    /api/monitoring/watchlist/<id>          — update entry
  DELETE /api/monitoring/watchlist/<id>          — delete entry
  POST   /api/monitoring/watchlist/<id>/check    — trigger immediate check
  POST   /api/monitoring/watchlist/<id>/enable   — enable/disable

Alerts
  GET    /api/monitoring/alerts                  — all alerts (filterable)
  GET    /api/monitoring/alerts/<alert_id>       — single alert
  POST   /api/monitoring/alerts/<alert_id>/acknowledge
  POST   /api/monitoring/alerts/<alert_id>/resolve
  POST   /api/monitoring/alerts/<alert_id>/dismiss

Snapshots
  GET    /api/monitoring/watchlist/<id>/snapshots   — snapshot history
  GET    /api/monitoring/watchlist/<id>/snapshots/latest

Summary
  GET    /api/monitoring/summary                 — counts, scheduler status
"""

import logging
from dataclasses import asdict
from datetime import datetime
from flask import Blueprint, jsonify, request

from blueprints.auth import require_auth
from alert_engine import (
    alert_store,
    WatchlistEntry,
    WATCHLIST_TYPES,
    ALERT_TYPES,
    CHECK_INTERVALS,
    SEVERITIES,
    ALERT_STATUSES,
)
from monitoring_scheduler import monitoring_scheduler

logger = logging.getLogger(__name__)
bp = Blueprint("monitoring", __name__)


# ---------------------------------------------------------------------------
# Watchlist CRUD
# ---------------------------------------------------------------------------

@bp.route("/api/monitoring/watchlist", methods=["GET"])
@require_auth
def list_watchlist():
    entries = alert_store.get_all_entries()
    result = []
    for e in entries:
        d = asdict(e)
        # Attach alert counts
        alerts = alert_store.get_alerts(watchlist_id=e.id, status="new")
        d["new_alert_count"] = len(alerts)
        result.append(d)
    return jsonify({"entries": result, "count": len(result)})


@bp.route("/api/monitoring/watchlist", methods=["POST"])
@require_auth
def create_watchlist_entry():
    data = request.get_json(silent=True) or {}

    if not data.get("value"):
        return jsonify({"error": "value is required (the target to monitor)"}), 400
    if data.get("entry_type", "domain") not in WATCHLIST_TYPES:
        return jsonify({"error": f"entry_type must be one of: {', '.join(WATCHLIST_TYPES)}"}), 400

    entry = WatchlistEntry(
        name=data.get("name", data.get("value", "")),
        entry_type=data.get("entry_type", "domain"),
        value=data["value"].strip(),
        check_interval_hours=int(data.get("check_interval_hours", 24)),
        alert_on=data.get("alert_on", list(ALERT_TYPES)),
        tags=data.get("tags", []),
        notes=data.get("notes", ""),
        ip_reputation_threshold=int(data.get("ip_reputation_threshold", 50)),
        alert_on_any_cert=bool(data.get("alert_on_any_cert", True)),
        notify_email=data.get("notify_email"),
    )
    alert_store.save_entry(entry)
    return jsonify(asdict(entry)), 201


@bp.route("/api/monitoring/watchlist/<entry_id>", methods=["GET"])
@require_auth
def get_watchlist_entry(entry_id: str):
    entry = alert_store.get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Entry not found"}), 404
    d = asdict(entry)
    d["recent_alerts"] = [asdict(a) for a in alert_store.get_alerts(watchlist_id=entry_id, limit=10)]
    d["latest_snapshot"] = asdict(alert_store.get_latest_snapshot(entry_id)) if alert_store.get_latest_snapshot(entry_id) else None
    return jsonify(d)


@bp.route("/api/monitoring/watchlist/<entry_id>", methods=["PUT"])
@require_auth
def update_watchlist_entry(entry_id: str):
    entry = alert_store.get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Entry not found"}), 404
    data = request.get_json(silent=True) or {}
    for field in ["name", "check_interval_hours", "alert_on", "tags", "notes",
                  "ip_reputation_threshold", "alert_on_any_cert", "notify_email", "enabled"]:
        if field in data:
            setattr(entry, field, data[field])
    alert_store.save_entry(entry)
    return jsonify(asdict(entry))


@bp.route("/api/monitoring/watchlist/<entry_id>", methods=["DELETE"])
@require_auth
def delete_watchlist_entry(entry_id: str):
    ok = alert_store.delete_entry(entry_id)
    if not ok:
        return jsonify({"error": "Entry not found"}), 404
    return jsonify({"ok": True})


@bp.route("/api/monitoring/watchlist/<entry_id>/check", methods=["POST"])
@require_auth
def trigger_check(entry_id: str):
    """Force an immediate infrastructure check for this entry."""
    result = monitoring_scheduler.trigger(entry_id)
    if result is None:
        return jsonify({"error": "Entry not found or disabled"}), 404
    return jsonify(result)


@bp.route("/api/monitoring/watchlist/<entry_id>/enable", methods=["POST"])
@require_auth
def toggle_entry(entry_id: str):
    entry = alert_store.get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Entry not found"}), 404
    data = request.get_json(silent=True) or {}
    entry.enabled = bool(data.get("enabled", not entry.enabled))
    alert_store.save_entry(entry)
    return jsonify({"ok": True, "enabled": entry.enabled})


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@bp.route("/api/monitoring/alerts", methods=["GET"])
@require_auth
def list_alerts():
    watchlist_id = request.args.get("watchlist_id")
    status = request.args.get("status")
    severity = request.args.get("severity")
    limit = min(int(request.args.get("limit", 200)), 500)
    alerts = alert_store.get_alerts(
        watchlist_id=watchlist_id or None,
        status=status or None,
        severity=severity or None,
        limit=limit,
    )
    return jsonify({
        "alerts": [asdict(a) for a in alerts],
        "count": len(alerts),
    })


@bp.route("/api/monitoring/alerts/<alert_id>", methods=["GET"])
@require_auth
def get_alert_detail(alert_id: str):
    alert = alert_store.get_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(asdict(alert))


@bp.route("/api/monitoring/alerts/<alert_id>/acknowledge", methods=["POST"])
@require_auth
def acknowledge_alert(alert_id: str):
    data = request.get_json(silent=True) or {}
    updated = alert_store.update_alert_status(alert_id, "acknowledged", by=data.get("by", "analyst"))
    if not updated:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(asdict(updated))


@bp.route("/api/monitoring/alerts/<alert_id>/resolve", methods=["POST"])
@require_auth
def resolve_alert(alert_id: str):
    data = request.get_json(silent=True) or {}
    updated = alert_store.update_alert_status(
        alert_id, "resolved",
        by=data.get("by", "analyst"),
        notes=data.get("notes", ""),
    )
    if not updated:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(asdict(updated))


@bp.route("/api/monitoring/alerts/<alert_id>/dismiss", methods=["POST"])
@require_auth
def dismiss_alert(alert_id: str):
    data = request.get_json(silent=True) or {}
    updated = alert_store.update_alert_status(
        alert_id, "dismissed",
        by=data.get("by", "analyst"),
        notes=data.get("notes", "False positive"),
    )
    if not updated:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(asdict(updated))


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

@bp.route("/api/monitoring/watchlist/<entry_id>/snapshots", methods=["GET"])
@require_auth
def get_snapshots(entry_id: str):
    if not alert_store.get_entry(entry_id):
        return jsonify({"error": "Entry not found"}), 404
    snaps = alert_store.get_snapshots(entry_id, limit=20)
    return jsonify({"snapshots": [asdict(s) for s in snaps], "count": len(snaps)})


@bp.route("/api/monitoring/watchlist/<entry_id>/snapshots/latest", methods=["GET"])
@require_auth
def get_latest_snapshot(entry_id: str):
    snap = alert_store.get_latest_snapshot(entry_id)
    if not snap:
        return jsonify({"error": "No snapshots yet — trigger a check first"}), 404
    return jsonify(asdict(snap))


# ---------------------------------------------------------------------------
# Summary & reference
# ---------------------------------------------------------------------------

@bp.route("/api/monitoring/summary", methods=["GET"])
@require_auth
def get_summary():
    return jsonify({
        "store": alert_store.summary(),
        "scheduler": {
            "running": monitoring_scheduler.is_running(),
        },
        "reference": {
            "watchlist_types": WATCHLIST_TYPES,
            "alert_types": ALERT_TYPES,
            "check_intervals": CHECK_INTERVALS,
            "severities": SEVERITIES,
            "statuses": ALERT_STATUSES,
        },
    })

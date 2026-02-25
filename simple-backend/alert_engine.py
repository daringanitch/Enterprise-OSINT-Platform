#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Alert Engine — Watchlist and Real-Time Monitoring
===================================================

Provides the data model and persistence layer for continuous monitoring:

  WatchlistEntry   — what to monitor (domain, IP, keyword, registrant…)
  InfraSnapshot    — point-in-time record of DNS/cert/port state
  MonitorAlert     — generated when a change or match is detected

Alert types:
  new_dns_record       — A/MX/TXT/NS record added or changed
  dns_record_removed   — Record disappeared
  new_certificate      — New SSL cert issued (from crt.sh CT log)
  shodan_port_change   — New open port or service appeared/disappeared
  keyword_match        — A monitored keyword found in a paste/forum
  registrant_match     — New domain registered to a monitored email/name
  threat_actor_active  — Known IOC or infrastructure became active
  ip_reputation_change — AbuseIPDB/VT score crossed threshold

All data is persisted to alert_store.json in APP_DATA_DIR.
"""

import json
import logging
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations (as string literals for easy JSON round-trip)
# ---------------------------------------------------------------------------

WATCHLIST_TYPES = [
    "domain",           # Monitor a domain for DNS, certs, WHOIS changes
    "ip",               # Monitor an IP for port/service/reputation changes
    "email",            # Monitor an email for credential breaches, registrations
    "keyword",          # Monitor keyword across paste sites, dark web feeds
    "registrant",       # Alert on new domains registered to this org/email
    "certificate_subject",  # Alert on new certs for pattern (e.g., *.evil.com)
    "threat_actor",     # Alert on infrastructure linked to a known actor
    "cidr",             # Monitor an IP block
    "asn",              # Monitor an Autonomous System Number
]

ALERT_TYPES = [
    "new_dns_record",
    "dns_record_removed",
    "dns_record_changed",
    "new_certificate",
    "certificate_expired",
    "shodan_port_change",
    "shodan_new_service",
    "keyword_match",
    "registrant_match",
    "threat_actor_active",
    "ip_reputation_change",
    "whois_change",
    "new_subdomain",
    "domain_expiry_warning",
]

SEVERITIES = ["info", "low", "medium", "high", "critical"]

ALERT_STATUSES = ["new", "acknowledged", "in_progress", "resolved", "dismissed"]

CHECK_INTERVALS = [
    {"label": "Every hour",    "hours": 1},
    {"label": "Every 6 hours", "hours": 6},
    {"label": "Every 12 hours","hours": 12},
    {"label": "Daily",         "hours": 24},
    {"label": "Every 3 days",  "hours": 72},
    {"label": "Weekly",        "hours": 168},
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class WatchlistEntry:
    """Something to monitor continuously."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""                        # Human label (e.g. "Corp main domain")
    entry_type: str = "domain"            # See WATCHLIST_TYPES
    value: str = ""                       # The actual target (domain, IP, keyword…)
    enabled: bool = True
    check_interval_hours: int = 24        # How often to check
    last_checked_at: Optional[str] = None
    next_check_at: Optional[str] = None
    alert_on: List[str] = field(default_factory=list)  # subset of ALERT_TYPES
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by: str = "analyst"
    # Thresholds
    ip_reputation_threshold: int = 50     # AbuseIPDB score above which to alert
    alert_on_any_cert: bool = True        # Alert on every new cert issuance
    notify_email: Optional[str] = None    # Future: email/webhook notification
    # Statistics
    total_checks: int = 0
    total_alerts: int = 0
    last_alert_at: Optional[str] = None


@dataclass
class InfraSnapshot:
    """
    Point-in-time snapshot of a monitored asset's infrastructure state.
    Successive snapshots are diffed to generate alerts.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    watchlist_id: str = ""
    captured_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    # e.g. {"A": ["1.2.3.4"], "MX": ["mail.example.com"], "TXT": [...], "NS": [...]}
    certificates: List[Dict] = field(default_factory=list)
    # [{subject, issuer, not_before, not_after, serial, san_list}]
    open_ports: List[int] = field(default_factory=list)
    # From Shodan/free port scanner
    services: List[Dict] = field(default_factory=list)
    # [{port, protocol, service, banner}]
    whois_registrar: str = ""
    whois_registrant_email: str = ""
    whois_creation_date: str = ""
    whois_expiry_date: str = ""
    whois_name_servers: List[str] = field(default_factory=list)
    ip_abuse_score: Optional[int] = None
    vt_malicious_count: Optional[int] = None
    raw_data: Optional[Dict] = None      # Full raw response for debugging


@dataclass
class MonitorAlert:
    """
    An alert generated when a monitored asset changes or a keyword is matched.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    watchlist_id: str = ""
    watchlist_name: str = ""
    alert_type: str = ""                  # See ALERT_TYPES
    severity: str = "medium"             # info | low | medium | high | critical
    title: str = ""
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    # What changed (for diff-based alerts)
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    diff_summary: Optional[str] = None
    # Status tracking
    status: str = "new"                  # See ALERT_STATUSES
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[str] = None
    resolution_notes: str = ""
    # Timestamps
    triggered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    # Links
    snapshot_id: Optional[str] = None   # The snapshot that triggered this
    investigation_id: Optional[str] = None  # If escalated to investigation
    false_positive: bool = False


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------

def diff_snapshots(old: InfraSnapshot, new: InfraSnapshot) -> List[MonitorAlert]:
    """
    Compare two infrastructure snapshots and return a list of alerts
    for anything that changed.
    """
    alerts: List[MonitorAlert] = []
    wid = new.watchlist_id

    # ── DNS Records ────────────────────────────────────────────────────────
    for rtype in set(list(old.dns_records.keys()) + list(new.dns_records.keys())):
        old_set = set(old.dns_records.get(rtype, []))
        new_set = set(new.dns_records.get(rtype, []))
        added = new_set - old_set
        removed = old_set - new_set

        for val in added:
            alerts.append(MonitorAlert(
                watchlist_id=wid,
                alert_type="new_dns_record",
                severity="medium",
                title=f"New {rtype} record: {val}",
                description=f"A new {rtype} DNS record was added: {val}",
                new_value=val,
                diff_summary=f"+{rtype}: {val}",
                details={"record_type": rtype, "value": val},
            ))

        for val in removed:
            alerts.append(MonitorAlert(
                watchlist_id=wid,
                alert_type="dns_record_removed",
                severity="low",
                title=f"Removed {rtype} record: {val}",
                description=f"A {rtype} DNS record was removed: {val}",
                old_value=val,
                diff_summary=f"-{rtype}: {val}",
                details={"record_type": rtype, "value": val},
            ))

    # ── Certificates ───────────────────────────────────────────────────────
    old_serials = {c.get("serial", "") for c in old.certificates}
    for cert in new.certificates:
        serial = cert.get("serial", "")
        if serial and serial not in old_serials:
            san = ", ".join(cert.get("san_list", [])[:5])
            alerts.append(MonitorAlert(
                watchlist_id=wid,
                alert_type="new_certificate",
                severity="low",
                title=f"New SSL certificate issued",
                description=f"New cert for {cert.get('subject', 'unknown')} — SANs: {san or 'none'}",
                new_value=cert.get("subject", ""),
                details=cert,
                diff_summary=f"New cert: {cert.get('subject', '')} (serial {serial})",
            ))

    # ── Open ports ─────────────────────────────────────────────────────────
    old_ports = set(old.open_ports)
    new_ports = set(new.open_ports)
    for port in new_ports - old_ports:
        severity = "high" if port in (22, 23, 3389, 5900, 1433, 3306, 5432) else "medium"
        alerts.append(MonitorAlert(
            watchlist_id=wid,
            alert_type="shodan_port_change",
            severity=severity,
            title=f"New open port: {port}",
            description=f"Port {port} was detected as newly open.",
            new_value=str(port),
            diff_summary=f"+port {port}",
            details={"port": port},
        ))
    for port in old_ports - new_ports:
        alerts.append(MonitorAlert(
            watchlist_id=wid,
            alert_type="shodan_port_change",
            severity="info",
            title=f"Port closed: {port}",
            description=f"Port {port} is no longer detected as open.",
            old_value=str(port),
            diff_summary=f"-port {port}",
            details={"port": port},
        ))

    # ── WHOIS changes ──────────────────────────────────────────────────────
    whois_fields = [
        ("whois_registrar", "Registrar changed"),
        ("whois_registrant_email", "Registrant email changed"),
        ("whois_expiry_date", "Domain expiry date changed"),
    ]
    for attr, label in whois_fields:
        oval = getattr(old, attr, "")
        nval = getattr(new, attr, "")
        if oval and nval and oval != nval:
            alerts.append(MonitorAlert(
                watchlist_id=wid,
                alert_type="whois_change",
                severity="medium",
                title=label,
                description=f"{label}: '{oval}' → '{nval}'",
                old_value=oval,
                new_value=nval,
                diff_summary=f"{attr}: {oval} → {nval}",
            ))

    # ── IP reputation spike ────────────────────────────────────────────────
    if (old.ip_abuse_score is not None and new.ip_abuse_score is not None
            and new.ip_abuse_score > old.ip_abuse_score + 10):
        alerts.append(MonitorAlert(
            watchlist_id=wid,
            alert_type="ip_reputation_change",
            severity="high" if new.ip_abuse_score >= 75 else "medium",
            title=f"IP abuse score increased: {old.ip_abuse_score} → {new.ip_abuse_score}",
            description=f"AbuseIPDB confidence score jumped by {new.ip_abuse_score - old.ip_abuse_score} points.",
            old_value=str(old.ip_abuse_score),
            new_value=str(new.ip_abuse_score),
            diff_summary=f"AbuseScore: {old.ip_abuse_score} → {new.ip_abuse_score}",
        ))

    return alerts


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class AlertStore:
    """JSON-file-backed persistence for watchlists, snapshots, and alerts."""

    def __init__(self):
        data_dir = os.environ.get('APP_DATA_DIR', '/app/data')
        self.path = Path(data_dir) / 'alert_store.json'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data: Dict[str, Any] = self._load()

    def _load(self) -> Dict:
        if self.path.exists():
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"alert_store.json unreadable, resetting: {e}")
        return {"watchlist": {}, "snapshots": {}, "alerts": {}}

    def _save(self):
        try:
            with open(self.path, 'w') as f:
                json.dump(self._data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"alert_store save failed: {e}")

    # ── Watchlist ──────────────────────────────────────────────────────────

    def save_entry(self, entry: WatchlistEntry) -> WatchlistEntry:
        self._data["watchlist"][entry.id] = asdict(entry)
        self._save()
        return entry

    def get_entry(self, entry_id: str) -> Optional[WatchlistEntry]:
        d = self._data["watchlist"].get(entry_id)
        return WatchlistEntry(**d) if d else None

    def get_all_entries(self, enabled_only: bool = False) -> List[WatchlistEntry]:
        entries = [WatchlistEntry(**v) for v in self._data["watchlist"].values()]
        if enabled_only:
            entries = [e for e in entries if e.enabled]
        return sorted(entries, key=lambda e: e.created_at, reverse=True)

    def delete_entry(self, entry_id: str) -> bool:
        if entry_id in self._data["watchlist"]:
            del self._data["watchlist"][entry_id]
            self._save()
            return True
        return False

    # ── Snapshots ─────────────────────────────────────────────────────────

    def save_snapshot(self, snap: InfraSnapshot) -> InfraSnapshot:
        self._data["snapshots"][snap.id] = asdict(snap)
        self._save()
        return snap

    def get_latest_snapshot(self, watchlist_id: str) -> Optional[InfraSnapshot]:
        snaps = [
            InfraSnapshot(**v)
            for v in self._data["snapshots"].values()
            if v.get("watchlist_id") == watchlist_id
        ]
        if not snaps:
            return None
        return max(snaps, key=lambda s: s.captured_at)

    def get_snapshots(self, watchlist_id: str, limit: int = 20) -> List[InfraSnapshot]:
        snaps = [
            InfraSnapshot(**v)
            for v in self._data["snapshots"].values()
            if v.get("watchlist_id") == watchlist_id
        ]
        return sorted(snaps, key=lambda s: s.captured_at, reverse=True)[:limit]

    # ── Alerts ────────────────────────────────────────────────────────────

    def save_alert(self, alert: MonitorAlert) -> MonitorAlert:
        self._data["alerts"][alert.id] = asdict(alert)
        self._save()
        return alert

    def save_alerts(self, alerts: List[MonitorAlert]) -> List[MonitorAlert]:
        for a in alerts:
            self._data["alerts"][a.id] = asdict(a)
        if alerts:
            self._save()
        return alerts

    def get_alert(self, alert_id: str) -> Optional[MonitorAlert]:
        d = self._data["alerts"].get(alert_id)
        return MonitorAlert(**d) if d else None

    def get_alerts(
        self,
        watchlist_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 200,
    ) -> List[MonitorAlert]:
        alerts = [MonitorAlert(**v) for v in self._data["alerts"].values()]
        if watchlist_id:
            alerts = [a for a in alerts if a.watchlist_id == watchlist_id]
        if status:
            alerts = [a for a in alerts if a.status == status]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        alerts.sort(key=lambda a: a.triggered_at, reverse=True)
        return alerts[:limit]

    def update_alert_status(self, alert_id: str, status: str, by: str = "analyst", notes: str = "") -> Optional[MonitorAlert]:
        alert = self.get_alert(alert_id)
        if not alert:
            return None
        alert.status = status
        now = datetime.utcnow().isoformat()
        if status == "acknowledged":
            alert.acknowledged_by = by
            alert.acknowledged_at = now
        elif status in ("resolved", "dismissed"):
            alert.resolved_by = by
            alert.resolved_at = now
            if notes:
                alert.resolution_notes = notes
        self.save_alert(alert)
        return alert

    def summary(self) -> Dict:
        alerts = [MonitorAlert(**v) for v in self._data["alerts"].values()]
        new_alerts = [a for a in alerts if a.status == "new"]
        return {
            "watchlist_entries": len(self._data["watchlist"]),
            "enabled_entries": len([e for e in self._data["watchlist"].values() if e.get("enabled", True)]),
            "total_alerts": len(alerts),
            "new_alerts": len(new_alerts),
            "by_severity": {
                sev: len([a for a in new_alerts if a.severity == sev])
                for sev in SEVERITIES
            },
            "snapshots": len(self._data["snapshots"]),
        }


# Global singleton
alert_store = AlertStore()

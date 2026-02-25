#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Monitoring Scheduler
=====================

Background thread that periodically checks each enabled watchlist entry,
captures a new InfraSnapshot, diffs it against the previous one, and
generates MonitorAlerts for changes.

Uses only free/no-key services by default:
  - DNS:            Python dns.resolver (stdlib)
  - WHOIS:          python-whois library
  - Certificates:   crt.sh CT log API (free, no key)
  - Port scan:      skipped without Shodan key (not doing active scanning)
  - IP reputation:  AbuseIPDB (if key configured) or GreyNoise community

Start the scheduler by calling monitoring_scheduler.start() from app.py.
It runs in a daemon thread and stops when the process exits.
"""

import logging
import threading
import time
import json
import socket
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)

# Lazy imports — don't fail at startup if libraries are missing
def _try_import(module_name):
    try:
        return __import__(module_name)
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Data collectors (each returns a partial snapshot dict)
# ---------------------------------------------------------------------------

def _collect_dns(target: str) -> Dict[str, List[str]]:
    """Collect DNS records using dnspython or stdlib fallback."""
    records: Dict[str, List[str]] = {}
    dns_module = _try_import("dns.resolver")
    if not dns_module:
        # stdlib fallback: at least A records
        try:
            info = socket.getaddrinfo(target, None)
            records["A"] = list({r[4][0] for r in info if r[0].name == "AF_INET"})
        except Exception:
            pass
        return records

    resolver = dns_module.resolver
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = resolver.resolve(target, rtype, lifetime=10)
            if rtype == "MX":
                records[rtype] = [str(r.exchange).rstrip(".") for r in answers]
            elif rtype == "TXT":
                records[rtype] = [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
            elif rtype == "NS":
                records[rtype] = [str(r.target).rstrip(".") for r in answers]
            else:
                records[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    return records


def _collect_certificates(target: str) -> List[Dict]:
    """Query crt.sh for recent certificate issuances (free, no key)."""
    import urllib.request
    import urllib.error
    certs = []
    try:
        url = f"https://crt.sh/?q={target}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Platform-Monitor/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        seen_serials = set()
        for entry in data[:50]:  # Cap at 50 most recent
            serial = entry.get("serial_number", "")
            if serial in seen_serials:
                continue
            seen_serials.add(serial)
            san_raw = entry.get("name_value", "")
            sans = [s.strip() for s in san_raw.split("\n") if s.strip()] if san_raw else []
            certs.append({
                "serial": serial,
                "subject": entry.get("common_name", ""),
                "issuer": entry.get("issuer_ca_id", ""),
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
                "san_list": sans,
                "logged_at": entry.get("entry_timestamp", ""),
            })
    except Exception as e:
        logger.debug(f"crt.sh query failed for {target}: {e}")
    return certs


def _collect_whois(target: str) -> Dict[str, str]:
    """Collect WHOIS data using python-whois."""
    whois_module = _try_import("whois")
    if not whois_module:
        return {}
    try:
        w = whois_module.whois(target)
        def _first(val):
            if isinstance(val, list):
                return str(val[0]) if val else ""
            return str(val) if val else ""
        return {
            "registrar": _first(getattr(w, "registrar", "")),
            "registrant_email": _first(getattr(w, "emails", "")),
            "creation_date": _first(getattr(w, "creation_date", "")),
            "expiry_date": _first(getattr(w, "expiration_date", "")),
            "name_servers": [str(ns).lower() for ns in (getattr(w, "name_servers", None) or [])],
        }
    except Exception as e:
        logger.debug(f"WHOIS failed for {target}: {e}")
        return {}


def _collect_ip_reputation(ip: str) -> Optional[int]:
    """Query AbuseIPDB if key is configured, return confidence score 0-100."""
    import os, urllib.request, urllib.error
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return None
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return data.get("data", {}).get("abuseConfidenceScore")
    except Exception as e:
        logger.debug(f"AbuseIPDB failed for {ip}: {e}")
        return None


# ---------------------------------------------------------------------------
# Snapshot builder
# ---------------------------------------------------------------------------

def build_snapshot(entry) -> "InfraSnapshot":  # type: ignore
    """
    Collect current infrastructure state for a watchlist entry
    and return an InfraSnapshot.  Import here to avoid circular imports.
    """
    from alert_engine import InfraSnapshot

    snap = InfraSnapshot(watchlist_id=entry.id)

    target = entry.value.strip()
    etype = entry.entry_type

    if etype in ("domain",):
        snap.dns_records = _collect_dns(target)
        snap.certificates = _collect_certificates(target)
        whois_data = _collect_whois(target)
        snap.whois_registrar = whois_data.get("registrar", "")
        snap.whois_registrant_email = whois_data.get("registrant_email", "")
        snap.whois_creation_date = whois_data.get("creation_date", "")
        snap.whois_expiry_date = whois_data.get("expiry_date", "")
        snap.whois_name_servers = whois_data.get("name_servers", [])

    elif etype == "ip":
        snap.ip_abuse_score = _collect_ip_reputation(target)

    elif etype == "certificate_subject":
        snap.certificates = _collect_certificates(target)

    # Note: keyword / threat_actor / registrant monitoring would require
    # premium feeds (paste-site scrapers, dark-web monitors).
    # Those are stubbed here and will be skipped until the relevant
    # service integrations are enabled.

    return snap


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

class MonitoringScheduler:
    """
    Background thread that runs watchlist checks at configured intervals.

    Usage:
        scheduler = MonitoringScheduler()
        scheduler.start()          # call once at app startup
        scheduler.stop()           # call at shutdown (optional, daemon thread exits with process)
        scheduler.trigger(entry_id)  # force immediate re-check of one entry
    """

    TICK_INTERVAL = 60  # seconds between scheduler loop iterations

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        self._last_run_at: Dict[str, str] = {}  # entry_id → ISO timestamp
        self._lock = threading.Lock()

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop,
            name="monitoring-scheduler",
            daemon=True,
        )
        self._thread.start()
        logger.info("Monitoring scheduler started")

    def stop(self):
        self._stop_event.set()
        self._running = False
        logger.info("Monitoring scheduler stopping")

    def is_running(self) -> bool:
        return self._running and (self._thread is not None) and self._thread.is_alive()

    def trigger(self, entry_id: str) -> Optional[Dict]:
        """Force an immediate check for one watchlist entry. Returns alert count."""
        from alert_engine import alert_store
        entry = alert_store.get_entry(entry_id)
        if not entry or not entry.enabled:
            return None
        return self._check_entry(entry)

    # ── Internal loop ──────────────────────────────────────────────────────

    def _loop(self):
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as e:
                logger.exception(f"Monitoring scheduler tick error: {e}")
            # Sleep in 5-second chunks so we can stop cleanly
            for _ in range(self.TICK_INTERVAL // 5):
                if self._stop_event.is_set():
                    break
                time.sleep(5)

    def _tick(self):
        """Check all overdue watchlist entries."""
        from alert_engine import alert_store
        entries = alert_store.get_all_entries(enabled_only=True)
        now = datetime.utcnow()
        for entry in entries:
            if self._is_due(entry, now):
                try:
                    result = self._check_entry(entry)
                    logger.info(
                        f"Checked {entry.entry_type}:{entry.value} — "
                        f"{result.get('alerts_generated', 0)} new alerts"
                    )
                except Exception as e:
                    logger.warning(f"Check failed for {entry.id} ({entry.value}): {e}")

    def _is_due(self, entry, now: datetime) -> bool:
        """Return True if this entry's next check time has passed."""
        if not entry.last_checked_at:
            return True  # Never checked — run immediately
        try:
            last = datetime.fromisoformat(entry.last_checked_at.replace("Z", ""))
            interval = timedelta(hours=entry.check_interval_hours)
            return now >= last + interval
        except Exception:
            return True

    def _check_entry(self, entry) -> Dict:
        """Run one check cycle: collect → snapshot → diff → alert."""
        from alert_engine import alert_store, diff_snapshots

        # Collect current state
        try:
            new_snap = build_snapshot(entry)
            new_snap.watchlist_id = entry.id
        except Exception as e:
            logger.warning(f"Snapshot collection failed for {entry.value}: {e}")
            return {"ok": False, "error": str(e)}

        # Get previous snapshot for diffing
        old_snap = alert_store.get_latest_snapshot(entry.id)

        # Save new snapshot
        alert_store.save_snapshot(new_snap)

        # Generate alerts from diff
        alerts_generated = 0
        if old_snap:
            new_alerts = diff_snapshots(old_snap, new_snap)
            # Filter to types the user wants
            if entry.alert_on:
                new_alerts = [a for a in new_alerts if a.alert_type in entry.alert_on]
            for alert in new_alerts:
                alert.watchlist_name = entry.name or entry.value
                alert.snapshot_id = new_snap.id
            if new_alerts:
                alert_store.save_alerts(new_alerts)
                alerts_generated = len(new_alerts)

        # Update entry metadata
        now_str = datetime.utcnow().isoformat()
        entry.last_checked_at = now_str
        entry.total_checks += 1
        if alerts_generated:
            entry.total_alerts += alerts_generated
            entry.last_alert_at = now_str
        alert_store.save_entry(entry)

        return {
            "ok": True,
            "entry_id": entry.id,
            "snapshot_id": new_snap.id,
            "alerts_generated": alerts_generated,
            "checked_at": now_str,
        }


# Global singleton
monitoring_scheduler = MonitoringScheduler()

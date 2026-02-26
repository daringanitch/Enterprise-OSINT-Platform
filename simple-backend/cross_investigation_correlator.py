"""
Cross-Investigation Correlator
================================

Scans all completed investigations and flags shared indicators — the same
registrant email, certificate thumbprint, C2 IP, or domain appearing across
two or more separate investigations.

Connections that look unrelated at first glance may share infrastructure,
operators, or campaigns.  This module surfaces those links automatically.

Usage
-----
    from cross_investigation_correlator import correlator

    # Scan all investigations and return correlation report
    report = correlator.run(investigations)

    # Find everything linked to a specific investigation
    links = correlator.links_for(inv_id, investigations)
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SharedIndicator:
    """A single indicator (value + type) shared across investigations."""
    indicator_value: str        # e.g. "admin@mailfast.pro"
    indicator_type: str         # domain | ip | email | cert_thumbprint | asn | registrant
    investigation_ids: List[str] = field(default_factory=list)
    investigation_targets: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None   # ISO timestamp of earliest investigation
    significance: str = "medium"       # low | medium | high | critical
    significance_reason: str = ""
    link_type: str = ""                # shared_registrant | shared_ip | shared_cert | shared_asn | shared_domain

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_value": self.indicator_value,
            "indicator_type": self.indicator_type,
            "investigation_ids": self.investigation_ids,
            "investigation_targets": self.investigation_targets,
            "shared_count": len(self.investigation_ids),
            "first_seen": self.first_seen,
            "significance": self.significance,
            "significance_reason": self.significance_reason,
            "link_type": self.link_type,
        }


@dataclass
class InvestigationLink:
    """A direct link between exactly two investigations via a shared indicator."""
    investigation_a: str
    investigation_b: str
    target_a: str
    target_b: str
    shared_indicators: List[SharedIndicator] = field(default_factory=list)
    link_strength: float = 0.0     # 0-1 composite score
    link_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigation_a": self.investigation_a,
            "investigation_b": self.investigation_b,
            "target_a": self.target_a,
            "target_b": self.target_b,
            "shared_indicators": [i.to_dict() for i in self.shared_indicators],
            "shared_count": len(self.shared_indicators),
            "link_strength": round(self.link_strength, 3),
            "link_summary": self.link_summary,
        }


@dataclass
class CorrelationReport:
    """Full cross-investigation correlation result."""
    investigations_scanned: int = 0
    shared_indicators: List[SharedIndicator] = field(default_factory=list)
    investigation_links: List[InvestigationLink] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigations_scanned": self.investigations_scanned,
            "shared_indicator_count": len(self.shared_indicators),
            "investigation_link_count": len(self.investigation_links),
            "shared_indicators": [i.to_dict() for i in self.shared_indicators],
            "investigation_links": [l.to_dict() for l in self.investigation_links],
            "generated_at": self.generated_at,
        }


# ---------------------------------------------------------------------------
# Significance rules
# ---------------------------------------------------------------------------

def _significance(indicator_type: str, shared_count: int) -> tuple[str, str]:
    """Return (significance_level, reason) for an indicator."""
    if indicator_type == "email":
        if shared_count >= 3:
            return "critical", f"Registrant email shared across {shared_count} investigations — likely same operator"
        return "high", "Registrant email shared — strong operator-level link"
    if indicator_type == "cert_thumbprint":
        return "critical", "Identical certificate thumbprint — same infrastructure cluster"
    if indicator_type == "ip":
        if shared_count >= 3:
            return "critical", f"C2/hosting IP shared across {shared_count} investigations"
        return "high", "IP address shared — may indicate shared hosting or C2 infrastructure"
    if indicator_type == "asn":
        return "medium", "Same ASN — shared hosting provider (may be coincidental)"
    if indicator_type == "domain":
        return "high", "Domain shared directly across investigations"
    if indicator_type == "registrant":
        return "high", "Registrant name or organisation shared"
    return "medium", "Indicator shared across investigations"


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------

class CrossInvestigationCorrelator:
    """
    Stateless correlator.  Pass a list of investigation dicts
    (``OSINTInvestigation.to_dict()`` or equivalent) and receive a
    :class:`CorrelationReport`.
    """

    def run(self, investigations: List[Dict[str, Any]]) -> CorrelationReport:
        """
        Scan *investigations* for shared indicators and return a
        :class:`CorrelationReport`.
        """
        if len(investigations) < 2:
            return CorrelationReport(investigations_scanned=len(investigations))

        # Step 1: Extract indicator sets per investigation
        inv_indicators: Dict[str, Dict[str, Set[str]]] = {}
        for inv in investigations:
            inv_id = inv.get("id", "")
            if inv_id:
                inv_indicators[inv_id] = self._extract_indicators(inv)

        # Step 2: Build inverted index: indicator → {inv_id, ...}
        # key = (indicator_type, indicator_value_lower)
        inverted: Dict[tuple, Set[str]] = {}
        for inv_id, type_map in inv_indicators.items():
            for itype, values in type_map.items():
                for val in values:
                    key = (itype, val.lower())
                    inverted.setdefault(key, set()).add(inv_id)

        # Step 3: Keep only indicators shared by ≥2 investigations
        shared: List[SharedIndicator] = []
        for (itype, ival), inv_ids in inverted.items():
            if len(inv_ids) < 2:
                continue
            sig, reason = _significance(itype, len(inv_ids))
            targets = []
            first_seen = None
            for iid in inv_ids:
                inv = next((i for i in investigations if i.get("id") == iid), {})
                t = (inv.get("target_profile") or {}).get("primary_identifier", iid)
                targets.append(t)
                created = inv.get("created_at")
                if created and (first_seen is None or created < first_seen):
                    first_seen = created

            link_type = self._link_type(itype)
            shared.append(SharedIndicator(
                indicator_value=ival,
                indicator_type=itype,
                investigation_ids=sorted(inv_ids),
                investigation_targets=targets,
                first_seen=first_seen,
                significance=sig,
                significance_reason=reason,
                link_type=link_type,
            ))

        # Sort by significance then shared_count
        sig_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        shared.sort(key=lambda x: (sig_order.get(x.significance, 3), -len(x.investigation_ids)))

        # Step 4: Build pairwise investigation links
        pairs: Dict[tuple, List[SharedIndicator]] = {}
        for indicator in shared:
            ids = sorted(indicator.investigation_ids)
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    pair = (ids[i], ids[j])
                    pairs.setdefault(pair, []).append(indicator)

        links: List[InvestigationLink] = []
        for (id_a, id_b), indicators in pairs.items():
            inv_a = next((i for i in investigations if i.get("id") == id_a), {})
            inv_b = next((i for i in investigations if i.get("id") == id_b), {})
            ta = (inv_a.get("target_profile") or {}).get("primary_identifier", id_a)
            tb = (inv_b.get("target_profile") or {}).get("primary_identifier", id_b)

            strength = self._link_strength(indicators)
            summary = self._link_summary(ta, tb, indicators)

            links.append(InvestigationLink(
                investigation_a=id_a,
                investigation_b=id_b,
                target_a=ta,
                target_b=tb,
                shared_indicators=indicators,
                link_strength=strength,
                link_summary=summary,
            ))

        links.sort(key=lambda x: x.link_strength, reverse=True)

        logger.info(
            "Cross-investigation correlation: %d investigations, %d shared indicators, %d links",
            len(investigations), len(shared), len(links),
        )

        return CorrelationReport(
            investigations_scanned=len(investigations),
            shared_indicators=shared,
            investigation_links=links,
        )

    def links_for(self, inv_id: str, investigations: List[Dict[str, Any]]) -> List[InvestigationLink]:
        """Return only the links involving a specific investigation."""
        report = self.run(investigations)
        return [
            link for link in report.investigation_links
            if inv_id in (link.investigation_a, link.investigation_b)
        ]

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_indicators(self, investigation: Dict[str, Any]) -> Dict[str, Set[str]]:
        """Extract typed indicators from one investigation."""
        result: Dict[str, Set[str]] = {
            "domain": set(), "ip": set(), "email": set(),
            "cert_thumbprint": set(), "asn": set(), "registrant": set(),
        }

        infra = investigation.get("infrastructure_intelligence") or {}

        for d in infra.get("domains", []):
            v = (d.get("domain") or "").strip()
            if v:
                result["domain"].add(v.lower())
            email = (d.get("registrant_email") or "").strip()
            if email and "[.]" not in email:   # skip defanged addresses
                result["email"].add(email.lower())

        for ip in infra.get("ip_addresses", []):
            v = (ip.get("ip") or "").strip()
            if v:
                result["ip"].add(v)
            asn = (ip.get("asn") or "").strip()
            if asn:
                result["asn"].add(asn.upper())

        for cert in infra.get("certificates", []):
            thumb = (cert.get("thumbprint") or "").strip()
            if thumb:
                result["cert_thumbprint"].add(thumb.upper())
            for san in cert.get("san", []):
                if san:
                    result["domain"].add(san.lower())

        # Secondary identifiers
        tp = investigation.get("target_profile") or {}
        for sec in tp.get("secondary_identifiers", []):
            if not sec:
                continue
            if "." in sec and not sec.startswith("AS"):
                import re
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', sec):
                    result["ip"].add(sec)
                else:
                    result["domain"].add(sec.lower())

        # Threat intel IOCs
        threat = investigation.get("threat_intelligence") or {}
        for ind in threat.get("network_indicators", []):
            v = (ind.get("value") or ind.get("indicator") or "").strip()
            itype = ind.get("type", "domain")
            if v and itype in result:
                result[itype].add(v.lower() if itype != "ip" else v)

        return result

    @staticmethod
    def _link_type(indicator_type: str) -> str:
        return {
            "email":          "shared_registrant",
            "cert_thumbprint": "shared_cert",
            "ip":             "shared_ip",
            "asn":            "shared_asn",
            "domain":         "shared_domain",
            "registrant":     "shared_registrant",
        }.get(indicator_type, "shared_indicator")

    @staticmethod
    def _link_strength(indicators: List[SharedIndicator]) -> float:
        """Composite link strength 0-1 based on significance of shared indicators."""
        sig_weights = {"critical": 0.40, "high": 0.25, "medium": 0.10, "low": 0.05}
        score = sum(sig_weights.get(i.significance, 0.05) for i in indicators)
        return min(score, 1.0)

    @staticmethod
    def _link_summary(target_a: str, target_b: str, indicators: List[SharedIndicator]) -> str:
        if not indicators:
            return ""
        top = indicators[0]
        extra = len(indicators) - 1
        summary = (
            f"{target_a!r} and {target_b!r} share {top.indicator_type} "
            f"{top.indicator_value!r}"
        )
        if extra > 0:
            summary += f" and {extra} other indicator{'s' if extra > 1 else ''}"
        summary += f" — {top.significance_reason}"
        return summary


# Module-level singleton
correlator = CrossInvestigationCorrelator()

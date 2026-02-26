"""
Pivot Engine
============

Analyses a completed investigation's graph data and intelligence results
to recommend the next entities an analyst should investigate.

Pivot suggestions are ranked by a composite score that considers:
  - Entity centrality (high-degree nodes with unexplored neighbours)
  - Unresolved relationships (edges pointing to entities with no data)
  - Cross-source corroboration (entity appears in 2+ intelligence sources)
  - Threat-indicator status (entity flagged by at least one threat feed)
  - Temporal recency (recently-observed entities rank higher)

Each suggestion carries an explanation suitable for display in the UI.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PivotSuggestion:
    """A single recommended pivot with score and explanation."""
    entity_value: str          # e.g. "185.220.101.47" or "admin@example.com"
    entity_type: str           # domain | ip | email | hash | certificate | registrant
    pivot_type: str            # expand_infrastructure | check_reputation | check_credentials
                               # | lookup_registration | enumerate_subdomains | cert_transparency
    score: float               # 0.0 – 1.0 composite priority score
    reason: str                # One-sentence human-readable explanation
    source_entities: List[str] = field(default_factory=list)  # what led here
    already_investigated: bool = False
    suggested_tools: List[str] = field(default_factory=list)  # e.g. ["whois", "shodan"]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_value": self.entity_value,
            "entity_type": self.entity_type,
            "pivot_type": self.pivot_type,
            "score": round(self.score, 3),
            "reason": self.reason,
            "source_entities": self.source_entities,
            "already_investigated": self.already_investigated,
            "suggested_tools": self.suggested_tools,
            "created_at": self.created_at,
        }


@dataclass
class PivotReport:
    """Full pivot analysis result for an investigation."""
    investigation_id: str
    target: str
    suggestions: List[PivotSuggestion] = field(default_factory=list)
    total_entities_analysed: int = 0
    coverage_score: float = 0.0   # 0-1: how much of the graph has been explored
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "target": self.target,
            "suggestions": [s.to_dict() for s in self.suggestions],
            "total_entities_analysed": self.total_entities_analysed,
            "coverage_score": round(self.coverage_score, 3),
            "generated_at": self.generated_at,
            "top_suggestion": self.suggestions[0].to_dict() if self.suggestions else None,
        }


# ---------------------------------------------------------------------------
# Pivot type → tool mapping
# ---------------------------------------------------------------------------

PIVOT_TOOLS: Dict[str, List[str]] = {
    "expand_infrastructure":  ["dns_records", "passive_dns", "shodan"],
    "check_reputation":       ["virustotal", "abuseipdb", "otx"],
    "check_credentials":      ["hibp", "dehashed", "hudson_rock"],
    "lookup_registration":    ["whois", "domaintools"],
    "enumerate_subdomains":   ["dns_brute", "crt_sh", "subfinder"],
    "cert_transparency":      ["crt_sh", "censys"],
    "social_footprint":       ["linkedin", "twitter", "github"],
}

# Heuristic weights
W_THREAT_FLAG      = 0.35
W_CORROBORATION    = 0.25
W_CENTRALITY       = 0.20
W_RECENCY          = 0.10
W_UNRESOLVED       = 0.10


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class PivotEngine:
    """
    Stateless pivot recommendation engine.

    Call :meth:`analyse` with a serialised investigation dict (as returned by
    ``OSINTInvestigation.to_dict()``) and receive a ranked
    :class:`PivotReport`.
    """

    # Entity types we know how to pivot from
    _PIVOTABLE_TYPES = {"domain", "ip", "email", "hash", "certificate", "registrant", "url"}

    def analyse(self, investigation: Dict[str, Any], max_suggestions: int = 10) -> PivotReport:
        """
        Analyse *investigation* and return up to *max_suggestions* ranked pivots.

        Parameters
        ----------
        investigation:
            Serialised investigation dict (``OSINTInvestigation.to_dict()``).
        max_suggestions:
            Maximum number of suggestions to return (default 10).
        """
        inv_id = investigation.get("id", "unknown")
        target = (investigation.get("target_profile") or {}).get("primary_identifier", "")

        # 1. Extract all known entities from the investigation
        known_entities = self._extract_known_entities(investigation)

        # 2. Extract candidate pivot targets not yet fully investigated
        candidates = self._extract_candidates(investigation, known_entities)

        # 3. Score each candidate
        scored: List[PivotSuggestion] = []
        for candidate in candidates:
            suggestion = self._score_candidate(candidate, investigation, known_entities)
            if suggestion is not None:
                scored.append(suggestion)

        # 4. Sort by score desc, deduplicate by entity_value
        seen: set = set()
        deduped: List[PivotSuggestion] = []
        for s in sorted(scored, key=lambda x: x.score, reverse=True):
            key = (s.entity_value.lower(), s.pivot_type)
            if key not in seen:
                seen.add(key)
                deduped.append(s)

        suggestions = deduped[:max_suggestions]

        # 5. Coverage score: ratio of known entities that have been resolved
        total = len(known_entities)
        resolved = sum(1 for e in known_entities.values() if e.get("resolved", False))
        coverage = (resolved / total) if total > 0 else 0.0

        logger.info(
            "Pivot analysis complete: inv=%s entities=%d candidates=%d suggestions=%d",
            inv_id, total, len(candidates), len(suggestions),
        )

        return PivotReport(
            investigation_id=inv_id,
            target=target,
            suggestions=suggestions,
            total_entities_analysed=total,
            coverage_score=coverage,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_known_entities(self, investigation: Dict[str, Any]) -> Dict[str, Dict]:
        """
        Walk the investigation dict and collect every entity we already have
        data for, keyed by lower-cased value.
        """
        entities: Dict[str, Dict] = {}

        def _add(value: str, etype: str, sources: List[str], resolved: bool = True,
                 threat_flagged: bool = False, recency_days: Optional[float] = None) -> None:
            if not value:
                return
            key = value.lower()
            if key not in entities:
                entities[key] = {
                    "value": value,
                    "type": etype,
                    "sources": set(sources),
                    "resolved": resolved,
                    "threat_flagged": threat_flagged,
                    "recency_days": recency_days,
                    "corroboration_count": len(sources),
                }
            else:
                entities[key]["sources"].update(sources)
                entities[key]["corroboration_count"] = len(entities[key]["sources"])
                if threat_flagged:
                    entities[key]["threat_flagged"] = True

        infra = investigation.get("infrastructure_intelligence") or {}

        # Domains
        for d in infra.get("domains", []):
            v = d.get("domain", "")
            _add(v, "domain", ["whois", "dns"], resolved=True,
                 threat_flagged=bool(d.get("risk_indicators")))

        # IPs
        for ip in infra.get("ip_addresses", []):
            v = ip.get("ip", "")
            _add(v, "ip", ["shodan", "abuseipdb"], resolved=True,
                 threat_flagged=ip.get("abuse_score", 0) > 30)

        # Certificates
        for cert in infra.get("certificates", []):
            thumb = cert.get("thumbprint", "")
            _add(thumb, "certificate", ["crt_sh"], resolved=True)
            for san in cert.get("san", []):
                _add(san, "domain", ["crt_sh"], resolved=False)

        # Threat intel entities
        threat = investigation.get("threat_intelligence") or {}
        for ind in threat.get("network_indicators", []):
            v = ind.get("value", "") or ind.get("indicator", "")
            _add(v, ind.get("type", "domain"), ["threat_intel"],
                 resolved=False, threat_flagged=True)

        for mal in threat.get("malware_indicators", []):
            v = mal.get("indicator", "")
            _add(v, mal.get("type", "domain"), ["virustotal"],
                 resolved=False, threat_flagged=True)

        # Social / paste intel
        social = investigation.get("social_intelligence") or {}
        for platform_data in (social.get("platforms") or {}).values():
            for result in (platform_data.get("results") or []):
                for field_name in ("email", "url", "domain"):
                    v = result.get(field_name, "")
                    if v:
                        _add(v, field_name, ["paste_sites"], resolved=False)

        # Secondary identifiers
        tp = investigation.get("target_profile") or {}
        for sec in tp.get("secondary_identifiers", []):
            # Guess type
            etype = "ip" if self._looks_like_ip(sec) else "domain"
            _add(sec, etype, ["target_profile"], resolved=False)

        return entities

    def _extract_candidates(
        self,
        investigation: Dict[str, Any],
        known_entities: Dict[str, Dict],
    ) -> List[Dict[str, Any]]:
        """
        Return a list of entity dicts that are known but not yet fully
        resolved — these are the pivot candidates.
        """
        candidates = []

        for key, entity in known_entities.items():
            if not entity.get("resolved", False):
                candidates.append(entity)
            elif entity.get("threat_flagged") and entity["corroboration_count"] < 3:
                # Threat-flagged but only seen in one source — worth expanding
                candidates.append({**entity, "resolved": False})

        # Also add registrant emails extracted from WHOIS / DNS TXT
        infra = investigation.get("infrastructure_intelligence") or {}
        for domain in infra.get("domains", []):
            email = domain.get("registrant_email", "")
            if email and email.lower() not in known_entities:
                candidates.append({
                    "value": email, "type": "email",
                    "sources": {"whois"}, "resolved": False,
                    "threat_flagged": False,
                    "corroboration_count": 1,
                    "recency_days": None,
                })

        # Extract ASNs from IPs
        for ip_entry in infra.get("ip_addresses", []):
            asn = ip_entry.get("asn", "")
            if asn and asn.lower() not in known_entities:
                candidates.append({
                    "value": asn, "type": "asn",
                    "sources": {"shodan"}, "resolved": False,
                    "threat_flagged": ip_entry.get("abuse_score", 0) > 30,
                    "corroboration_count": 1,
                    "recency_days": None,
                })

        return candidates

    def _score_candidate(
        self,
        candidate: Dict[str, Any],
        investigation: Dict[str, Any],
        known_entities: Dict[str, Dict],
    ) -> Optional[PivotSuggestion]:
        """Score a single candidate and build a PivotSuggestion."""
        value = candidate.get("value", "")
        etype = candidate.get("type", "domain")
        sources = list(candidate.get("sources", []))
        corroboration = candidate.get("corroboration_count", 1)
        threat_flagged = candidate.get("threat_flagged", False)
        recency_days = candidate.get("recency_days")

        if not value or etype not in self._PIVOTABLE_TYPES and etype not in ("asn",):
            return None

        # --- Compute score components ---
        threat_score = W_THREAT_FLAG if threat_flagged else 0.0
        corr_score   = W_CORROBORATION * min(corroboration / 3.0, 1.0)
        # Centrality proxy: number of resolved neighbours referencing this entity
        neighbours = sum(
            1 for e in known_entities.values()
            if value.lower() in str(e.get("sources", ""))
        )
        centrality_score = W_CENTRALITY * min(neighbours / 5.0, 1.0)
        recency_score = 0.0
        if recency_days is not None:
            recency_score = W_RECENCY * max(0.0, 1.0 - recency_days / 30.0)
        unresolved_score = W_UNRESOLVED  # flat bonus for being unresolved

        composite = threat_score + corr_score + centrality_score + recency_score + unresolved_score
        composite = min(composite, 1.0)

        # --- Determine pivot type and reason ---
        pivot_type, reason = self._classify_pivot(etype, value, threat_flagged, corroboration, sources)

        return PivotSuggestion(
            entity_value=value,
            entity_type=etype,
            pivot_type=pivot_type,
            score=composite,
            reason=reason,
            source_entities=sources,
            already_investigated=False,
            suggested_tools=PIVOT_TOOLS.get(pivot_type, []),
        )

    def _classify_pivot(
        self,
        etype: str,
        value: str,
        threat_flagged: bool,
        corroboration: int,
        sources: List[str],
    ) -> tuple[str, str]:
        """Return (pivot_type, reason) for a candidate."""
        if etype == "email":
            return (
                "check_credentials",
                f"Registrant email {value!r} should be checked against breach databases "
                f"— operator OPSEC failures are a common attribution anchor.",
            )
        if etype == "certificate":
            return (
                "cert_transparency",
                f"Certificate {value[:16]}… may have Subject Alternative Names linking "
                f"to additional infrastructure not yet mapped.",
            )
        if etype == "ip":
            if threat_flagged:
                return (
                    "check_reputation",
                    f"IP {value} is threat-flagged but reputation data is incomplete — "
                    f"AbuseIPDB, VirusTotal, and Shodan lookups are recommended.",
                )
            return (
                "expand_infrastructure",
                f"IP {value} appears in intelligence data but has not been fully "
                f"enumerated — reverse DNS, ASN context, and port scan recommended.",
            )
        if etype == "domain":
            if corroboration >= 2:
                return (
                    "enumerate_subdomains",
                    f"Domain {value!r} is corroborated by {corroboration} sources but "
                    f"subdomain enumeration has not been performed.",
                )
            return (
                "lookup_registration",
                f"Domain {value!r} linked from existing infrastructure but WHOIS and "
                f"registration history have not been retrieved.",
            )
        if etype == "asn":
            return (
                "expand_infrastructure",
                f"ASN {value} hosts the C2 IP — enumerating other hosts in this ASN may "
                f"reveal additional campaign infrastructure.",
            )
        if etype == "hash":
            return (
                "check_reputation",
                f"File hash {value[:12]}… should be submitted to VirusTotal and MalwareBazaar "
                f"for malware family identification.",
            )
        return (
            "check_reputation",
            f"Entity {value!r} ({etype}) appeared in intelligence data and warrants "
            f"further investigation.",
        )

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        import re
        return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value))


# Module-level singleton
pivot_engine = PivotEngine()

"""
STIX 2.1 Export + MISP Integration
====================================

Converts OSINT investigations and correlation results to standards-compliant
STIX 2.1 bundles and optionally pushes/pulls them from a MISP instance.

Classes
-------
STIXExporter
    Converts :class:`~models.OSINTInvestigation` and
    :class:`~intelligence_correlation.CorrelationResult` objects to
    ``stix2.Bundle`` objects.

MISPClient
    Async aiohttp client for the MISP REST API.  Graceful degradation
    when MISP is not configured.

Example::

    exporter = STIXExporter()
    bundle = exporter.export_investigation(investigation, correlation)
    print(exporter.to_json(bundle))
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency: stix2
# ---------------------------------------------------------------------------

try:
    import stix2  # type: ignore

    _STIX2_AVAILABLE = True
except ImportError:
    stix2 = None  # type: ignore
    _STIX2_AVAILABLE = False
    logger.warning(
        "stix_export: 'stix2' package not installed — STIX export disabled. "
        "Install with: pip install stix2"
    )

# ---------------------------------------------------------------------------
# Optional dependency: aiohttp (already in requirements.txt)
# ---------------------------------------------------------------------------

try:
    import aiohttp  # type: ignore

    _AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None  # type: ignore
    _AIOHTTP_AVAILABLE = False


# ---------------------------------------------------------------------------
# STIXExporter
# ---------------------------------------------------------------------------

class STIXExporter:
    """
    Convert OSINT investigations to STIX 2.1 bundles.

    Produces:

    * An ``identity`` SDO representing the platform
    * A ``report`` SDO summarising the investigation
    * Domain-specific SCOs and SDOs for each entity in the correlation
    * ``relationship`` SDOs linking entities together
    * ``attack-pattern`` SDOs for MITRE technique IDs found in findings
    """

    # Maps EntityType string values → STIX object types
    ENTITY_TO_STIX_TYPE: Dict[str, str] = {
        "domain":         "domain-name",
        "ip_address":     "ipv4-addr",
        "url":            "url",
        "email":          "email-addr",
        "hash":           "file",
        "threat_actor":   "threat-actor",
        "malware_family": "malware",
        "vulnerability":  "vulnerability",
        "cve":            "vulnerability",
        "attack_pattern": "attack-pattern",
        "campaign":       "campaign",
        "tool":           "tool",
        "certificate":    "x509-certificate",
        "cryptocurrency": "url",          # No native STIX type; use custom url with note
        "organization":   "identity",
        "person":         "identity",
        "social_account": "user-account",
    }

    # Maps RelationshipType string values → STIX relationship-type strings
    RELATIONSHIP_TYPE_MAP: Dict[str, str] = {
        "resolves_to":       "resolves-to",
        "attributed_to":     "attributed-to",
        "targets":           "targets",
        "uses_technique":    "uses",
        "delivers":          "delivers",
        "drops":             "drops",
        "exploits":          "exploits",
        "communicates_with": "communicates-with",
        "variant_of":        "variant-of",
        "part_of":           "part-of",
        "hosts":             "hosts",
        "owned_by":          "owned-by",
        "owns":              "owns",
        "associated_with":   "related-to",
        "subdomain_of":      "related-to",
        "uses_technology":   "uses",
        "member_of":         "member-of",
    }

    def __init__(self, org_name: str = "Enterprise OSINT Platform"):
        if not _STIX2_AVAILABLE:
            logger.warning("STIXExporter: stix2 library unavailable.")
            self._identity = None
            return

        self._identity = stix2.Identity(
            name=org_name,
            identity_class="system",
            description="Automated threat intelligence platform",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_investigation(
        self,
        investigation: Any,
        correlation: Any = None,
    ) -> Any:
        """
        Build a complete STIX 2.1 bundle for the investigation.

        Parameters
        ----------
        investigation:
            An :class:`~models.OSINTInvestigation` instance (or dict).
        correlation:
            Optional :class:`~intelligence_correlation.CorrelationResult`
            (or dict) to include entities and relationships.

        Returns a ``stix2.Bundle`` or a plain dict with an ``error`` key
        when the stix2 library is unavailable.
        """
        if not _STIX2_AVAILABLE:
            return {"error": "stix2 package not installed", "type": "bundle"}

        objects: List[Any] = [self._identity]

        # --- Entity objects ---
        id_map: Dict[str, str] = {}  # entity id → STIX object id
        if correlation is not None:
            entities_dict = (
                correlation.get("entities", {})
                if isinstance(correlation, dict)
                else getattr(correlation, "entities", {})
            )
            for entity_id, entity in (entities_dict.items() if isinstance(entities_dict, dict) else []):
                stix_obj = self._entity_to_stix(entity)
                if stix_obj is not None:
                    objects.append(stix_obj)
                    id_map[entity_id] = stix_obj.id

            # --- Relationship objects ---
            relationships_list = (
                correlation.get("relationships", [])
                if isinstance(correlation, dict)
                else getattr(correlation, "relationships", [])
            )
            for rel in relationships_list:
                rel_obj = self._relationship_to_stix(rel, id_map)
                if rel_obj is not None:
                    objects.append(rel_obj)

            # --- MITRE ATT&CK techniques ---
            mitre_ids: List[str] = (
                correlation.get("mitre_techniques", [])
                if isinstance(correlation, dict)
                else getattr(correlation, "mitre_techniques", [])
            ) or []
            objects.extend(self._mitre_techniques_to_stix(mitre_ids))

        # --- Report SDO ---
        report = self._make_report(investigation, objects)
        objects.append(report)

        return stix2.Bundle(objects=objects, allow_custom=True)

    def export_iocs(self, correlation: Any) -> Any:
        """
        Build an IOC-only bundle: domains, IPs, URLs, hashes, CVEs as STIX
        ``Indicator`` SDOs with appropriate patterns.

        Returns a ``stix2.Bundle`` or error dict.
        """
        if not _STIX2_AVAILABLE:
            return {"error": "stix2 package not installed", "type": "bundle"}

        objects: List[Any] = [self._identity]

        entities_dict = (
            correlation.get("entities", {})
            if isinstance(correlation, dict)
            else getattr(correlation, "entities", {})
        ) or {}

        ioc_types = {"domain", "ip_address", "url", "hash", "cve", "email"}

        for entity_id, entity in (entities_dict.items() if isinstance(entities_dict, dict) else []):
            entity_type = (
                entity.get("type") if isinstance(entity, dict)
                else getattr(getattr(entity, "entity_type", None), "value", None)
            )
            value = (
                entity.get("value") if isinstance(entity, dict)
                else getattr(entity, "value", None)
            )
            if entity_type not in ioc_types or not value:
                continue

            pattern = self._build_indicator_pattern(entity_type, value)
            if pattern is None:
                continue

            try:
                indicator = stix2.Indicator(
                    name=f"{entity_type}: {value}",
                    indicator_types=["malicious-activity"],
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=datetime.now(tz=timezone.utc),
                    created_by_ref=self._identity.id,
                )
                objects.append(indicator)
            except Exception as exc:
                logger.debug("stix_export: skipping indicator for %s: %s", value, exc)

        return stix2.Bundle(objects=objects, allow_custom=True)

    def to_json(self, bundle: Any) -> str:
        """Serialise a ``stix2.Bundle`` to a pretty-printed JSON string."""
        if not _STIX2_AVAILABLE:
            import json
            return json.dumps(bundle, indent=2)
        return bundle.serialize(pretty=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_report(self, investigation: Any, objects: List[Any]) -> Any:
        """Build a STIX Report SDO summarising the investigation."""
        inv_dict = (
            investigation if isinstance(investigation, dict)
            else getattr(investigation, "__dict__", {})
        )

        # Collect all object IDs for the report's object_refs
        object_refs = [o.id for o in objects if hasattr(o, "id")]
        if not object_refs:
            object_refs = [self._identity.id]

        name = (
            inv_dict.get("name")
            or inv_dict.get("id", "OSINT Investigation")
        )
        description = inv_dict.get("summary") or inv_dict.get("notes") or ""

        return stix2.Report(
            name=str(name),
            description=str(description)[:4096],
            report_types=["threat-report"],
            published=datetime.now(tz=timezone.utc),
            object_refs=object_refs,
            created_by_ref=self._identity.id,
        )

    def _entity_to_stix(self, entity: Any) -> Optional[Any]:
        """Convert a single entity to a STIX object. Returns None on failure."""
        if not _STIX2_AVAILABLE:
            return None

        entity_type = (
            entity.get("type") if isinstance(entity, dict)
            else getattr(getattr(entity, "entity_type", None), "value", None)
        )
        value = (
            entity.get("value") if isinstance(entity, dict)
            else getattr(entity, "value", None)
        )

        if not entity_type or not value:
            return None

        try:
            if entity_type == "domain":
                return stix2.DomainName(value=value)
            elif entity_type == "ip_address":
                return stix2.IPv4Address(value=value)
            elif entity_type == "url":
                return stix2.URL(value=value)
            elif entity_type == "email":
                return stix2.EmailAddress(value=value)
            elif entity_type in ("hash",):
                return stix2.File(
                    hashes={"SHA-256": value} if len(value) == 64 else {"MD5": value}
                )
            elif entity_type in ("threat_actor",):
                return stix2.ThreatActor(
                    name=value,
                    threat_actor_types=["unknown"],
                )
            elif entity_type in ("vulnerability", "cve"):
                return stix2.Vulnerability(
                    name=value,
                    external_references=[
                        stix2.ExternalReference(
                            source_name="cve",
                            external_id=value,
                        )
                    ] if value.upper().startswith("CVE-") else [],
                )
            elif entity_type == "attack_pattern":
                return stix2.AttackPattern(
                    name=value,
                    external_references=[
                        stix2.ExternalReference(
                            source_name="mitre-attack",
                            external_id=value,
                        )
                    ],
                )
            elif entity_type in ("organization", "person"):
                identity_class = "organization" if entity_type == "organization" else "individual"
                return stix2.Identity(
                    name=value,
                    identity_class=identity_class,
                )
            elif entity_type == "certificate":
                return stix2.X509Certificate(
                    subject=value,
                )
            # Unsupported type — skip silently
            return None
        except Exception as exc:
            logger.debug("stix_export: _entity_to_stix failed for %s/%s: %s", entity_type, value, exc)
            return None

    def _relationship_to_stix(
        self,
        rel: Any,
        id_map: Dict[str, str],
    ) -> Optional[Any]:
        """Convert a :class:`~intelligence_correlation.Relationship` to a STIX Relationship."""
        if not _STIX2_AVAILABLE:
            return None

        rel_dict = rel if isinstance(rel, dict) else getattr(rel, "__dict__", {})

        source_id = rel_dict.get("source_id") or getattr(rel, "source_id", None)
        target_id = rel_dict.get("target_id") or getattr(rel, "target_id", None)
        rel_type_raw = (
            rel_dict.get("relationship_type")
            or getattr(getattr(rel, "relationship_type", None), "value", None)
            or ""
        )

        stix_rel_type = self.RELATIONSHIP_TYPE_MAP.get(
            str(rel_type_raw).lower(), "related-to"
        )

        stix_source = id_map.get(source_id)
        stix_target = id_map.get(target_id)

        if not stix_source or not stix_target:
            return None

        try:
            return stix2.Relationship(
                relationship_type=stix_rel_type,
                source_ref=stix_source,
                target_ref=stix_target,
                created_by_ref=self._identity.id,
            )
        except Exception as exc:
            logger.debug("stix_export: _relationship_to_stix failed: %s", exc)
            return None

    def _mitre_techniques_to_stix(self, technique_ids: List[str]) -> List[Any]:
        """Convert a list of MITRE technique IDs to STIX AttackPattern SDOs."""
        if not _STIX2_AVAILABLE:
            return []

        result = []
        for tid in technique_ids:
            try:
                ap = stix2.AttackPattern(
                    name=f"MITRE ATT&CK {tid}",
                    external_references=[
                        stix2.ExternalReference(
                            source_name="mitre-attack",
                            external_id=tid,
                            url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                        )
                    ],
                    created_by_ref=self._identity.id,
                )
                result.append(ap)
            except Exception as exc:
                logger.debug("stix_export: skipping technique %s: %s", tid, exc)
        return result

    @staticmethod
    def _build_indicator_pattern(entity_type: str, value: str) -> Optional[str]:
        """Build a STIX pattern string for an entity value."""
        if entity_type == "domain":
            return f"[domain-name:value = '{value}']"
        elif entity_type == "ip_address":
            return f"[ipv4-addr:value = '{value}']"
        elif entity_type == "url":
            return f"[url:value = '{value}']"
        elif entity_type == "email":
            return f"[email-addr:value = '{value}']"
        elif entity_type == "hash":
            if len(value) == 64:
                return f"[file:hashes.'SHA-256' = '{value}']"
            elif len(value) == 32:
                return f"[file:hashes.MD5 = '{value}']"
            else:
                return f"[file:hashes.SHA-1 = '{value}']"
        elif entity_type == "cve":
            return f"[vulnerability:name = '{value}']"
        return None


# ---------------------------------------------------------------------------
# MISPClient
# ---------------------------------------------------------------------------


class MISPClient:
    """
    Async MISP REST API client.

    Gracefully handles missing configuration: if *url* or *api_key* are
    empty the client silently returns error dicts rather than raising.

    Usage::

        async with MISPClient(url, api_key) as client:
            status = await client.health_check()
            if status.get("healthy"):
                await client.push_stix_bundle(bundle_json)
    """

    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        self.base = (url or "").rstrip("/")
        self.api_key = api_key or ""
        self.verify_ssl = verify_ssl
        self._session: Optional[Any] = None
        self._configured = bool(self.base and self.api_key)

    @property
    def configured(self) -> bool:
        return self._configured

    async def __aenter__(self) -> "MISPClient":
        if _AIOHTTP_AVAILABLE and self._configured:
            self._session = aiohttp.ClientSession(
                headers={
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }
            )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    async def health_check(self) -> Dict[str, Any]:
        """
        Check MISP server connectivity and return version info.

        Returns::

            {"healthy": bool, "version": str | None, "error": str | None}
        """
        if not self._configured:
            return {"healthy": False, "version": None, "error": "MISP not configured"}
        if not _AIOHTTP_AVAILABLE:
            return {"healthy": False, "version": None, "error": "aiohttp not installed"}

        try:
            async with self._session.get(
                f"{self.base}/servers/getVersion.json",
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "healthy": True,
                        "version": data.get("version"),
                        "error": None,
                    }
                return {
                    "healthy": False,
                    "version": None,
                    "error": f"HTTP {resp.status}",
                }
        except Exception as exc:
            logger.warning("MISPClient.health_check failed: %s", exc)
            return {"healthy": False, "version": None, "error": str(exc)}

    async def push_stix_bundle(self, bundle_json: str) -> Dict[str, Any]:
        """
        Push a STIX 2.1 bundle JSON string to MISP via the STIX 2 import API.

        Returns::

            {"success": bool, "misp_event_id": str | None, "error": str | None}
        """
        if not self._configured:
            return {"success": False, "misp_event_id": None, "error": "MISP not configured"}
        if not _AIOHTTP_AVAILABLE:
            return {"success": False, "misp_event_id": None, "error": "aiohttp not installed"}

        try:
            async with self._session.post(
                f"{self.base}/events/importFromJson",
                data=bundle_json,
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status in (200, 201):
                    data = await resp.json()
                    event_id = data.get("Event", {}).get("id") or data.get("id")
                    return {"success": True, "misp_event_id": event_id, "error": None}
                body = await resp.text()
                return {
                    "success": False,
                    "misp_event_id": None,
                    "error": f"HTTP {resp.status}: {body[:200]}",
                }
        except Exception as exc:
            logger.warning("MISPClient.push_stix_bundle failed: %s", exc)
            return {"success": False, "misp_event_id": None, "error": str(exc)}

    async def pull_events(
        self,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Pull MISP events (optionally filtered by date).

        Returns a list of raw MISP event dicts.
        """
        if not self._configured:
            return []
        if not _AIOHTTP_AVAILABLE:
            return []

        params: Dict[str, Any] = {"limit": limit, "page": 1}
        if since is not None:
            params["from"] = since.strftime("%Y-%m-%d")

        try:
            async with self._session.post(
                f"{self.base}/events/restSearch",
                json={"returnFormat": "json", **params},
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("response", [])
                logger.warning(
                    "MISPClient.pull_events: HTTP %s", resp.status
                )
                return []
        except Exception as exc:
            logger.warning("MISPClient.pull_events failed: %s", exc)
            return []

    async def search(
        self,
        value: str,
        type_: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search MISP for a specific attribute value.

        Parameters
        ----------
        value:
            The attribute value to search (e.g. an IP, domain, hash).
        type_:
            Optional MISP attribute type filter (e.g. ``"ip-dst"``, ``"domain"``).

        Returns a list of matching MISP attribute dicts.
        """
        if not self._configured:
            return []
        if not _AIOHTTP_AVAILABLE:
            return []

        payload: Dict[str, Any] = {
            "returnFormat": "json",
            "value": value,
            "limit": 50,
        }
        if type_:
            payload["type"] = type_

        try:
            async with self._session.post(
                f"{self.base}/attributes/restSearch",
                json=payload,
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("response", {}).get("Attribute", [])
                return []
        except Exception as exc:
            logger.warning("MISPClient.search failed: %s", exc)
            return []

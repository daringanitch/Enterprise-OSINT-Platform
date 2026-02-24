"""
NLP Intelligence Pipeline
=========================

Extracts structured threat intelligence from unstructured text using:
  * Regex patterns (always available) — CVEs, MITRE techniques, crypto wallet
    addresses, onion domains, known threat-actor names, temporal expressions.
  * langdetect (required, lightweight) — ISO 639-1 language detection.
  * spaCy en_core_web_sm (optional, heavyweight) — named-entity recognition
    for PERSON, ORG, and GPE/LOC.  Graceful degradation when unavailable.

Example::

    pipeline = NLPPipeline()
    result = pipeline.analyze("CVE-2021-44228 exploited by APT28 on 2021-12-10")
    print(result.cves)              # ['CVE-2021-44228']
    print(result.threat_actors)     # ['APT28']
    print(result.temporal_expressions[0]['text'])  # '2021-12-10'
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------

# spaCy — optional; heavy model requires separate download
try:
    import spacy as _spacy  # type: ignore

    try:
        _nlp = _spacy.load("en_core_web_sm")
        _SPACY_AVAILABLE = True
        logger.debug("nlp_pipeline: spaCy en_core_web_sm loaded successfully")
    except OSError:
        _nlp = None
        _SPACY_AVAILABLE = False
        logger.info(
            "nlp_pipeline: spaCy installed but 'en_core_web_sm' model not found. "
            "Install with: python -m spacy download en_core_web_sm"
        )
except ImportError:
    _nlp = None
    _SPACY_AVAILABLE = False
    logger.info(
        "nlp_pipeline: spaCy not installed — NER disabled. "
        "Install with: pip install spacy && python -m spacy download en_core_web_sm"
    )

# langdetect — required but guarded for graceful degradation
try:
    from langdetect import detect as _detect, DetectorFactory as _DetectorFactory  # type: ignore

    _DetectorFactory.seed = 0  # deterministic output
    _LANGDETECT_AVAILABLE = True
except ImportError:
    _detect = None  # type: ignore
    _LANGDETECT_AVAILABLE = False
    logger.warning(
        "nlp_pipeline: 'langdetect' not installed — language detection disabled. "
        "Install with: pip install langdetect"
    )


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------


@dataclass
class NLPResult:
    """Structured output from the NLP pipeline."""

    # Language
    language: Optional[str] = None          # ISO 639-1 code, e.g. 'en', 'ru'
    language_non_english: bool = False

    # Threat indicators (regex-extracted)
    cves: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)

    # Cryptocurrency addresses
    bitcoin_addresses: List[str] = field(default_factory=list)
    ethereum_addresses: List[str] = field(default_factory=list)

    # Dark-web / anonymisation
    onion_domains: List[str] = field(default_factory=list)

    # Temporal expressions
    temporal_expressions: List[Dict[str, Any]] = field(default_factory=list)

    # NER (spaCy — empty when unavailable)
    persons: List[str] = field(default_factory=list)
    organizations: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)

    # Metadata
    spacy_used: bool = False
    extracted_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict (JSON-safe)."""
        return {
            "language": self.language,
            "language_non_english": self.language_non_english,
            "cves": self.cves,
            "mitre_techniques": self.mitre_techniques,
            "threat_actors": self.threat_actors,
            "bitcoin_addresses": self.bitcoin_addresses,
            "ethereum_addresses": self.ethereum_addresses,
            "onion_domains": self.onion_domains,
            "temporal_expressions": self.temporal_expressions,
            "persons": self.persons,
            "organizations": self.organizations,
            "locations": self.locations,
            "spacy_used": self.spacy_used,
            "extracted_at": self.extracted_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class NLPPipeline:
    """
    Stateless NLP pipeline — all patterns compiled once at class level.

    Instantiate once and call :meth:`analyze` or :meth:`analyze_batch`
    repeatedly.  Thread-safe: no mutable state between calls.
    """

    # --- Compiled regex patterns ---

    # CVE IDs: CVE-YYYY-NNNNN (4–7 digit suffix)
    _CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    # MITRE ATT&CK technique IDs: T1234 or T1234.567
    _MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

    # Bitcoin P2PKH/P2SH addresses (legacy; 26–34 chars, starts with 1 or 3)
    _BTC = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")

    # Ethereum addresses: 0x followed by exactly 40 hex chars
    _ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

    # Onion v2 (16 chars base32) and v3 (56 chars base32)
    _ONION = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)

    # Temporal expressions: ISO dates, long-form dates, quarterly expressions
    _TEMPORAL = re.compile(
        r"\b(?:"
        r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|"
        r"Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|"
        r"Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
        r")\s+\d{1,2},?\s+\d{4}"
        r"|\d{4}-\d{2}-\d{2}"
        r"|Q[1-4]\s+\d{4}\b",
        re.IGNORECASE,
    )

    # Known threat-actor strings — matched case-insensitively
    _KNOWN_ACTORS: List[str] = [
        "APT1", "APT28", "APT29", "APT32", "APT33", "APT34",
        "APT35", "APT38", "APT40", "APT41",
        "Lazarus Group", "Cobalt Group",
        "FIN7", "FIN8",
        "Sandworm", "Turla",
        "Cozy Bear", "Fancy Bear",
        "Carbanak",
        "DarkSide", "REvil", "Conti", "LockBit", "BlackCat", "ALPHV",
        "Cl0p", "Clop",
        "Scattered Spider",
        "Volt Typhoon", "Salt Typhoon",
    ]

    # Build a single compiled pattern for actor detection
    _ACTOR_RE = re.compile(
        r"\b(?:" + "|".join(re.escape(a) for a in _KNOWN_ACTORS) + r")\b",
        re.IGNORECASE,
    )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, text: str) -> NLPResult:
        """
        Analyse a single piece of text and return an :class:`NLPResult`.

        Always runs regex extraction.  Adds spaCy NER if available.
        Adds language detection if *langdetect* is available.
        """
        if not isinstance(text, str):
            text = str(text or "")

        result = NLPResult()

        # Language detection
        if _LANGDETECT_AVAILABLE and text.strip():
            try:
                result.language = _detect(text)
                result.language_non_english = result.language != "en"
            except Exception:
                result.language = None

        # Regex extractions
        result.cves = self._extract_cves(text)
        result.mitre_techniques = self._extract_mitre(text)
        result.threat_actors = self._extract_actors(text)
        result.bitcoin_addresses = self._extract_btc(text)
        result.ethereum_addresses = self._extract_eth(text)
        result.onion_domains = self._extract_onion(text)
        result.temporal_expressions = self._extract_temporal(text)

        # Optional spaCy NER
        if _SPACY_AVAILABLE and _nlp is not None:
            try:
                doc = _nlp(text[:100_000])  # cap at 100k chars for safety
                result.persons = self._ner_entities(doc, {"PERSON"})
                result.organizations = self._ner_entities(doc, {"ORG"})
                result.locations = self._ner_entities(doc, {"GPE", "LOC"})
                result.spacy_used = True
            except Exception as exc:
                logger.warning("nlp_pipeline: spaCy NER failed: %s", exc)

        return result

    def analyze_batch(self, texts: List[str]) -> List[NLPResult]:
        """Analyse a list of texts. Returns a list of :class:`NLPResult` in order."""
        return [self.analyze(t) for t in texts]

    def to_entities(self, result: NLPResult) -> List[Dict[str, Any]]:
        """
        Convert an :class:`NLPResult` to a list of entity dicts compatible
        with the ``EntityExtractor`` output format used by
        ``IntelligenceCorrelator``.

        Entity dict schema::

            {
                "type": str,          # EntityType value string
                "value": str,         # canonical value
                "confidence": float,  # 0.0–1.0
                "source": "nlp",
                "metadata": dict,     # extra fields (e.g. technique_id for MITRE)
            }
        """
        entities: List[Dict[str, Any]] = []

        for cve in result.cves:
            entities.append({
                "type": "cve",
                "value": cve.upper(),
                "confidence": 0.95,
                "source": "nlp",
                "metadata": {},
            })

        for technique in result.mitre_techniques:
            entities.append({
                "type": "attack_pattern",
                "value": technique,
                "confidence": 0.90,
                "source": "nlp",
                "metadata": {"mitre_technique_id": technique},
            })

        for actor in result.threat_actors:
            entities.append({
                "type": "threat_actor",
                "value": actor,
                "confidence": 0.85,
                "source": "nlp",
                "metadata": {"is_threat_actor": True},
            })

        for btc in result.bitcoin_addresses:
            entities.append({
                "type": "cryptocurrency",
                "value": btc,
                "confidence": 0.90,
                "source": "nlp",
                "metadata": {"currency": "BTC"},
            })

        for eth in result.ethereum_addresses:
            entities.append({
                "type": "cryptocurrency",
                "value": eth,
                "confidence": 0.90,
                "source": "nlp",
                "metadata": {"currency": "ETH"},
            })

        for onion in result.onion_domains:
            entities.append({
                "type": "domain",
                "value": onion.lower(),
                "confidence": 0.95,
                "source": "nlp",
                "metadata": {"dark_web": True},
            })

        for person in result.persons:
            entities.append({
                "type": "person",
                "value": person,
                "confidence": 0.75,
                "source": "nlp",
                "metadata": {"ner_label": "PERSON"},
            })

        for org in result.organizations:
            entities.append({
                "type": "organization",
                "value": org,
                "confidence": 0.75,
                "source": "nlp",
                "metadata": {"ner_label": "ORG"},
            })

        for loc in result.locations:
            entities.append({
                "type": "location",
                "value": loc,
                "confidence": 0.70,
                "source": "nlp",
                "metadata": {"ner_label": "GPE/LOC"},
            })

        return entities

    # ------------------------------------------------------------------
    # Regex extraction helpers
    # ------------------------------------------------------------------

    @classmethod
    def _extract_cves(cls, text: str) -> List[str]:
        matches = cls._CVE.findall(text)
        # Normalise to uppercase and deduplicate while preserving order
        seen: set = set()
        result = []
        for m in matches:
            upper = m.upper()
            if upper not in seen:
                seen.add(upper)
                result.append(upper)
        return result

    @classmethod
    def _extract_mitre(cls, text: str) -> List[str]:
        matches = cls._MITRE.findall(text)
        seen: set = set()
        result = []
        for m in matches:
            if m not in seen:
                seen.add(m)
                result.append(m)
        return result

    @classmethod
    def _extract_actors(cls, text: str) -> List[str]:
        matches = cls._ACTOR_RE.findall(text)
        seen: set = set()
        result = []
        for m in matches:
            # Normalise by looking up in _KNOWN_ACTORS (preserves canonical casing)
            canonical = next(
                (a for a in cls._KNOWN_ACTORS if a.lower() == m.lower()), m
            )
            if canonical not in seen:
                seen.add(canonical)
                result.append(canonical)
        return result

    @classmethod
    def _extract_btc(cls, text: str) -> List[str]:
        matches = cls._BTC.findall(text)
        seen: set = set()
        result = []
        for m in matches:
            if m not in seen:
                seen.add(m)
                result.append(m)
        return result

    @classmethod
    def _extract_eth(cls, text: str) -> List[str]:
        matches = cls._ETH.findall(text)
        seen: set = set()
        result = []
        for m in matches:
            if m not in seen:
                seen.add(m)
                result.append(m)
        return result

    @classmethod
    def _extract_onion(cls, text: str) -> List[str]:
        matches = cls._ONION.findall(text)
        seen: set = set()
        result = []
        for m in matches:
            lower = m.lower()
            if lower not in seen:
                seen.add(lower)
                result.append(lower)
        return result

    @classmethod
    def _extract_temporal(cls, text: str) -> List[Dict[str, Any]]:
        result = []
        for match in cls._TEMPORAL.finditer(text):
            result.append({
                "text": match.group(0),
                "position": match.start(),
            })
        return result

    # ------------------------------------------------------------------
    # spaCy helper
    # ------------------------------------------------------------------

    @staticmethod
    def _ner_entities(doc: Any, labels: set) -> List[str]:
        """Extract unique entity strings for the given spaCy label set."""
        seen: set = set()
        result = []
        for ent in doc.ents:
            if ent.label_ in labels:
                text = ent.text.strip()
                if text and text not in seen:
                    seen.add(text)
                    result.append(text)
        return result

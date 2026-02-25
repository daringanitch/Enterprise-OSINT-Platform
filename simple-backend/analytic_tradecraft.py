#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Analytic Tradecraft Engine
===========================

Implements intelligence community (IC) structured analytic techniques:

  • NATO/Admiralty source-reliability + information-credibility matrix
  • IC-standard confidence levels with controlled vocabulary
  • Analysis of Competing Hypotheses (ACH) workflow
  • Alternative explanations tracking (anti-confirmation-bias)
  • Devil's Advocacy and Team A/Team B dissent capture
  • Conclusion registry with mandatory caveats

All data is persisted to JSON files in APP_DATA_DIR so no PostgreSQL
table changes are required.

Reference standards:
  - NATO STANAG 2511 (Admiralty scale)
  - ICD 203 (IC analytic standards)
  - ICD 206 (sourcing standards)
  - Sherman Kent's "Words of Estimative Probability"
"""

import json
import logging
import os
import uuid
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NATO / Admiralty Scale
# ---------------------------------------------------------------------------

class SourceReliability(str, Enum):
    """NATO STANAG 2511 source reliability grades."""
    A = "A"  # Completely Reliable — no doubt about authenticity/trustworthiness/competency; history of complete reliability
    B = "B"  # Usually Reliable — minor doubt; history of valid information most of the time
    C = "C"  # Fairly Reliable — some doubt; provided valid information in the past
    D = "D"  # Not Usually Reliable — significant doubt; provided valid information in the past but generally unreliable
    E = "E"  # Unreliable — lacking authenticity; history of invalid information
    F = "F"  # Reliability Cannot Be Judged — no basis for evaluating reliability

SOURCE_RELIABILITY_LABELS = {
    "A": "Completely Reliable",
    "B": "Usually Reliable",
    "C": "Fairly Reliable",
    "D": "Not Usually Reliable",
    "E": "Unreliable",
    "F": "Cannot Be Judged",
}

SOURCE_RELIABILITY_DESCRIPTIONS = {
    "A": "No doubt about authenticity, trustworthiness, or competency. Consistent history of reliability.",
    "B": "Minor doubts. Has provided valid information most of the time.",
    "C": "Some doubt. Has provided valid information in the past.",
    "D": "Significant doubt. Has provided valid information occasionally but is generally unreliable.",
    "E": "Lacking in authenticity, trustworthiness, and competency. History of invalid information.",
    "F": "Insufficient basis to evaluate the reliability of this source.",
}


class InformationCredibility(str, Enum):
    """NATO STANAG 2511 information credibility grades."""
    C1 = "1"  # Confirmed — confirmed by other independent sources; consistent with past reports; logical
    C2 = "2"  # Probably True — not confirmed; consistent with other information; logical; comes from reliable source
    C3 = "3"  # Possibly True — not confirmed; reasonably consistent; some basis for logical deduction; source not confirmed
    C4 = "4"  # Doubtful — not confirmed; illogical; conflicts with other information
    C5 = "5"  # Improbable — very doubtful; contradicts other information; logical impossibility
    C6 = "6"  # Cannot Be Judged — insufficient basis to evaluate credibility

INFO_CREDIBILITY_LABELS = {
    "1": "Confirmed",
    "2": "Probably True",
    "3": "Possibly True",
    "4": "Doubtful",
    "5": "Improbable",
    "6": "Cannot Be Judged",
}

INFO_CREDIBILITY_DESCRIPTIONS = {
    "1": "Confirmed by other independent sources; consistent with past reporting; logically consistent.",
    "2": "Not confirmed but consistent with other information; logical; from a reliable source.",
    "3": "Not confirmed; reasonably consistent with other information; logical deduction possible.",
    "4": "Not confirmed; not logical; contradicts some other information on the subject.",
    "5": "Contradicts other information on the subject; logical impossibility.",
    "6": "Insufficient basis to evaluate credibility of this information.",
}


# ---------------------------------------------------------------------------
# IC Confidence Levels (ICD 203)
# ---------------------------------------------------------------------------

class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"

CONFIDENCE_LANGUAGE = {
    "high": {
        "label": "High Confidence",
        "hedge": "we assess with high confidence",
        "description": "Based on high-quality information and/or sound analytic reasoning. Analytic judgments are not meant to imply certainty or factual knowledge.",
        "wep_words": ["almost certainly", "highly likely", "very likely"],
        "probability_range": "85–99%",
        "color": "green",
    },
    "moderate": {
        "label": "Moderate Confidence",
        "hedge": "we assess with moderate confidence",
        "description": "Based on credible and plausible information, but with information gaps or analytical uncertainty.",
        "wep_words": ["likely", "probably", "we believe"],
        "probability_range": "55–84%",
        "color": "yellow",
    },
    "low": {
        "label": "Low Confidence",
        "hedge": "we note with low confidence",
        "description": "Based on fragmentary or questionable information, or significant analytic uncertainty. The analytic judgment is weakly held.",
        "wep_words": ["might", "could", "we cannot confirm", "possible"],
        "probability_range": "10–54%",
        "color": "orange",
    },
}

# Words of Estimative Probability (Sherman Kent scale)
WEP_SCALE = [
    {"phrase": "almost certainly",      "probability": "93%",  "confidence": "high"},
    {"phrase": "highly likely",         "probability": "88%",  "confidence": "high"},
    {"phrase": "very likely",           "probability": "83%",  "confidence": "high"},
    {"phrase": "likely",                "probability": "70%",  "confidence": "moderate"},
    {"phrase": "probably",              "probability": "65%",  "confidence": "moderate"},
    {"phrase": "we believe",            "probability": "55%",  "confidence": "moderate"},
    {"phrase": "roughly even chance",   "probability": "50%",  "confidence": "moderate"},
    {"phrase": "possibly",              "probability": "30%",  "confidence": "low"},
    {"phrase": "might",                 "probability": "20%",  "confidence": "low"},
    {"phrase": "could",                 "probability": "15%",  "confidence": "low"},
    {"phrase": "unlikely",              "probability": "12%",  "confidence": "low"},
    {"phrase": "almost certainly not",  "probability": "5%",   "confidence": "low"},
]


# ---------------------------------------------------------------------------
# ACH Evidence Consistency
# ---------------------------------------------------------------------------

class ACHConsistency(str, Enum):
    CONSISTENT   = "C"   # Evidence is consistent with the hypothesis
    INCONSISTENT = "I"   # Evidence is inconsistent — this is most diagnostic
    NEUTRAL      = "N"   # Evidence neither supports nor refutes
    NOT_APPLICABLE = "NA" # Evidence does not apply to this hypothesis


ACH_CONSISTENCY_WEIGHT = {
    "C":  0,   # Consistent evidence barely changes relative probability
    "I": -2,   # Inconsistency is the key diagnostic signal (Heuer)
    "N":  0,
    "NA": 0,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IntelligenceItem:
    """A single piece of intelligence with provenance and Admiralty ratings."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    title: str = ""
    content: str = ""
    source_name: str = ""
    source_type: str = ""    # human, technical, osint, document, etc.
    source_reliability: str = "F"   # A-F
    info_credibility: str = "6"     # 1-6
    collection_method: str = ""     # dns_lookup, whois, virustotal, etc.
    collected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: List[str] = field(default_factory=list)
    raw_data: Optional[Dict] = None
    analyst_notes: str = ""
    created_by: str = "system"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def admiralty_code(self) -> str:
        return f"{self.source_reliability}{self.info_credibility}"

    @property
    def reliability_label(self) -> str:
        return SOURCE_RELIABILITY_LABELS.get(self.source_reliability, "Unknown")

    @property
    def credibility_label(self) -> str:
        return INFO_CREDIBILITY_LABELS.get(self.info_credibility, "Unknown")


@dataclass
class Hypothesis:
    """A candidate explanation for observed intelligence."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    title: str = ""
    description: str = ""
    hypothesis_type: str = "primary"   # primary | alternative | null | devil_advocate
    status: str = "open"               # open | confirmed | rejected | tentative
    created_by: str = "analyst"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    rejection_rationale: str = ""      # Required when status=rejected
    notes: str = ""


@dataclass
class ACHCell:
    """One cell in the ACH matrix: (evidence_id, hypothesis_id) → consistency."""
    evidence_id: str = ""
    hypothesis_id: str = ""
    consistency: str = "NA"       # ACHConsistency value
    analyst_rationale: str = ""
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class AlternativeExplanation:
    """
    A documented alternative explanation for a conclusion.
    Analysts must explain why this alternative was rejected.
    Prevents confirmation bias being baked into reports.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    conclusion_id: str = ""
    alternative_text: str = ""
    why_considered: str = ""
    why_rejected: str = ""           # Must be filled to close
    rejection_confidence: str = "moderate"
    created_by: str = "analyst"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    status: str = "open"             # open | closed


@dataclass
class DevilsAdvocacy:
    """
    Designated dissent — "what if we're wrong about the primary conclusion?"
    The analyst or a designated devil's advocate documents the strongest
    possible case against the primary assessment.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    conclusion_id: str = ""
    challenge_text: str = ""         # The strongest argument against the main conclusion
    evidence_gaps: List[str] = field(default_factory=list)  # What would change the assessment
    response_text: str = ""          # Lead analyst's response to the challenge
    status: str = "open"             # open | responded | accepted | dismissed
    created_by: str = "devil_advocate"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class AnalyticConclusion:
    """
    A formal intelligence conclusion with IC-standard confidence language,
    mandatory alternative explanations, and optional devil's advocacy.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    title: str = ""
    assessment_text: str = ""        # Full analytical assessment
    confidence_level: str = "low"    # high | moderate | low
    wep_phrase: str = "possibly"     # Sherman Kent word of estimative probability
    key_judgement: str = ""          # One-sentence bottom line (ICD 203)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    primary_hypothesis_id: Optional[str] = None
    analytic_caveats: List[str] = field(default_factory=list)
    information_gaps: List[str] = field(default_factory=list)
    collection_gaps: List[str] = field(default_factory=list)
    requires_alternative_explanations: bool = True
    requires_devils_advocacy: bool = False
    status: str = "draft"            # draft | in_review | finalised
    created_by: str = "analyst"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def generate_ic_statement(self) -> str:
        """Generate IC-standard assessment sentence."""
        hedge = CONFIDENCE_LANGUAGE[self.confidence_level]["hedge"]
        return f"We assess with {self.confidence_level} confidence that {self.assessment_text.lower().rstrip('.')}."

    def completeness_check(self, alternatives: List[AlternativeExplanation], advocacies: List[DevilsAdvocacy]) -> Dict:
        """Return a completeness report for the review workflow."""
        issues = []
        if not self.key_judgement:
            issues.append("Missing key judgement (bottom-line-up-front sentence)")
        if not self.supporting_evidence_ids:
            issues.append("No supporting evidence linked")
        if self.requires_alternative_explanations and not alternatives:
            issues.append("At least one alternative explanation must be documented")
        open_alts = [a for a in alternatives if a.status == "open"]
        if open_alts:
            issues.append(f"{len(open_alts)} alternative explanation(s) not yet closed")
        if self.requires_devils_advocacy and not advocacies:
            issues.append("Devil's advocacy challenge required but not completed")
        open_das = [d for d in advocacies if d.status == "open"]
        if open_das:
            issues.append(f"{len(open_das)} devil's advocacy challenge(s) not yet responded to")
        return {"complete": len(issues) == 0, "issues": issues}


# ---------------------------------------------------------------------------
# ACH Matrix calculator
# ---------------------------------------------------------------------------

def compute_ach_scores(
    hypotheses: List[Hypothesis],
    evidence_items: List[IntelligenceItem],
    cells: List[ACHCell],
) -> List[Dict]:
    """
    Compute Heuer's ACH diagnostic scores.

    The key insight: we look for evidence that DISTINGUISHES between hypotheses.
    Inconsistencies are most diagnostic (they rule out hypotheses).
    Evidence consistent with ALL hypotheses is not diagnostic.

    Returns a sorted list of hypotheses with their inconsistency scores.
    Lower score = fewer inconsistencies = more likely.
    """
    # Build lookup: (evidence_id, hypothesis_id) -> consistency
    cell_map: Dict[tuple, str] = {(c.evidence_id, c.hypothesis_id): c.consistency for c in cells}

    results = []
    for hyp in hypotheses:
        score = 0
        inconsistencies = []
        consistencies = []
        for ev in evidence_items:
            consistency = cell_map.get((ev.id, hyp.id), "NA")
            weight = ACH_CONSISTENCY_WEIGHT.get(consistency, 0)
            score += weight
            if consistency == "I":
                inconsistencies.append(ev.id)
            elif consistency == "C":
                consistencies.append(ev.id)

        results.append({
            "hypothesis_id": hyp.id,
            "hypothesis_title": hyp.title,
            "inconsistency_score": score,   # More negative = more inconsistencies
            "inconsistency_count": len(inconsistencies),
            "consistency_count": len(consistencies),
            "inconsistent_evidence_ids": inconsistencies,
            "consistent_evidence_ids": consistencies,
            "rank": 0,  # filled below
        })

    # Rank: highest score (fewest inconsistencies) = rank 1
    results.sort(key=lambda x: x["inconsistency_score"], reverse=True)
    for i, r in enumerate(results):
        r["rank"] = i + 1
    return results


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class TradecraftStore:
    """JSON-file-backed persistence for all tradecraft objects."""

    def __init__(self):
        data_dir = os.environ.get('APP_DATA_DIR', '/app/data')
        self.path = Path(data_dir) / 'tradecraft.json'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data: Dict[str, Any] = self._load()

    def _load(self) -> Dict:
        if self.path.exists():
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"tradecraft.json unreadable, resetting: {e}")
        return {
            "intelligence_items": {},
            "hypotheses": {},
            "ach_cells": {},          # key: "ev_id::hyp_id"
            "conclusions": {},
            "alternatives": {},
            "advocacies": {},
        }

    def _save(self):
        try:
            with open(self.path, 'w') as f:
                json.dump(self._data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"tradecraft save failed: {e}")

    # ── Intelligence Items ─────────────────────────────────────────────────

    def save_intel_item(self, item: IntelligenceItem) -> IntelligenceItem:
        self._data["intelligence_items"][item.id] = asdict(item)
        self._save()
        return item

    def get_intel_items(self, investigation_id: str) -> List[IntelligenceItem]:
        return [
            IntelligenceItem(**v)
            for v in self._data["intelligence_items"].values()
            if v.get("investigation_id") == investigation_id
        ]

    def get_intel_item(self, item_id: str) -> Optional[IntelligenceItem]:
        d = self._data["intelligence_items"].get(item_id)
        return IntelligenceItem(**d) if d else None

    def delete_intel_item(self, item_id: str) -> bool:
        if item_id in self._data["intelligence_items"]:
            del self._data["intelligence_items"][item_id]
            self._save()
            return True
        return False

    # ── Hypotheses ─────────────────────────────────────────────────────────

    def save_hypothesis(self, h: Hypothesis) -> Hypothesis:
        self._data["hypotheses"][h.id] = asdict(h)
        self._save()
        return h

    def get_hypotheses(self, investigation_id: str) -> List[Hypothesis]:
        return [
            Hypothesis(**v)
            for v in self._data["hypotheses"].values()
            if v.get("investigation_id") == investigation_id
        ]

    def get_hypothesis(self, hyp_id: str) -> Optional[Hypothesis]:
        d = self._data["hypotheses"].get(hyp_id)
        return Hypothesis(**d) if d else None

    def delete_hypothesis(self, hyp_id: str) -> bool:
        if hyp_id in self._data["hypotheses"]:
            del self._data["hypotheses"][hyp_id]
            self._save()
            return True
        return False

    # ── ACH Cells ─────────────────────────────────────────────────────────

    def set_ach_cell(self, cell: ACHCell) -> ACHCell:
        key = f"{cell.evidence_id}::{cell.hypothesis_id}"
        self._data["ach_cells"][key] = asdict(cell)
        self._save()
        return cell

    def get_ach_cells(self, investigation_id: str) -> List[ACHCell]:
        """Return all ACH cells for the investigation's evidence/hypotheses."""
        ev_ids = {i.id for i in self.get_intel_items(investigation_id)}
        hyp_ids = {h.id for h in self.get_hypotheses(investigation_id)}
        result = []
        for key, val in self._data["ach_cells"].items():
            if val.get("evidence_id") in ev_ids and val.get("hypothesis_id") in hyp_ids:
                result.append(ACHCell(**val))
        return result

    # ── Conclusions ────────────────────────────────────────────────────────

    def save_conclusion(self, c: AnalyticConclusion) -> AnalyticConclusion:
        c.updated_at = datetime.utcnow().isoformat()
        self._data["conclusions"][c.id] = asdict(c)
        self._save()
        return c

    def get_conclusions(self, investigation_id: str) -> List[AnalyticConclusion]:
        return [
            AnalyticConclusion(**v)
            for v in self._data["conclusions"].values()
            if v.get("investigation_id") == investigation_id
        ]

    def get_conclusion(self, cid: str) -> Optional[AnalyticConclusion]:
        d = self._data["conclusions"].get(cid)
        return AnalyticConclusion(**d) if d else None

    # ── Alternative Explanations ───────────────────────────────────────────

    def save_alternative(self, alt: AlternativeExplanation) -> AlternativeExplanation:
        self._data["alternatives"][alt.id] = asdict(alt)
        self._save()
        return alt

    def get_alternatives(self, conclusion_id: str) -> List[AlternativeExplanation]:
        return [
            AlternativeExplanation(**v)
            for v in self._data["alternatives"].values()
            if v.get("conclusion_id") == conclusion_id
        ]

    def get_alternative(self, alt_id: str) -> Optional[AlternativeExplanation]:
        d = self._data["alternatives"].get(alt_id)
        return AlternativeExplanation(**d) if d else None

    # ── Devil's Advocacy ───────────────────────────────────────────────────

    def save_advocacy(self, da: DevilsAdvocacy) -> DevilsAdvocacy:
        self._data["advocacies"][da.id] = asdict(da)
        self._save()
        return da

    def get_advocacies(self, conclusion_id: str) -> List[DevilsAdvocacy]:
        return [
            DevilsAdvocacy(**v)
            for v in self._data["advocacies"].values()
            if v.get("conclusion_id") == conclusion_id
        ]

    def get_advocacy(self, da_id: str) -> Optional[DevilsAdvocacy]:
        d = self._data["advocacies"].get(da_id)
        return DevilsAdvocacy(**d) if d else None


# Global singleton
tradecraft_store = TradecraftStore()

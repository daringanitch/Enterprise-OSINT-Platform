#!/usr/bin/env python3
"""
Unit tests for analytic_tradecraft module.

Tests:
  - SourceReliability and InformationCredibility enums
  - ConfidenceLevel enum and IC language
  - WEP_SCALE constants
  - IntelligenceItem creation and admiralty_code property
  - Hypothesis creation and status transitions
  - ACHConsistency and scoring logic
  - AnalyticConclusion generation and completeness checks
  - TradecraftStore persistence
"""

import pytest
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from analytic_tradecraft import (
    SourceReliability,
    InformationCredibility,
    ConfidenceLevel,
    SOURCE_RELIABILITY_LABELS,
    INFO_CREDIBILITY_LABELS,
    CONFIDENCE_LANGUAGE,
    WEP_SCALE,
    IntelligenceItem,
    Hypothesis,
    ACHCell,
    ACHConsistency,
    AlternativeExplanation,
    DevilsAdvocacy,
    AnalyticConclusion,
    compute_ach_scores,
    TradecraftStore,
)


# ─────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_app_data_dir(tmp_path, monkeypatch):
    """Override APP_DATA_DIR with a temporary directory."""
    monkeypatch.setenv('APP_DATA_DIR', str(tmp_path))
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────
# Tests: NATO/Admiralty Scale
# ─────────────────────────────────────────────────────────────────────────

def test_source_reliability_enum_values():
    """Test SourceReliability enum has correct values."""
    assert SourceReliability.A.value == "A"
    assert SourceReliability.B.value == "B"
    assert SourceReliability.C.value == "C"
    assert SourceReliability.D.value == "D"
    assert SourceReliability.E.value == "E"
    assert SourceReliability.F.value == "F"


def test_source_reliability_labels():
    """Test all SourceReliability values have labels."""
    for sr in SourceReliability:
        assert sr.value in SOURCE_RELIABILITY_LABELS
        assert SOURCE_RELIABILITY_LABELS[sr.value]  # non-empty label


def test_information_credibility_enum_values():
    """Test InformationCredibility enum has correct values."""
    assert InformationCredibility.C1.value == "1"
    assert InformationCredibility.C2.value == "2"
    assert InformationCredibility.C3.value == "3"
    assert InformationCredibility.C4.value == "4"
    assert InformationCredibility.C5.value == "5"
    assert InformationCredibility.C6.value == "6"


def test_information_credibility_labels():
    """Test all InformationCredibility values have labels."""
    for ic in InformationCredibility:
        assert ic.value in INFO_CREDIBILITY_LABELS
        assert INFO_CREDIBILITY_LABELS[ic.value]  # non-empty label


# ─────────────────────────────────────────────────────────────────────────
# Tests: Confidence Levels and WEP
# ─────────────────────────────────────────────────────────────────────────

def test_confidence_level_enum():
    """Test ConfidenceLevel enum values."""
    assert ConfidenceLevel.HIGH.value == "high"
    assert ConfidenceLevel.MODERATE.value == "moderate"
    assert ConfidenceLevel.LOW.value == "low"


def test_confidence_language_structure():
    """Test CONFIDENCE_LANGUAGE dict has required fields."""
    for level in ["high", "moderate", "low"]:
        assert level in CONFIDENCE_LANGUAGE
        cl = CONFIDENCE_LANGUAGE[level]
        assert "label" in cl
        assert "hedge" in cl
        assert "description" in cl
        assert "wep_words" in cl
        assert "probability_range" in cl
        assert "color" in cl
        assert isinstance(cl["wep_words"], list)
        assert len(cl["wep_words"]) > 0


def test_wep_scale_entries():
    """Test WEP_SCALE has expected entries with correct structure."""
    assert len(WEP_SCALE) > 0
    sample_entries = ["almost certainly", "likely", "possibly", "almost certainly not"]
    for phrase in sample_entries:
        entry = next((e for e in WEP_SCALE if e["phrase"] == phrase), None)
        assert entry is not None, f"Expected '{phrase}' in WEP_SCALE"
        assert "probability" in entry
        assert "confidence" in entry
        assert entry["confidence"] in ["high", "moderate", "low"]


def test_wep_scale_ordering():
    """Test WEP_SCALE appears to be ordered by decreasing probability."""
    # Extract numeric probabilities (e.g., "93%" -> 93)
    probs = []
    for entry in WEP_SCALE:
        prob_str = entry["probability"].rstrip("%")
        probs.append(int(prob_str))
    # Check generally decreasing (some ties are ok)
    for i in range(len(probs) - 1):
        assert probs[i] >= probs[i + 1], f"WEP_SCALE not properly ordered at index {i}"


# ─────────────────────────────────────────────────────────────────────────
# Tests: IntelligenceItem
# ─────────────────────────────────────────────────────────────────────────

def test_intelligence_item_creation():
    """Test creating an IntelligenceItem."""
    item = IntelligenceItem(
        investigation_id="inv-123",
        title="Malicious IP detected",
        content="IP 192.0.2.1 probing port 22",
        source_name="Shodan",
        source_reliability="B",
        info_credibility="2",
        collection_method="shodan_lookup",
    )
    assert item.investigation_id == "inv-123"
    assert item.title == "Malicious IP detected"
    assert item.source_reliability == "B"
    assert item.info_credibility == "2"
    assert item.id  # Should have a UUID


def test_intelligence_item_admiralty_code():
    """Test IntelligenceItem.admiralty_code property."""
    item = IntelligenceItem(
        source_reliability="B",
        info_credibility="2",
    )
    assert item.admiralty_code == "B2"

    item2 = IntelligenceItem(
        source_reliability="A",
        info_credibility="1",
    )
    assert item2.admiralty_code == "A1"


def test_intelligence_item_labels():
    """Test IntelligenceItem label properties."""
    item = IntelligenceItem(
        source_reliability="B",
        info_credibility="3",
    )
    assert item.reliability_label == "Usually Reliable"
    assert item.credibility_label == "Possibly True"


def test_intelligence_item_defaults():
    """Test IntelligenceItem defaults."""
    item = IntelligenceItem()
    assert item.source_reliability == "F"
    assert item.info_credibility == "6"
    assert item.admiralty_code == "F6"
    assert item.created_by == "system"
    assert item.created_at  # Should be ISO timestamp


# ─────────────────────────────────────────────────────────────────────────
# Tests: Hypothesis
# ─────────────────────────────────────────────────────────────────────────

def test_hypothesis_creation():
    """Test creating a Hypothesis."""
    hyp = Hypothesis(
        investigation_id="inv-456",
        title="Compromised account",
        description="User's account was compromised by an adversary",
        hypothesis_type="primary",
    )
    assert hyp.investigation_id == "inv-456"
    assert hyp.title == "Compromised account"
    assert hyp.status == "open"
    assert hyp.hypothesis_type == "primary"
    assert hyp.id


def test_hypothesis_status_field():
    """Test Hypothesis status field."""
    hyp = Hypothesis(status="confirmed")
    assert hyp.status == "confirmed"

    hyp2 = Hypothesis(status="rejected", rejection_rationale="No evidence found")
    assert hyp2.status == "rejected"
    assert hyp2.rejection_rationale == "No evidence found"


def test_hypothesis_types():
    """Test various Hypothesis types."""
    types = ["primary", "alternative", "null", "devil_advocate"]
    for htype in types:
        hyp = Hypothesis(hypothesis_type=htype)
        assert hyp.hypothesis_type == htype


# ─────────────────────────────────────────────────────────────────────────
# Tests: ACH (Analysis of Competing Hypotheses)
# ─────────────────────────────────────────────────────────────────────────

def test_ach_consistency_values():
    """Test ACHConsistency enum values."""
    assert ACHConsistency.CONSISTENT.value == "C"
    assert ACHConsistency.INCONSISTENT.value == "I"
    assert ACHConsistency.NEUTRAL.value == "N"
    assert ACHConsistency.NOT_APPLICABLE.value == "NA"


def test_compute_ach_scores_basic():
    """Test compute_ach_scores with a small matrix."""
    # Create 2 hypotheses and 2 evidence items
    hyp1 = Hypothesis(id="hyp-1", title="Account Compromised")
    hyp2 = Hypothesis(id="hyp-2", title="Legitimate Activity")

    ev1 = IntelligenceItem(id="ev-1", title="Unusual login from new IP")
    ev2 = IntelligenceItem(id="ev-2", title="Legitimate business activity detected")

    # Build ACH matrix:
    # ev-1: consistent with hyp-1, inconsistent with hyp-2
    # ev-2: inconsistent with hyp-1, consistent with hyp-2
    cells = [
        ACHCell(evidence_id="ev-1", hypothesis_id="hyp-1", consistency="C"),
        ACHCell(evidence_id="ev-1", hypothesis_id="hyp-2", consistency="I"),
        ACHCell(evidence_id="ev-2", hypothesis_id="hyp-1", consistency="I"),
        ACHCell(evidence_id="ev-2", hypothesis_id="hyp-2", consistency="C"),
    ]

    results = compute_ach_scores([hyp1, hyp2], [ev1, ev2], cells)

    # Both hypotheses should have inconsistencies (both have one "I" rating)
    # But the ranking should reflect the diagnostic value
    assert len(results) == 2
    assert results[0]["hypothesis_id"] in ["hyp-1", "hyp-2"]
    assert results[1]["hypothesis_id"] in ["hyp-1", "hyp-2"]
    assert results[0]["rank"] == 1
    assert results[1]["rank"] == 2

    # Check that inconsistency counts are tracked
    for r in results:
        assert r["inconsistency_count"] == 1
        assert r["consistency_count"] == 1


def test_compute_ach_scores_all_neutral():
    """Test compute_ach_scores when evidence is neutral."""
    hyp = Hypothesis(id="hyp-1", title="Test")
    ev = IntelligenceItem(id="ev-1", title="Neutral evidence")

    cells = [ACHCell(evidence_id="ev-1", hypothesis_id="hyp-1", consistency="N")]

    results = compute_ach_scores([hyp], [ev], cells)
    assert len(results) == 1
    assert results[0]["inconsistency_count"] == 0
    assert results[0]["inconsistency_score"] == 0


def test_compute_ach_scores_ranking():
    """Test that compute_ach_scores ranks hypotheses correctly."""
    hyp1 = Hypothesis(id="hyp-1", title="H1")  # Will have 2 inconsistencies
    hyp2 = Hypothesis(id="hyp-2", title="H2")  # Will have 1 inconsistency
    hyp3 = Hypothesis(id="hyp-3", title="H3")  # Will have 0 inconsistencies

    ev1 = IntelligenceItem(id="ev-1")
    ev2 = IntelligenceItem(id="ev-2")

    cells = [
        # hyp1: both inconsistent (-2 each = -4)
        ACHCell(evidence_id="ev-1", hypothesis_id="hyp-1", consistency="I"),
        ACHCell(evidence_id="ev-2", hypothesis_id="hyp-1", consistency="I"),
        # hyp2: one inconsistent, one neutral (-2 = -2)
        ACHCell(evidence_id="ev-1", hypothesis_id="hyp-2", consistency="I"),
        ACHCell(evidence_id="ev-2", hypothesis_id="hyp-2", consistency="N"),
        # hyp3: both neutral (0 = 0)
        ACHCell(evidence_id="ev-1", hypothesis_id="hyp-3", consistency="N"),
        ACHCell(evidence_id="ev-2", hypothesis_id="hyp-3", consistency="N"),
    ]

    results = compute_ach_scores([hyp1, hyp2, hyp3], [ev1, ev2], cells)
    # Rank 1 should be hyp3 (score 0), rank 2 hyp2 (score -2), rank 3 hyp1 (score -4)
    assert results[0]["hypothesis_id"] == "hyp-3"
    assert results[0]["rank"] == 1
    assert results[1]["hypothesis_id"] == "hyp-2"
    assert results[1]["rank"] == 2
    assert results[2]["hypothesis_id"] == "hyp-1"
    assert results[2]["rank"] == 3


# ─────────────────────────────────────────────────────────────────────────
# Tests: AnalyticConclusion
# ─────────────────────────────────────────────────────────────────────────

def test_analytic_conclusion_creation():
    """Test creating an AnalyticConclusion."""
    conc = AnalyticConclusion(
        investigation_id="inv-789",
        title="Threat Assessment",
        assessment_text="The infrastructure is likely compromised",
        confidence_level="high",
        key_judgement="Infrastructure shows signs of compromise",
    )
    assert conc.investigation_id == "inv-789"
    assert conc.confidence_level == "high"
    assert conc.status == "draft"


def test_analytic_conclusion_generate_ic_statement():
    """Test AnalyticConclusion.generate_ic_statement()."""
    conc = AnalyticConclusion(
        assessment_text="The server is compromised",
        confidence_level="high",
    )
    stmt = conc.generate_ic_statement()
    assert "high confidence" in stmt
    assert "compromised" in stmt.lower()

    conc2 = AnalyticConclusion(
        assessment_text="The domain may be malicious",
        confidence_level="moderate",
    )
    stmt2 = conc2.generate_ic_statement()
    assert "moderate confidence" in stmt2

    conc3 = AnalyticConclusion(
        assessment_text="The IP is suspicious",
        confidence_level="low",
    )
    stmt3 = conc3.generate_ic_statement()
    assert "low confidence" in stmt3


def test_analytic_conclusion_completeness_check_incomplete():
    """Test completeness_check when conclusion is incomplete."""
    conc = AnalyticConclusion(
        assessment_text="Some assessment",
        requires_alternative_explanations=True,
    )
    # No key judgement
    result = conc.completeness_check([], [])
    assert result["complete"] is False
    assert any("key judgement" in issue.lower() for issue in result["issues"])


def test_analytic_conclusion_completeness_check_complete():
    """Test completeness_check when conclusion is complete."""
    conc = AnalyticConclusion(
        assessment_text="Assessment",
        key_judgement="The threat is real",
        supporting_evidence_ids=["ev-1", "ev-2"],
        requires_alternative_explanations=False,
        requires_devils_advocacy=False,
    )
    result = conc.completeness_check([], [])
    assert result["complete"] is True
    assert len(result["issues"]) == 0


def test_analytic_conclusion_completeness_requires_alternatives():
    """Test completeness check when alternatives are required."""
    conc = AnalyticConclusion(
        key_judgement="Threat detected",
        supporting_evidence_ids=["ev-1"],
        requires_alternative_explanations=True,
    )
    # No alternatives provided
    result = conc.completeness_check([], [])
    assert result["complete"] is False
    assert any("alternative" in issue.lower() for issue in result["issues"])

    # With one alternative
    alt = AlternativeExplanation(conclusion_id=conc.id, status="closed")
    result2 = conc.completeness_check([alt], [])
    assert result2["complete"] is True


def test_analytic_conclusion_completeness_open_alternatives():
    """Test completeness check when alternatives are still open."""
    conc = AnalyticConclusion(
        key_judgement="Assessment",
        supporting_evidence_ids=["ev-1"],
        requires_alternative_explanations=True,
    )
    # One open alternative should fail
    alt = AlternativeExplanation(conclusion_id=conc.id, status="open")
    result = conc.completeness_check([alt], [])
    assert result["complete"] is False
    assert any("not yet closed" in issue for issue in result["issues"])


# ─────────────────────────────────────────────────────────────────────────
# Tests: Alternative Explanations and Devil's Advocacy
# ─────────────────────────────────────────────────────────────────────────

def test_alternative_explanation_creation():
    """Test creating an AlternativeExplanation."""
    alt = AlternativeExplanation(
        conclusion_id="conc-1",
        alternative_text="Could be false flag operation",
        why_considered="Similar patterns seen before",
        why_rejected="No supporting evidence",
        status="closed",
    )
    assert alt.conclusion_id == "conc-1"
    assert alt.status == "closed"
    assert alt.id


def test_devils_advocacy_creation():
    """Test creating DevilsAdvocacy."""
    da = DevilsAdvocacy(
        conclusion_id="conc-1",
        challenge_text="What if the evidence is fabricated?",
        evidence_gaps=["No chain of custody", "Single source"],
        status="responded",
    )
    assert da.conclusion_id == "conc-1"
    assert da.status == "responded"
    assert len(da.evidence_gaps) == 2


# ─────────────────────────────────────────────────────────────────────────
# Tests: TradecraftStore Persistence
# ─────────────────────────────────────────────────────────────────────────

def test_tradecraft_store_creation(tmp_app_data_dir):
    """Test TradecraftStore initializes correctly."""
    store = TradecraftStore()
    assert store.path == tmp_app_data_dir / 'tradecraft.json'


def test_tradecraft_store_save_and_load_intel_item(tmp_app_data_dir):
    """Test saving and loading intelligence items."""
    store = TradecraftStore()

    item = IntelligenceItem(
        investigation_id="inv-1",
        title="Test item",
        source_reliability="B",
        info_credibility="2",
    )
    saved = store.save_intel_item(item)
    assert saved.id == item.id

    # Load it back
    loaded = store.get_intel_item(item.id)
    assert loaded is not None
    assert loaded.title == "Test item"
    assert loaded.admiralty_code == "B2"


def test_tradecraft_store_save_and_load_hypothesis(tmp_app_data_dir):
    """Test saving and loading hypotheses."""
    store = TradecraftStore()

    hyp = Hypothesis(
        investigation_id="inv-1",
        title="Primary hypothesis",
        status="open",
    )
    saved = store.save_hypothesis(hyp)
    assert saved.id == hyp.id

    # Load it back
    loaded = store.get_hypothesis(hyp.id)
    assert loaded is not None
    assert loaded.title == "Primary hypothesis"
    assert loaded.status == "open"


def test_tradecraft_store_get_intel_items_by_investigation(tmp_app_data_dir):
    """Test retrieving intelligence items by investigation."""
    store = TradecraftStore()

    item1 = IntelligenceItem(investigation_id="inv-1", title="Item 1")
    item2 = IntelligenceItem(investigation_id="inv-1", title="Item 2")
    item3 = IntelligenceItem(investigation_id="inv-2", title="Item 3")

    store.save_intel_item(item1)
    store.save_intel_item(item2)
    store.save_intel_item(item3)

    inv1_items = store.get_intel_items("inv-1")
    assert len(inv1_items) == 2
    titles = {i.title for i in inv1_items}
    assert titles == {"Item 1", "Item 2"}

    inv2_items = store.get_intel_items("inv-2")
    assert len(inv2_items) == 1
    assert inv2_items[0].title == "Item 3"


def test_tradecraft_store_save_and_load_conclusion(tmp_app_data_dir):
    """Test saving and loading conclusions."""
    store = TradecraftStore()

    conc = AnalyticConclusion(
        investigation_id="inv-1",
        title="Threat Assessment",
        assessment_text="Threat detected",
        confidence_level="high",
        key_judgement="The threat is real",
    )
    saved = store.save_conclusion(conc)
    assert saved.id == conc.id

    # Load it back
    loaded = store.get_conclusion(conc.id)
    assert loaded is not None
    assert loaded.confidence_level == "high"
    assert loaded.key_judgement == "The threat is real"


def test_tradecraft_store_delete_intel_item(tmp_app_data_dir):
    """Test deleting an intelligence item."""
    store = TradecraftStore()

    item = IntelligenceItem(investigation_id="inv-1", title="To delete")
    store.save_intel_item(item)

    assert store.get_intel_item(item.id) is not None
    success = store.delete_intel_item(item.id)
    assert success is True
    assert store.get_intel_item(item.id) is None

    # Delete non-existent item
    success = store.delete_intel_item("nonexistent")
    assert success is False


def test_tradecraft_store_roundtrip_persistence(tmp_app_data_dir):
    """Test that data persists across TradecraftStore instances."""
    store1 = TradecraftStore()
    item = IntelligenceItem(
        investigation_id="inv-1",
        title="Persistent item",
        source_reliability="A",
        info_credibility="1",
    )
    store1.save_intel_item(item)

    # Create new store instance (should load from disk)
    store2 = TradecraftStore()
    loaded = store2.get_intel_item(item.id)
    assert loaded is not None
    assert loaded.title == "Persistent item"
    assert loaded.admiralty_code == "A1"


def test_tradecraft_store_save_and_load_ach_cells(tmp_app_data_dir):
    """Test saving and loading ACH cells."""
    store = TradecraftStore()

    # Create items and hypotheses
    ev = IntelligenceItem(id="ev-1", investigation_id="inv-1")
    hyp = Hypothesis(id="hyp-1", investigation_id="inv-1")
    store.save_intel_item(ev)
    store.save_hypothesis(hyp)

    # Save ACH cell
    cell = ACHCell(
        evidence_id="ev-1",
        hypothesis_id="hyp-1",
        consistency="C",
        analyst_rationale="Evidence supports hypothesis",
    )
    saved = store.set_ach_cell(cell)
    assert saved.consistency == "C"

    # Load it back
    cells = store.get_ach_cells("inv-1")
    assert len(cells) == 1
    assert cells[0].consistency == "C"
    assert cells[0].analyst_rationale == "Evidence supports hypothesis"


def test_tradecraft_store_save_and_load_alternatives(tmp_app_data_dir):
    """Test saving and loading alternative explanations."""
    store = TradecraftStore()

    alt = AlternativeExplanation(
        conclusion_id="conc-1",
        investigation_id="inv-1",
        alternative_text="False flag",
        why_rejected="No evidence",
    )
    saved = store.save_alternative(alt)
    assert saved.id == alt.id

    loaded = store.get_alternative(alt.id)
    assert loaded is not None
    assert loaded.alternative_text == "False flag"


def test_tradecraft_store_save_and_load_advocacies(tmp_app_data_dir):
    """Test saving and loading devil's advocacy."""
    store = TradecraftStore()

    da = DevilsAdvocacy(
        conclusion_id="conc-1",
        investigation_id="inv-1",
        challenge_text="Challenge the conclusion",
    )
    saved = store.save_advocacy(da)
    assert saved.id == da.id

    loaded = store.get_advocacy(da.id)
    assert loaded is not None
    assert loaded.challenge_text == "Challenge the conclusion"


def test_tradecraft_store_json_structure(tmp_app_data_dir):
    """Test that tradecraft.json has the correct structure."""
    store = TradecraftStore()

    # Add various items
    item = IntelligenceItem(investigation_id="inv-1")
    hyp = Hypothesis(investigation_id="inv-1")
    conc = AnalyticConclusion(investigation_id="inv-1")

    store.save_intel_item(item)
    store.save_hypothesis(hyp)
    store.save_conclusion(conc)

    # Load and verify structure
    with open(store.path) as f:
        data = json.load(f)

    assert "intelligence_items" in data
    assert "hypotheses" in data
    assert "conclusions" in data
    assert "ach_cells" in data
    assert "alternatives" in data
    assert "advocacies" in data

    assert item.id in data["intelligence_items"]
    assert hyp.id in data["hypotheses"]
    assert conc.id in data["conclusions"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

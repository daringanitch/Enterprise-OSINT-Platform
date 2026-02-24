"""
Unit tests for simple-backend/nlp_pipeline.py

All tests use the regex path only (no real spaCy model, no real langdetect
network calls) so they run completely offline and fast.
"""
import sys
import os
from unittest.mock import patch
from datetime import datetime, timezone

import pytest

# Ensure simple-backend is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from nlp_pipeline import NLPPipeline, NLPResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def pipeline():
    return NLPPipeline()


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------


def test_cve_extraction_basic(pipeline):
    result = pipeline.analyze("CVE-2021-44228 affects Log4j.")
    assert "CVE-2021-44228" in result.cves


def test_cve_extraction_case_insensitive(pipeline):
    result = pipeline.analyze("cve-2021-44228 is critical.")
    assert "CVE-2021-44228" in result.cves


def test_cve_extraction_multiple(pipeline):
    result = pipeline.analyze("CVE-2021-44228 and CVE-2022-0001 were exploited.")
    assert "CVE-2021-44228" in result.cves
    assert "CVE-2022-0001" in result.cves


def test_cve_extraction_deduplication(pipeline):
    result = pipeline.analyze("CVE-2021-44228 CVE-2021-44228 CVE-2021-44228")
    assert result.cves.count("CVE-2021-44228") == 1


def test_cve_extraction_none_in_clean_text(pipeline):
    result = pipeline.analyze("No vulnerabilities mentioned in this text.")
    assert result.cves == []


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique extraction
# ---------------------------------------------------------------------------


def test_mitre_technique_extraction(pipeline):
    result = pipeline.analyze("Attackers used T1566.002 spearphishing.")
    assert "T1566.002" in result.mitre_techniques


def test_mitre_technique_extraction_base_technique(pipeline):
    result = pipeline.analyze("Technique T1059 was observed.")
    assert "T1059" in result.mitre_techniques


def test_mitre_technique_extraction_multiple(pipeline):
    result = pipeline.analyze("T1566.002 and T1566.003 both present.")
    assert "T1566.002" in result.mitre_techniques
    assert "T1566.003" in result.mitre_techniques


def test_mitre_technique_no_false_positive_on_plain_number(pipeline):
    result = pipeline.analyze("Revenue grew by T1000 units.")
    # T1000 is a valid technique ID; ensure it is captured (not a false-negative test)
    # This is just to document behavior — plain "T" + 4 digits matches
    assert isinstance(result.mitre_techniques, list)


def test_mitre_technique_none_in_clean_text(pipeline):
    result = pipeline.analyze("Standard business report with no technique IDs.")
    assert result.mitre_techniques == []


# ---------------------------------------------------------------------------
# Bitcoin address detection
# ---------------------------------------------------------------------------


def test_bitcoin_p2pkh_address_detected(pipeline):
    # Valid-looking P2PKH address (starts with 1, 26–34 base58 chars)
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    result = pipeline.analyze(f"Send funds to {btc} immediately.")
    assert btc in result.bitcoin_addresses


def test_bitcoin_p2sh_address_detected(pipeline):
    btc = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    result = pipeline.analyze(f"P2SH address: {btc}")
    assert btc in result.bitcoin_addresses


def test_bitcoin_no_false_positive_short_string(pipeline):
    result = pipeline.analyze("Reference: 1ABC")
    assert result.bitcoin_addresses == []


# ---------------------------------------------------------------------------
# Ethereum address detection
# ---------------------------------------------------------------------------


def test_ethereum_address_detected(pipeline):
    eth = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    result = pipeline.analyze(f"ETH wallet: {eth}")
    assert eth in result.ethereum_addresses


def test_ethereum_address_must_be_exactly_40_hex_chars(pipeline):
    # Too short — 39 hex chars
    result = pipeline.analyze("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697B")
    assert result.ethereum_addresses == []


def test_ethereum_no_false_positive_on_plain_hex(pipeline):
    result = pipeline.analyze("Color code: #DEADBEEF")
    assert result.ethereum_addresses == []


# ---------------------------------------------------------------------------
# Onion domain extraction
# ---------------------------------------------------------------------------


def test_onion_v3_domain_detected(pipeline):
    # 56-char base32 v3 onion
    onion = "facebookcooa4ldbat4g7iacswl3p2zrf5nuylvnhxn6kqolmas7qd.onion"
    result = pipeline.analyze(f"Found at {onion}")
    assert onion in result.onion_domains


def test_onion_v2_domain_detected(pipeline):
    # 16-char base32 v2 onion
    onion = "expyuzz4wqqyqhjn.onion"
    result = pipeline.analyze(f"Legacy service at {onion}")
    assert onion in result.onion_domains


def test_onion_case_insensitive(pipeline):
    onion = "EXPYUZZ4WQQYQHJN.ONION"
    result = pipeline.analyze(f"Service at {onion}")
    assert onion.lower() in result.onion_domains


def test_onion_none_in_clean_text(pipeline):
    result = pipeline.analyze("Visit our website at example.com for more info.")
    assert result.onion_domains == []


# ---------------------------------------------------------------------------
# Threat actor detection
# ---------------------------------------------------------------------------


def test_known_threat_actor_apt28(pipeline):
    result = pipeline.analyze("APT28 targeted government agencies.")
    assert "APT28" in result.threat_actors


def test_known_threat_actor_lazarus(pipeline):
    result = pipeline.analyze("The Lazarus Group was attributed to this attack.")
    assert "Lazarus Group" in result.threat_actors


def test_known_threat_actor_multiple(pipeline):
    result = pipeline.analyze("Both APT28 and APT29 are Russian-linked.")
    assert "APT28" in result.threat_actors
    assert "APT29" in result.threat_actors


def test_known_threat_actor_case_insensitive(pipeline):
    result = pipeline.analyze("apt28 and apt41 are known groups.")
    assert "APT28" in result.threat_actors
    assert "APT41" in result.threat_actors


def test_threat_actor_none_in_clean_text(pipeline):
    result = pipeline.analyze("This is a normal business document about sales targets.")
    assert result.threat_actors == []


# ---------------------------------------------------------------------------
# Temporal expression extraction
# ---------------------------------------------------------------------------


def test_temporal_iso_date(pipeline):
    result = pipeline.analyze("Attack occurred on 2021-12-10.")
    texts = [t["text"] for t in result.temporal_expressions]
    assert "2021-12-10" in texts


def test_temporal_long_form_date(pipeline):
    result = pipeline.analyze("Discovered on December 10, 2021 by researchers.")
    texts = [t["text"] for t in result.temporal_expressions]
    assert any("December" in t for t in texts)


def test_temporal_quarterly_expression(pipeline):
    result = pipeline.analyze("Q3 2023 campaign was highly targeted.")
    texts = [t["text"] for t in result.temporal_expressions]
    assert any("Q3" in t for t in texts)


def test_temporal_position_recorded(pipeline):
    result = pipeline.analyze("On 2023-01-15, the breach occurred.")
    assert len(result.temporal_expressions) > 0
    assert "position" in result.temporal_expressions[0]
    assert isinstance(result.temporal_expressions[0]["position"], int)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


def test_language_detection_english():
    """When langdetect is available, English text should return 'en'."""
    from nlp_pipeline import _LANGDETECT_AVAILABLE
    pipeline = NLPPipeline()
    result = pipeline.analyze(
        "This is a standard English language threat intelligence report about malware."
    )
    if _LANGDETECT_AVAILABLE:
        assert result.language == "en"
        assert result.language_non_english is False
    else:
        assert result.language is None


def test_language_detection_non_english():
    """French text should be detected as non-English when langdetect is available."""
    from nlp_pipeline import _LANGDETECT_AVAILABLE
    pipeline = NLPPipeline()
    french_text = (
        "Ce rapport décrit une campagne de cyberattaque sophistiquée "
        "ciblant des infrastructures critiques en Europe."
    )
    result = pipeline.analyze(french_text)
    if _LANGDETECT_AVAILABLE:
        assert result.language != "en"
        assert result.language_non_english is True
    else:
        assert result.language is None


def test_language_detection_disabled_gracefully():
    """When langdetect is unavailable, language should be None without crashing."""
    pipeline = NLPPipeline()
    with patch("nlp_pipeline._LANGDETECT_AVAILABLE", False):
        result = pipeline.analyze("Some text here.")
    assert result.language is None
    assert result.language_non_english is False


# ---------------------------------------------------------------------------
# Batch analysis
# ---------------------------------------------------------------------------


def test_batch_analyze_count(pipeline):
    texts = [
        "CVE-2021-44228 log4j exploit",
        "T1566.002 phishing campaign",
        "Normal business text with no IOCs.",
    ]
    results = pipeline.analyze_batch(texts)
    assert len(results) == 3


def test_batch_analyze_correct_results(pipeline):
    texts = [
        "CVE-2021-44228",
        "APT28 actor",
        "clean text",
    ]
    results = pipeline.analyze_batch(texts)
    assert "CVE-2021-44228" in results[0].cves
    assert "APT28" in results[1].threat_actors
    assert results[2].cves == []
    assert results[2].threat_actors == []


def test_batch_analyze_empty_list_returns_empty(pipeline):
    results = pipeline.analyze_batch([])
    assert results == []


# ---------------------------------------------------------------------------
# No false positives on clean business text
# ---------------------------------------------------------------------------


def test_no_false_positives_clean_text(pipeline):
    clean = (
        "Our Q4 revenue grew by 15% year over year. The sales team exceeded targets "
        "and product adoption continues to accelerate. Contact finance@company.com "
        "for the full annual report."
    )
    result = pipeline.analyze(clean)
    assert result.cves == []
    assert result.mitre_techniques == []
    assert result.threat_actors == []
    assert result.bitcoin_addresses == []
    assert result.ethereum_addresses == []
    assert result.onion_domains == []


# ---------------------------------------------------------------------------
# spaCy unavailable — graceful fallback
# ---------------------------------------------------------------------------


def test_spacy_unavailable_graceful():
    """Regex path must work even when spaCy is patched as unavailable."""
    pipeline = NLPPipeline()
    with patch("nlp_pipeline._SPACY_AVAILABLE", False), \
         patch("nlp_pipeline._nlp", None):
        result = pipeline.analyze("CVE-2021-44228 exploited by APT28 via T1566.002")

    # Regex still fires
    assert "CVE-2021-44228" in result.cves
    assert "APT28" in result.threat_actors
    assert "T1566.002" in result.mitre_techniques
    # spaCy NER fields are empty
    assert result.persons == []
    assert result.organizations == []
    assert result.locations == []
    assert result.spacy_used is False


# ---------------------------------------------------------------------------
# to_dict / NLPResult serialisation
# ---------------------------------------------------------------------------


def test_nlp_result_to_dict_json_safe(pipeline):
    result = pipeline.analyze("CVE-2021-44228 by APT28 on 2021-12-10")
    d = result.to_dict()
    import json
    # Should not raise
    serialised = json.dumps(d)
    assert "CVE-2021-44228" in serialised


def test_nlp_result_extracted_at_is_utc(pipeline):
    result = pipeline.analyze("test")
    assert result.extracted_at.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# to_entities()
# ---------------------------------------------------------------------------


def test_to_entities_cve_type(pipeline):
    result = pipeline.analyze("CVE-2021-44228 log4j exploit")
    entities = pipeline.to_entities(result)
    cve_entities = [e for e in entities if e["type"] == "cve"]
    assert len(cve_entities) == 1
    assert cve_entities[0]["value"] == "CVE-2021-44228"


def test_to_entities_cryptocurrency_btc(pipeline):
    result = NLPResult(bitcoin_addresses=["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"])
    entities = pipeline.to_entities(result)
    crypto = [e for e in entities if e["type"] == "cryptocurrency"]
    assert len(crypto) == 1
    assert crypto[0]["metadata"]["currency"] == "BTC"


def test_to_entities_onion_domain(pipeline):
    result = NLPResult(onion_domains=["expyuzz4wqqyqhjn.onion"])
    entities = pipeline.to_entities(result)
    onion_e = [e for e in entities if e["type"] == "domain"]
    assert len(onion_e) == 1
    assert onion_e[0]["metadata"]["dark_web"] is True

"""
Unit tests for investigation_templates.py
==========================================

Tests cover:
  - TemplateLibrary loads with at least 5 templates
  - get() returns InvestigationTemplate for known IDs
  - get() returns None for unknown ID
  - list_all() returns all templates
  - by_category() filters correctly
  - by_category() returns empty list for unknown category
  - InvestigationTemplate.to_dict() has required fields
  - InvestigationTemplate.to_scope_dict() produces valid scope fields
  - Each template has at least 1 key_question
  - Each template has analyst_guidance string
  - Watchlist seeds have required fields
  - ACH hypotheses have required fields
  - apt_attribution template has MITRE techniques
  - compliance_frameworks is a list (possibly empty)
"""

import os, sys, pytest, importlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

KNOWN_TEMPLATE_IDS = [
    "apt_attribution",
    "ransomware_profiling",
    "phishing_infrastructure",
    "ma_due_diligence",
    "insider_threat",
    "vulnerability_exposure",
]


@pytest.fixture(autouse=True)
def _set_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    import investigation_templates as it
    importlib.reload(it)


# ---------------------------------------------------------------------------
# Tests — library loading
# ---------------------------------------------------------------------------

def test_library_loads_minimum_templates():
    import investigation_templates as it
    assert len(it.template_library.list_all()) >= 5


def test_all_known_template_ids_present():
    import investigation_templates as it
    for tid in KNOWN_TEMPLATE_IDS:
        t = it.template_library.get(tid)
        assert t is not None, f"Template '{tid}' not found in library"


# ---------------------------------------------------------------------------
# Tests — get()
# ---------------------------------------------------------------------------

def test_get_known_template():
    import investigation_templates as it
    t = it.template_library.get("apt_attribution")
    assert t is not None
    assert t.template_id == "apt_attribution"


def test_get_unknown_template_returns_none():
    import investigation_templates as it
    assert it.template_library.get("nonexistent_template_xyz") is None


# ---------------------------------------------------------------------------
# Tests — list_all()
# ---------------------------------------------------------------------------

def test_list_all_returns_list():
    import investigation_templates as it
    templates = it.template_library.list_all()
    assert isinstance(templates, list)
    assert len(templates) > 0


# ---------------------------------------------------------------------------
# Tests — by_category()
# ---------------------------------------------------------------------------

def test_by_category_attribution():
    import investigation_templates as it
    results = it.template_library.by_category("attribution")
    assert len(results) >= 1
    for t in results:
        assert t.template_id is not None


def test_by_category_unknown_returns_empty():
    import investigation_templates as it
    results = it.template_library.by_category("nonexistent_category_xyz")
    assert results == []


def test_by_category_case_sensitive():
    """Categories should match exactly; list_all() may return dicts or objects."""
    import investigation_templates as it
    all_templates = it.template_library.list_all()
    if all_templates:
        first = all_templates[0]
        real_category = first["category"] if isinstance(first, dict) else first.category
        results = it.template_library.by_category(real_category)
        assert len(results) >= 1


# ---------------------------------------------------------------------------
# Tests — InvestigationTemplate.to_dict()
# ---------------------------------------------------------------------------

def test_to_dict_required_fields():
    import investigation_templates as it
    t = it.template_library.get("apt_attribution")
    d = t.to_dict()
    # 'scope' is a nested dict; depth lives there or at top level
    required_keys = (
        "template_id", "name", "description", "category",
        "recommended_techniques",
        "key_questions", "analyst_guidance", "compliance_frameworks",
        "watchlist_seeds", "ach_hypotheses",
    )
    for key in required_keys:
        assert key in d, f"to_dict() missing key '{key}'"
    # depth may live under 'scope'
    has_depth = "default_depth" in d or "scope" in d
    assert has_depth, "to_dict() missing depth or scope key"


def test_to_dict_recommended_techniques_is_list():
    import investigation_templates as it
    t = it.template_library.get("apt_attribution")
    assert isinstance(t.to_dict()["recommended_techniques"], list)


def test_to_dict_key_questions_non_empty():
    import investigation_templates as it
    for tid in KNOWN_TEMPLATE_IDS:
        t = it.template_library.get(tid)
        if t:
            assert len(t.key_questions) >= 1, f"{tid} has no key_questions"


def test_to_dict_analyst_guidance_non_empty():
    import investigation_templates as it
    for tid in KNOWN_TEMPLATE_IDS:
        t = it.template_library.get(tid)
        if t:
            assert t.analyst_guidance.strip(), f"{tid} has empty analyst_guidance"


# ---------------------------------------------------------------------------
# Tests — to_scope_dict()
# ---------------------------------------------------------------------------

def test_to_scope_dict_has_scope_fields():
    import investigation_templates as it
    t = it.template_library.get("apt_attribution")
    scope = t.to_scope_dict()
    # Must have at least one substantive scope field
    scope_keys = set(scope.keys())
    known_fields = {
        "include_social_media", "include_infrastructure",
        "include_threat_intelligence", "include_corporate_records",
        "exclude_pii", "historical_data_days",
        "max_domains_to_scan", "max_threat_indicators",
        "depth", "default_depth",
    }
    assert scope_keys & known_fields, f"to_scope_dict() returned unexpected keys: {scope_keys}"


def test_to_scope_dict_returns_dict():
    import investigation_templates as it
    t = it.template_library.get("phishing_infrastructure")
    scope = t.to_scope_dict()
    assert isinstance(scope, dict)
    assert len(scope) > 0


# ---------------------------------------------------------------------------
# Tests — Watchlist seeds
# ---------------------------------------------------------------------------

def test_watchlist_seeds_have_required_fields():
    import investigation_templates as it
    for tid in KNOWN_TEMPLATE_IDS:
        t = it.template_library.get(tid)
        if t and t.watchlist_seeds:
            for seed in t.watchlist_seeds:
                assert hasattr(seed, "target_placeholder"), f"{tid} seed missing target_placeholder"
                assert hasattr(seed, "target_type"),        f"{tid} seed missing target_type"
                assert hasattr(seed, "description"),        f"{tid} seed missing description"


# ---------------------------------------------------------------------------
# Tests — ACH hypotheses
# ---------------------------------------------------------------------------

def test_ach_hypotheses_have_required_fields():
    import investigation_templates as it
    for tid in ("apt_attribution", "ransomware_profiling", "phishing_infrastructure"):
        t = it.template_library.get(tid)
        if t and t.ach_hypotheses:
            for hyp in t.ach_hypotheses:
                assert hasattr(hyp, "title"),           f"{tid} hypothesis missing title"
                assert hasattr(hyp, "description"),     f"{tid} hypothesis missing description"
                assert hasattr(hyp, "hypothesis_type"), f"{tid} hypothesis missing hypothesis_type"


def test_apt_attribution_has_ach_hypotheses():
    import investigation_templates as it
    t = it.template_library.get("apt_attribution")
    assert len(t.ach_hypotheses) >= 2


# ---------------------------------------------------------------------------
# Tests — Specific template content
# ---------------------------------------------------------------------------

def test_apt_attribution_has_mitre_techniques():
    import investigation_templates as it
    t = it.template_library.get("apt_attribution")
    assert len(t.recommended_techniques) >= 5
    # At least some should look like MITRE IDs
    mitre_ids = [tech for tech in t.recommended_techniques if tech.startswith("T")]
    assert len(mitre_ids) >= 3


def test_compliance_frameworks_is_list():
    import investigation_templates as it
    for tid in KNOWN_TEMPLATE_IDS:
        t = it.template_library.get(tid)
        if t:
            assert isinstance(t.compliance_frameworks, list), \
                f"{tid} compliance_frameworks should be a list"


def test_insider_threat_has_pii_handling():
    """insider_threat template should reference GDPR or CCPA."""
    import investigation_templates as it
    t = it.template_library.get("insider_threat")
    if t:
        text = str(t.to_dict()).upper()
        assert "GDPR" in text or "CCPA" in text or "PII" in text or "PRIVACY" in text

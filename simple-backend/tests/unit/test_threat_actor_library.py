"""
Unit tests for threat_actor_library.py
=======================================

Tests cover:
  - Library loads with at least 20 actors
  - get() returns a ThreatActorDossier for a known ID
  - get() returns None for unknown ID
  - search() finds actors by name fragment
  - search() finds actors by alias
  - find_by_technique() returns actors using a given MITRE ID
  - find_by_sector() returns actors targeting a given sector
  - match_ttps() ranks actors by overlap score, returns top_n
  - match_ttps() overlap_score is between 0 and 1
  - match_ttps() matched_techniques lists only the intersection
  - summary_list() returns compact dicts with required keys
  - ThreatActorDossier.to_dict() has all required fields
  - Nation-state actors have type 'nation-state'
  - Criminal actors have motivation 'financial'
"""

import os, sys, pytest, importlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))


@pytest.fixture(autouse=True)
def _set_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    import threat_actor_library as tal
    importlib.reload(tal)


# ---------------------------------------------------------------------------
# Tests — library loading
# ---------------------------------------------------------------------------

def test_library_loads_minimum_actors():
    import threat_actor_library as tal
    assert len(tal.actor_library.summary_list()) >= 20


# ---------------------------------------------------------------------------
# Tests — get()
# ---------------------------------------------------------------------------

def test_get_known_actor_by_id():
    import threat_actor_library as tal
    actor = tal.actor_library.get("apt28")
    assert actor is not None
    assert "APT28" in actor.name or "apt28" in actor.actor_id.lower()


def test_get_unknown_actor_returns_none():
    import threat_actor_library as tal
    assert tal.actor_library.get("nonexistent_actor_xyz") is None


# ---------------------------------------------------------------------------
# Tests — search()
# ---------------------------------------------------------------------------

def test_search_by_name_fragment():
    import threat_actor_library as tal
    results = tal.actor_library.search("Lazarus")
    assert len(results) >= 1
    names = [a.name for a in results]
    assert any("Lazarus" in n for n in names)


def test_search_by_alias():
    import threat_actor_library as tal
    # APT29 is also known as Cozy Bear
    results = tal.actor_library.search("Cozy Bear")
    assert len(results) >= 1


def test_search_empty_query_returns_empty_or_all():
    """Empty query should return [] or all actors — not crash."""
    import threat_actor_library as tal
    try:
        results = tal.actor_library.search("")
        assert isinstance(results, list)
    except Exception as exc:
        pytest.fail(f"search('') raised an exception: {exc}")


# ---------------------------------------------------------------------------
# Tests — find_by_technique()
# ---------------------------------------------------------------------------

def test_find_by_technique_spearphishing():
    import threat_actor_library as tal
    # T1566.001 (Spearphishing Attachment) is widely used
    results = tal.actor_library.find_by_technique("T1566.001")
    assert len(results) >= 1


def test_find_by_technique_unknown_returns_empty():
    import threat_actor_library as tal
    results = tal.actor_library.find_by_technique("T9999.999")
    assert results == []


# ---------------------------------------------------------------------------
# Tests — find_by_sector()
# ---------------------------------------------------------------------------

def test_find_by_sector_financial():
    import threat_actor_library as tal
    results = tal.actor_library.find_by_sector("financial")
    assert len(results) >= 1


def test_find_by_sector_case_insensitive():
    import threat_actor_library as tal
    lower = tal.actor_library.find_by_sector("government")
    upper = tal.actor_library.find_by_sector("Government")
    assert len(lower) == len(upper)


# ---------------------------------------------------------------------------
# Tests — match_ttps()
# ---------------------------------------------------------------------------

def test_match_ttps_returns_list():
    import threat_actor_library as tal
    results = tal.actor_library.match_ttps(["T1566.001", "T1071.001"])
    assert isinstance(results, list)


def test_match_ttps_returns_ttp_match_results():
    """match_ttps returns TTPMatchResult objects with actor, matched_techniques, match_score."""
    import threat_actor_library as tal
    results = tal.actor_library.match_ttps(["T1566.001"], min_match=1)
    assert isinstance(results, list)
    if results:
        r = results[0]
        assert hasattr(r, "actor")
        assert hasattr(r, "matched_techniques")
        assert hasattr(r, "match_score")


def test_match_ttps_overlap_score_range():
    import threat_actor_library as tal
    results = tal.actor_library.match_ttps(["T1566.001", "T1071.001"], min_match=1)
    for r in results:
        assert 0.0 <= r.match_score <= 1.0, f"match_score out of range: {r.match_score}"


def test_match_ttps_matched_techniques_subset():
    """matched_techniques should only contain techniques from the query."""
    import threat_actor_library as tal
    queried = ["T1566.001", "T1071.001", "T1090.003"]
    results = tal.actor_library.match_ttps(queried, min_match=1)
    for r in results:
        for t in r.matched_techniques:
            assert t in queried, f"Matched technique {t} not in query"


def test_match_ttps_sorted_descending():
    import threat_actor_library as tal
    results = tal.actor_library.match_ttps(["T1566.001", "T1071.001"], min_match=1)
    scores = [r.match_score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_match_ttps_no_techniques_returns_empty_or_all():
    import threat_actor_library as tal
    try:
        results = tal.actor_library.match_ttps([], min_match=1)
        assert isinstance(results, list)
    except Exception:
        pass  # Raising on empty input is acceptable


# ---------------------------------------------------------------------------
# Tests — summary_list()
# ---------------------------------------------------------------------------

def test_summary_list_required_keys():
    import threat_actor_library as tal
    summaries = tal.actor_library.summary_list()
    required = {"actor_id", "name", "actor_type", "motivation"}
    for s in summaries[:5]:
        for key in required:
            assert key in s, f"summary missing key '{key}'"


# ---------------------------------------------------------------------------
# Tests — ThreatActorDossier.to_dict()
# ---------------------------------------------------------------------------

def test_to_dict_has_required_fields():
    import threat_actor_library as tal
    actor = tal.actor_library.get("apt28")
    if actor is None:
        summaries = tal.actor_library.summary_list()
        actor = tal.actor_library.get(summaries[0]["actor_id"])
    d = actor.to_dict()
    for key in ("actor_id", "name", "actor_type", "motivation", "mitre_techniques"):
        assert key in d, f"to_dict() missing key '{key}'"


# ---------------------------------------------------------------------------
# Tests — type / motivation classification
# ---------------------------------------------------------------------------

def test_apt28_is_nation_state():
    import threat_actor_library as tal
    actor = tal.actor_library.get("apt28")
    if actor:
        assert actor.actor_type.lower() in ("nation-state", "nation_state", "nation state")


def test_fin7_is_criminal_or_financial():
    import threat_actor_library as tal
    results = tal.actor_library.search("FIN7")
    if results:
        actor = results[0]
        assert actor.actor_type.lower() in ("criminal", "cybercriminal") or \
               actor.motivation.lower() == "financial"

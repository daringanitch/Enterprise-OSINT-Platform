#!/usr/bin/env python3
"""
Unit tests for utils.geographical_scope.

Tests:
  - normalize_country() across alpha-2 codes, country names, and placeholders
  - derive_geographical_scope() reading every field that carries a country
  - expand_region_aliases() turning 'EU' into member-state codes
  - the regression this module fixes: scope derived from real collector output
"""

import pytest

from models import InfrastructureIntelligence
from utils.geographical_scope import (
    EU_MEMBER_STATES,
    derive_geographical_scope,
    expand_region_aliases,
    normalize_country,
)


# ─────────────────────────────────────────────────────────────────────────
# normalize_country
# ─────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('value,expected', [
    ('US', 'US'),
    ('us', 'US'),
    (' de ', 'DE'),
    ('United States', 'US'),
    ('united states of america', 'US'),
    ('Germany', 'DE'),
    ('United Kingdom', 'GB'),
    ('Brazil', 'BR'),
])
def test_normalize_country_recognized(value, expected):
    assert normalize_country(value) == expected


@pytest.mark.parametrize('value', [
    'Unknown', 'unknown', 'N/A', 'none', '', '   ', '-',
])
def test_normalize_country_rejects_placeholders(value):
    assert normalize_country(value) is None


@pytest.mark.parametrize('value', [
    None, 42, [], {}, 'Republic of Nowhere', 'XYZ',
])
def test_normalize_country_rejects_unusable(value):
    assert normalize_country(value) is None


def test_normalize_country_never_maps_us_state_to_country_code():
    """'California' must not become 'CA', which is Canada and triggers PIPEDA."""
    assert normalize_country('California') is None


# ─────────────────────────────────────────────────────────────────────────
# derive_geographical_scope
# ─────────────────────────────────────────────────────────────────────────

def test_derive_returns_empty_for_missing_intelligence():
    assert derive_geographical_scope(None) == []
    assert derive_geographical_scope(InfrastructureIntelligence()) == []


def test_derive_reads_geolocated_ip_country_code():
    """ip-api returns 'countryCode'; that is the field geoip wiring will store."""
    infra = InfrastructureIntelligence(
        ip_addresses=[{'ip': '8.8.8.8', 'countryCode': 'US'}]
    )
    assert derive_geographical_scope(infra) == ['US']


def test_derive_reads_whois_registrant_country():
    infra = InfrastructureIntelligence(
        domains=[{'domain': 'example.de', 'country': 'DE'}]
    )
    assert derive_geographical_scope(infra) == ['DE']


def test_derive_reads_shodan_country_name():
    """Shodan returns a full country name, not a code."""
    infra = InfrastructureIntelligence(
        exposed_services=[{'port': 443, 'country': 'United States'}]
    )
    assert derive_geographical_scope(infra) == ['US']


def test_derive_merges_all_sources_and_deduplicates():
    infra = InfrastructureIntelligence(
        ip_addresses=[
            {'ip': '1.1.1.1', 'countryCode': 'US'},
            {'ip': '2.2.2.2', 'country': 'France'},
        ],
        domains=[{'domain': 'example.com', 'country': 'US'}],
        exposed_services=[{'port': 80, 'country': 'Germany'}],
    )
    assert derive_geographical_scope(infra) == ['US', 'FR', 'DE']


def test_derive_skips_unknown_and_malformed_entries():
    infra = InfrastructureIntelligence(
        ip_addresses=[
            {'ip': '1.1.1.1', 'country': 'Unknown'},
            'not-a-dict',
            {'ip': '3.3.3.3'},
        ],
        exposed_services=[{'port': 443, 'country': 'Unknown'}],
    )
    assert derive_geographical_scope(infra) == []


def test_derive_handles_legacy_location_key():
    """Older records and the simulated fallback use 'location'."""
    infra = InfrastructureIntelligence(
        ip_addresses=[{'ip': '192.168.1.100', 'location': 'US'}]
    )
    assert derive_geographical_scope(infra) == ['US']


def test_derive_matches_real_dns_collector_output_shape():
    """Regression: the orchestrator's DNS branch stores no country at all.

    Before the fix this silently produced a hardcoded scope. It must now
    produce an empty scope so the caller can apply an explicit fallback.
    """
    infra = InfrastructureIntelligence(
        ip_addresses=[
            {'ip': '93.184.216.34', 'source': 'dns_resolution_enhanced',
             'record_type': 'A'},
        ]
    )
    assert derive_geographical_scope(infra) == []


# ─────────────────────────────────────────────────────────────────────────
# expand_region_aliases
# ─────────────────────────────────────────────────────────────────────────

def test_expand_eu_alias_to_member_states():
    expanded = expand_region_aliases(['EU'])
    assert set(expanded) == set(EU_MEMBER_STATES)


def test_expand_preserves_country_codes_and_subdivisions():
    assert expand_region_aliases(['US', 'US-CA']) == ['US', 'US-CA']


def test_expand_deduplicates_across_alias_and_explicit_code():
    expanded = expand_region_aliases(['DE', 'EU'])
    assert expanded.count('DE') == 1


def test_expand_handles_empty_and_malformed():
    assert expand_region_aliases([]) == []
    assert expand_region_aliases(None) == []
    assert expand_region_aliases([None, 42, 'US']) == ['US']

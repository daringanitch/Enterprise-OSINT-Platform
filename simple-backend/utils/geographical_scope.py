#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Derive an investigation's geographical scope from collected infrastructure data.

The compliance framework matches jurisdictions on ISO 3166-1 alpha-2 country
codes, but the intelligence sources disagree on format: Shodan returns country
names ("United States"), WHOIS returns alpha-2 codes ("US"), and ip-api returns
both. This module normalizes whatever is present into alpha-2 codes.

Only country-level codes are emitted. 'US-CA' (California, for CCPA) is a
subdivision code added by the caller, not derived here.
"""

import logging

logger = logging.getLogger(__name__)

# Region alias understood by the compliance framework's jurisdiction matching.
# Not an ISO country code, so it is expanded before matching.
EU_MEMBER_STATES = frozenset({
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR',
    'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL',
    'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
})

# Country names seen in Shodan/ip-api responses, mapped to alpha-2.
# Deliberately partial: unrecognized names are dropped rather than guessed,
# because a wrong jurisdiction is worse than a missing one.
_COUNTRY_NAME_TO_CODE = {
    'united states': 'US',
    'united states of america': 'US',
    'usa': 'US',
    'united kingdom': 'GB',
    'great britain': 'GB',
    'canada': 'CA',
    'germany': 'DE',
    'france': 'FR',
    'netherlands': 'NL',
    'ireland': 'IE',
    'spain': 'ES',
    'italy': 'IT',
    'sweden': 'SE',
    'poland': 'PL',
    'belgium': 'BE',
    'austria': 'AT',
    'denmark': 'DK',
    'finland': 'FI',
    'portugal': 'PT',
    'czechia': 'CZ',
    'czech republic': 'CZ',
    'romania': 'RO',
    'bulgaria': 'BG',
    'greece': 'GR',
    'hungary': 'HU',
    'croatia': 'HR',
    'slovakia': 'SK',
    'slovenia': 'SI',
    'estonia': 'EE',
    'latvia': 'LV',
    'lithuania': 'LT',
    'luxembourg': 'LU',
    'malta': 'MT',
    'cyprus': 'CY',
    'brazil': 'BR',
    'australia': 'AU',
    'japan': 'JP',
    'india': 'IN',
    'singapore': 'SG',
    'switzerland': 'CH',
    'norway': 'NO',
    'china': 'CN',
    'russia': 'RU',
    'russian federation': 'RU',
    'south korea': 'KR',
    'korea, republic of': 'KR',
    'mexico': 'MX',
    'south africa': 'ZA',
    'new zealand': 'NZ',
    'israel': 'IL',
    'turkey': 'TR',
    'ukraine': 'UA',
}

# Values that appear in place of real data and must never become a jurisdiction.
_PLACEHOLDERS = frozenset({'unknown', 'n/a', 'na', 'none', 'null', '-', ''})


def normalize_country(value) -> str | None:
    """Normalize a country name or code to ISO 3166-1 alpha-2, or None.

    Returns None for placeholders, unrecognized names, and non-strings, so
    callers can filter without guessing at ambiguous input.
    """
    if not isinstance(value, str):
        return None

    cleaned = value.strip()
    if cleaned.lower() in _PLACEHOLDERS:
        return None

    # Already an alpha-2 code.
    if len(cleaned) == 2 and cleaned.isalpha():
        return cleaned.upper()

    return _COUNTRY_NAME_TO_CODE.get(cleaned.lower())


def derive_geographical_scope(infrastructure_intelligence) -> list:
    """Collect ISO alpha-2 country codes from an InfrastructureIntelligence record.

    Reads every field that carries country information today: geolocated IP
    addresses, WHOIS registrant countries on domains, and Shodan country names
    on exposed services. Returns codes in first-seen order, deduplicated.
    Returns an empty list when nothing geographic was collected — the caller
    decides what an empty scope means.
    """
    if not infrastructure_intelligence:
        return []

    scope = []

    def _add(value):
        code = normalize_country(value)
        if code and code not in scope:
            scope.append(code)

    # IP geolocation. 'countryCode' is ip-api's field name; 'country' and
    # 'location' are the shapes older records and fallbacks use.
    for ip_info in getattr(infrastructure_intelligence, 'ip_addresses', None) or []:
        if not isinstance(ip_info, dict):
            continue
        for key in ('countryCode', 'country_code', 'country', 'location'):
            if key in ip_info:
                _add(ip_info[key])

    # WHOIS registrant country.
    for domain in getattr(infrastructure_intelligence, 'domains', None) or []:
        if isinstance(domain, dict):
            _add(domain.get('country'))

    # Shodan country names on exposed services.
    for service in getattr(infrastructure_intelligence, 'exposed_services', None) or []:
        if isinstance(service, dict):
            _add(service.get('country'))

    return scope


def expand_region_aliases(scope) -> list:
    """Expand non-ISO region aliases (currently 'EU') into member country codes.

    The compliance framework matches alpha-2 codes only, so a literal 'EU' in
    a scope list silently matches nothing. Callers that may carry aliases run
    the scope through this before jurisdiction matching.
    """
    expanded = []
    for entry in scope or []:
        if not isinstance(entry, str):
            continue
        value = entry.strip().upper()
        if value == 'EU':
            for code in sorted(EU_MEMBER_STATES):
                if code not in expanded:
                    expanded.append(code)
        elif value and value not in expanded:
            expanded.append(value)
    return expanded


def merge_geolocation(ip_addresses: list, geo: dict) -> list:
    """Merge a geolocation result onto the matching entry in `ip_addresses`.

    Coordinates travel with the IP they describe rather than sitting in a
    side channel, so anything reading `ip_addresses` (compliance scope, the
    report generator, a map view) sees them without a second lookup.

    Existing keys on the entry are preserved unless geolocation supplies a
    value — DNS provenance such as `source` and `record_type` must survive.
    An IP that no entry matches is appended, since geolocation can arrive for
    an address DNS did not surface.
    """
    if not isinstance(geo, dict):
        return ip_addresses

    geo_ip = geo.get('ip')
    if not geo_ip:
        return ip_addresses

    fields = {
        'countryCode': geo.get('countryCode'),
        'country': geo.get('country'),
        'city': geo.get('city'),
        'region': geo.get('region'),
        'latitude': geo.get('latitude'),
        'longitude': geo.get('longitude'),
        'accuracy_radius_km': geo.get('accuracy_radius_km'),
        'geo_source': geo.get('data_source'),
    }
    # Drop empties so a partial result can't blank a value another source set.
    fields = {k: v for k, v in fields.items() if v is not None}

    matched = False
    for entry in ip_addresses:
        if isinstance(entry, dict) and entry.get('ip') == geo_ip:
            entry.update(fields)
            matched = True

    if not matched:
        ip_addresses.append({'ip': geo_ip, 'source': 'geolocation', **fields})

    return ip_addresses

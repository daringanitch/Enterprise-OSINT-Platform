#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Service Configuration Manager
==============================

Central catalog of all intelligence services, their tiers, API key requirements,
and persistent configuration storage.

Design goals:
  - Every service works in some form without an API key (free tier or mock)
  - Clear distinction between free / freemium / paid services
  - Keys stored in a local JSON file that survives container restarts
  - Keys are loaded into os.environ so existing code picks them up automatically
"""

import os
import json
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ServiceDefinition:
    """Static definition of a service – never changes at runtime."""
    id: str                         # Unique snake_case identifier
    name: str                       # Display name
    description: str                # One-line purpose
    category: str                   # "threat" | "network" | "social" | "ai" | "breach"
    tier: str                       # "free" | "freemium" | "paid"
    tier_note: str                  # Human-readable tier summary, e.g. "500 req/day free"
    works_without_key: bool         # True if the service provides value without a key
    env_var: Optional[str]          # Environment variable name for the API key
    signup_url: Optional[str]       # Where to get a free key
    docs_url: Optional[str]         # API documentation
    rate_limit_note: Optional[str]  # e.g. "4 req/min on free plan"
    enabled_by_default: bool        # Should the service be active out of the box


# ---------------------------------------------------------------------------
# Service catalog
# ---------------------------------------------------------------------------

SERVICE_CATALOG: List[ServiceDefinition] = [

    # ── Free (no key needed) ──────────────────────────────────────────────

    ServiceDefinition(
        id="dns",
        name="DNS Resolution",
        description="Resolve domain names to IPs, enumerate subdomains, check DNS records (A, MX, TXT, NS, CNAME).",
        category="network",
        tier="free",
        tier_note="Completely free – uses system resolver",
        works_without_key=True,
        env_var=None,
        signup_url=None,
        docs_url=None,
        rate_limit_note=None,
        enabled_by_default=True,
    ),
    ServiceDefinition(
        id="whois",
        name="WHOIS Lookup",
        description="Domain registrar information, registration dates, name servers, and registrant contact details.",
        category="network",
        tier="free",
        tier_note="Completely free – standard WHOIS protocol",
        works_without_key=True,
        env_var=None,
        signup_url=None,
        docs_url=None,
        rate_limit_note=None,
        enabled_by_default=True,
    ),
    ServiceDefinition(
        id="certificate_transparency",
        name="Certificate Transparency (crt.sh)",
        description="Discover subdomains via SSL/TLS certificate logs. Reveals hidden infrastructure without active scanning.",
        category="network",
        tier="free",
        tier_note="Completely free – no key needed",
        works_without_key=True,
        env_var=None,
        signup_url="https://crt.sh",
        docs_url="https://crt.sh",
        rate_limit_note="Soft rate limit – be polite",
        enabled_by_default=True,
    ),
    ServiceDefinition(
        id="ip_geolocation",
        name="IP Geolocation (ip-api.com)",
        description="Country, city, ISP, ASN, and GPS coordinates for IP addresses.",
        category="network",
        tier="free",
        tier_note="45 req/min free, no key required",
        works_without_key=True,
        env_var=None,
        signup_url="https://ip-api.com",
        docs_url="https://ip-api.com/docs",
        rate_limit_note="45 req/min on free tier",
        enabled_by_default=True,
    ),
    ServiceDefinition(
        id="urlscan",
        name="URLScan.io",
        description="Submit URLs for sandboxed scanning – screenshots, network traffic, DOM analysis, verdicts.",
        category="threat",
        tier="freemium",
        tier_note="Basic lookups free; API key unlocks higher limits",
        works_without_key=True,
        env_var="URLSCAN_API_KEY",
        signup_url="https://urlscan.io/user/signup",
        docs_url="https://urlscan.io/docs/api/",
        rate_limit_note="Public scans are rate-limited; key gives 5,000/day",
        enabled_by_default=True,
    ),
    ServiceDefinition(
        id="malwarebazaar",
        name="MalwareBazaar (abuse.ch)",
        description="Query a public malware database for file hashes, malware families, tags, and signatures.",
        category="threat",
        tier="free",
        tier_note="Completely free – no key needed",
        works_without_key=True,
        env_var=None,
        signup_url="https://bazaar.abuse.ch",
        docs_url="https://bazaar.abuse.ch/api/",
        rate_limit_note="Fair-use rate limit",
        enabled_by_default=True,
    ),
    ServiceDefinition(
        id="threatfox",
        name="ThreatFox (abuse.ch)",
        description="Community IOC database: IPs, domains, URLs, and file hashes linked to malware campaigns.",
        category="threat",
        tier="free",
        tier_note="Completely free – no key needed",
        works_without_key=True,
        env_var=None,
        signup_url="https://threatfox.abuse.ch",
        docs_url="https://threatfox.abuse.ch/api/",
        rate_limit_note="Fair-use rate limit",
        enabled_by_default=True,
    ),

    # ── Freemium (free with a free account / API key) ─────────────────────

    ServiceDefinition(
        id="virustotal",
        name="VirusTotal",
        description="Scan files, URLs, IPs, and domains against 70+ antivirus engines and intelligence feeds.",
        category="threat",
        tier="freemium",
        tier_note="Free: 500 lookups/day, 4 req/min",
        works_without_key=False,
        env_var="VIRUSTOTAL_API_KEY",
        signup_url="https://www.virustotal.com/gui/join-us",
        docs_url="https://developers.virustotal.com/reference",
        rate_limit_note="4 req/min / 500 req/day on free plan",
        enabled_by_default=False,
    ),
    ServiceDefinition(
        id="abuseipdb",
        name="AbuseIPDB",
        description="IP reputation database – reports of malicious activity, confidence scores, ISP, usage type.",
        category="threat",
        tier="freemium",
        tier_note="Free: 1,000 checks/day",
        works_without_key=False,
        env_var="ABUSEIPDB_API_KEY",
        signup_url="https://www.abuseipdb.com/register",
        docs_url="https://docs.abuseipdb.com/",
        rate_limit_note="1,000 req/day on free plan",
        enabled_by_default=False,
    ),
    ServiceDefinition(
        id="alienvault_otx",
        name="AlienVault OTX",
        description="Open Threat Exchange – community pulses, IOC enrichment, threat actor profiles.",
        category="threat",
        tier="freemium",
        tier_note="Free with account – unlimited community lookups",
        works_without_key=False,
        env_var="ALIENVAULT_API_KEY",
        signup_url="https://otx.alienvault.com/accounts/signup",
        docs_url="https://otx.alienvault.com/api",
        rate_limit_note="No hard limit on free community plan",
        enabled_by_default=False,
    ),
    ServiceDefinition(
        id="greynoise",
        name="GreyNoise Community",
        description="Determine if an IP is scanning the internet vs. targeting you. Reduces alert fatigue.",
        category="threat",
        tier="freemium",
        tier_note="Free: 50 req/day community API",
        works_without_key=False,
        env_var="GREYNOISE_API_KEY",
        signup_url="https://www.greynoise.io/signup",
        docs_url="https://docs.greynoise.io/",
        rate_limit_note="50 req/day on free community plan",
        enabled_by_default=False,
    ),
    ServiceDefinition(
        id="hibp",
        name="Have I Been Pwned",
        description="Check if email addresses or domains appear in known data breaches.",
        category="breach",
        tier="freemium",
        tier_note="Password check free; breach search needs free key (limited) or paid",
        works_without_key=True,
        env_var="HIBP_API_KEY",
        signup_url="https://haveibeenpwned.com/API/Key",
        docs_url="https://haveibeenpwned.com/API/v3",
        rate_limit_note="1 req/1.5s on free plan; paid plans unlocked",
        enabled_by_default=True,
    ),
    ServiceDefinition(
        id="shodan",
        name="Shodan",
        description="Internet-wide port scan data, service banners, vulnerabilities, device fingerprinting.",
        category="network",
        tier="freemium",
        tier_note="Free: limited 2 credits/month; full access from $49/mo",
        works_without_key=False,
        env_var="SHODAN_API_KEY",
        signup_url="https://account.shodan.io/register",
        docs_url="https://developer.shodan.io/api",
        rate_limit_note="Free plan: 2 query credits/month (very limited)",
        enabled_by_default=False,
    ),
    ServiceDefinition(
        id="censys",
        name="Censys",
        description="Internet-wide scan data for hosts, certificates, and services. Alternative to Shodan.",
        category="network",
        tier="freemium",
        tier_note="Free: 250 queries/month",
        works_without_key=False,
        env_var="CENSYS_API_ID",
        signup_url="https://search.censys.io/register",
        docs_url="https://search.censys.io/api",
        rate_limit_note="250 queries/month on free plan",
        enabled_by_default=False,
    ),
    ServiceDefinition(
        id="github",
        name="GitHub",
        description="Search public repositories, code, commits, and user profiles for intelligence gathering.",
        category="social",
        tier="freemium",
        tier_note="Free: 10 unauthenticated req/min; key gives 30/min",
        works_without_key=True,
        env_var="GITHUB_TOKEN",
        signup_url="https://github.com/settings/tokens",
        docs_url="https://docs.github.com/en/rest",
        rate_limit_note="30 req/min with free token",
        enabled_by_default=True,
    ),

    # ── Paid (optional premium features) ─────────────────────────────────

    ServiceDefinition(
        id="openai",
        name="OpenAI (GPT-4)",
        description="AI-powered threat profiling, pattern analysis, executive summaries, and investigation narratives.",
        category="ai",
        tier="paid",
        tier_note="Pay-per-token; ~$0.01–$0.03 per investigation summary",
        works_without_key=False,
        env_var="OPENAI_API_KEY",
        signup_url="https://platform.openai.com/signup",
        docs_url="https://platform.openai.com/docs",
        rate_limit_note="Depends on your tier / spend limit",
        enabled_by_default=False,
    ),
    ServiceDefinition(
        id="twitter",
        name="Twitter / X",
        description="Search tweets, user profiles, and follower networks for social intelligence.",
        category="social",
        tier="paid",
        tier_note="Basic access $100/mo; free tier deprecated in 2023",
        works_without_key=False,
        env_var="TWITTER_BEARER_TOKEN",
        signup_url="https://developer.twitter.com/en/portal/petition/basic/basic-info",
        docs_url="https://developer.twitter.com/en/docs",
        rate_limit_note="Basic: 500k tweets/month",
        enabled_by_default=False,
    ),
    ServiceDefinition(
        id="dehashed",
        name="Dehashed",
        description="Breached credential search across billions of records – emails, usernames, passwords, IPs.",
        category="breach",
        tier="paid",
        tier_note="From $5.49/mo; individual queries also available",
        works_without_key=False,
        env_var="DEHASHED_API_KEY",
        signup_url="https://dehashed.com/register",
        docs_url="https://dehashed.com/docs",
        rate_limit_note="Depends on subscription tier",
        enabled_by_default=False,
    ),
    ServiceDefinition(
        id="shodan_premium",
        name="Shodan (Membership)",
        description="Full Shodan API access including historic data, vulnerability tracking, and alerts.",
        category="network",
        tier="paid",
        tier_note="Membership from $49; API plan from $999/year",
        works_without_key=False,
        env_var="SHODAN_API_KEY",  # Same env var as free Shodan
        signup_url="https://account.shodan.io/billing/plan",
        docs_url="https://developer.shodan.io/api",
        rate_limit_note="100 query credits/month on membership",
        enabled_by_default=False,
    ),
]


# ---------------------------------------------------------------------------
# Config storage
# ---------------------------------------------------------------------------

class ServiceConfigManager:
    """
    Manages enabled/disabled state for services and persists API keys
    to a local JSON file. Keys are injected into os.environ so all
    existing code continues to work unchanged.
    """

    def __init__(self):
        data_dir = os.environ.get('APP_DATA_DIR', '/app/data')
        self.config_path = Path(data_dir) / 'service_config.json'
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._config: Dict[str, Any] = self._load()
        self._apply_keys_to_env()

    # ── Persistence ────────────────────────────────────────────────────────

    def _load(self) -> Dict[str, Any]:
        """Load config from disk (or create defaults)."""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"service_config.json unreadable, resetting: {e}")

        # Build default config from catalog
        default: Dict[str, Any] = {
            "services": {},
            "api_keys": {},  # env_var -> encrypted-ish stored value
            "updated_at": datetime.utcnow().isoformat(),
        }
        for svc in SERVICE_CATALOG:
            default["services"][svc.id] = {
                "enabled": svc.enabled_by_default,
            }
        return default

    def _save(self):
        """Persist config to disk."""
        self._config["updated_at"] = datetime.utcnow().isoformat()
        try:
            with open(self.config_path, "w") as f:
                json.dump(self._config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save service_config.json: {e}")

    def _apply_keys_to_env(self):
        """Inject stored API keys into os.environ."""
        for env_var, key_value in self._config.get("api_keys", {}).items():
            if key_value and not os.environ.get(env_var):
                os.environ[env_var] = key_value
                logger.info(f"Loaded {env_var} from service config")

    # ── Service enable/disable ─────────────────────────────────────────────

    def set_service_enabled(self, service_id: str, enabled: bool) -> bool:
        if service_id not in {s.id for s in SERVICE_CATALOG}:
            return False
        self._config.setdefault("services", {})[service_id] = {"enabled": enabled}
        self._save()
        return True

    def is_service_enabled(self, service_id: str) -> bool:
        svc_state = self._config.get("services", {}).get(service_id)
        if svc_state is not None:
            return svc_state.get("enabled", False)
        # Fall back to catalog default
        for svc in SERVICE_CATALOG:
            if svc.id == service_id:
                return svc.enabled_by_default
        return False

    # ── API key management ─────────────────────────────────────────────────

    def save_api_key(self, env_var: str, key_value: str) -> bool:
        """Store an API key and inject it into the environment."""
        if not env_var or not key_value:
            return False
        key_value = key_value.strip()
        if not key_value:
            return False
        self._config.setdefault("api_keys", {})[env_var] = key_value
        os.environ[env_var] = key_value
        self._save()
        logger.info(f"API key saved for {env_var}")
        return True

    def delete_api_key(self, env_var: str) -> bool:
        """Remove an API key from storage and environment."""
        self._config.setdefault("api_keys", {}).pop(env_var, None)
        os.environ.pop(env_var, None)
        self._save()
        logger.info(f"API key removed for {env_var}")
        return True

    def has_api_key(self, env_var: str) -> bool:
        """Return True if a key is stored (in file or env)."""
        if not env_var:
            return True  # Service needs no key
        return bool(
            self._config.get("api_keys", {}).get(env_var)
            or os.environ.get(env_var)
        )

    def key_preview(self, env_var: str) -> Optional[str]:
        """Return a masked preview like sk-...Ab3X, or None."""
        val = self._config.get("api_keys", {}).get(env_var) or os.environ.get(env_var)
        if not val:
            return None
        if len(val) <= 8:
            return "•" * len(val)
        return val[:4] + "•" * (len(val) - 8) + val[-4:]

    # ── Status reporting ───────────────────────────────────────────────────

    def get_all_services_status(self) -> List[Dict]:
        """Return full status list for the frontend."""
        results = []
        for svc in SERVICE_CATALOG:
            has_key = self.has_api_key(svc.env_var) if svc.env_var else True
            enabled = self.is_service_enabled(svc.id)

            if not svc.env_var:
                key_status = "not_required"
            elif has_key:
                key_status = "configured"
            else:
                key_status = "missing"

            results.append({
                **asdict(svc),
                "enabled": enabled,
                "key_status": key_status,
                "key_preview": self.key_preview(svc.env_var) if svc.env_var else None,
                "operational": enabled and (svc.works_without_key or has_key),
            })
        return results

    def get_service_status(self, service_id: str) -> Optional[Dict]:
        for item in self.get_all_services_status():
            if item["id"] == service_id:
                return item
        return None

    def summary(self) -> Dict:
        all_svcs = self.get_all_services_status()
        enabled = [s for s in all_svcs if s["enabled"]]
        operational = [s for s in all_svcs if s["operational"]]
        return {
            "total": len(all_svcs),
            "enabled": len(enabled),
            "operational": len(operational),
            "needs_key": len([s for s in enabled if s["key_status"] == "missing"]),
        }


# Global singleton
service_config = ServiceConfigManager()

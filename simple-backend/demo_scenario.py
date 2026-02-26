#!/usr/bin/env python3
"""
Demo Scenario Seeder
====================

Seeds the platform with a realistic, fully-worked investigation suitable for
live demos.  Run once before showing the platform to an audience.

Scenario: "Operation SHATTERED PANE"
-------------------------------------
A financial-sector SOC receives a phishing alert pointing to the domain
secure-docview-portal[.]net.  This script pre-populates what the platform
would surface after running a comprehensive investigation:

  - 7 related domains linked via shared SSL certificate SANs and a
    common registrant email found in a breach database
  - C2 IP flagged by AbuseIPDB (47 reports) and 8/85 VirusTotal engines
  - MITRE ATT&CK techniques T1566.001, T1071.001, T1090.003, T1027
  - ACH matrix comparing Cobalt Group vs FIN7 vs independent actor
    attribution — evidence tips to Cobalt Group (HIGH confidence)
  - 3 active monitoring alerts on the watchlist
  - IC-standard conclusion with a devil's advocate challenge

Usage
-----
    cd Enterprise-OSINT-Platform/simple-backend
    APP_DATA_DIR=/tmp python demo_scenario.py          # seed only
    APP_DATA_DIR=/tmp python demo_scenario.py --reset  # wipe + re-seed
"""

import os
import sys
import uuid
import argparse
import json
import shutil
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Allow running from project root
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))

APP_DATA_DIR = os.environ.get("APP_DATA_DIR", "/tmp/osint_demo")
os.makedirs(APP_DATA_DIR, exist_ok=True)
os.environ.setdefault("APP_DATA_DIR", APP_DATA_DIR)
os.environ.setdefault("JWT_SECRET_KEY", "demo-secret-key-not-for-production")
os.environ.setdefault("PLATFORM_MODE", "demo")
os.environ.setdefault("DEMO_MODE", "true")

# ---------------------------------------------------------------------------
# Stable UUIDs so repeated runs produce the same IDs
# ---------------------------------------------------------------------------
INV_ID           = "d3m0-0001-0000-0000-shattered-pane"
WATCHLIST_MAIN   = "wl-d3m0-main-domain-0000-00000001"
WATCHLIST_C2IP   = "wl-d3m0-c2ip-addr-0000-00000002"
WATCHLIST_ACTOR  = "wl-d3m0-threat-actor-00-00000003"
HYP_COBALT       = "hyp-d3m0-cobalt-group-0000000001"
HYP_FIN7         = "hyp-d3m0-fin7-00000000-0000000002"
HYP_INDEP        = "hyp-d3m0-independent-actor-000003"
CONCL_ID         = "concl-d3m0-attribution-000000001"
ALT_ID           = "alt-d3m0-fin7-alternative-000001"
DA_ID            = "da-d3m0-devils-advocate-0000001"

# Eight intel items for the ACH matrix
ITEM_CERT_SAN    = "item-d3m0-cert-san-pivot-000001"
ITEM_REGISTRANT  = "item-d3m0-registrant-email-00002"
ITEM_ABUSEIPDB   = "item-d3m0-abuseipdb-score-00003"
ITEM_MITRE_TTP   = "item-d3m0-mitre-ttps-match-0004"
ITEM_MALWARE     = "item-d3m0-malware-families-00005"
ITEM_TIMING      = "item-d3m0-infra-timing-000006"
ITEM_BEACON      = "item-d3m0-beacon-pattern-00007"
ITEM_CREDENTIAL  = "item-d3m0-credential-exposure-08"


def ts(days_ago: float = 0, hours_ago: float = 0) -> str:
    """Return an ISO-8601 UTC timestamp offset from now."""
    dt = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)
    return dt.isoformat() + "Z"


# ============================================================================
# INVESTIGATION
# ============================================================================

def make_investigation() -> dict:
    """Craft a fully-completed OSINTInvestigation dict."""
    return {
        "id": INV_ID,
        "workspace_id": "default",
        "target_profile": {
            "target_id": "tp-" + INV_ID,
            "target_type": "domain",
            "primary_identifier": "secure-docview-portal.net",
            "secondary_identifiers": [
                "185.220.101.47",
                "update-auth-signin.net",
                "docs-secure-viewer.com",
                "portal-auth-docview.org",
            ],
            "scope_restrictions": {},
            "compliance_requirements": ["GDPR"],
            "geographic_scope": ["RU", "UA", "US"],
            "data_retention_days": 30,
            "created_at": ts(2),
        },
        "investigation_type": "comprehensive",
        "scope": {
            "include_social_media": True,
            "include_infrastructure": True,
            "include_threat_intelligence": True,
            "include_corporate_records": True,
            "include_public_records": True,
            "max_social_posts": 1000,
            "max_domains_to_scan": 100,
            "max_threat_indicators": 500,
            "historical_data_days": 90,
            "max_investigation_hours": 24,
            "exclude_pii": True,
            "exclude_protected_categories": True,
            "require_consent_verification": False,
        },
        "priority": "high",
        "status": "completed",
        "progress": {
            "stage": "completed",
            "stage_progress": 1.0,
            "overall_progress": 1.0,
            "current_activity": "Investigation complete",
            "data_points_collected": 847,
            "errors_encountered": 2,
            "warnings": [
                "WHOIS privacy protection active — registrant details obscured",
                "Shodan rate limit reached; port scan results may be incomplete",
            ],
            "last_updated": ts(1, 6),
        },
        "investigator_id": "demo-analyst",
        "investigator_name": "Demo Analyst",
        "created_at": ts(2),
        "updated_at": ts(1, 6),
        "completed_at": ts(1, 6),
        "title": "Operation SHATTERED PANE — Phishing Infrastructure Analysis",
        "description": (
            "Investigate phishing domain secure-docview-portal[.]net flagged by "
            "email security gateway.  Determine scope of infrastructure cluster, "
            "threat actor attribution, and victim exposure."
        ),
        "notes": (
            "Initial tip from SOC ticket #2024-4471.  Domain appeared in a "
            "targeted spearphishing email impersonating DocuSign sent to three "
            "finance-department employees.  None clicked.  Escalated for full "
            "OSINT investigation."
        ),

        # ---- Infrastructure -----------------------------------------------
        "infrastructure_intelligence": {
            "domains": [
                {
                    "domain": "secure-docview-portal.net",
                    "registrar": "NameCheap, Inc.",
                    "created": ts(45),
                    "expires": ts(-320),
                    "registrant_email": "admin@mailfast[.]pro",
                    "privacy_protected": True,
                    "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
                    "risk_indicators": ["recently_registered", "privacy_protected", "phishing_pattern"],
                    "notes": "Registered 45 days ago; Cloudflare proxied.",
                },
                {
                    "domain": "update-auth-signin.net",
                    "registrar": "NameCheap, Inc.",
                    "created": ts(47),
                    "expires": ts(-318),
                    "registrant_email": "admin@mailfast[.]pro",
                    "privacy_protected": True,
                    "notes": "Sibling domain; same registrant, registered 2 days earlier.",
                    "risk_indicators": ["recently_registered", "shared_registrant"],
                },
                {
                    "domain": "docs-secure-viewer.com",
                    "registrar": "NameCheap, Inc.",
                    "created": ts(47),
                    "expires": ts(-318),
                    "registrant_email": "admin@mailfast[.]pro",
                    "privacy_protected": True,
                    "notes": "Shares SSL certificate SAN with primary domain.",
                    "risk_indicators": ["recently_registered", "cert_san_linked"],
                },
                {
                    "domain": "portal-auth-docview.org",
                    "registrar": "NameCheap, Inc.",
                    "created": ts(46),
                    "expires": ts(-319),
                    "registrant_email": "admin@mailfast[.]pro",
                    "privacy_protected": True,
                    "notes": "Fourth domain in cluster; same SSL cert thumbprint.",
                    "risk_indicators": ["recently_registered", "cert_san_linked"],
                },
                {
                    "domain": "secure-auth-verify.io",
                    "registrar": "NameCheap, Inc.",
                    "created": ts(44),
                    "notes": "Found via passive DNS — resolves to same C2 IP.",
                    "risk_indicators": ["c2_infrastructure"],
                },
                {
                    "domain": "docusign-verify-portal.net",
                    "registrar": "NameCheap, Inc.",
                    "created": ts(50),
                    "notes": "Earlier campaign domain; same operator fingerprint.",
                    "risk_indicators": ["recently_registered", "brand_impersonation"],
                },
                {
                    "domain": "login-secure-docs.com",
                    "registrar": "NameCheap, Inc.",
                    "created": ts(50),
                    "notes": "Earliest domain in cluster; likely initial staging.",
                    "risk_indicators": ["recently_registered", "c2_infrastructure"],
                },
            ],
            "ip_addresses": [
                {
                    "ip": "185.220.101.47",
                    "asn": "AS4134",
                    "org": "ChinaNet Backbone",
                    "country": "RU",
                    "abuse_score": 82,
                    "virustotal_positives": 8,
                    "virustotal_total": 85,
                    "shodan_ports": [80, 443, 8080, 22],
                    "shodan_banners": {
                        "443": "nginx/1.18.0",
                        "22": "OpenSSH 8.2",
                        "8080": "Apache Tomcat/9.0.65",
                    },
                    "last_seen_malicious": ts(3),
                    "threat_reports": 47,
                    "risk_indicators": ["high_abuse_score", "malware_c2", "tor_adjacent"],
                    "notes": (
                        "Hosted on a VPS range commonly associated with Cobalt Group "
                        "C2 infrastructure.  47 AbuseIPDB reports over 30 days."
                    ),
                },
                {
                    "ip": "103.224.182.247",
                    "asn": "AS55933",
                    "org": "Cablonet Leased Line",
                    "country": "HK",
                    "abuse_score": 34,
                    "notes": "Secondary relay; lower confidence attribution.",
                    "risk_indicators": ["relay_node"],
                },
            ],
            "certificates": [
                {
                    "thumbprint": "A3:F1:22:9C:44:BB:7E:12:0D:88:C4:11:EE:3A:90:F2:17:55:AB:CD",
                    "subject": "secure-docview-portal.net",
                    "issuer": "Let's Encrypt",
                    "issued": ts(44),
                    "expires": ts(-47),
                    "san": [
                        "secure-docview-portal.net",
                        "update-auth-signin.net",
                        "docs-secure-viewer.com",
                        "portal-auth-docview.org",
                    ],
                    "notes": (
                        "Single certificate covers all four primary phishing domains — "
                        "the SAN pivot is the key link between domains."
                    ),
                }
            ],
            "dns_records": {
                "A":    ["185.220.101.47"],
                "MX":   ["10 mail.secure-docview-portal.net"],
                "TXT":  ["v=spf1 include:mailfast.pro ~all"],
                "NS":   ["ns1.cloudflare.com", "ns2.cloudflare.com"],
                "CNAME": [],
            },
            "exposed_services": [
                {"port": 443,  "service": "HTTPS",        "version": "nginx/1.18.0",     "risk": "medium"},
                {"port": 8080, "service": "HTTP-Alt",     "version": "Tomcat/9.0.65",   "risk": "high"},
                {"port": 22,   "service": "SSH",          "version": "OpenSSH_8.2",     "risk": "medium"},
                {"port": 80,   "service": "HTTP",         "version": "nginx/1.18.0",    "risk": "low"},
            ],
            "risk_indicators": [
                "Brand impersonation (DocuSign)",
                "All 7 domains registered within a 7-day window",
                "Shared registrant email found in credential breach database",
                "IP flagged by 47 AbuseIPDB reports (30-day window)",
                "SSL SAN links 4 phishing domains to single operator",
                "TXT record references mailfast[.]pro — a known bulletproof mailer",
            ],
        },

        # ---- Threat intelligence -------------------------------------------
        "threat_intelligence": {
            "malware_indicators": [
                {
                    "type": "domain",
                    "indicator": "secure-docview-portal.net",
                    "malware_family": "CobaltStrike Beacon",
                    "confidence": 0.78,
                    "source": "VirusTotal",
                    "first_seen": ts(42),
                    "tags": ["phishing", "c2", "cobalt-strike"],
                },
                {
                    "type": "ip",
                    "indicator": "185.220.101.47",
                    "malware_family": "CobaltStrike C2",
                    "confidence": 0.85,
                    "source": "AbuseIPDB + Shodan",
                    "tags": ["c2", "beacon", "https-traffic"],
                },
            ],
            "network_indicators": [
                {"type": "domain", "value": d, "confidence": 0.80}
                for d in [
                    "secure-docview-portal.net", "update-auth-signin.net",
                    "docs-secure-viewer.com", "portal-auth-docview.org",
                    "secure-auth-verify.io", "docusign-verify-portal.net",
                    "login-secure-docs.com",
                ]
            ],
            "behavioral_indicators": [
                {
                    "description": "HTTPS beacon traffic on port 443 using malleable C2 profile",
                    "technique": "T1071.001",
                    "confidence": 0.82,
                },
                {
                    "description": "Multi-hop proxy routing via HK relay before reaching C2",
                    "technique": "T1090.003",
                    "confidence": 0.70,
                },
                {
                    "description": "Payload obfuscation using XOR encoding",
                    "technique": "T1027",
                    "confidence": 0.65,
                },
            ],
            "threat_actors": [
                {
                    "name": "Cobalt Group",
                    "aliases": ["GOLD KINGSWOOD", "Cobalt Spider", "TEMP.Metastrike"],
                    "attribution_confidence": 0.74,
                    "motivation": "Financial — targeting financial institutions",
                    "origin": "Russia / Eastern Europe",
                    "tools": ["CobaltStrike", "Metasploit", "custom .NET loaders"],
                    "notes": (
                        "Infrastructure pattern, beacon timing, and TTP overlap with "
                        "Cobalt Group campaigns documented in FireEye 2023 report.  "
                        "See ACH matrix for alternative hypotheses."
                    ),
                }
            ],
            "campaigns": [
                {
                    "name": "SHATTERED PANE",
                    "status": "active",
                    "start_date": ts(50),
                    "targeted_sectors": ["Financial Services", "Insurance", "Banking"],
                    "targeted_regions": ["EU", "NA", "APAC"],
                    "attack_vector": "Spearphishing via DocuSign impersonation",
                    "lure_theme": "Urgent document signature required",
                    "known_victims": 3,
                    "suspected_victims": "12–20 (based on infrastructure scale)",
                }
            ],
            "risk_score": 87.3,
            "confidence_level": 0.74,
            "mitre_techniques": [
                "T1566.001",   # Spearphishing Attachment
                "T1071.001",   # Application Layer Protocol: Web
                "T1090.003",   # Proxy: Multi-hop Proxy
                "T1027",       # Obfuscated Files or Information
                "T1583.001",   # Acquire Infrastructure: Domains
                "T1588.002",   # Obtain Capabilities: Tool
            ],
        },

        # ---- Social intelligence -------------------------------------------
        "social_intelligence": {
            "platforms": {
                "paste_sites": {
                    "results": [
                        {
                            "site": "Pastebin",
                            "url": "https://pastebin.com/[REDACTED]",
                            "date": ts(30),
                            "snippet": "admin@mailfast[.]pro :: Passw0rd!23 [DB: mailfast_users]",
                            "type": "credential_leak",
                            "note": "Registrant email found in plaintext credential dump.",
                        }
                    ]
                },
                "dark_web": {
                    "results": [
                        {
                            "forum": "XSS[.]is",
                            "date": ts(20),
                            "type": "infrastructure_sale",
                            "note": "Similar domain pattern advertised as 'ready phishing kit' for financial sector.",
                        }
                    ]
                }
            },
            "sentiment_analysis": {},
            "reputation_score": 12.0,
            "threat_indicators": [
                "Registrant email in credential breach",
                "Domain pattern advertised on criminal forums",
            ],
        },

        # ---- Key findings --------------------------------------------------
        "key_findings": [
            "Single SSL certificate SAN field links 4 phishing domains to one operator — the pivot that revealed the full infrastructure cluster.",
            "All 7 domains registered within a 7-day window via NameCheap using the same registrant email admin@mailfast[.]pro, which appears in a plaintext credential dump.",
            "C2 IP 185.220.101.47 has 47 AbuseIPDB reports and 8/85 VirusTotal detections; Shodan shows CobaltStrike default Tomcat listener on port 8080.",
            "TTP overlap (T1566.001 spearphishing, malleable C2 profile, multi-hop HK relay) is consistent with Cobalt Group's documented 2023 financial-sector campaign pattern.",
            "Registrant's operational security failure (using a breached email) suggests this is not a nation-state actor with rigorous tradecraft.",
            "At least 3 victim organizations identified via beacon check-in logs recovered from passive DNS; estimated 12–20 total based on infrastructure scale.",
        ],
        "recommendations": [
            "Block all 7 domains and the C2 IP at perimeter and DNS sinkhole immediately.",
            "Hunt for CobaltStrike Beacon IOCs (SHA256 hashes in full STIX export) in EDR telemetry across financial-sector peers.",
            "Notify affected organizations via ISAC disclosure within 24 hours.",
            "Monitor mailfast[.]pro for new domain registrations — operator will likely stand up replacement infrastructure within 2 weeks.",
            "Submit STIX bundle to FS-ISAC and MISP community for broader sector awareness.",
        ],
        "risk_score": 87.3,
        "confidence_level": 0.74,
        "tags": ["cobalt-group", "spearphishing", "docusign-lure", "financial-sector", "cobalt-strike"],
    }


# ============================================================================
# WATCHLIST ENTRIES + ALERTS
# ============================================================================

def make_watchlist_entries() -> list:
    return [
        {
            "id": WATCHLIST_MAIN,
            "target": "secure-docview-portal.net",
            "target_type": "domain",
            "description": "Primary phishing domain — SHATTERED PANE campaign",
            "enabled": True,
            "check_interval_hours": 1,
            "tags": ["shattered-pane", "phishing", "priority"],
            "created_at": ts(1, 18),
            "last_checked": ts(0, 1),
            "total_alerts": 3,
            "last_alert_at": ts(0, 2),
        },
        {
            "id": WATCHLIST_C2IP,
            "target": "185.220.101.47",
            "target_type": "ip",
            "description": "C2 server IP — monitor for new domains resolving here",
            "enabled": True,
            "check_interval_hours": 4,
            "tags": ["shattered-pane", "c2"],
            "created_at": ts(1, 18),
            "last_checked": ts(0, 4),
            "total_alerts": 2,
            "last_alert_at": ts(0, 5),
        },
        {
            "id": WATCHLIST_ACTOR,
            "target": "Cobalt Group",
            "target_type": "threat_actor",
            "description": "Track Cobalt Group infrastructure patterns",
            "enabled": True,
            "check_interval_hours": 24,
            "tags": ["threat-actor", "cobalt-group"],
            "created_at": ts(1, 18),
            "last_checked": ts(0, 8),
            "total_alerts": 1,
            "last_alert_at": ts(0, 9),
        },
    ]


def make_alerts() -> list:
    return [
        {
            "id": "alert-d3m0-new-cert-000000001",
            "watchlist_id": WATCHLIST_MAIN,
            "watchlist_name": "secure-docview-portal.net",
            "alert_type": "new_certificate",
            "severity": "high",
            "title": "New Let's Encrypt certificate issued",
            "description": (
                "A new TLS certificate was issued for secure-docview-portal.net "
                "covering 4 SANs.  This is the certificate that pivoted the investigation "
                "to reveal the full 7-domain cluster."
            ),
            "before": {},
            "after": {
                "san": ["secure-docview-portal.net", "update-auth-signin.net",
                        "docs-secure-viewer.com", "portal-auth-docview.org"],
                "issuer": "Let's Encrypt",
            },
            "status": "in_progress",
            "created_at": ts(1, 6),
            "updated_at": ts(0, 2),
        },
        {
            "id": "alert-d3m0-ip-reputation-0002",
            "watchlist_id": WATCHLIST_C2IP,
            "watchlist_name": "185.220.101.47",
            "alert_type": "ip_reputation_change",
            "severity": "critical",
            "title": "IP reputation score jumped +31 points (51 → 82)",
            "description": (
                "AbuseIPDB confidence score increased significantly.  "
                "New reports reference CobaltStrike C2 activity and phishing redirects."
            ),
            "before": {"abuse_score": 51, "report_count": 22},
            "after":  {"abuse_score": 82, "report_count": 47},
            "status": "new",
            "created_at": ts(0, 8),
            "updated_at": ts(0, 8),
        },
        {
            "id": "alert-d3m0-new-domain-000003",
            "watchlist_id": WATCHLIST_MAIN,
            "watchlist_name": "secure-docview-portal.net",
            "alert_type": "new_subdomain",
            "severity": "medium",
            "title": "New subdomain detected: mail.secure-docview-portal.net",
            "description": (
                "A mail subdomain appeared in DNS, suggesting the operator may be "
                "activating the MX record for phishing email delivery."
            ),
            "before": {},
            "after":  {"subdomain": "mail.secure-docview-portal.net", "a_record": "185.220.101.47"},
            "status": "new",
            "created_at": ts(0, 3),
            "updated_at": ts(0, 3),
        },
    ]


# ============================================================================
# TRADECRAFT (Intel items, hypotheses, ACH cells, conclusion)
# ============================================================================

def make_intel_items() -> list:
    now = ts()
    return [
        {
            "id": ITEM_CERT_SAN,
            "investigation_id": INV_ID,
            "title": "SSL certificate SAN links 4 phishing domains",
            "content": (
                "Certificate thumbprint A3:F1:22:9C… has 4 Subject Alternative Names: "
                "secure-docview-portal.net, update-auth-signin.net, docs-secure-viewer.com, "
                "portal-auth-docview.org.  All registered within a 7-day window via NameCheap."
            ),
            "source_name": "Certificate Transparency (crt.sh)",
            "source_type": "technical",
            "source_reliability": "A",   # Completely reliable — CT logs are authoritative
            "info_credibility": "1",     # Confirmed by direct CT log query
            "collection_method": "certificate_transparency",
            "tags": ["infrastructure", "cert", "pivot"],
            "analyst_notes": "This is the anchor finding.  All other pivots flow from this cert.",
            "created_by": "demo-analyst",
            "created_at": ts(1, 10),
            "collected_at": ts(1, 10),
        },
        {
            "id": ITEM_REGISTRANT,
            "investigation_id": INV_ID,
            "title": "Registrant email admin@mailfast[.]pro found in breach database",
            "content": (
                "Passive DNS + WHOIS history reveals registrant email admin@mailfast[.]pro "
                "(privacy protection was lifted on an earlier domain registration).  "
                "Hudson Rock Cavalier shows this email in infostealer logs dated 90 days ago, "
                "with plaintext credential: admin@mailfast[.]pro :: Passw0rd!23."
            ),
            "source_name": "Hudson Rock Cavalier / WHOIS history",
            "source_type": "technical",
            "source_reliability": "B",   # Usually reliable
            "info_credibility": "2",     # Probably true
            "collection_method": "credential_intelligence",
            "tags": ["registrant", "credential", "opsec-failure"],
            "analyst_notes": (
                "Operator reused an email address that had already been compromised "
                "by infostealer malware.  This is an OPSEC failure inconsistent with "
                "disciplined nation-state tradecraft."
            ),
            "created_by": "demo-analyst",
            "created_at": ts(1, 8),
            "collected_at": ts(1, 8),
        },
        {
            "id": ITEM_ABUSEIPDB,
            "investigation_id": INV_ID,
            "title": "C2 IP 185.220.101.47 — 47 AbuseIPDB reports, 8/85 VirusTotal",
            "content": (
                "AbuseIPDB confidence score 82/100 based on 47 community reports over 30 days.  "
                "Categories: Web Attack (18), Phishing (15), Hacking (9), Port Scan (5).  "
                "VirusTotal: 8 of 85 security vendors flag as malicious (CobaltStrike C2, "
                "Phishing, Malware Distribution).  Shodan shows port 8080 banner consistent "
                "with CobaltStrike default Tomcat HTTPS listener."
            ),
            "source_name": "AbuseIPDB / VirusTotal / Shodan",
            "source_type": "technical",
            "source_reliability": "A",
            "info_credibility": "1",
            "collection_method": "threat_intelligence_lookup",
            "tags": ["c2", "reputation", "virustotal"],
            "analyst_notes": "Shodan port 8080 Tomcat banner is a high-confidence CobaltStrike indicator.",
            "created_by": "demo-analyst",
            "created_at": ts(1, 9),
            "collected_at": ts(1, 9),
        },
        {
            "id": ITEM_MITRE_TTP,
            "investigation_id": INV_ID,
            "title": "TTP cluster matches Cobalt Group 2023 campaign pattern",
            "content": (
                "Observed TTPs: T1566.001 (Spearphishing), T1071.001 (HTTPS C2), "
                "T1090.003 (multi-hop HK relay proxy), T1027 (XOR payload obfuscation).  "
                "FireEye/Mandiant 2023 report documents identical TTP cluster for Cobalt Group "
                "financial-sector campaigns.  FIN7 uses overlapping T1566 and T1071 TTPs "
                "but not the HK relay pattern documented here."
            ),
            "source_name": "Mandiant Threat Intelligence / MITRE ATT&CK",
            "source_type": "document",
            "source_reliability": "A",
            "info_credibility": "2",   # Probably true — indirect match to known report
            "collection_method": "threat_intelligence_report",
            "tags": ["mitre", "ttp", "cobalt-group"],
            "analyst_notes": "HK relay hop is the most discriminating indicator separating Cobalt Group from FIN7.",
            "created_by": "demo-analyst",
            "created_at": ts(1, 7),
            "collected_at": ts(1, 7),
        },
        {
            "id": ITEM_MALWARE,
            "investigation_id": INV_ID,
            "title": "CobaltStrike Beacon default profile detected on port 8080",
            "content": (
                "Shodan banner for 185.220.101.47:8080 returns an Apache Tomcat 9.0.65 "
                "response.  Combined with the /submit.php URI pattern in passive DNS logs, "
                "this matches the CobaltStrike default Tomcat HTTPS listener profile.  "
                "Both Cobalt Group and FIN7 use CobaltStrike; this indicator is consistent "
                "with both hypotheses."
            ),
            "source_name": "Shodan / Passive DNS",
            "source_type": "technical",
            "source_reliability": "A",
            "info_credibility": "2",
            "collection_method": "shodan_banner_analysis",
            "tags": ["cobalt-strike", "c2", "malware"],
            "analyst_notes": "Consistent with both Cobalt Group and FIN7 — not discriminating alone.",
            "created_by": "demo-analyst",
            "created_at": ts(1, 8),
            "collected_at": ts(1, 8),
        },
        {
            "id": ITEM_TIMING,
            "investigation_id": INV_ID,
            "title": "Domain registration timing cluster: 7 domains in 7 days",
            "content": (
                "All 7 domains registered between 47 and 40 days ago.  "
                "The compressed registration window suggests pre-campaign infrastructure "
                "staging.  WHOIS creation timestamps are within business hours UTC+3 "
                "(Moscow / Eastern European time zone)."
            ),
            "source_name": "WHOIS history",
            "source_type": "technical",
            "source_reliability": "A",
            "info_credibility": "1",
            "collection_method": "whois_lookup",
            "tags": ["infrastructure", "timing", "registration"],
            "analyst_notes": "UTC+3 working-hours pattern is corroborating but not conclusive for Eastern European attribution.",
            "created_by": "demo-analyst",
            "created_at": ts(1, 10),
            "collected_at": ts(1, 10),
        },
        {
            "id": ITEM_BEACON,
            "investigation_id": INV_ID,
            "title": "Beacon check-in interval: 60-second jitter pattern",
            "content": (
                "Passive DNS query logs for secure-docview-portal.net show a "
                "consistent 60 ± 5 second resolution interval from 3 distinct source IPs.  "
                "This matches CobaltStrike Beacon's default sleep/jitter configuration "
                "and indicates active compromised hosts checking in."
            ),
            "source_name": "CIRCL Passive DNS",
            "source_type": "technical",
            "source_reliability": "B",
            "info_credibility": "2",
            "collection_method": "passive_dns",
            "tags": ["beacon", "c2", "active-compromise"],
            "analyst_notes": (
                "3 source IPs are likely victim machines.  "
                "Notified ISAC with anonymized IOCs."
            ),
            "created_by": "demo-analyst",
            "created_at": ts(1, 5),
            "collected_at": ts(1, 5),
        },
        {
            "id": ITEM_CREDENTIAL,
            "investigation_id": INV_ID,
            "title": "Registrant email in infostealer credential dump — OPSEC failure",
            "content": (
                "admin@mailfast[.]pro found in Hudson Rock Cavalier with full credential "
                "context: the machine was infected with RedLine Stealer 90 days ago, "
                "suggesting the operator's own workstation may be compromised.  "
                "Plaintext password recovered.  This level of OPSEC failure is inconsistent "
                "with disciplined APT tradecraft and more consistent with a financially "
                "motivated criminal actor."
            ),
            "source_name": "Hudson Rock Cavalier",
            "source_type": "technical",
            "source_reliability": "B",
            "info_credibility": "2",
            "collection_method": "credential_intelligence",
            "tags": ["credential", "opsec", "redline", "attribution"],
            "analyst_notes": "Key differentiator: nation-state APTs rarely use personal emails with poor OPSEC.",
            "created_by": "demo-analyst",
            "created_at": ts(1, 6),
            "collected_at": ts(1, 6),
        },
    ]


def make_hypotheses() -> list:
    return [
        {
            "id": HYP_COBALT,
            "investigation_id": INV_ID,
            "title": "Cobalt Group (GOLD KINGSWOOD)",
            "description": (
                "Infrastructure, TTPs, tooling, and targeting profile are consistent with "
                "Cobalt Group's documented 2023 financial-sector spearphishing campaigns.  "
                "The HK relay hop, CobaltStrike Beacon profile, and NameCheap domain "
                "registration pattern have all been attributed to this actor in prior reporting."
            ),
            "hypothesis_type": "primary",
            "status": "tentative",
            "created_by": "demo-analyst",
            "created_at": ts(1, 5),
            "updated_at": ts(0, 8),
            "notes": "Highest scored hypothesis in ACH matrix.",
        },
        {
            "id": HYP_FIN7,
            "investigation_id": INV_ID,
            "title": "FIN7 (Carbanak Group)",
            "description": (
                "FIN7 also targets financial services with DocuSign-themed lures and uses "
                "CobaltStrike.  However, FIN7's documented infrastructure patterns favour "
                "direct routing rather than multi-hop HK relays, and their OPSEC is "
                "generally tighter."
            ),
            "hypothesis_type": "alternative",
            "status": "open",
            "created_by": "demo-analyst",
            "created_at": ts(1, 5),
            "updated_at": ts(0, 8),
            "notes": "Cannot be fully excluded without additional malware sample analysis.",
        },
        {
            "id": HYP_INDEP,
            "investigation_id": INV_ID,
            "title": "Independent cybercriminal actor / affiliate",
            "description": (
                "An independent actor or Cobalt Group affiliate using purchased/leaked "
                "tooling could replicate this infrastructure pattern.  The OPSEC failure "
                "(breached registrant email) supports a less-disciplined independent actor "
                "over an established group with rigorous tradecraft."
            ),
            "hypothesis_type": "alternative",
            "status": "open",
            "created_by": "demo-analyst",
            "created_at": ts(1, 5),
            "updated_at": ts(0, 8),
            "notes": "Would explain OPSEC failure but not the precise TTP match to prior Cobalt Group reporting.",
        },
    ]


def make_ach_cells() -> list:
    """
    ACH matrix: 8 evidence items × 3 hypotheses.
    Consistency values: C (consistent), I (inconsistent), NA (not applicable),
                        N (neutral)
    """
    # (evidence_id, hypothesis_id, consistency, rationale)
    matrix = [
        # --- Cert SAN pivot ---
        (ITEM_CERT_SAN, HYP_COBALT, "C",
         "Cobalt Group routinely clusters phishing domains on a single cert."),
        (ITEM_CERT_SAN, HYP_FIN7,   "C",
         "FIN7 also uses multi-domain certs; not discriminating."),
        (ITEM_CERT_SAN, HYP_INDEP,  "C",
         "Any actor could use Let's Encrypt multi-SAN cert."),

        # --- Registrant email in breach ---
        (ITEM_REGISTRANT, HYP_COBALT, "N",
         "Cobalt Group operators have shown variable OPSEC; ambiguous."),
        (ITEM_REGISTRANT, HYP_FIN7,   "I",
         "FIN7 maintains tighter OPSEC; personal email in breach dump is atypical."),
        (ITEM_REGISTRANT, HYP_INDEP,  "C",
         "Independent actors typically have weaker OPSEC; consistent."),

        # --- AbuseIPDB / VT score ---
        (ITEM_ABUSEIPDB, HYP_COBALT, "C",
         "IP range commonly associated with Cobalt Group C2 hosting."),
        (ITEM_ABUSEIPDB, HYP_FIN7,   "N",
         "FIN7 also uses bulletproof VPS; not discriminating."),
        (ITEM_ABUSEIPDB, HYP_INDEP,  "C",
         "Widely available VPS — consistent with any actor."),

        # --- TTP cluster ---
        (ITEM_MITRE_TTP, HYP_COBALT, "C",
         "Exact TTP cluster (including HK relay) documented in Cobalt Group 2023 report."),
        (ITEM_MITRE_TTP, HYP_FIN7,   "I",
         "FIN7 uses T1566/T1071 but not the HK multi-hop relay pattern."),
        (ITEM_MITRE_TTP, HYP_INDEP,  "I",
         "Precise HK relay replication requires knowledge of Cobalt Group playbooks."),

        # --- CobaltStrike Beacon ---
        (ITEM_MALWARE, HYP_COBALT, "C",
         "Cobalt Group is named after CobaltStrike; consistent."),
        (ITEM_MALWARE, HYP_FIN7,   "C",
         "FIN7 also uses CobaltStrike; consistent but not discriminating."),
        (ITEM_MALWARE, HYP_INDEP,  "C",
         "CobaltStrike is widely available on criminal forums."),

        # --- Domain timing / UTC+3 ---
        (ITEM_TIMING, HYP_COBALT, "C",
         "UTC+3 working-hours pattern matches Eastern European operator."),
        (ITEM_TIMING, HYP_FIN7,   "C",
         "FIN7 also operates from Eastern Europe; ambiguous."),
        (ITEM_TIMING, HYP_INDEP,  "N",
         "UTC+3 is consistent with many regions; not highly discriminating."),

        # --- Beacon check-in pattern ---
        (ITEM_BEACON, HYP_COBALT, "C",
         "60-second default jitter matches Cobalt Group's known Beacon profiles."),
        (ITEM_BEACON, HYP_FIN7,   "N",
         "FIN7 also uses default profiles; ambiguous."),
        (ITEM_BEACON, HYP_INDEP,  "C",
         "Default profile = any actor using unmodified CobaltStrike."),

        # --- Credential / OPSEC failure ---
        (ITEM_CREDENTIAL, HYP_COBALT, "N",
         "Some Cobalt Group operators have shown OPSEC lapses; ambiguous."),
        (ITEM_CREDENTIAL, HYP_FIN7,   "I",
         "FIN7 tradecraft is generally tighter; OPSEC failure is inconsistent."),
        (ITEM_CREDENTIAL, HYP_INDEP,  "C",
         "OPSEC failure strongly consistent with independent/less-experienced actor."),
    ]

    cells = []
    for ev_id, hyp_id, consistency, rationale in matrix:
        cells.append({
            "evidence_id": ev_id,
            "hypothesis_id": hyp_id,
            "consistency": consistency,
            "analyst_rationale": rationale,
            "updated_at": ts(0, 8),
        })
    return cells


def make_conclusion() -> dict:
    return {
        "id": CONCL_ID,
        "investigation_id": INV_ID,
        "title": "Attribution Assessment: Operation SHATTERED PANE",
        "statement": (
            "We assess with MODERATE-HIGH confidence that the SHATTERED PANE phishing "
            "infrastructure was operated by Cobalt Group (GOLD KINGSWOOD) or a closely "
            "affiliated actor.  The infrastructure pattern, TTP cluster, and CobaltStrike "
            "usage are consistent with Cobalt Group's documented 2023 financial-sector "
            "campaigns, and the HK multi-hop relay pattern is a discriminating indicator "
            "not observed in FIN7 campaigns.  The OPSEC failure (compromised registrant "
            "email) introduces uncertainty; it may indicate a less-disciplined affiliate "
            "rather than Cobalt Group core operators."
        ),
        "confidence_level": "moderate_high",
        "ic_language": "We assess with moderate-high confidence",
        "key_evidence": [
            ITEM_CERT_SAN,
            ITEM_MITRE_TTP,
            ITEM_ABUSEIPDB,
            ITEM_BEACON,
        ],
        "key_assumptions": [
            "The HK relay pattern documented in the 2023 Mandiant report is sufficiently unique to Cobalt Group to serve as a discriminating indicator.",
            "The OPSEC failure does not preclude Cobalt Group attribution — some group members have shown variable tradecraft quality.",
        ],
        "caveats": [
            "Without a malware sample for binary analysis, CobaltStrike attribution to Cobalt Group vs FIN7 remains inferential.",
            "The registrant OPSEC failure is inconsistent with Cobalt Group core operators and may indicate an affiliate.",
            "Nation-state actors (e.g. APT28) occasionally outsource targeting infrastructure to criminal groups; cannot be fully excluded.",
        ],
        "alternative_views": [ALT_ID],
        "status": "finalized",
        "created_by": "demo-analyst",
        "created_at": ts(0, 6),
        "updated_at": ts(0, 4),
    }


def make_alternative() -> dict:
    return {
        "id": ALT_ID,
        "investigation_id": INV_ID,
        "conclusion_id": CONCL_ID,
        "alternative_text": "FIN7 or an independent actor mimicking Cobalt Group TTPs",
        "why_considered": (
            "FIN7 uses overlapping tooling (CobaltStrike) and targets financial institutions "
            "with DocuSign-themed lures.  An independent actor purchasing a Cobalt Group "
            "playbook from a criminal forum could replicate the TTP pattern without being "
            "Cobalt Group itself."
        ),
        "why_rejected": (
            "FIN7 does not use the HK multi-hop relay pattern documented here, which "
            "appears in Cobalt Group-specific reporting.  An independent actor replicating "
            "the full TTP cluster including the HK relay would require access to internal "
            "Cobalt Group playbooks — possible but a higher-burden claim."
        ),
        "rejection_confidence": "moderate",
        "created_by": "demo-analyst",
        "created_at": ts(0, 6),
        "status": "closed",
    }


def make_devils_advocate() -> dict:
    return {
        "id": DA_ID,
        "investigation_id": INV_ID,
        "conclusion_id": CONCL_ID,
        "challenge_text": (
            "The primary attribution may be overfit to Cobalt Group because the analyst "
            "started the investigation with that hypothesis after seeing the VPS range.  "
            "The OPSEC failure (compromised registrant email, plain-text credential in "
            "breach dump) is fundamentally at odds with the tradecraft discipline of a "
            "group that has evaded attribution for years.  The HK relay could be "
            "coincidental given how many actors route through Hong Kong.  The strongest "
            "case is that this is an independent actor who read the same Mandiant report "
            "we did and deliberately mimicked Cobalt Group TTPs as a false flag."
        ),
        "evidence_gaps": [
            "No malware sample available for binary attribution (compiler fingerprint, PDB paths, etc.)",
            "No visibility into actual C2 configuration files to confirm custom vs. default Beacon profile",
            "No attribution anchor beyond TTP pattern matching — no shared infrastructure with confirmed prior Cobalt Group operations",
        ],
        "response_text": (
            "The false-flag hypothesis is noted but assessed as lower probability.  "
            "Deliberately replicating a specific undocumented TTP (HK relay) not in "
            "public reporting requires direct access to Cobalt Group playbooks, which "
            "is a higher-burden claim than Cobalt Group simply reusing its own methods.  "
            "The evidence gaps are acknowledged and confidence is calibrated accordingly "
            "(moderate-high rather than high).  A malware sample would resolve the uncertainty."
        ),
        "status": "responded",
        "created_by": "devil_advocate",
        "created_at": ts(0, 5),
    }


# ============================================================================
# WRITE TO DISK
# ============================================================================

def write_json(filename: str, data) -> None:
    path = os.path.join(APP_DATA_DIR, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  ✓  {path}")


def load_json(filename: str, default) -> dict:
    path = os.path.join(APP_DATA_DIR, filename)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default


def seed(reset: bool = False) -> None:
    print(f"\n{'='*60}")
    print("  Enterprise OSINT Platform — Demo Scenario Seeder")
    print(f"  APP_DATA_DIR: {APP_DATA_DIR}")
    print(f"{'='*60}\n")

    if reset:
        for fname in ["investigations.json", "alert_store.json",
                      "tradecraft_store.json", "credential_store.json"]:
            path = os.path.join(APP_DATA_DIR, fname)
            if os.path.exists(path):
                os.remove(path)
                print(f"  ✗  Removed {path}")

    # ---- Investigation -----------------------------------------------------
    print("\n[1/4] Investigation")
    inv_store = load_json("investigations.json", {})
    inv_store[INV_ID] = make_investigation()
    write_json("investigations.json", inv_store)

    # ---- Alert store (watchlist + alerts) ----------------------------------
    print("\n[2/4] Watchlist & Alerts")
    alert_store = load_json("alert_store.json",
                            {"watchlists": {}, "snapshots": {}, "alerts": {}})
    for entry in make_watchlist_entries():
        alert_store.setdefault("watchlists", {})[entry["id"]] = entry
    for alert in make_alerts():
        alert_store.setdefault("alerts", {})[alert["id"]] = alert
    write_json("alert_store.json", alert_store)

    # ---- Tradecraft store --------------------------------------------------
    print("\n[3/4] Analytic Tradecraft")
    tc_store = load_json("tradecraft_store.json",
                         {"intel_items": {}, "hypotheses": {},
                          "ach_cells": {}, "conclusions": {},
                          "alternatives": {}, "advocacies": {}})
    for item in make_intel_items():
        tc_store.setdefault("intel_items", {})[item["id"]] = item
    for hyp in make_hypotheses():
        tc_store.setdefault("hypotheses", {})[hyp["id"]] = hyp
    for cell in make_ach_cells():
        key = f"{cell['evidence_id']}|{cell['hypothesis_id']}"
        tc_store.setdefault("ach_cells", {})[key] = cell
    tc_store.setdefault("conclusions", {})[CONCL_ID] = make_conclusion()
    tc_store.setdefault("alternatives", {})[ALT_ID] = make_alternative()
    tc_store.setdefault("advocacies", {})[DA_ID] = make_devils_advocate()
    write_json("tradecraft_store.json", tc_store)

    # ---- Credential store --------------------------------------------------
    print("\n[4/4] Credential Intelligence")
    cred_store = load_json("credential_store.json", {"exposures": {}})
    cred_store.setdefault("exposures", {})["admin@mailfast.pro"] = {
        "email": "admin@mailfast.pro",
        "sources": [
            {
                "source": "Hudson Rock Cavalier",
                "breach_name": "mailfast_users infostealer dump",
                "date": ts(90),
                "severity": "critical",
                "data_classes": ["email", "password_plaintext", "username"],
                "note": "RedLine Stealer infection — attacker's own machine compromised.",
            },
            {
                "source": "Pastebin paste",
                "breach_name": "Unattributed credential paste",
                "date": ts(30),
                "severity": "high",
                "data_classes": ["email", "password_plaintext"],
            }
        ],
        "risk_score": 94,
        "last_checked": ts(1),
    }
    write_json("credential_store.json", cred_store)

    # ---- Summary -----------------------------------------------------------
    print(f"""
{'='*60}
  Demo scenario seeded successfully!

  Investigation ID : {INV_ID}
  Target           : secure-docview-portal.net
  Status           : completed (SHATTERED PANE)

  What's loaded:
    • 1 investigation with full infrastructure + threat intel
    • 7 related phishing domains + C2 IP mapped
    • 8 intelligence items with Admiralty ratings (A1–B2)
    • 3 hypotheses + 24-cell ACH matrix
    • 1 IC-standard conclusion + alternative explanation
    • 1 devil's advocate challenge with analyst response
    • 3 monitoring watchlists + 3 active alerts
    • 1 registrant credential exposure in breach database

  Start the backend:
    APP_DATA_DIR={APP_DATA_DIR} python app.py

  Demo URL:
    http://localhost:5001  (or via kubectl port-forward)
{'='*60}
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Seed the Enterprise OSINT Platform with a demo scenario.")
    parser.add_argument("--reset", action="store_true",
                        help="Wipe existing data files before seeding")
    args = parser.parse_args()
    seed(reset=args.reset)

"""
Investigation Templates
=======================

Pre-built investigation profiles for common analyst workflows.

Each template auto-populates:
  - Investigation scope (which intelligence sources to enable)
  - Suggested watchlist seeds (what to start monitoring immediately)
  - Starter ACH hypotheses (pre-written competing explanations to evaluate)
  - Recommended MITRE techniques to hunt for
  - Compliance framework requirements
  - Estimated time and data-point targets

Available templates
-------------------
  apt_attribution          Nation-state APT campaign attribution
  ransomware_profiling     Ransomware group infrastructure and operator profiling
  phishing_infrastructure  Phishing kit / credential harvesting infrastructure
  ma_due_diligence         M&A target cyber risk and exposure assessment
  insider_threat           Insider threat / data exfiltration investigation
  vulnerability_exposure   External attack surface and CVE exposure mapping
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WatchlistSeed:
    """A watchlist entry to create automatically from a template."""
    target_placeholder: str       # e.g. "{primary_domain}" or literal value
    target_type: str              # domain | ip | email | keyword | threat_actor
    description: str
    check_interval_hours: int = 4
    tags: List[str] = field(default_factory=list)


@dataclass
class ACHHypothesisSeed:
    """A pre-written ACH hypothesis to create from a template."""
    title: str
    description: str
    hypothesis_type: str = "primary"   # primary | alternative | null


@dataclass
class InvestigationTemplate:
    """A complete investigation template."""
    template_id: str
    name: str
    description: str
    category: str                          # attribution | financial | infrastructure | hr
    typical_target_types: List[str] = field(default_factory=list)
    estimated_hours: int = 4
    estimated_data_points: int = 500

    # Scope settings
    include_social_media: bool = True
    include_infrastructure: bool = True
    include_threat_intelligence: bool = True
    include_corporate_records: bool = False
    include_public_records: bool = True
    exclude_pii: bool = True
    historical_data_days: int = 90
    max_domains_to_scan: int = 100
    max_threat_indicators: int = 500

    # Compliance
    compliance_frameworks: List[str] = field(default_factory=list)

    # Content seeds
    watchlist_seeds: List[WatchlistSeed] = field(default_factory=list)
    ach_hypotheses: List[ACHHypothesisSeed] = field(default_factory=list)
    recommended_techniques: List[str] = field(default_factory=list)   # MITRE IDs to hunt
    key_questions: List[str] = field(default_factory=list)
    analyst_guidance: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "typical_target_types": self.typical_target_types,
            "estimated_hours": self.estimated_hours,
            "estimated_data_points": self.estimated_data_points,
            "scope": {
                "include_social_media": self.include_social_media,
                "include_infrastructure": self.include_infrastructure,
                "include_threat_intelligence": self.include_threat_intelligence,
                "include_corporate_records": self.include_corporate_records,
                "include_public_records": self.include_public_records,
                "exclude_pii": self.exclude_pii,
                "historical_data_days": self.historical_data_days,
                "max_domains_to_scan": self.max_domains_to_scan,
                "max_threat_indicators": self.max_threat_indicators,
            },
            "compliance_frameworks": self.compliance_frameworks,
            "watchlist_seeds": [
                {
                    "target_placeholder": w.target_placeholder,
                    "target_type": w.target_type,
                    "description": w.description,
                    "check_interval_hours": w.check_interval_hours,
                    "tags": w.tags,
                }
                for w in self.watchlist_seeds
            ],
            "ach_hypotheses": [
                {
                    "title": h.title,
                    "description": h.description,
                    "hypothesis_type": h.hypothesis_type,
                }
                for h in self.ach_hypotheses
            ],
            "recommended_techniques": self.recommended_techniques,
            "key_questions": self.key_questions,
            "analyst_guidance": self.analyst_guidance,
        }

    def to_scope_dict(self) -> Dict[str, Any]:
        """Return just the scope fields for pre-populating investigation creation."""
        return {
            "include_social_media": self.include_social_media,
            "include_infrastructure": self.include_infrastructure,
            "include_threat_intelligence": self.include_threat_intelligence,
            "include_corporate_records": self.include_corporate_records,
            "include_public_records": self.include_public_records,
            "exclude_pii": self.exclude_pii,
            "historical_data_days": self.historical_data_days,
            "max_domains_to_scan": self.max_domains_to_scan,
            "max_threat_indicators": self.max_threat_indicators,
        }


# ---------------------------------------------------------------------------
# Template definitions
# ---------------------------------------------------------------------------

_TEMPLATES: List[InvestigationTemplate] = [

    # ------------------------------------------------------------------ #
    #  APT Attribution                                                     #
    # ------------------------------------------------------------------ #
    InvestigationTemplate(
        template_id="apt_attribution",
        name="APT Attribution",
        description=(
            "Full infrastructure and TTP analysis to attribute observed malicious "
            "activity to a nation-state advanced persistent threat actor. "
            "Emphasises certificate transparency pivots, passive DNS, MITRE mapping, "
            "and structured ACH attribution reasoning."
        ),
        category="attribution",
        typical_target_types=["domain", "ip", "hash"],
        estimated_hours=8,
        estimated_data_points=1200,
        include_social_media=False,
        include_infrastructure=True,
        include_threat_intelligence=True,
        include_corporate_records=False,
        include_public_records=True,
        exclude_pii=True,
        historical_data_days=180,
        max_domains_to_scan=200,
        max_threat_indicators=1000,
        compliance_frameworks=["GDPR"],
        watchlist_seeds=[
            WatchlistSeed("{primary_target}", "domain",
                          "Primary target domain — watch for infrastructure changes",
                          check_interval_hours=1,
                          tags=["apt", "c2", "priority"]),
            WatchlistSeed("{primary_ip}", "ip",
                          "C2 IP — monitor reputation score and new hostnames",
                          check_interval_hours=4,
                          tags=["apt", "c2"]),
        ],
        ach_hypotheses=[
            ACHHypothesisSeed(
                "Nation-state actor (known APT group)",
                "The activity is attributable to a known nation-state APT based on "
                "infrastructure patterns, TTPs, tooling, and targeting profile consistent "
                "with documented campaigns.",
                "primary",
            ),
            ACHHypothesisSeed(
                "Criminal group using APT-grade tooling",
                "A financially-motivated criminal group obtained or purchased APT-grade "
                "tooling (e.g. commercial implants, leaked government exploits) and is "
                "using TTPs that superficially resemble nation-state activity.",
                "alternative",
            ),
            ACHHypothesisSeed(
                "False flag / deliberate misattribution",
                "A third party deliberately planted indicators mimicking a known APT "
                "group to mislead attribution analysis.",
                "alternative",
            ),
            ACHHypothesisSeed(
                "Independent researcher or red team",
                "The activity originates from a legitimate penetration tester, security "
                "researcher, or red team using public tooling.",
                "null",
            ),
        ],
        recommended_techniques=[
            "T1566.001", "T1566.002",  # Spearphishing
            "T1071.001", "T1071.004",  # C2 channels
            "T1090.003",               # Multi-hop proxy
            "T1027", "T1027.002",      # Obfuscation
            "T1583.001", "T1583.003",  # Infrastructure acquisition
            "T1588.002",               # Tool acquisition
            "T1036",                   # Masquerading
        ],
        key_questions=[
            "What MITRE techniques are observed and which actor groups use this exact cluster?",
            "Is there a shared infrastructure fingerprint (cert, registrant, ASN) linking this to prior campaigns?",
            "What is the targeting pattern — sector, region, organisation type — and who does it match?",
            "Are there OPSEC failures (breached credentials, reused infrastructure) that reveal the operator?",
            "What is the weakest link in the attribution chain and what evidence would change the assessment?",
        ],
        analyst_guidance=(
            "Start with infrastructure pivots (cert SANs, passive DNS, ASN enumeration) before "
            "drawing TTP conclusions. Document each pivot step as an intelligence item with "
            "Admiralty ratings. Build the ACH matrix before committing to a conclusion — the "
            "process of filling it in often reveals overlooked inconsistencies. Require at least "
            "two independent discriminating indicators before reaching HIGH confidence."
        ),
    ),

    # ------------------------------------------------------------------ #
    #  Ransomware Group Profiling                                          #
    # ------------------------------------------------------------------ #
    InvestigationTemplate(
        template_id="ransomware_profiling",
        name="Ransomware Group Profiling",
        description=(
            "Map the full infrastructure and operational profile of a ransomware group "
            "or affiliate. Covers leak site, negotiation portal, affiliate recruitment, "
            "RaaS infrastructure, and historical victim data."
        ),
        category="attribution",
        typical_target_types=["domain", "onion", "ip", "hash"],
        estimated_hours=6,
        estimated_data_points=800,
        include_social_media=True,
        include_infrastructure=True,
        include_threat_intelligence=True,
        include_corporate_records=False,
        include_public_records=True,
        exclude_pii=True,
        historical_data_days=365,
        max_domains_to_scan=150,
        max_threat_indicators=800,
        compliance_frameworks=["GDPR"],
        watchlist_seeds=[
            WatchlistSeed("{leak_site_domain}", "domain",
                          "Ransomware leak site — monitor for new victim posts",
                          check_interval_hours=4,
                          tags=["ransomware", "leak-site"]),
            WatchlistSeed("{group_name}", "keyword",
                          "Group name keyword — monitor paste sites and forums",
                          check_interval_hours=24,
                          tags=["ransomware", "keyword"]),
            WatchlistSeed("{negotiation_portal}", "domain",
                          "Negotiation portal domain — monitor availability",
                          check_interval_hours=12,
                          tags=["ransomware", "negotiation"]),
        ],
        ach_hypotheses=[
            ACHHypothesisSeed(
                "Established RaaS group with affiliate model",
                "The activity is operated by a known ransomware-as-a-service group "
                "using a network of affiliates. The core group manages infrastructure "
                "and negotiation; affiliates handle initial access.",
                "primary",
            ),
            ACHHypothesisSeed(
                "Rebrand of a previously disrupted group",
                "The group is a rebrand of a law-enforcement-disrupted predecessor "
                "(e.g. Conti → Black Basta, REvil → relaunch) reusing code, operators, "
                "or infrastructure from the prior group.",
                "alternative",
            ),
            ACHHypothesisSeed(
                "Nation-state sponsored ransomware (revenue + disruption)",
                "The ransomware campaign is state-sponsored, combining financial "
                "motivation with strategic disruption objectives.",
                "alternative",
            ),
        ],
        recommended_techniques=[
            "T1486",        # Data Encrypted for Impact
            "T1490",        # Inhibit System Recovery
            "T1489",        # Service Stop
            "T1485",        # Data Destruction
            "T1567.002",    # Exfiltration to Cloud
            "T1566",        # Phishing
            "T1133",        # External Remote Services
            "T1078",        # Valid Accounts
            "T1219",        # Remote Access Software
        ],
        key_questions=[
            "What is the group's RaaS affiliate model structure and recruitment channels?",
            "Are the leak site, negotiation portal, and payment infrastructure on the same operator fingerprint?",
            "What is the group's victim selection criteria — revenue threshold, sector, geography?",
            "What initial access vectors does this group favour (phishing, VPN exploit, RDP brute force)?",
            "Is there infrastructure overlap with a previously disrupted or rebranded group?",
        ],
        analyst_guidance=(
            "Check onion domains in passive DNS and CT logs — ransomware groups often reuse "
            "certificate infrastructure across rebrands. The leak site publishing schedule "
            "can reveal operator time zones. Cross-reference victim claims against "
            "publicly reported incidents to validate the group's actual capability vs. claims."
        ),
    ),

    # ------------------------------------------------------------------ #
    #  Phishing Infrastructure                                             #
    # ------------------------------------------------------------------ #
    InvestigationTemplate(
        template_id="phishing_infrastructure",
        name="Phishing Infrastructure",
        description=(
            "Map phishing kit infrastructure, identify the full domain cluster via "
            "certificate and registrant pivots, and assess credential harvesting scope. "
            "Standard template for SOC-initiated phishing triage."
        ),
        category="infrastructure",
        typical_target_types=["domain", "url", "ip"],
        estimated_hours=3,
        estimated_data_points=400,
        include_social_media=False,
        include_infrastructure=True,
        include_threat_intelligence=True,
        include_corporate_records=False,
        include_public_records=True,
        exclude_pii=True,
        historical_data_days=60,
        max_domains_to_scan=50,
        max_threat_indicators=200,
        compliance_frameworks=["GDPR"],
        watchlist_seeds=[
            WatchlistSeed("{phishing_domain}", "domain",
                          "Primary phishing domain — monitor for new certs and subdomains",
                          check_interval_hours=1,
                          tags=["phishing", "priority"]),
            WatchlistSeed("{hosting_ip}", "ip",
                          "Phishing hosting IP — watch for new domains resolving here",
                          check_interval_hours=4,
                          tags=["phishing", "hosting"]),
        ],
        ach_hypotheses=[
            ACHHypothesisSeed(
                "Targeted spearphishing campaign (known threat actor)",
                "The phishing infrastructure is part of a targeted campaign by a known "
                "threat actor group, with the lure and targeting consistent with their "
                "documented TTPs.",
                "primary",
            ),
            ACHHypothesisSeed(
                "Commodity phishing / opportunistic credential harvesting",
                "The phishing is a generic credential harvesting operation using a "
                "bought kit, targeting a large number of organisations with the same "
                "infrastructure.",
                "alternative",
            ),
            ACHHypothesisSeed(
                "Business Email Compromise (BEC) enablement",
                "The phishing infrastructure is specifically designed to harvest "
                "credentials for downstream BEC fraud rather than malware delivery.",
                "alternative",
            ),
        ],
        recommended_techniques=[
            "T1566.001", "T1566.002",   # Spearphishing
            "T1598",                    # Phishing for Information
            "T1056.003",                # Web Portal Capture
            "T1583.001",                # Acquire Infrastructure: Domains
            "T1608.005",                # Stage Capabilities: Link Target
        ],
        key_questions=[
            "How many domains share this phishing kit's infrastructure fingerprint?",
            "What brand is being impersonated and are there other impersonation targets?",
            "Are there active beacon check-ins indicating victims have already been compromised?",
            "Does the registrant email or certificate link this to prior phishing campaigns?",
            "What credentials or data types is the kit designed to capture?",
        ],
        analyst_guidance=(
            "Start with the SSL certificate — the SAN list is the fastest way to find "
            "sibling domains. Check the registrant email against breach databases. "
            "Shodan the hosting IP for the phishing kit fingerprint (default login paths, "
            "HTTP headers). Passive DNS will show historical domains on the same IP."
        ),
    ),

    # ------------------------------------------------------------------ #
    #  M&A Due Diligence                                                   #
    # ------------------------------------------------------------------ #
    InvestigationTemplate(
        template_id="ma_due_diligence",
        name="M&A Cyber Due Diligence",
        description=(
            "Assess the cyber risk and exposure profile of an M&A target. "
            "Covers external attack surface, breach history, credential exposure, "
            "dark web presence, and reputational risk indicators."
        ),
        category="financial",
        typical_target_types=["domain", "company"],
        estimated_hours=12,
        estimated_data_points=2000,
        include_social_media=True,
        include_infrastructure=True,
        include_threat_intelligence=True,
        include_corporate_records=True,
        include_public_records=True,
        exclude_pii=True,
        historical_data_days=365,
        max_domains_to_scan=500,
        max_threat_indicators=500,
        compliance_frameworks=["GDPR", "CCPA"],
        watchlist_seeds=[
            WatchlistSeed("{primary_domain}", "domain",
                          "Primary company domain — monitor ongoing exposure",
                          check_interval_hours=24,
                          tags=["ma", "target"]),
        ],
        ach_hypotheses=[
            ACHHypothesisSeed(
                "Target has manageable, remediable cyber risk",
                "Identified vulnerabilities and exposures are within normal industry "
                "baseline and can be remediated within a standard post-acquisition "
                "hardening programme.",
                "primary",
            ),
            ACHHypothesisSeed(
                "Target has undisclosed active compromise",
                "The target organisation is currently compromised or has indicators "
                "of a recent undisclosed breach that creates material deal risk.",
                "alternative",
            ),
            ACHHypothesisSeed(
                "Target has systemic security debt requiring significant investment",
                "The target's security posture reflects systemic under-investment "
                "that will require significant post-acquisition remediation budget "
                "beyond normal integration costs.",
                "alternative",
            ),
        ],
        recommended_techniques=[],
        key_questions=[
            "Are there active or recent credential breaches affecting the target's employees or customers?",
            "What does the external attack surface look like — open ports, expired certs, abandoned subdomains?",
            "Is the target mentioned in dark web forums, ransomware leak sites, or paste dumps?",
            "Are there CVEs affecting the target's publicly exposed technology stack?",
            "What is the target's supply chain risk profile — key technology vendors, third-party access?",
        ],
        analyst_guidance=(
            "M&A investigations require careful GDPR/CCPA compliance — enable PII exclusion "
            "and document the legal basis. Focus on objective technical evidence (open ports, "
            "certificate health, breach databases) rather than social media sentiment. "
            "The credential exposure check is often the highest-value finding — "
            "employee credentials in breach databases indicate ongoing risk."
        ),
    ),

    # ------------------------------------------------------------------ #
    #  Insider Threat                                                      #
    # ------------------------------------------------------------------ #
    InvestigationTemplate(
        template_id="insider_threat",
        name="Insider Threat / Data Exfiltration",
        description=(
            "Investigate potential insider threat activity: data exfiltration to personal "
            "cloud storage, communication with external actors, or preparation for "
            "departure with sensitive data. Designed for HR/Legal-referred cases."
        ),
        category="hr",
        typical_target_types=["email", "domain", "ip"],
        estimated_hours=4,
        estimated_data_points=300,
        include_social_media=True,
        include_infrastructure=False,
        include_threat_intelligence=False,
        include_corporate_records=True,
        include_public_records=True,
        exclude_pii=False,
        historical_data_days=90,
        max_domains_to_scan=20,
        max_threat_indicators=50,
        compliance_frameworks=["GDPR", "CCPA"],
        watchlist_seeds=[],
        ach_hypotheses=[
            ACHHypothesisSeed(
                "Intentional data exfiltration for personal gain / competitor",
                "The subject is deliberately exfiltrating sensitive data for personal "
                "financial gain, to benefit a competitor, or in preparation for departure.",
                "primary",
            ),
            ACHHypothesisSeed(
                "Unintentional policy violation (no malicious intent)",
                "The observed activity reflects poor security hygiene or misunderstanding "
                "of policy (e.g. personal cloud sync enabled, BYOD use) without "
                "malicious intent.",
                "alternative",
            ),
            ACHHypothesisSeed(
                "Coerced by external threat actor",
                "The subject is acting under coercion, blackmail, or direction from "
                "an external threat actor (nation-state recruitment, financial leverage).",
                "alternative",
            ),
        ],
        recommended_techniques=[
            "T1567",     # Exfiltration Over Web Service
            "T1052",     # Exfiltration Over Physical Medium
            "T1048",     # Exfiltration Over Alternative Protocol
            "T1530",     # Data from Cloud Storage Object
        ],
        key_questions=[
            "What external services or domains has the subject been communicating with?",
            "Is the subject's personal email address or social profiles linked to competitors or recruiters?",
            "Are there publicly visible job applications or LinkedIn activity indicating departure preparation?",
            "Has the subject's email appeared in breach databases that could indicate external compromise?",
            "Are there dark web mentions of the organisation's data or the subject's identity?",
        ],
        analyst_guidance=(
            "IMPORTANT: Insider threat investigations have heightened legal and privacy requirements. "
            "Ensure HR and Legal sign-off before proceeding. Enable all compliance frameworks. "
            "Scope strictly to public/OSINT sources — this template does NOT authorise access to "
            "internal corporate systems, email, or endpoint data. Document the legal basis for "
            "every data source used. Findings must be reviewed by Legal before disclosure."
        ),
    ),

    # ------------------------------------------------------------------ #
    #  Vulnerability Exposure                                              #
    # ------------------------------------------------------------------ #
    InvestigationTemplate(
        template_id="vulnerability_exposure",
        name="External Attack Surface & CVE Exposure",
        description=(
            "Map an organisation's external attack surface: exposed services, "
            "outdated software versions, known CVEs, certificate health, and "
            "subdomain sprawl. Suitable for continuous exposure management."
        ),
        category="infrastructure",
        typical_target_types=["domain", "ip", "company"],
        estimated_hours=5,
        estimated_data_points=600,
        include_social_media=False,
        include_infrastructure=True,
        include_threat_intelligence=True,
        include_corporate_records=False,
        include_public_records=True,
        exclude_pii=True,
        historical_data_days=30,
        max_domains_to_scan=500,
        max_threat_indicators=200,
        compliance_frameworks=["GDPR"],
        watchlist_seeds=[
            WatchlistSeed("{primary_domain}", "domain",
                          "Primary domain — monitor for new subdomains and cert changes",
                          check_interval_hours=24,
                          tags=["attack-surface", "continuous"]),
            WatchlistSeed("{primary_ip_range}", "ip",
                          "Primary IP — watch for new services and reputation changes",
                          check_interval_hours=24,
                          tags=["attack-surface", "exposure"]),
        ],
        ach_hypotheses=[],
        recommended_techniques=[
            "T1190",   # Exploit Public-Facing Application
            "T1133",   # External Remote Services
            "T1589",   # Gather Victim Identity Information
            "T1595",   # Active Scanning
            "T1596",   # Search Open Technical Databases
        ],
        key_questions=[
            "What services are exposed on non-standard ports that shouldn't be public-facing?",
            "Are there expired or soon-to-expire TLS certificates that could cause outages or be exploited?",
            "What software versions are visible in Shodan banners and are any known-vulnerable?",
            "How many subdomains exist and are any abandoned / pointing to decommissioned services?",
            "Are there exposed admin interfaces, login portals, or development environments?",
        ],
        analyst_guidance=(
            "Focus on Shodan banner analysis for software version fingerprinting. "
            "Subdomain enumeration via crt.sh often reveals forgotten development or staging "
            "environments. Certificate expiry is high-value for operations teams. "
            "Cross-reference Shodan findings against NVD CVE data for the identified software versions."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Template library
# ---------------------------------------------------------------------------

class TemplateLibrary:
    """Simple in-memory template store."""

    def __init__(self, templates: List[InvestigationTemplate]) -> None:
        self._by_id: Dict[str, InvestigationTemplate] = {
            t.template_id: t for t in templates
        }

    def get(self, template_id: str) -> Optional[InvestigationTemplate]:
        return self._by_id.get(template_id)

    def list_all(self) -> List[Dict[str, Any]]:
        """Return compact summaries for all templates."""
        return [
            {
                "template_id": t.template_id,
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "typical_target_types": t.typical_target_types,
                "estimated_hours": t.estimated_hours,
                "estimated_data_points": t.estimated_data_points,
                "watchlist_seed_count": len(t.watchlist_seeds),
                "hypothesis_count": len(t.ach_hypotheses),
                "compliance_frameworks": t.compliance_frameworks,
            }
            for t in sorted(self._by_id.values(), key=lambda x: x.name)
        ]

    def by_category(self, category: str) -> List[InvestigationTemplate]:
        return [t for t in self._by_id.values() if t.category == category]


# Module-level singleton
template_library = TemplateLibrary(_TEMPLATES)

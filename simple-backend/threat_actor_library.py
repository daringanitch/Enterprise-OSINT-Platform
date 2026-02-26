"""
Threat Actor Library
====================

Curated dossiers for ~50 major threat actors covering nation-state APTs,
financially-motivated criminal groups, and hacktivist collectives.

Each dossier includes:
  - Aliases, origin country, motivation, activity period
  - Primary targets (sectors and regions)
  - Signature TTPs (MITRE ATT&CK technique IDs)
  - Known malware families and tools
  - Infrastructure fingerprints for pivot analysis
  - Confidence notes and key public references

Usage
-----
    from threat_actor_library import actor_library

    # Look up by name or alias
    dossier = actor_library.get("APT28")

    # Find actors matching a MITRE technique
    actors = actor_library.find_by_technique("T1566.001")

    # Find actors targeting a sector
    actors = actor_library.find_by_sector("Financial Services")

    # Find actors matching a set of TTPs (returns ranked matches)
    matches = actor_library.match_ttps(["T1566.001", "T1071.001", "T1090.003"])
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ThreatActorDossier:
    """Complete dossier for a single threat actor."""
    actor_id: str                        # Internal stable ID e.g. "apt28"
    name: str                            # Primary name
    aliases: List[str] = field(default_factory=list)
    origin_country: str = ""             # ISO 3166-1 alpha-2 or descriptive
    actor_type: str = ""                 # nation-state | criminal | hacktivist | unknown
    motivation: str = ""                 # espionage | financial | disruption | ideological
    activity_since: str = ""             # e.g. "2007"
    activity_status: str = "active"      # active | dormant | disbanded | unknown
    description: str = ""

    # Targeting
    targeted_sectors: List[str] = field(default_factory=list)
    targeted_regions: List[str] = field(default_factory=list)

    # TTPs
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)     # TA00xx
    tools: List[str] = field(default_factory=list)             # malware families + frameworks
    initial_access_vectors: List[str] = field(default_factory=list)

    # Infrastructure fingerprints (for pivot matching)
    infrastructure_patterns: List[str] = field(default_factory=list)
    known_c2_asns: List[str] = field(default_factory=list)
    hosting_preferences: List[str] = field(default_factory=list)  # e.g. "Cloudflare", "Hetzner"

    # Attribution
    attributed_by: List[str] = field(default_factory=list)     # e.g. ["Mandiant", "CrowdStrike"]
    confidence: str = "moderate"                               # high | moderate | low
    notes: str = ""
    references: List[str] = field(default_factory=list)        # URLs to public reports

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "name": self.name,
            "aliases": self.aliases,
            "origin_country": self.origin_country,
            "actor_type": self.actor_type,
            "motivation": self.motivation,
            "activity_since": self.activity_since,
            "activity_status": self.activity_status,
            "description": self.description,
            "targeted_sectors": self.targeted_sectors,
            "targeted_regions": self.targeted_regions,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "tools": self.tools,
            "initial_access_vectors": self.initial_access_vectors,
            "infrastructure_patterns": self.infrastructure_patterns,
            "known_c2_asns": self.known_c2_asns,
            "hosting_preferences": self.hosting_preferences,
            "attributed_by": self.attributed_by,
            "confidence": self.confidence,
            "notes": self.notes,
            "references": self.references,
        }

    def matches_technique(self, technique: str) -> bool:
        return technique.upper() in [t.upper() for t in self.mitre_techniques]

    def matches_sector(self, sector: str) -> bool:
        sl = sector.lower()
        return any(sl in s.lower() for s in self.targeted_sectors)


@dataclass
class TTPMatchResult:
    """Result of matching a set of TTPs against the library."""
    actor: ThreatActorDossier
    matched_techniques: List[str]
    match_score: float          # 0-1: proportion of query TTPs matched
    total_actor_techniques: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor": self.actor.to_dict(),
            "matched_techniques": self.matched_techniques,
            "match_score": round(self.match_score, 3),
            "total_actor_techniques": self.total_actor_techniques,
        }


# ---------------------------------------------------------------------------
# Actor data
# ---------------------------------------------------------------------------

_ACTORS: List[ThreatActorDossier] = [

    # ------------------------------------------------------------------ APTs
    ThreatActorDossier(
        actor_id="apt28",
        name="APT28",
        aliases=["Fancy Bear", "Sofacy", "STRONTIUM", "Pawn Storm", "Sednit", "Forest Blizzard"],
        origin_country="RU",
        actor_type="nation-state",
        motivation="espionage",
        activity_since="2007",
        activity_status="active",
        description=(
            "Russian GRU Unit 26165 / 74455. One of the most prolific state-sponsored "
            "actors, conducting political espionage, election interference, and military "
            "intelligence collection globally."
        ),
        targeted_sectors=["Government", "Defense", "Political Organizations", "Media", "Energy"],
        targeted_regions=["EU", "NA", "Eastern Europe", "Middle East"],
        mitre_techniques=[
            "T1566.001", "T1566.002", "T1078", "T1190", "T1059.001",
            "T1071.001", "T1027", "T1083", "T1003.001", "T1036.005",
            "T1105", "T1070.004", "T1547.001",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0010", "TA0011"],
        tools=["X-Agent", "X-Tunnel", "Sofacy", "Zebrocy", "LoJax", "Drovorub", "GooseEgg"],
        initial_access_vectors=["Spearphishing", "Credential stuffing", "Exploitation of public-facing applications"],
        infrastructure_patterns=["Short-lived VPS", "Compromised routers as proxies", "Cloudflare CDN for C2"],
        attributed_by=["Mandiant", "CrowdStrike", "TrendMicro", "US DoJ"],
        confidence="high",
        references=["https://www.mandiant.com/resources/apt28-a-window-into-russias-cyber-espionage-operations"],
    ),

    ThreatActorDossier(
        actor_id="apt29",
        name="APT29",
        aliases=["Cozy Bear", "NOBELIUM", "Midnight Blizzard", "The Dukes", "Yttrium"],
        origin_country="RU",
        actor_type="nation-state",
        motivation="espionage",
        activity_since="2008",
        activity_status="active",
        description=(
            "Russian SVR foreign intelligence service. Known for patient, long-term "
            "intrusions and supply-chain attacks (SolarWinds SUNBURST). Highly evasive."
        ),
        targeted_sectors=["Government", "Think Tanks", "Healthcare", "Technology", "Diplomatic"],
        targeted_regions=["NA", "EU", "Global"],
        mitre_techniques=[
            "T1566.001", "T1195.002", "T1078.004", "T1059.001", "T1059.003",
            "T1071.001", "T1071.004", "T1573.002", "T1027.010", "T1036",
            "T1003", "T1560", "T1041",
        ],
        mitre_tactics=["TA0001", "TA0003", "TA0005", "TA0006", "TA0009", "TA0010", "TA0011"],
        tools=["SUNBURST", "TEARDROP", "GoldMax", "Cobalt Strike", "MagicWeb", "WellMess"],
        initial_access_vectors=["Supply chain compromise", "Spearphishing", "OAuth abuse", "Password spray"],
        infrastructure_patterns=["Legitimate cloud services as C2 (AWS, Azure, Dropbox)", "Long dwell times (months)", "Living-off-the-land"],
        attributed_by=["Mandiant", "Microsoft", "US CISA", "NCSC UK"],
        confidence="high",
        references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a"],
    ),

    ThreatActorDossier(
        actor_id="apt41",
        name="APT41",
        aliases=["Double Dragon", "Winnti Group", "BARIUM", "Wicked Panda", "Earth Baku"],
        origin_country="CN",
        actor_type="nation-state",
        motivation="espionage, financial",
        activity_since="2012",
        activity_status="active",
        description=(
            "Dual-purpose Chinese actor combining state-sponsored espionage with "
            "financially-motivated cybercrime (gaming industry, crypto). Unique in "
            "openly pursuing both missions simultaneously."
        ),
        targeted_sectors=["Healthcare", "Technology", "Telecommunications", "Gaming", "Financial", "Government"],
        targeted_regions=["NA", "EU", "APAC", "Middle East"],
        mitre_techniques=[
            "T1190", "T1078", "T1059.003", "T1059.001", "T1566.001",
            "T1071.001", "T1090", "T1027", "T1036.005", "T1547.001",
            "T1003.001", "T1105", "T1560.001",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0007", "TA0008", "TA0010"],
        tools=["Winnti", "ShadowPad", "PlugX", "Cobalt Strike", "DEADEYE", "LOWKEY"],
        initial_access_vectors=["Exploitation of public-facing apps", "Supply chain", "Spearphishing"],
        infrastructure_patterns=["Compromised legitimate websites as watering holes", "Fast-flux DNS"],
        attributed_by=["Mandiant", "CrowdStrike", "US DoJ indictment"],
        confidence="high",
        references=["https://www.mandiant.com/resources/apt41-initiates-global-intrusion-campaign-using-multiple-exploits"],
    ),

    ThreatActorDossier(
        actor_id="apt32",
        name="APT32",
        aliases=["OceanLotus", "SeaLotus", "Canvas Cyclone", "Cobalt Kitty"],
        origin_country="VN",
        actor_type="nation-state",
        motivation="espionage",
        activity_since="2012",
        activity_status="active",
        description=(
            "Vietnamese state-sponsored group targeting foreign governments, "
            "journalists, dissidents, and corporations with business interests in Vietnam."
        ),
        targeted_sectors=["Government", "Media", "NGO", "Automotive", "Hospitality"],
        targeted_regions=["APAC", "EU", "NA"],
        mitre_techniques=[
            "T1566.001", "T1204.002", "T1059.007", "T1059.001", "T1071.001",
            "T1027", "T1547.001", "T1055", "T1083", "T1003",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0009"],
        tools=["SOUNDBITE", "WINDSHIELD", "PHOREAL", "Cobalt Strike", "Denis"],
        initial_access_vectors=["Spearphishing with macro-laden Office documents", "Watering hole"],
        infrastructure_patterns=["Legitimate-looking domains mimicking news sites", "GitHub for C2"],
        attributed_by=["Mandiant", "ESET", "Volexity"],
        confidence="high",
        references=["https://www.mandiant.com/resources/cyber-espionage-apt32"],
    ),

    ThreatActorDossier(
        actor_id="apt33",
        name="APT33",
        aliases=["Elfin", "Refined Kitten", "Holmium", "Peach Sandstorm"],
        origin_country="IR",
        actor_type="nation-state",
        motivation="espionage, disruption",
        activity_since="2013",
        activity_status="active",
        description=(
            "Iranian IRGC-linked group targeting aviation, energy, and defense industries. "
            "Known for deploying destructive wiper malware (Shamoon) alongside espionage."
        ),
        targeted_sectors=["Aviation", "Energy", "Defense", "Government", "Petrochemical"],
        targeted_regions=["Middle East", "NA", "EU"],
        mitre_techniques=[
            "T1566.001", "T1566.002", "T1078", "T1133", "T1059.001",
            "T1071.001", "T1027", "T1486", "T1485",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0040"],
        tools=["TURNEDUP", "NANOCORE", "NETWIRE", "Shamoon", "StoneDrill"],
        initial_access_vectors=["Spearphishing", "Valid accounts (password spray)", "VPN exploitation"],
        infrastructure_patterns=["Iranian hosting providers", "Free dynamic DNS"],
        attributed_by=["Mandiant", "Microsoft", "Symantec"],
        confidence="high",
        references=["https://www.mandiant.com/resources/apt33-insights-into-iranian-cyber-espionage"],
    ),

    ThreatActorDossier(
        actor_id="apt34",
        name="APT34",
        aliases=["OilRig", "Helix Kitten", "Crambus", "Hazel Sandstorm"],
        origin_country="IR",
        actor_type="nation-state",
        motivation="espionage",
        activity_since="2014",
        activity_status="active",
        description=(
            "Iranian Ministry of Intelligence (MOIS)-linked group focused on "
            "Middle East government and critical infrastructure, using DNS tunneling C2."
        ),
        targeted_sectors=["Government", "Financial", "Energy", "Telecommunications", "Chemical"],
        targeted_regions=["Middle East", "EU", "NA"],
        mitre_techniques=[
            "T1566.001", "T1566.002", "T1071.004", "T1568.001", "T1059.006",
            "T1078", "T1027", "T1055", "T1003.001",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0011"],
        tools=["POWRUNER", "BONDUPDATER", "QUADAGENT", "RDAT", "Karkoff", "SideTwist"],
        initial_access_vectors=["Spearphishing", "Exploitation of public-facing apps", "Valid accounts"],
        infrastructure_patterns=["DNS-over-HTTPS tunneling", "Legitimate cloud services"],
        attributed_by=["Palo Alto Unit42", "Mandiant", "CrowdStrike"],
        confidence="high",
        references=["https://unit42.paloaltonetworks.com/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-delivering-helminth-backdoor/"],
    ),

    ThreatActorDossier(
        actor_id="lazarus",
        name="Lazarus Group",
        aliases=["Hidden Cobra", "Zinc", "Diamond Sleet", "Guardians of Peace", "APT38 (financial subset)"],
        origin_country="KP",
        actor_type="nation-state",
        motivation="espionage, financial",
        activity_since="2009",
        activity_status="active",
        description=(
            "North Korean RGB-linked group responsible for the Sony hack, WannaCry, "
            "Bangladesh Bank heist ($81M), and sustained cryptocurrency theft to fund "
            "the DPRK regime. Most financially-damaging threat actor globally."
        ),
        targeted_sectors=["Financial", "Cryptocurrency", "Defense", "Government", "Media"],
        targeted_regions=["Global"],
        mitre_techniques=[
            "T1566.001", "T1195.002", "T1059.001", "T1071.001", "T1090.003",
            "T1027", "T1036.005", "T1486", "T1560", "T1005",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0009", "TA0010", "TA0040"],
        tools=["BLINDINGCAN", "HOPLIGHT", "ELECTRUM", "WannaCry", "Manuscrypt", "DTRACK"],
        initial_access_vectors=["Spearphishing (fake job offers)", "Supply chain", "Trojanized software"],
        infrastructure_patterns=["Compromised third-party infrastructure", "TOR for anonymization", "Cryptocurrency mixers"],
        attributed_by=["US CISA", "Mandiant", "Kaspersky", "US DoJ"],
        confidence="high",
        references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a"],
    ),

    ThreatActorDossier(
        actor_id="volt_typhoon",
        name="Volt Typhoon",
        aliases=["BRONZE SILHOUETTE", "Vanguard Panda", "Dev-0391"],
        origin_country="CN",
        actor_type="nation-state",
        motivation="espionage, pre-positioning",
        activity_since="2021",
        activity_status="active",
        description=(
            "PRC state-sponsored actor pre-positioning on US critical infrastructure "
            "for potential disruptive operations. Unique for living-off-the-land "
            "exclusively — no custom malware, only native OS tools."
        ),
        targeted_sectors=["Critical Infrastructure", "Government", "Military", "Utilities", "Telecommunications"],
        targeted_regions=["NA", "Guam"],
        mitre_techniques=[
            "T1078.003", "T1190", "T1059.004", "T1059.003", "T1069",
            "T1087", "T1049", "T1070.003", "T1071.001", "T1090",
        ],
        mitre_tactics=["TA0001", "TA0003", "TA0005", "TA0007", "TA0008", "TA0011"],
        tools=["Living-off-the-land only (cmd, netsh, wmic, ntdsutil, certutil, etc.)"],
        initial_access_vectors=["Exploitation of internet-facing Fortinet, Citrix, Cisco devices"],
        infrastructure_patterns=["SOHO routers as proxies (ASUS, Cisco, D-Link, Netgear)", "KV-botnet"],
        attributed_by=["Microsoft", "US CISA", "NSA", "Five Eyes"],
        confidence="high",
        references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a"],
    ),

    ThreatActorDossier(
        actor_id="salt_typhoon",
        name="Salt Typhoon",
        aliases=["GhostEmperor", "FamousSparrow", "Earth Estries"],
        origin_country="CN",
        actor_type="nation-state",
        motivation="espionage",
        activity_since="2019",
        activity_status="active",
        description=(
            "PRC actor specializing in telecommunications infrastructure compromise. "
            "Responsible for the 2024 breach of US telecom carriers and interception "
            "of communications of government officials."
        ),
        targeted_sectors=["Telecommunications", "Government", "ISPs", "Legal"],
        targeted_regions=["NA", "EU", "APAC"],
        mitre_techniques=[
            "T1190", "T1078", "T1021.001", "T1059.001", "T1027",
            "T1071.001", "T1041", "T1560",
        ],
        mitre_tactics=["TA0001", "TA0003", "TA0005", "TA0006", "TA0009", "TA0010"],
        tools=["SparrowDoor", "ShadowPad", "Demodex", "custom kernel rootkits"],
        initial_access_vectors=["Exploitation of edge devices (Cisco, Fortinet, Ivanti)", "Valid accounts"],
        infrastructure_patterns=["Deep persistence in telco infrastructure", "Modified firmware"],
        attributed_by=["Microsoft", "Mandiant", "US CISA"],
        confidence="high",
        references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"],
    ),

    ThreatActorDossier(
        actor_id="sandworm",
        name="Sandworm",
        aliases=["Voodoo Bear", "Seashell Blizzard", "IRIDIUM", "TeleBots", "Unit 74455"],
        origin_country="RU",
        actor_type="nation-state",
        motivation="disruption, espionage",
        activity_since="2009",
        activity_status="active",
        description=(
            "Russian GRU Unit 74455. Most destructive cyber actor — responsible for "
            "NotPetya ($10B+ damage), Ukraine power grid attacks, Olympic Destroyer, "
            "and ongoing attacks against Ukrainian critical infrastructure."
        ),
        targeted_sectors=["Critical Infrastructure", "Energy", "Government", "Financial", "Media"],
        targeted_regions=["Ukraine", "EU", "NA", "Global"],
        mitre_techniques=[
            "T1059.003", "T1059.001", "T1078", "T1190", "T1195",
            "T1486", "T1485", "T1561", "T1071.001", "T1027",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0005", "TA0006", "TA0040"],
        tools=["NotPetya", "BlackEnergy", "Industroyer", "Cyclops Blink", "Prestige", "CRASHOVERRIDE"],
        initial_access_vectors=["Supply chain", "Spearphishing", "Exploitation of internet-facing systems"],
        infrastructure_patterns=["Compromised SOHO routers (Cyclops Blink botnet)", "Living-off-the-land post-compromise"],
        attributed_by=["US DoJ", "UK NCSC", "Mandiant", "ESET"],
        confidence="high",
        references=["https://www.justice.gov/opa/pr/six-russian-gru-officers-charged-connection-worldwide-deployment-destructive-malware"],
    ),

    # ------------------------------------------------------------------ Criminal
    ThreatActorDossier(
        actor_id="cobalt_group",
        name="Cobalt Group",
        aliases=["GOLD KINGSWOOD", "Cobalt Spider", "TEMP.Metastrike"],
        origin_country="RU/UA",
        actor_type="criminal",
        motivation="financial",
        activity_since="2016",
        activity_status="active",
        description=(
            "Financially-motivated criminal group targeting banks and financial "
            "institutions via spearphishing and ATM jackpotting. Named after their "
            "primary tool, Cobalt Strike."
        ),
        targeted_sectors=["Financial Services", "Banking", "Insurance", "ATM Networks"],
        targeted_regions=["EU", "NA", "APAC", "Middle East", "CIS"],
        mitre_techniques=[
            "T1566.001", "T1566.002", "T1071.001", "T1090.003", "T1027",
            "T1059.001", "T1036", "T1078", "T1204.002",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0008", "TA0011"],
        tools=["Cobalt Strike", "Metasploit", "More_eggs", "custom .NET loaders"],
        initial_access_vectors=["DocuSign-themed spearphishing", "Resume-themed lures", "Financial document lures"],
        infrastructure_patterns=["NameCheap domain registrations", "Multi-hop HK relay proxy", "Cloudflare CDN", "Bulletproof VPS (Russian/Eastern European providers)"],
        known_c2_asns=["AS4134", "AS9002", "AS15626"],
        hosting_preferences=["NameCheap", "Hetzner", "OVH", "Bulletproof hosters"],
        attributed_by=["Group-IB", "Mandiant", "Europol (arrests 2018)"],
        confidence="high",
        references=["https://www.group-ib.com/resources/threat-research/cobalt-group-2-0/"],
    ),

    ThreatActorDossier(
        actor_id="fin7",
        name="FIN7",
        aliases=["Carbanak Group", "Navigator Group", "Gold Niagara", "ELBRUS"],
        origin_country="RU/UA",
        actor_type="criminal",
        motivation="financial",
        activity_since="2015",
        activity_status="active",
        description=(
            "Sophisticated criminal group primarily targeting point-of-sale systems "
            "in retail and hospitality. Evolved into ransomware operations (DarkSide, "
            "BlackMatter) and pen-test front company (Bastion Secure)."
        ),
        targeted_sectors=["Retail", "Hospitality", "Restaurant", "Financial", "Technology"],
        targeted_regions=["NA", "EU"],
        mitre_techniques=[
            "T1566.001", "T1566.002", "T1204.002", "T1059.001", "T1059.003",
            "T1071.001", "T1027", "T1036.005", "T1003.001", "T1486",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0040"],
        tools=["Carbanak", "GRIFFON", "BIRDWATCH", "Cobalt Strike", "BOOSTWRITE"],
        initial_access_vectors=["Restaurant-themed spearphishing", "Fake resumes", "LinkedIn social engineering"],
        infrastructure_patterns=["Direct VPS routing (no multi-hop relay)", "US/EU hosting providers"],
        attributed_by=["Mandiant", "FBI", "DOJ (indictments 2023)"],
        confidence="high",
        references=["https://www.mandiant.com/resources/fin7-group-targets-personnel-involved-sec-filings"],
    ),

    ThreatActorDossier(
        actor_id="lockbit",
        name="LockBit",
        aliases=["GOLD MYSTIC", "Water Selkie"],
        origin_country="RU (suspected)",
        actor_type="criminal",
        motivation="financial",
        activity_since="2019",
        activity_status="active",
        description=(
            "Most prolific ransomware-as-a-service (RaaS) operation globally. "
            "LockBit 3.0 introduced bug bounty program. Taken down by Operation Cronos "
            "in 2024 but resumed operations."
        ),
        targeted_sectors=["All sectors (opportunistic)"],
        targeted_regions=["Global"],
        mitre_techniques=[
            "T1190", "T1078", "T1566.001", "T1059.001", "T1486",
            "T1490", "T1489", "T1027", "T1083", "T1135",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0007", "TA0040"],
        tools=["LockBit 3.0 / Black", "Cobalt Strike", "RClone", "AnyDesk"],
        initial_access_vectors=["RDP brute force", "Phishing", "Exploitation of public-facing apps", "Affiliate initial access brokers"],
        infrastructure_patterns=["TOR-based leak sites", "Affiliate model (IABs)"],
        attributed_by=["FBI", "NCA UK", "Europol"],
        confidence="high",
        references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a"],
    ),

    ThreatActorDossier(
        actor_id="cl0p",
        name="Cl0p",
        aliases=["TA505", "GOLD TAHOE", "Lace Tempest"],
        origin_country="RU (suspected)",
        actor_type="criminal",
        motivation="financial",
        activity_since="2019",
        activity_status="active",
        description=(
            "Ransomware and data extortion group that pioneered mass-exploitation of "
            "zero-days in file transfer software (MOVEit, GoAnywhere, Accellion FTA) "
            "affecting hundreds of organizations simultaneously."
        ),
        targeted_sectors=["All sectors via mass zero-day exploitation"],
        targeted_regions=["Global"],
        mitre_techniques=[
            "T1190", "T1059.001", "T1486", "T1537", "T1560",
            "T1041", "T1027", "T1036",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0009", "TA0010", "TA0040"],
        tools=["Cl0p ransomware", "DEWMODE", "LEMURLOOT (MOVEit exploit webshell)"],
        initial_access_vectors=["Zero-day exploitation of managed file transfer software"],
        infrastructure_patterns=["Onion-based extortion sites", "No encryption in MOVEit campaign (data theft only)"],
        attributed_by=["Mandiant", "Microsoft", "FBI"],
        confidence="high",
        references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"],
    ),

    ThreatActorDossier(
        actor_id="scattered_spider",
        name="Scattered Spider",
        aliases=["UNC3944", "Roasted 0ktapus", "Starfraud", "Muddled Libra"],
        origin_country="NA/EU (English-speaking)",
        actor_type="criminal",
        motivation="financial",
        activity_since="2022",
        activity_status="active",
        description=(
            "English-speaking cybercriminal group (~16-22 year old members) known for "
            "sophisticated social engineering of helpdesks and IT staff. Responsible "
            "for MGM Resorts and Caesars Entertainment breaches ($100M+ impact)."
        ),
        targeted_sectors=["Hospitality", "Gaming", "Telecommunications", "Technology", "Financial"],
        targeted_regions=["NA", "EU"],
        mitre_techniques=[
            "T1566.004", "T1598", "T1621", "T1078.004", "T1556.006",
            "T1059.001", "T1486", "T1537", "T1530",
        ],
        mitre_tactics=["TA0001", "TA0003", "TA0005", "TA0006", "TA0009", "TA0040"],
        tools=["Cobalt Strike", "ALPHV/BlackCat", "AnyDesk", "ScreenConnect", "Azure AD manipulation"],
        initial_access_vectors=["Helpdesk social engineering (SIM swapping, MFA fatigue bombing)", "SMS phishing (smishing)"],
        infrastructure_patterns=["Telegram for C2 coordination", "Legitimate cloud storage for exfil"],
        attributed_by=["Mandiant", "CrowdStrike", "FBI"],
        confidence="high",
        references=["https://www.mandiant.com/resources/blog/unc3944-targets-saas-applications"],
    ),

    ThreatActorDossier(
        actor_id="alphv_blackcat",
        name="ALPHV / BlackCat",
        aliases=["Noberus", "GOLD BLAZER"],
        origin_country="RU (suspected)",
        actor_type="criminal",
        motivation="financial",
        activity_since="2021",
        activity_status="disrupted",
        description=(
            "First major RaaS written in Rust. Sophisticated multi-extortion model. "
            "Disrupted by FBI in late 2023; responsible for Change Healthcare breach "
            "($22M ransom paid, largest US healthcare breach)."
        ),
        targeted_sectors=["Healthcare", "Financial", "Government", "Technology"],
        targeted_regions=["NA", "EU", "Global"],
        mitre_techniques=[
            "T1190", "T1078", "T1059.004", "T1486", "T1490",
            "T1560", "T1537", "T1027",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0005", "TA0009", "TA0040"],
        tools=["BlackCat/ALPHV ransomware (Rust)", "ExMatter", "Cobalt Strike"],
        initial_access_vectors=["Initial access brokers", "Valid credentials", "Exploitation of edge devices"],
        infrastructure_patterns=["TOR-based infrastructure", "Onion leak sites"],
        attributed_by=["FBI", "Mandiant", "US CISA"],
        confidence="high",
        references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a"],
    ),

    ThreatActorDossier(
        actor_id="darkside",
        name="DarkSide",
        aliases=["Carbon Spider", "GOLD SOUTHFIELD"],
        origin_country="RU (suspected)",
        actor_type="criminal",
        motivation="financial",
        activity_since="2020",
        activity_status="disbanded",
        description=(
            "RaaS responsible for the Colonial Pipeline attack (2021), causing fuel "
            "shortages across the US East Coast. Disbanded after US government pressure; "
            "members likely regrouped as BlackMatter."
        ),
        targeted_sectors=["Energy", "Manufacturing", "Financial"],
        targeted_regions=["NA", "EU"],
        mitre_techniques=[
            "T1078", "T1566.001", "T1059.001", "T1486", "T1490",
            "T1560", "T1027",
        ],
        mitre_tactics=["TA0001", "TA0003", "TA0005", "TA0040"],
        tools=["DarkSide ransomware", "Cobalt Strike", "Mimikatz"],
        initial_access_vectors=["Compromised RDP", "Initial access brokers"],
        infrastructure_patterns=["TOR .onion leak sites", "Bulletproof Eastern European hosting"],
        attributed_by=["FBI", "Mandiant"],
        confidence="high",
        notes="Disbanded 2021 after Colonial Pipeline; members regrouped as BlackMatter.",
        references=["https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations"],
    ),

    ThreatActorDossier(
        actor_id="revil",
        name="REvil",
        aliases=["Sodinokibi", "GOLD SOUTHFIELD (overlap)", "Pinchy Spider"],
        origin_country="RU",
        actor_type="criminal",
        motivation="financial",
        activity_since="2019",
        activity_status="disbanded",
        description=(
            "Prolific RaaS behind the Kaseya VSA supply-chain attack affecting 1,500+ "
            "businesses and JBS Foods ($11M ransom). Disrupted by Russian FSB arrests "
            "in January 2022."
        ),
        targeted_sectors=["All sectors (opportunistic)"],
        targeted_regions=["Global"],
        mitre_techniques=[
            "T1195.002", "T1078", "T1486", "T1490", "T1059.001",
            "T1560", "T1027",
        ],
        mitre_tactics=["TA0001", "TA0003", "TA0005", "TA0040"],
        tools=["REvil/Sodinokibi ransomware", "Cobalt Strike"],
        initial_access_vectors=["Supply chain (MSP/RMM exploitation)", "Initial access brokers"],
        infrastructure_patterns=["TOR infrastructure", "Happy Blog leak site"],
        attributed_by=["FBI", "Mandiant", "US Treasury (sanctions)"],
        confidence="high",
        notes="Core members arrested by Russian FSB Jan 2022; operations ceased.",
        references=["https://www.justice.gov/opa/pr/justice-department-charges-russian-national-kaseya-ransomware-attack"],
    ),

    ThreatActorDossier(
        actor_id="conti",
        name="Conti",
        aliases=["GOLD ULRICK", "Wizard Spider (predecessor)"],
        origin_country="RU",
        actor_type="criminal",
        motivation="financial",
        activity_since="2020",
        activity_status="disbanded",
        description=(
            "Most prolific ransomware group of 2021-2022. Disbanded after internal "
            "chat leaks exposed operations and threatened Costa Rica government. Members "
            "migrated to BlackBasta, Quantum, Royal, and other groups."
        ),
        targeted_sectors=["Healthcare", "Government", "Critical Infrastructure", "All sectors"],
        targeted_regions=["Global"],
        mitre_techniques=[
            "T1566.001", "T1078", "T1059.001", "T1059.003", "T1486",
            "T1490", "T1560", "T1027", "T1135",
        ],
        mitre_tactics=["TA0001", "TA0003", "TA0005", "TA0006", "TA0007", "TA0040"],
        tools=["Conti ransomware", "TrickBot", "BazarLoader", "Cobalt Strike"],
        initial_access_vectors=["BazarLoader phishing", "TrickBot", "Initial access brokers"],
        infrastructure_patterns=["Victim named on TOR blog within hours of infection"],
        attributed_by=["US CISA", "FBI", "Mandiant"],
        confidence="high",
        notes="Disbanded May 2022; chat logs leaked by Ukrainian researcher.",
        references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a"],
    ),

    ThreatActorDossier(
        actor_id="lapsus",
        name="Lapsus$",
        aliases=["DEV-0537", "Strawberry Tempest"],
        origin_country="UK/BR (English-speaking teens)",
        actor_type="criminal",
        motivation="financial, notoriety",
        activity_since="2021",
        activity_status="dormant",
        description=(
            "Teenage extortion group responsible for breaches of Microsoft, Okta, "
            "Samsung, Nvidia, and Uber. No ransomware — pure data theft and extortion. "
            "Several members arrested in UK and Brazil."
        ),
        targeted_sectors=["Technology", "Telecommunications", "Government"],
        targeted_regions=["NA", "EU", "Global"],
        mitre_techniques=[
            "T1566.004", "T1621", "T1598", "T1078.004", "T1537",
            "T1530", "T1059.001",
        ],
        mitre_tactics=["TA0001", "TA0003", "TA0005", "TA0009", "TA0010"],
        tools=["No custom malware — uses legitimate tools and purchased credentials"],
        initial_access_vectors=["SIM swapping", "MFA fatigue bombing", "Social engineering of employees", "Buying credentials on criminal forums"],
        infrastructure_patterns=["Telegram for coordination and victim communication"],
        attributed_by=["Microsoft", "Mandiant", "UK NCCU"],
        confidence="high",
        references=["https://www.microsoft.com/en-us/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/"],
    ),

    ThreatActorDossier(
        actor_id="turla",
        name="Turla",
        aliases=["Snake", "Venomous Bear", "Secret Blizzard", "Waterbug", "Uroburos"],
        origin_country="RU",
        actor_type="nation-state",
        motivation="espionage",
        activity_since="2004",
        activity_status="active",
        description=(
            "Russian FSB-linked group known for extremely long-term, stealthy intrusions. "
            "Famously hijacked other threat actors' C2 infrastructure (Iranian OilRig). "
            "Uses satellite communications for C2 to avoid detection."
        ),
        targeted_sectors=["Government", "Defense", "Military", "Diplomatic"],
        targeted_regions=["EU", "Middle East", "CIS", "Global"],
        mitre_techniques=[
            "T1566.001", "T1078", "T1059.001", "T1071.001", "T1020",
            "T1027", "T1036", "T1055", "T1070",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0009", "TA0011"],
        tools=["Carbon", "Snake", "ComRAT", "Kazuar", "TinyTurla", "KOPILUWAK"],
        initial_access_vectors=["Spearphishing", "Watering holes", "Hijacking other actors' infrastructure"],
        infrastructure_patterns=["Satellite C2 (VSAT hijacking)", "Compromised third-party infrastructure", "Extremely long dwell times (years)"],
        attributed_by=["ESET", "Kaspersky", "Mandiant", "US CISA"],
        confidence="high",
        references=["https://www.eset.com/int/about/newsroom/research/turla-hijacks-satellite-internet-links/"],
    ),

    ThreatActorDossier(
        actor_id="apt40",
        name="APT40",
        aliases=["TEMP.Periscope", "Bronze Mohawk", "Leviathan", "Kryptonite Panda", "Gingham Typhoon"],
        origin_country="CN",
        actor_type="nation-state",
        motivation="espionage",
        activity_since="2013",
        activity_status="active",
        description=(
            "Chinese MSS-linked group targeting maritime, defense, and government sectors. "
            "Known for rapid exploitation of newly-disclosed CVEs (often within hours). "
            "Indicted by US DoJ in 2021."
        ),
        targeted_sectors=["Maritime", "Defense", "Aviation", "Government", "Research"],
        targeted_regions=["NA", "EU", "APAC"],
        mitre_techniques=[
            "T1190", "T1133", "T1078", "T1059.001", "T1071.001",
            "T1027", "T1036", "T1003",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0006"],
        tools=["BADFLICK", "AIRBREAK", "PHOTO", "Gh0st RAT", "Cobalt Strike"],
        initial_access_vectors=["Rapid CVE exploitation", "Spearphishing", "VPN exploitation"],
        infrastructure_patterns=["Chinese commercial hosting", "Compromised legitimate websites"],
        attributed_by=["Mandiant", "US DoJ (indictment)", "CISA"],
        confidence="high",
        references=["https://www.justice.gov/opa/pr/four-chinese-nationals-working-secret-police-charged-global-computer-intrusion-campaign"],
    ),

    ThreatActorDossier(
        actor_id="kimsuky",
        name="Kimsuky",
        aliases=["Velvet Chollima", "Black Banshee", "Thallium", "Emerald Sleet", "TA406"],
        origin_country="KP",
        actor_type="nation-state",
        motivation="espionage",
        activity_since="2012",
        activity_status="active",
        description=(
            "North Korean RGB-linked group focused on intelligence collection from "
            "governments, think tanks, and academic institutions with North Korea policy expertise. "
            "Known for spearphishing and credential harvesting."
        ),
        targeted_sectors=["Government", "Think Tanks", "Academic", "Defense", "Media"],
        targeted_regions=["NA", "EU", "South Korea", "Japan"],
        mitre_techniques=[
            "T1566.001", "T1566.002", "T1598.003", "T1078", "T1059.001",
            "T1071.001", "T1027", "T1113", "T1056.001",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0009"],
        tools=["BabyShark", "AppleSeed", "RandomQuery", "FlowerPower"],
        initial_access_vectors=["Spearphishing with North Korea policy themes", "Credential harvesting pages"],
        infrastructure_patterns=["Korean-language lures", "Compromised South Korean web servers"],
        attributed_by=["US CISA", "Mandiant", "Microsoft"],
        confidence="high",
        references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a"],
    ),

    ThreatActorDossier(
        actor_id="charming_kitten",
        name="Charming Kitten",
        aliases=["APT35", "Phosphorus", "Mint Sandstorm", "TA453", "Yellow Garuda"],
        origin_country="IR",
        actor_type="nation-state",
        motivation="espionage",
        activity_since="2014",
        activity_status="active",
        description=(
            "Iranian IRGC Intelligence Organization-linked group focused on academic "
            "researchers, journalists, activists, and government officials. Known for "
            "elaborate and patient social engineering personas."
        ),
        targeted_sectors=["Academic", "Government", "Media", "NGO", "Healthcare"],
        targeted_regions=["Middle East", "NA", "EU"],
        mitre_techniques=[
            "T1566.001", "T1598", "T1078", "T1059.001", "T1071.001",
            "T1027", "T1113", "T1056.001",
        ],
        mitre_tactics=["TA0001", "TA0003", "TA0005", "TA0006", "TA0009"],
        tools=["PowerShell Empire", "CharmPower", "HYPERSCRAPE", "custom Android surveillanceware"],
        initial_access_vectors=["Social engineering (fake researcher personas)", "Spearphishing", "Credential phishing"],
        infrastructure_patterns=["Google-lookalike credential harvesting pages", "Fake conference invitations"],
        attributed_by=["Microsoft", "Proofpoint", "Google TAG", "ClearSky"],
        confidence="high",
        references=["https://blog.google/threat-analysis-group/countering-threats-iran/"],
    ),

    ThreatActorDossier(
        actor_id="fin8",
        name="FIN8",
        aliases=["Syssphinx", "GOLD PREP"],
        origin_country="Unknown",
        actor_type="criminal",
        motivation="financial",
        activity_since="2016",
        activity_status="active",
        description=(
            "Sophisticated financial-sector actor known for long periods of inactivity "
            "between campaigns. Recently adopted ransomware (White Rabbit) alongside "
            "traditional POS malware. Known for SARDONIC backdoor."
        ),
        targeted_sectors=["Retail", "Hospitality", "Financial", "Healthcare"],
        targeted_regions=["NA", "EU"],
        mitre_techniques=[
            "T1566.001", "T1204.002", "T1059.001", "T1071.001", "T1027",
            "T1036.005", "T1003.001", "T1486",
        ],
        mitre_tactics=["TA0001", "TA0002", "TA0003", "TA0005", "TA0040"],
        tools=["PUNCHTRACK", "BADHATCH", "SARDONIC", "White Rabbit ransomware"],
        initial_access_vectors=["Spearphishing", "Exploitation of public-facing applications"],
        infrastructure_patterns=["Long operational pauses", "Careful target selection"],
        attributed_by=["Mandiant", "Bitdefender"],
        confidence="moderate",
        references=["https://www.bitdefender.com/blog/labs/bitdefender-finds-new-fin8-activity/"],
    ),

    ThreatActorDossier(
        actor_id="wizard_spider",
        name="Wizard Spider",
        aliases=["GOLD ULRICK", "UNC1878"],
        origin_country="RU",
        actor_type="criminal",
        motivation="financial",
        activity_since="2016",
        activity_status="active",
        description=(
            "Russian criminal group that created TrickBot and later Ryuk ransomware. "
            "Pioneered big-game hunting ransomware targeting hospitals and large enterprises. "
            "Parent group of Conti."
        ),
        targeted_sectors=["Healthcare", "Government", "Financial", "All sectors"],
        targeted_regions=["NA", "EU"],
        mitre_techniques=[
            "T1566.001", "T1059.003", "T1059.001", "T1078", "T1486",
            "T1490", "T1027", "T1547.001",
        ],
        mitre_tactics=["TA0001", "TA0003", "TA0005", "TA0006", "TA0007", "TA0040"],
        tools=["TrickBot", "Ryuk", "BazarLoader", "Cobalt Strike"],
        initial_access_vectors=["Spam email with malicious Office documents", "Emotet (partnership)"],
        infrastructure_patterns=["TrickBot C2 infrastructure", "Fast-flux DNS"],
        attributed_by=["Mandiant", "CrowdStrike", "US CISA"],
        confidence="high",
        references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-302a"],
    ),
]


# ---------------------------------------------------------------------------
# Library class
# ---------------------------------------------------------------------------

class ThreatActorLibrary:
    """Searchable index of threat actor dossiers."""

    def __init__(self, actors: List[ThreatActorDossier]) -> None:
        self._by_id: Dict[str, ThreatActorDossier] = {a.actor_id: a for a in actors}
        # Build alias index (lower-cased)
        self._alias_index: Dict[str, str] = {}
        for actor in actors:
            self._alias_index[actor.name.lower()] = actor.actor_id
            for alias in actor.aliases:
                key = alias.lower().split("(")[0].strip()
                if key:
                    self._alias_index[key] = actor.actor_id

    def get(self, name: str) -> Optional[ThreatActorDossier]:
        """Look up by primary name, alias, or actor_id (case-insensitive)."""
        key = name.lower().strip()
        actor_id = self._alias_index.get(key) or self._by_id.get(key) and key
        if actor_id and actor_id in self._by_id:
            return self._by_id[actor_id]
        # Partial match fallback
        for alias_key, aid in self._alias_index.items():
            if key in alias_key or alias_key in key:
                return self._by_id.get(aid)
        return None

    def get_by_id(self, actor_id: str) -> Optional[ThreatActorDossier]:
        return self._by_id.get(actor_id)

    def all(self) -> List[ThreatActorDossier]:
        return list(self._by_id.values())

    def find_by_technique(self, technique: str) -> List[ThreatActorDossier]:
        t = technique.upper()
        return [a for a in self._by_id.values() if a.matches_technique(t)]

    def find_by_sector(self, sector: str) -> List[ThreatActorDossier]:
        return [a for a in self._by_id.values() if a.matches_sector(sector)]

    def find_by_country(self, country_code: str) -> List[ThreatActorDossier]:
        cc = country_code.upper()
        return [a for a in self._by_id.values() if cc in a.origin_country.upper()]

    def find_by_type(self, actor_type: str) -> List[ThreatActorDossier]:
        t = actor_type.lower()
        return [a for a in self._by_id.values() if t in a.actor_type.lower()]

    def match_ttps(self, techniques: List[str], min_match: int = 1) -> List[TTPMatchResult]:
        """
        Return actors ranked by how many of *techniques* they are known to use.
        Only returns actors with at least *min_match* matching techniques.
        """
        query = {t.upper() for t in techniques}
        results: List[TTPMatchResult] = []
        for actor in self._by_id.values():
            actor_ttps = {t.upper() for t in actor.mitre_techniques}
            matched = list(query & actor_ttps)
            if len(matched) >= min_match:
                score = len(matched) / len(query) if query else 0.0
                results.append(TTPMatchResult(
                    actor=actor,
                    matched_techniques=sorted(matched),
                    match_score=score,
                    total_actor_techniques=len(actor_ttps),
                ))
        return sorted(results, key=lambda x: x.match_score, reverse=True)

    def search(self, query: str) -> List[ThreatActorDossier]:
        """Full-text search across names, aliases, tools, and description."""
        q = query.lower()
        results = []
        for actor in self._by_id.values():
            text = " ".join([
                actor.name, actor.description,
                " ".join(actor.aliases),
                " ".join(actor.tools),
                " ".join(actor.targeted_sectors),
            ]).lower()
            if q in text:
                results.append(actor)
        return results

    def summary_list(self) -> List[Dict[str, Any]]:
        """Compact list suitable for the library browser UI."""
        return [
            {
                "actor_id": a.actor_id,
                "name": a.name,
                "aliases": a.aliases[:3],
                "origin_country": a.origin_country,
                "actor_type": a.actor_type,
                "motivation": a.motivation,
                "activity_status": a.activity_status,
                "targeted_sectors": a.targeted_sectors[:3],
                "technique_count": len(a.mitre_techniques),
                "tool_count": len(a.tools),
            }
            for a in sorted(self._by_id.values(), key=lambda x: x.name)
        ]


# Module-level singleton
actor_library = ThreatActorLibrary(_ACTORS)

#!/usr/bin/env python3
"""
Advanced Analysis Engine

Risk scoring, MITRE ATT&CK mapping, trend analysis, executive summaries,
and visual report generation for OSINT investigations.
"""

import logging
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from collections import defaultdict
import json
import math

logger = logging.getLogger(__name__)


# =============================================================================
# MITRE ATT&CK Framework
# =============================================================================

class MITRETactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class MITRETechnique:
    """MITRE ATT&CK Technique"""
    technique_id: str
    name: str
    tactic: MITRETactic
    description: str
    detection: str = ""
    mitigation: str = ""
    severity: str = "medium"  # low, medium, high, critical


# Common MITRE techniques relevant to OSINT findings
MITRE_TECHNIQUES = {
    # Reconnaissance
    "T1592": MITRETechnique("T1592", "Gather Victim Host Information", MITRETactic.RECONNAISSANCE,
        "Adversaries may gather host information for targeting",
        "Monitor for suspicious scanning activity",
        "Limit exposed information"),
    "T1590": MITRETechnique("T1590", "Gather Victim Network Information", MITRETactic.RECONNAISSANCE,
        "Adversaries gather network infrastructure details",
        "Monitor DNS queries and network scans",
        "Implement network segmentation"),
    "T1589": MITRETechnique("T1589", "Gather Victim Identity Information", MITRETactic.RECONNAISSANCE,
        "Adversaries collect identity information",
        "Monitor for credential exposure",
        "Implement strong identity management", "high"),
    "T1591": MITRETechnique("T1591", "Gather Victim Org Information", MITRETactic.RECONNAISSANCE,
        "Adversaries research organization structure",
        "Monitor social media exposure",
        "Limit public corporate information"),

    # Resource Development
    "T1583": MITRETechnique("T1583", "Acquire Infrastructure", MITRETactic.RESOURCE_DEVELOPMENT,
        "Adversaries acquire infrastructure for operations",
        "Monitor for suspicious domain registrations",
        "Implement domain monitoring"),
    "T1584": MITRETechnique("T1584", "Compromise Infrastructure", MITRETactic.RESOURCE_DEVELOPMENT,
        "Adversaries compromise third-party infrastructure",
        "Monitor for infrastructure compromise indicators",
        "Implement vendor security assessments"),

    # Initial Access
    "T1566": MITRETechnique("T1566", "Phishing", MITRETactic.INITIAL_ACCESS,
        "Adversaries use phishing for initial access",
        "Email security monitoring",
        "Security awareness training", "high"),
    "T1190": MITRETechnique("T1190", "Exploit Public-Facing Application", MITRETactic.INITIAL_ACCESS,
        "Adversaries exploit vulnerable services",
        "Monitor exposed services",
        "Patch management, WAF", "critical"),

    # Credential Access
    "T1110": MITRETechnique("T1110", "Brute Force", MITRETactic.CREDENTIAL_ACCESS,
        "Adversaries use brute force attacks",
        "Monitor authentication failures",
        "Account lockout policies", "high"),
    "T1555": MITRETechnique("T1555", "Credentials from Password Stores", MITRETactic.CREDENTIAL_ACCESS,
        "Adversaries extract stored credentials",
        "Monitor credential store access",
        "Secure credential storage", "critical"),

    # Command and Control
    "T1071": MITRETechnique("T1071", "Application Layer Protocol", MITRETactic.COMMAND_AND_CONTROL,
        "Adversaries use application protocols for C2",
        "Network traffic analysis",
        "Protocol inspection", "high"),
    "T1102": MITRETechnique("T1102", "Web Service", MITRETactic.COMMAND_AND_CONTROL,
        "Adversaries use web services for C2",
        "Monitor cloud service usage",
        "Cloud access controls"),

    # Exfiltration
    "T1041": MITRETechnique("T1041", "Exfiltration Over C2 Channel", MITRETactic.EXFILTRATION,
        "Adversaries exfiltrate via C2",
        "Monitor outbound data flows",
        "DLP implementation", "critical"),
}


class MITREMapper:
    """Maps OSINT findings to MITRE ATT&CK techniques"""

    # Mapping rules: finding indicators -> technique IDs
    MAPPING_RULES = {
        # Infrastructure findings
        'exposed_service': ['T1190', 'T1592'],
        'open_port': ['T1190', 'T1592'],
        'subdomain': ['T1590', 'T1592'],
        'dns_record': ['T1590'],
        'certificate': ['T1590', 'T1583'],

        # Threat indicators
        'malware_indicator': ['T1071', 'T1102'],
        'c2_indicator': ['T1071', 'T1102', 'T1041'],
        'threat_actor': ['T1583', 'T1584'],
        'phishing_url': ['T1566'],
        'malicious_url': ['T1566', 'T1190'],

        # Credential/breach findings
        'data_breach': ['T1589', 'T1555'],
        'credential_exposure': ['T1589', 'T1555', 'T1110'],
        'paste_mention': ['T1589'],

        # Social/organizational
        'social_account': ['T1591', 'T1589'],
        'employee_info': ['T1589', 'T1591'],
        'organization_info': ['T1591'],

        # Code exposure
        'code_repository': ['T1592', 'T1555'],
        'secret_exposure': ['T1555', 'T1589'],
    }

    @classmethod
    def map_findings(cls, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Map investigation findings to MITRE ATT&CK techniques.

        Args:
            findings: Dictionary of investigation findings

        Returns:
            List of mapped techniques with context
        """
        mapped_techniques = {}

        def add_technique(technique_id: str, evidence: str, source: str):
            if technique_id in MITRE_TECHNIQUES:
                if technique_id not in mapped_techniques:
                    technique = MITRE_TECHNIQUES[technique_id]
                    mapped_techniques[technique_id] = {
                        'technique_id': technique_id,
                        'name': technique.name,
                        'tactic': technique.tactic.value,
                        'description': technique.description,
                        'detection': technique.detection,
                        'mitigation': technique.mitigation,
                        'severity': technique.severity,
                        'evidence': [],
                        'sources': set()
                    }
                mapped_techniques[technique_id]['evidence'].append(evidence)
                mapped_techniques[technique_id]['sources'].add(source)

        # Map infrastructure findings
        infra = findings.get('infrastructure', {})

        for service in infra.get('exposed_services', []):
            service_name = service.get('service', 'unknown') if isinstance(service, dict) else str(service)
            port = service.get('port', '') if isinstance(service, dict) else ''
            for tid in cls.MAPPING_RULES.get('exposed_service', []):
                add_technique(tid, f"Exposed service: {service_name}:{port}", "infrastructure_scan")

        for subdomain in infra.get('subdomains', []):
            for tid in cls.MAPPING_RULES.get('subdomain', []):
                add_technique(tid, f"Subdomain discovered: {subdomain}", "dns_enumeration")

        # Map threat findings
        threat = findings.get('threat', {})

        for indicator in threat.get('malware_indicators', []):
            ioc_type = indicator.get('type', '') if isinstance(indicator, dict) else ''
            for tid in cls.MAPPING_RULES.get('malware_indicator', []):
                add_technique(tid, f"Malware indicator: {ioc_type}", "threat_intel")

        for indicator in threat.get('network_indicators', []):
            threat_type = indicator.get('threat_type', 'unknown') if isinstance(indicator, dict) else ''
            if 'c2' in str(threat_type).lower():
                for tid in cls.MAPPING_RULES.get('c2_indicator', []):
                    add_technique(tid, f"C2 indicator detected", "threat_intel")

        for actor in threat.get('threat_actors', []):
            name = actor.get('name', 'Unknown') if isinstance(actor, dict) else str(actor)
            for tid in cls.MAPPING_RULES.get('threat_actor', []):
                add_technique(tid, f"Threat actor: {name}", "threat_intel")

        # Map expanded source findings
        expanded = findings.get('expanded_sources', {})

        # Breach intelligence
        breach_intel = expanded.get('breach_intel', {})
        if isinstance(breach_intel, dict) and breach_intel.get('success'):
            breaches = breach_intel.get('data', {}).get('breaches', [])
            for breach in breaches:
                name = breach.get('name', 'Unknown') if isinstance(breach, dict) else ''
                for tid in cls.MAPPING_RULES.get('data_breach', []):
                    add_technique(tid, f"Data breach: {name}", "breach_intel")

        # URL intelligence (phishing/malware)
        url_intel = expanded.get('url_intel', {})
        if isinstance(url_intel, dict) and url_intel.get('success'):
            mal_urls = url_intel.get('data', {}).get('malicious_urls', [])
            for url_info in mal_urls:
                threat_type = url_info.get('threat_type', 'unknown') if isinstance(url_info, dict) else ''
                for tid in cls.MAPPING_RULES.get('malicious_url', []):
                    add_technique(tid, f"Malicious URL ({threat_type})", "url_intel")

        # Code intelligence
        code_intel = expanded.get('code_intel', {})
        if isinstance(code_intel, dict) and code_intel.get('success'):
            exposures = code_intel.get('data', {}).get('potential_exposures', [])
            for exposure in exposures:
                exp_type = exposure.get('type', 'unknown') if isinstance(exposure, dict) else ''
                for tid in cls.MAPPING_RULES.get('secret_exposure', []):
                    add_technique(tid, f"Code exposure: {exp_type}", "code_intel")

        # Convert sets to lists for JSON serialization
        result = []
        for tid, data in mapped_techniques.items():
            data['sources'] = list(data['sources'])
            data['evidence_count'] = len(data['evidence'])
            result.append(data)

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        result.sort(key=lambda x: severity_order.get(x['severity'], 4))

        return result

    @classmethod
    def get_attack_surface_summary(cls, mapped_techniques: List[Dict]) -> Dict[str, Any]:
        """Generate attack surface summary from mapped techniques"""
        tactics_covered = set()
        severity_counts = defaultdict(int)

        for technique in mapped_techniques:
            tactics_covered.add(technique['tactic'])
            severity_counts[technique['severity']] += 1

        return {
            'total_techniques': len(mapped_techniques),
            'tactics_covered': list(tactics_covered),
            'tactic_count': len(tactics_covered),
            'severity_distribution': dict(severity_counts),
            'critical_count': severity_counts.get('critical', 0),
            'high_count': severity_counts.get('high', 0),
            'attack_surface_score': cls._calculate_attack_surface_score(mapped_techniques)
        }

    @classmethod
    def _calculate_attack_surface_score(cls, techniques: List[Dict]) -> float:
        """Calculate attack surface score (0-100)"""
        if not techniques:
            return 0.0

        severity_weights = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
        total_score = sum(severity_weights.get(t['severity'], 5) for t in techniques)

        # Normalize to 0-100, cap at 100
        return min(100.0, total_score)


# =============================================================================
# Risk Scoring Engine
# =============================================================================

class RiskCategory(Enum):
    """Risk categories for scoring"""
    INFRASTRUCTURE = "infrastructure"
    THREAT = "threat"
    CREDENTIAL = "credential"
    REPUTATION = "reputation"
    COMPLIANCE = "compliance"
    DATA_EXPOSURE = "data_exposure"


@dataclass
class RiskFactor:
    """Individual risk factor"""
    category: RiskCategory
    name: str
    score: float  # 0-100
    weight: float  # 0-1
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class RiskScore:
    """Comprehensive risk score"""
    overall_score: float
    risk_level: str  # critical, high, medium, low
    category_scores: Dict[str, float]
    factors: List[RiskFactor]
    trend: str  # increasing, stable, decreasing
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'overall_score': round(self.overall_score, 1),
            'risk_level': self.risk_level,
            'category_scores': {k: round(v, 1) for k, v in self.category_scores.items()},
            'factors': [
                {
                    'category': f.category.value,
                    'name': f.name,
                    'score': round(f.score, 1),
                    'weight': f.weight,
                    'evidence': f.evidence[:3],  # Limit evidence
                    'recommendations': f.recommendations[:2]
                }
                for f in self.factors
            ],
            'trend': self.trend,
            'confidence': round(self.confidence, 2),
            'factor_count': len(self.factors)
        }


class RiskScoringEngine:
    """
    Advanced risk scoring engine with weighted factors
    """

    # Category weights (must sum to 1.0)
    CATEGORY_WEIGHTS = {
        RiskCategory.THREAT: 0.25,
        RiskCategory.CREDENTIAL: 0.20,
        RiskCategory.INFRASTRUCTURE: 0.20,
        RiskCategory.DATA_EXPOSURE: 0.15,
        RiskCategory.REPUTATION: 0.10,
        RiskCategory.COMPLIANCE: 0.10,
    }

    # Risk level thresholds
    RISK_LEVELS = {
        'critical': 80,
        'high': 60,
        'medium': 40,
        'low': 0
    }

    def calculate_risk(self, findings: Dict[str, Any],
                      correlation_results: Optional[Dict] = None,
                      mitre_mapping: Optional[List[Dict]] = None) -> RiskScore:
        """
        Calculate comprehensive risk score from investigation findings.

        Args:
            findings: Investigation findings dictionary
            correlation_results: Optional correlation analysis results
            mitre_mapping: Optional MITRE ATT&CK mapping

        Returns:
            RiskScore with detailed breakdown
        """
        factors = []

        # Infrastructure risks
        factors.extend(self._assess_infrastructure_risk(findings.get('infrastructure', {})))

        # Threat risks
        factors.extend(self._assess_threat_risk(findings.get('threat', {})))

        # Credential/breach risks
        factors.extend(self._assess_credential_risk(findings.get('expanded_sources', {})))

        # Data exposure risks
        factors.extend(self._assess_data_exposure_risk(findings))

        # Reputation risks
        factors.extend(self._assess_reputation_risk(findings.get('social', {})))

        # Compliance risks
        factors.extend(self._assess_compliance_risk(findings))

        # Factor in MITRE mapping if available
        if mitre_mapping:
            factors.extend(self._assess_mitre_risk(mitre_mapping))

        # Calculate category scores
        category_scores = self._calculate_category_scores(factors)

        # Calculate overall score
        overall_score = sum(
            category_scores.get(cat.value, 0) * weight
            for cat, weight in self.CATEGORY_WEIGHTS.items()
        )

        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)

        # Calculate confidence based on data completeness
        confidence = self._calculate_confidence(findings, factors)

        return RiskScore(
            overall_score=overall_score,
            risk_level=risk_level,
            category_scores=category_scores,
            factors=factors,
            trend='stable',  # Would need historical data for actual trend
            confidence=confidence
        )

    def _assess_infrastructure_risk(self, infra: Dict) -> List[RiskFactor]:
        """Assess infrastructure-related risks"""
        factors = []

        # Exposed services risk
        exposed_services = infra.get('exposed_services', [])
        if exposed_services:
            high_risk_ports = [22, 23, 3389, 445, 135, 139]
            high_risk_count = sum(1 for s in exposed_services
                                 if isinstance(s, dict) and s.get('port') in high_risk_ports)

            score = min(100, len(exposed_services) * 10 + high_risk_count * 20)
            factors.append(RiskFactor(
                category=RiskCategory.INFRASTRUCTURE,
                name="Exposed Services",
                score=score,
                weight=0.4,
                evidence=[f"{len(exposed_services)} services exposed, {high_risk_count} high-risk"],
                recommendations=["Review and restrict unnecessary exposed services",
                               "Implement network segmentation"]
            ))

        # Subdomain enumeration risk
        subdomains = infra.get('subdomains', [])
        if len(subdomains) > 10:
            score = min(100, len(subdomains) * 2)
            factors.append(RiskFactor(
                category=RiskCategory.INFRASTRUCTURE,
                name="Large Attack Surface",
                score=score,
                weight=0.3,
                evidence=[f"{len(subdomains)} subdomains discovered"],
                recommendations=["Audit subdomain inventory",
                               "Remove unused subdomains"]
            ))

        # SSL/Certificate issues
        certificates = infra.get('certificates', [])
        expired_certs = [c for c in certificates if isinstance(c, dict)
                        and c.get('expired', False)]
        if expired_certs:
            factors.append(RiskFactor(
                category=RiskCategory.INFRASTRUCTURE,
                name="Certificate Issues",
                score=70,
                weight=0.3,
                evidence=[f"{len(expired_certs)} expired certificates"],
                recommendations=["Renew expired certificates",
                               "Implement certificate monitoring"]
            ))

        return factors

    def _assess_threat_risk(self, threat: Dict) -> List[RiskFactor]:
        """Assess threat intelligence risks"""
        factors = []

        # Malware indicators
        malware = threat.get('malware_indicators', [])
        if malware:
            factors.append(RiskFactor(
                category=RiskCategory.THREAT,
                name="Malware Indicators",
                score=min(100, len(malware) * 25),
                weight=0.4,
                evidence=[f"{len(malware)} malware indicators found"],
                recommendations=["Investigate and remediate malware",
                               "Review security controls"]
            ))

        # Network threat indicators
        network = threat.get('network_indicators', [])
        c2_indicators = [n for n in network if isinstance(n, dict)
                        and 'c2' in str(n.get('threat_type', '')).lower()]
        if c2_indicators:
            factors.append(RiskFactor(
                category=RiskCategory.THREAT,
                name="C2 Communication",
                score=90,
                weight=0.4,
                evidence=[f"{len(c2_indicators)} C2 indicators detected"],
                recommendations=["Immediate incident response",
                               "Network isolation recommended"]
            ))

        # Threat actors
        actors = threat.get('threat_actors', [])
        if actors:
            factors.append(RiskFactor(
                category=RiskCategory.THREAT,
                name="Threat Actor Association",
                score=min(100, len(actors) * 30),
                weight=0.2,
                evidence=[f"{len(actors)} threat actors identified"],
                recommendations=["Review threat actor TTPs",
                               "Implement targeted defenses"]
            ))

        return factors

    def _assess_credential_risk(self, expanded: Dict) -> List[RiskFactor]:
        """Assess credential and breach risks"""
        factors = []

        breach_intel = expanded.get('breach_intel', {})
        if isinstance(breach_intel, dict) and breach_intel.get('success'):
            data = breach_intel.get('data', {})
            breaches = data.get('breaches', [])
            total_records = data.get('total_records_exposed', 0)

            if breaches:
                score = min(100, len(breaches) * 20 + (total_records / 10000))
                factors.append(RiskFactor(
                    category=RiskCategory.CREDENTIAL,
                    name="Data Breaches",
                    score=score,
                    weight=0.5,
                    evidence=[f"{len(breaches)} breaches, {total_records:,} records exposed"],
                    recommendations=["Force password resets for affected users",
                                   "Implement credential monitoring"]
                ))

        code_intel = expanded.get('code_intel', {})
        if isinstance(code_intel, dict) and code_intel.get('success'):
            exposures = code_intel.get('data', {}).get('potential_exposures', [])
            secret_exposures = [e for e in exposures if isinstance(e, dict)
                               and e.get('type') in ['api_key', 'password', 'secret', 'token']]
            if secret_exposures:
                factors.append(RiskFactor(
                    category=RiskCategory.CREDENTIAL,
                    name="Secret Exposure in Code",
                    score=85,
                    weight=0.5,
                    evidence=[f"{len(secret_exposures)} secrets exposed in code"],
                    recommendations=["Rotate exposed credentials immediately",
                                   "Implement secret scanning"]
                ))

        return factors

    def _assess_data_exposure_risk(self, findings: Dict) -> List[RiskFactor]:
        """Assess data exposure risks"""
        factors = []

        expanded = findings.get('expanded_sources', {})

        # URL intelligence for malicious URLs
        url_intel = expanded.get('url_intel', {})
        if isinstance(url_intel, dict) and url_intel.get('success'):
            mal_urls = url_intel.get('data', {}).get('malicious_urls', [])
            if mal_urls:
                factors.append(RiskFactor(
                    category=RiskCategory.DATA_EXPOSURE,
                    name="Malicious URLs",
                    score=min(100, len(mal_urls) * 15),
                    weight=0.5,
                    evidence=[f"{len(mal_urls)} malicious URLs associated"],
                    recommendations=["Block identified malicious URLs",
                                   "Investigate potential compromise"]
                ))

        # News mentions (negative)
        news_intel = expanded.get('news_intel', {})
        if isinstance(news_intel, dict) and news_intel.get('success'):
            articles = news_intel.get('data', {}).get('articles', [])
            negative_articles = [a for a in articles if isinstance(a, dict)
                                and a.get('sentiment') == 'negative']
            if negative_articles:
                factors.append(RiskFactor(
                    category=RiskCategory.DATA_EXPOSURE,
                    name="Negative Media Coverage",
                    score=min(60, len(negative_articles) * 10),
                    weight=0.3,
                    evidence=[f"{len(negative_articles)} negative news articles"],
                    recommendations=["Monitor media mentions",
                                   "Prepare incident response communications"]
                ))

        return factors

    def _assess_reputation_risk(self, social: Dict) -> List[RiskFactor]:
        """Assess reputation risks from social media"""
        factors = []

        sentiment = social.get('sentiment_analysis', {})
        if sentiment:
            negative_sentiment = sentiment.get('negative', 0)
            if negative_sentiment > 0.3:
                factors.append(RiskFactor(
                    category=RiskCategory.REPUTATION,
                    name="Negative Social Sentiment",
                    score=min(100, negative_sentiment * 100),
                    weight=0.5,
                    evidence=[f"{negative_sentiment:.0%} negative sentiment"],
                    recommendations=["Monitor social media channels",
                                   "Address customer concerns"]
                ))

        return factors

    def _assess_compliance_risk(self, findings: Dict) -> List[RiskFactor]:
        """Assess compliance risks"""
        factors = []

        # Check for PII exposure indicators
        expanded = findings.get('expanded_sources', {})
        breach_intel = expanded.get('breach_intel', {})

        if isinstance(breach_intel, dict) and breach_intel.get('success'):
            data_classes = breach_intel.get('data', {}).get('data_classes_exposed', [])
            pii_classes = ['email', 'password', 'name', 'phone', 'address', 'ssn', 'dob']
            pii_exposed = [c for c in data_classes if any(p in c.lower() for p in pii_classes)]

            if pii_exposed:
                factors.append(RiskFactor(
                    category=RiskCategory.COMPLIANCE,
                    name="PII Exposure",
                    score=min(100, len(pii_exposed) * 15),
                    weight=0.6,
                    evidence=[f"PII types exposed: {', '.join(pii_exposed[:3])}"],
                    recommendations=["Conduct GDPR/CCPA impact assessment",
                                   "Notify affected individuals if required"]
                ))

        return factors

    def _assess_mitre_risk(self, mitre_mapping: List[Dict]) -> List[RiskFactor]:
        """Factor in MITRE ATT&CK mapping"""
        factors = []

        critical_techniques = [t for t in mitre_mapping if t.get('severity') == 'critical']
        high_techniques = [t for t in mitre_mapping if t.get('severity') == 'high']

        if critical_techniques:
            factors.append(RiskFactor(
                category=RiskCategory.THREAT,
                name="Critical MITRE Techniques",
                score=95,
                weight=0.3,
                evidence=[f"{len(critical_techniques)} critical techniques mapped"],
                recommendations=["Immediate security review required",
                               "Implement technique-specific mitigations"]
            ))

        if high_techniques:
            factors.append(RiskFactor(
                category=RiskCategory.THREAT,
                name="High-Risk MITRE Techniques",
                score=75,
                weight=0.2,
                evidence=[f"{len(high_techniques)} high-risk techniques mapped"],
                recommendations=["Review security posture",
                               "Prioritize mitigation efforts"]
            ))

        return factors

    def _calculate_category_scores(self, factors: List[RiskFactor]) -> Dict[str, float]:
        """Calculate weighted scores per category"""
        category_totals = defaultdict(lambda: {'weighted_sum': 0, 'weight_sum': 0})

        for factor in factors:
            cat = factor.category.value
            category_totals[cat]['weighted_sum'] += factor.score * factor.weight
            category_totals[cat]['weight_sum'] += factor.weight

        scores = {}
        for cat, totals in category_totals.items():
            if totals['weight_sum'] > 0:
                scores[cat] = totals['weighted_sum'] / totals['weight_sum']
            else:
                scores[cat] = 0

        return scores

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        for level, threshold in sorted(self.RISK_LEVELS.items(),
                                       key=lambda x: x[1], reverse=True):
            if score >= threshold:
                return level
        return 'low'

    def _calculate_confidence(self, findings: Dict, factors: List[RiskFactor]) -> float:
        """Calculate confidence score based on data completeness"""
        data_sources = 0
        if findings.get('infrastructure'):
            data_sources += 1
        if findings.get('social'):
            data_sources += 1
        if findings.get('threat'):
            data_sources += 1
        if findings.get('expanded_sources'):
            expanded = findings['expanded_sources']
            data_sources += sum(1 for v in expanded.values()
                               if isinstance(v, dict) and v.get('success'))

        # More sources = higher confidence
        source_confidence = min(1.0, data_sources / 6)

        # More factors = higher confidence
        factor_confidence = min(1.0, len(factors) / 10)

        return (source_confidence + factor_confidence) / 2


# =============================================================================
# Executive Summary Generator
# =============================================================================

class ExecutiveSummaryGenerator:
    """Generates AI-style executive summaries from investigation data"""

    SEVERITY_PHRASES = {
        'critical': [
            "requires immediate attention",
            "presents critical security concerns",
            "demands urgent remediation"
        ],
        'high': [
            "poses significant security risks",
            "requires prompt attention",
            "should be prioritized for remediation"
        ],
        'medium': [
            "presents moderate security concerns",
            "should be addressed in the near term",
            "requires planned remediation"
        ],
        'low': [
            "presents minimal immediate risk",
            "should be monitored",
            "can be addressed during routine maintenance"
        ]
    }

    def generate_summary(self,
                        target: str,
                        risk_score: RiskScore,
                        mitre_mapping: List[Dict],
                        findings: Dict[str, Any],
                        correlation: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate comprehensive executive summary.

        Returns structured summary with key sections.
        """
        summary = {
            'title': f"Executive Intelligence Summary: {target}",
            'generated_at': datetime.utcnow().isoformat(),
            'classification': 'CONFIDENTIAL',
            'overview': self._generate_overview(target, risk_score, findings),
            'key_findings': self._generate_key_findings(risk_score, mitre_mapping, findings),
            'risk_assessment': self._generate_risk_section(risk_score),
            'threat_landscape': self._generate_threat_section(mitre_mapping),
            'recommendations': self._generate_recommendations(risk_score, mitre_mapping),
            'metrics': self._generate_metrics(findings, correlation),
            'conclusion': self._generate_conclusion(target, risk_score)
        }

        return summary

    def _generate_overview(self, target: str, risk_score: RiskScore,
                          findings: Dict) -> str:
        """Generate overview paragraph"""
        risk_phrase = self.SEVERITY_PHRASES.get(risk_score.risk_level,
                                                self.SEVERITY_PHRASES['medium'])[0]

        # Count data points
        entity_count = 0
        if findings.get('infrastructure'):
            infra = findings['infrastructure']
            entity_count += len(infra.get('subdomains', []))
            entity_count += len(infra.get('ip_addresses', []))

        overview = (
            f"This investigation of {target} {risk_phrase}. "
            f"Analysis was conducted across multiple intelligence sources, "
            f"identifying {entity_count} infrastructure components and "
            f"resulting in an overall risk score of {risk_score.overall_score:.0f}/100 "
            f"({risk_score.risk_level.upper()} risk level). "
            f"The assessment confidence level is {risk_score.confidence:.0%}."
        )

        return overview

    def _generate_key_findings(self, risk_score: RiskScore,
                              mitre_mapping: List[Dict],
                              findings: Dict) -> List[Dict[str, Any]]:
        """Generate prioritized key findings"""
        key_findings = []

        # Top risk factors
        for factor in sorted(risk_score.factors,
                           key=lambda x: x.score * x.weight, reverse=True)[:5]:
            key_findings.append({
                'category': factor.category.value,
                'finding': factor.name,
                'severity': self._score_to_severity(factor.score),
                'impact': factor.evidence[0] if factor.evidence else "See details",
                'priority': 'immediate' if factor.score > 80 else
                           'high' if factor.score > 60 else 'medium'
            })

        # Critical MITRE techniques
        critical = [t for t in mitre_mapping if t.get('severity') == 'critical'][:3]
        for technique in critical:
            key_findings.append({
                'category': 'threat_technique',
                'finding': f"MITRE {technique['technique_id']}: {technique['name']}",
                'severity': 'critical',
                'impact': technique['description'][:100],
                'priority': 'immediate'
            })

        return key_findings[:7]  # Limit to top 7

    def _generate_risk_section(self, risk_score: RiskScore) -> Dict[str, Any]:
        """Generate risk assessment section"""
        return {
            'overall_assessment': f"{risk_score.risk_level.upper()} RISK",
            'score': risk_score.overall_score,
            'category_breakdown': [
                {
                    'category': cat,
                    'score': score,
                    'level': self._score_to_severity(score)
                }
                for cat, score in sorted(risk_score.category_scores.items(),
                                        key=lambda x: x[1], reverse=True)
            ],
            'trend': risk_score.trend,
            'confidence': f"{risk_score.confidence:.0%}"
        }

    def _generate_threat_section(self, mitre_mapping: List[Dict]) -> Dict[str, Any]:
        """Generate threat landscape section"""
        tactics = defaultdict(list)
        for technique in mitre_mapping:
            tactics[technique['tactic']].append(technique)

        attack_surface = MITREMapper.get_attack_surface_summary(mitre_mapping)

        return {
            'attack_surface_score': attack_surface['attack_surface_score'],
            'techniques_identified': len(mitre_mapping),
            'tactics_covered': list(tactics.keys()),
            'kill_chain_coverage': self._assess_kill_chain(tactics),
            'top_techniques': [
                {
                    'id': t['technique_id'],
                    'name': t['name'],
                    'severity': t['severity']
                }
                for t in mitre_mapping[:5]
            ]
        }

    def _generate_recommendations(self, risk_score: RiskScore,
                                 mitre_mapping: List[Dict]) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations"""
        recommendations = []
        seen_recs = set()

        # From risk factors
        for factor in sorted(risk_score.factors,
                           key=lambda x: x.score, reverse=True):
            for rec in factor.recommendations:
                if rec not in seen_recs:
                    seen_recs.add(rec)
                    recommendations.append({
                        'recommendation': rec,
                        'priority': 'immediate' if factor.score > 80 else
                                   'short_term' if factor.score > 50 else 'long_term',
                        'category': factor.category.value
                    })

        # From MITRE mitigations
        for technique in mitre_mapping[:5]:
            if technique.get('mitigation') and technique['mitigation'] not in seen_recs:
                seen_recs.add(technique['mitigation'])
                recommendations.append({
                    'recommendation': technique['mitigation'],
                    'priority': 'immediate' if technique['severity'] == 'critical' else 'short_term',
                    'category': 'threat_mitigation'
                })

        return recommendations[:10]  # Top 10 recommendations

    def _generate_metrics(self, findings: Dict,
                         correlation: Optional[Dict]) -> Dict[str, Any]:
        """Generate investigation metrics"""
        metrics = {
            'data_sources_analyzed': 0,
            'entities_discovered': 0,
            'relationships_mapped': 0,
            'timeline_events': 0,
            'findings_generated': 0
        }

        # Count sources
        if findings.get('infrastructure'):
            metrics['data_sources_analyzed'] += 1
        if findings.get('social'):
            metrics['data_sources_analyzed'] += 1
        if findings.get('threat'):
            metrics['data_sources_analyzed'] += 1

        expanded = findings.get('expanded_sources', {})
        metrics['data_sources_analyzed'] += sum(
            1 for v in expanded.values()
            if isinstance(v, dict) and v.get('success')
        )

        # From correlation
        if correlation:
            metrics['entities_discovered'] = correlation.get('entity_count', 0)
            metrics['relationships_mapped'] = correlation.get('relationship_count', 0)
            metrics['timeline_events'] = correlation.get('event_count', 0)

        return metrics

    def _generate_conclusion(self, target: str, risk_score: RiskScore) -> str:
        """Generate conclusion paragraph"""
        if risk_score.risk_level == 'critical':
            action = "Immediate incident response and remediation actions are required."
        elif risk_score.risk_level == 'high':
            action = "Prompt security improvements and monitoring enhancements are recommended."
        elif risk_score.risk_level == 'medium':
            action = "Planned security improvements should be implemented."
        else:
            action = "Routine monitoring and periodic reassessment are recommended."

        return (
            f"Based on comprehensive analysis of {target}, the overall security posture "
            f"has been assessed as {risk_score.risk_level.upper()} risk with a score of "
            f"{risk_score.overall_score:.0f}/100. {action} "
            f"This assessment should be reviewed and updated regularly as new intelligence "
            f"becomes available."
        )

    def _score_to_severity(self, score: float) -> str:
        """Convert numeric score to severity level"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        return 'low'

    def _assess_kill_chain(self, tactics: Dict) -> str:
        """Assess kill chain coverage"""
        early_stage = ['reconnaissance', 'resource_development', 'initial_access']
        mid_stage = ['execution', 'persistence', 'privilege_escalation', 'defense_evasion']
        late_stage = ['credential_access', 'discovery', 'lateral_movement', 'collection']
        impact_stage = ['command_and_control', 'exfiltration', 'impact']

        stages = []
        if any(t in tactics for t in early_stage):
            stages.append('early')
        if any(t in tactics for t in mid_stage):
            stages.append('mid')
        if any(t in tactics for t in late_stage):
            stages.append('late')
        if any(t in tactics for t in impact_stage):
            stages.append('impact')

        if len(stages) >= 3:
            return "Full kill chain coverage - active threat likely"
        elif len(stages) == 2:
            return "Partial kill chain coverage - potential threat developing"
        elif len(stages) == 1:
            return f"Limited to {stages[0]} stage activities"
        return "Minimal kill chain indicators"


# =============================================================================
# Trend Analysis
# =============================================================================

@dataclass
class TrendDataPoint:
    """Single data point for trend analysis"""
    timestamp: datetime
    value: float
    category: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class TrendAnalyzer:
    """Analyzes trends over time from investigation data"""

    def analyze_trends(self, timeline: List[Dict],
                      historical_data: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """
        Analyze trends from timeline and historical data.

        Args:
            timeline: List of timeline events from correlation
            historical_data: Optional historical investigation data

        Returns:
            Trend analysis results
        """
        if not timeline:
            return {
                'trend_available': False,
                'message': 'Insufficient data for trend analysis'
            }

        # Analyze event distribution
        event_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        monthly_counts = defaultdict(int)

        for event in timeline:
            event_type = event.get('event_type', 'unknown')
            severity = event.get('severity', 'info')
            event_counts[event_type] += 1
            severity_counts[severity] += 1

            # Extract month for temporal analysis
            timestamp = event.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    month_key = dt.strftime('%Y-%m')
                    monthly_counts[month_key] += 1
                except:
                    pass

        # Determine trend direction
        trend_direction = self._calculate_trend_direction(monthly_counts)

        # Identify patterns
        patterns = self._identify_patterns(timeline, event_counts)

        return {
            'trend_available': True,
            'event_distribution': dict(event_counts),
            'severity_distribution': dict(severity_counts),
            'temporal_distribution': dict(monthly_counts),
            'trend_direction': trend_direction,
            'patterns': patterns,
            'total_events': len(timeline),
            'analysis_period': self._get_analysis_period(timeline)
        }

    def _calculate_trend_direction(self, monthly_counts: Dict[str, int]) -> str:
        """Calculate overall trend direction"""
        if len(monthly_counts) < 2:
            return 'insufficient_data'

        sorted_months = sorted(monthly_counts.items())
        if len(sorted_months) >= 2:
            recent = sorted_months[-1][1]
            previous = sorted_months[-2][1]

            if recent > previous * 1.2:
                return 'increasing'
            elif recent < previous * 0.8:
                return 'decreasing'

        return 'stable'

    def _identify_patterns(self, timeline: List[Dict],
                          event_counts: Dict[str, int]) -> List[Dict[str, Any]]:
        """Identify notable patterns in the data"""
        patterns = []

        # Most common event types
        top_events = sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_events:
            patterns.append({
                'type': 'frequent_events',
                'description': f"Most common: {top_events[0][0]} ({top_events[0][1]} occurrences)",
                'significance': 'high' if top_events[0][1] > 5 else 'medium'
            })

        # Critical event clustering
        critical_events = [e for e in timeline if e.get('severity') == 'critical']
        if len(critical_events) >= 2:
            patterns.append({
                'type': 'critical_cluster',
                'description': f"{len(critical_events)} critical events detected",
                'significance': 'high'
            })

        return patterns

    def _get_analysis_period(self, timeline: List[Dict]) -> Dict[str, str]:
        """Get the time period covered by the timeline"""
        timestamps = []
        for event in timeline:
            ts = event.get('timestamp', '')
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    timestamps.append(dt)
                except:
                    pass

        if timestamps:
            return {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat(),
                'duration_days': (max(timestamps) - min(timestamps)).days
            }

        return {'start': None, 'end': None, 'duration_days': 0}


# =============================================================================
# Chart Data Generator
# =============================================================================

class ChartDataGenerator:
    """Generates chart-ready data for visualization"""

    @staticmethod
    def risk_distribution_chart(risk_score: RiskScore) -> Dict[str, Any]:
        """Generate data for risk distribution pie/donut chart"""
        return {
            'chart_type': 'pie',
            'title': 'Risk Distribution by Category',
            'data': [
                {
                    'label': cat.replace('_', ' ').title(),
                    'value': round(score, 1),
                    'color': ChartDataGenerator._get_risk_color(score)
                }
                for cat, score in risk_score.category_scores.items()
                if score > 0
            ]
        }

    @staticmethod
    def severity_bar_chart(mitre_mapping: List[Dict]) -> Dict[str, Any]:
        """Generate data for MITRE severity bar chart"""
        severity_counts = defaultdict(int)
        for technique in mitre_mapping:
            severity_counts[technique.get('severity', 'medium')] += 1

        order = ['critical', 'high', 'medium', 'low']
        return {
            'chart_type': 'bar',
            'title': 'MITRE Techniques by Severity',
            'data': [
                {
                    'label': sev.title(),
                    'value': severity_counts.get(sev, 0),
                    'color': ChartDataGenerator._get_severity_color(sev)
                }
                for sev in order
            ]
        }

    @staticmethod
    def timeline_chart(timeline: List[Dict]) -> Dict[str, Any]:
        """Generate data for timeline visualization"""
        # Group by month
        monthly_data = defaultdict(lambda: {'info': 0, 'warning': 0, 'critical': 0})

        for event in timeline:
            ts = event.get('timestamp', '')
            severity = event.get('severity', 'info')
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    month_key = dt.strftime('%Y-%m')
                    monthly_data[month_key][severity] += 1
                except:
                    pass

        return {
            'chart_type': 'stacked_bar',
            'title': 'Events Over Time',
            'categories': sorted(monthly_data.keys()),
            'series': [
                {'name': 'Critical', 'data': [monthly_data[m]['critical'] for m in sorted(monthly_data.keys())], 'color': '#dc3545'},
                {'name': 'Warning', 'data': [monthly_data[m]['warning'] for m in sorted(monthly_data.keys())], 'color': '#ffc107'},
                {'name': 'Info', 'data': [monthly_data[m]['info'] for m in sorted(monthly_data.keys())], 'color': '#17a2b8'}
            ]
        }

    @staticmethod
    def entity_type_chart(entities: Dict) -> Dict[str, Any]:
        """Generate data for entity type distribution"""
        type_counts = defaultdict(int)
        for entity_id, entity in entities.items():
            entity_type = entity.get('type', 'unknown')
            type_counts[entity_type] += 1

        return {
            'chart_type': 'horizontal_bar',
            'title': 'Entities by Type',
            'data': [
                {'label': t.replace('_', ' ').title(), 'value': c}
                for t, c in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
            ]
        }

    @staticmethod
    def risk_gauge_chart(risk_score: RiskScore) -> Dict[str, Any]:
        """Generate data for risk score gauge"""
        return {
            'chart_type': 'gauge',
            'title': 'Overall Risk Score',
            'value': round(risk_score.overall_score, 1),
            'max': 100,
            'thresholds': [
                {'value': 40, 'color': '#28a745', 'label': 'Low'},
                {'value': 60, 'color': '#ffc107', 'label': 'Medium'},
                {'value': 80, 'color': '#fd7e14', 'label': 'High'},
                {'value': 100, 'color': '#dc3545', 'label': 'Critical'}
            ]
        }

    @staticmethod
    def _get_risk_color(score: float) -> str:
        """Get color based on risk score"""
        if score >= 80:
            return '#dc3545'  # Red
        elif score >= 60:
            return '#fd7e14'  # Orange
        elif score >= 40:
            return '#ffc107'  # Yellow
        return '#28a745'  # Green

    @staticmethod
    def _get_severity_color(severity: str) -> str:
        """Get color based on severity level"""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745'
        }
        return colors.get(severity, '#6c757d')


# =============================================================================
# Main Advanced Analysis Engine
# =============================================================================

class AdvancedAnalysisEngine:
    """
    Main engine for advanced analysis combining all components.
    """

    def __init__(self):
        self.risk_engine = RiskScoringEngine()
        self.summary_generator = ExecutiveSummaryGenerator()
        self.trend_analyzer = TrendAnalyzer()
        self.chart_generator = ChartDataGenerator()

    def analyze(self,
               target: str,
               findings: Dict[str, Any],
               correlation_results: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Perform comprehensive advanced analysis.

        Args:
            target: Investigation target
            findings: Investigation findings
            correlation_results: Optional correlation results

        Returns:
            Complete analysis results
        """
        logger.info(f"Starting advanced analysis for {target}")

        # MITRE ATT&CK mapping
        mitre_mapping = MITREMapper.map_findings(findings)
        attack_surface = MITREMapper.get_attack_surface_summary(mitre_mapping)

        # Risk scoring
        risk_score = self.risk_engine.calculate_risk(
            findings,
            correlation_results,
            mitre_mapping
        )

        # Trend analysis (from correlation timeline)
        timeline = []
        if correlation_results:
            timeline = correlation_results.get('timeline', [])
        trends = self.trend_analyzer.analyze_trends(timeline)

        # Executive summary
        executive_summary = self.summary_generator.generate_summary(
            target,
            risk_score,
            mitre_mapping,
            findings,
            correlation_results
        )

        # Chart data
        charts = {
            'risk_distribution': self.chart_generator.risk_distribution_chart(risk_score),
            'severity_breakdown': self.chart_generator.severity_bar_chart(mitre_mapping),
            'risk_gauge': self.chart_generator.risk_gauge_chart(risk_score)
        }

        if timeline:
            charts['timeline'] = self.chart_generator.timeline_chart(timeline)

        if correlation_results and correlation_results.get('entities'):
            charts['entity_distribution'] = self.chart_generator.entity_type_chart(
                correlation_results['entities']
            )

        result = {
            'target': target,
            'analyzed_at': datetime.utcnow().isoformat(),
            'risk_score': risk_score.to_dict(),
            'mitre_mapping': {
                'techniques': mitre_mapping,
                'attack_surface': attack_surface,
                'technique_count': len(mitre_mapping)
            },
            'trends': trends,
            'executive_summary': executive_summary,
            'charts': charts,
            'analysis_metadata': {
                'engine_version': '1.0.0',
                'components_used': ['mitre_mapper', 'risk_scorer', 'trend_analyzer',
                                   'summary_generator', 'chart_generator']
            }
        }

        logger.info(f"Advanced analysis complete: risk={risk_score.overall_score:.0f}, "
                   f"techniques={len(mitre_mapping)}")

        return result


# Global instance
advanced_analysis_engine = AdvancedAnalysisEngine()

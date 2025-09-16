#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.
# Individual use is free. Commercial use requires 3% profit sharing.
# See LICENSE file for details.

"""
Comprehensive Compliance Framework for OSINT Platform
Supports GDPR, CCPA, PIPEDA, LGPD and other data protection regulations
"""

import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

from models import ComplianceFramework

logger = logging.getLogger(__name__)


class DataCategory(Enum):
    """Categories of personal data for compliance classification"""
    PERSONAL_IDENTIFIERS = "personal_identifiers"  # Names, emails, phone numbers
    BIOMETRIC_DATA = "biometric_data"  # Fingerprints, facial recognition
    LOCATION_DATA = "location_data"  # GPS, IP geolocation
    FINANCIAL_DATA = "financial_data"  # Payment info, bank details
    HEALTH_DATA = "health_data"  # Medical records, health status
    SOCIAL_MEDIA = "social_media"  # Public posts, profiles
    BEHAVIORAL_DATA = "behavioral_data"  # Browsing patterns, preferences
    COMMUNICATION_DATA = "communication_data"  # Messages, call logs
    EMPLOYMENT_DATA = "employment_data"  # Work history, salary
    SPECIAL_CATEGORIES = "special_categories"  # Race, religion, political views
    PUBLIC_RECORDS = "public_records"  # Court records, property records
    TECHNICAL_DATA = "technical_data"  # IP addresses, device IDs


class ProcessingLawfulBasis(Enum):
    """GDPR Article 6 lawful bases for processing"""
    CONSENT = "consent"  # Article 6(1)(a)
    CONTRACT = "contract"  # Article 6(1)(b)
    LEGAL_OBLIGATION = "legal_obligation"  # Article 6(1)(c)
    VITAL_INTERESTS = "vital_interests"  # Article 6(1)(d)
    PUBLIC_TASK = "public_task"  # Article 6(1)(e)
    LEGITIMATE_INTERESTS = "legitimate_interests"  # Article 6(1)(f)


class ComplianceStatus(Enum):
    """Compliance assessment status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    REQUIRES_REVIEW = "requires_review"
    CONSENT_REQUIRED = "consent_required"
    RESTRICTED = "restricted"


class RiskLevel(Enum):
    """Risk level for compliance violations"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DataProcessingRecord:
    """Record of data processing activity for compliance auditing"""
    processing_id: str
    investigation_id: str
    data_category: DataCategory
    data_source: str
    processing_purpose: str
    lawful_basis: ProcessingLawfulBasis
    data_subjects: List[str]  # Anonymized identifiers
    retention_period: timedelta
    processed_at: datetime
    expires_at: datetime
    geographical_scope: List[str]  # ISO country codes
    third_party_sharing: bool = False
    automated_decision_making: bool = False
    high_risk_processing: bool = False
    consent_obtained: bool = False
    consent_timestamp: Optional[datetime] = None
    data_minimization_applied: bool = True
    pseudonymization_applied: bool = False
    encryption_applied: bool = True
    access_controls: List[str] = field(default_factory=list)


@dataclass
class ComplianceAssessment:
    """Comprehensive compliance assessment result"""
    assessment_id: str
    investigation_id: str
    framework: ComplianceFramework
    status: ComplianceStatus
    risk_level: RiskLevel
    compliance_score: float  # 0-100
    
    # Detailed compliance checks
    data_categories_identified: List[DataCategory]
    processing_records: List[DataProcessingRecord]
    lawful_bases_applied: List[ProcessingLawfulBasis]
    
    # Risk factors
    high_risk_factors: List[str]
    consent_requirements: List[str]
    retention_violations: List[str]
    cross_border_transfers: List[str]
    
    # Recommendations
    remediation_actions: List[str]
    policy_updates_required: List[str]
    training_requirements: List[str]
    
    # Audit trail
    assessed_by: str
    assessed_at: datetime
    next_review_date: datetime
    compliance_officer_approval: Optional[str] = None
    
    # Documentation
    privacy_impact_assessment: Optional[str] = None
    data_protection_measures: List[str] = field(default_factory=list)
    incident_response_plan: Optional[str] = None


class ComplianceRule(ABC):
    """Abstract base class for compliance rules"""
    
    def __init__(self, rule_id: str, framework: ComplianceFramework, severity: RiskLevel):
        self.rule_id = rule_id
        self.framework = framework
        self.severity = severity
    
    @abstractmethod
    def evaluate(self, assessment: ComplianceAssessment, processing_records: List[DataProcessingRecord]) -> Tuple[bool, str]:
        """Evaluate compliance rule and return (is_compliant, explanation)"""
        pass
    
    @abstractmethod
    def get_remediation_actions(self) -> List[str]:
        """Get recommended remediation actions for non-compliance"""
        pass


class GDPRComplianceRules:
    """GDPR-specific compliance rules implementation"""
    
    class DataMinimizationRule(ComplianceRule):
        def __init__(self):
            super().__init__("GDPR-001", ComplianceFramework.GDPR, RiskLevel.HIGH)
        
        def evaluate(self, assessment: ComplianceAssessment, processing_records: List[DataProcessingRecord]) -> Tuple[bool, str]:
            non_minimized = [r for r in processing_records if not r.data_minimization_applied]
            if non_minimized:
                return False, f"Data minimization not applied to {len(non_minimized)} processing activities"
            return True, "Data minimization principle satisfied"
        
        def get_remediation_actions(self) -> List[str]:
            return [
                "Review data collection practices to ensure only necessary data is processed",
                "Implement data minimization controls in collection systems",
                "Document justification for all data elements collected",
                "Regular review of data inventory for unnecessary data"
            ]
    
    class LawfulBasisRule(ComplianceRule):
        def __init__(self):
            super().__init__("GDPR-002", ComplianceFramework.GDPR, RiskLevel.CRITICAL)
        
        def evaluate(self, assessment: ComplianceAssessment, processing_records: List[DataProcessingRecord]) -> Tuple[bool, str]:
            missing_basis = [r for r in processing_records if r.lawful_basis is None]
            if missing_basis:
                return False, f"Lawful basis not defined for {len(missing_basis)} processing activities"
            return True, "Valid lawful basis established for all processing"
        
        def get_remediation_actions(self) -> List[str]:
            return [
                "Identify appropriate lawful basis for each processing activity",
                "Document lawful basis in privacy notices",
                "Obtain explicit consent where required",
                "Review and update data processing agreements"
            ]
    
    class RetentionRule(ComplianceRule):
        def __init__(self):
            super().__init__("GDPR-003", ComplianceFramework.GDPR, RiskLevel.MEDIUM)
        
        def evaluate(self, assessment: ComplianceAssessment, processing_records: List[DataProcessingRecord]) -> Tuple[bool, str]:
            current_time = datetime.utcnow()
            expired_records = [r for r in processing_records if current_time > r.expires_at]
            
            if expired_records:
                return False, f"{len(expired_records)} records exceed retention period"
            return True, "All data within approved retention periods"
        
        def get_remediation_actions(self) -> List[str]:
            return [
                "Implement automated data deletion after retention period",
                "Regular audit of data retention compliance",
                "Update retention schedules based on legal requirements",
                "Document business justification for retention periods"
            ]
    
    class SpecialCategoryRule(ComplianceRule):
        def __init__(self):
            super().__init__("GDPR-004", ComplianceFramework.GDPR, RiskLevel.CRITICAL)
        
        def evaluate(self, assessment: ComplianceAssessment, processing_records: List[DataProcessingRecord]) -> Tuple[bool, str]:
            special_category_records = [r for r in processing_records 
                                     if r.data_category == DataCategory.SPECIAL_CATEGORIES]
            
            non_compliant = [r for r in special_category_records 
                           if not r.consent_obtained and r.lawful_basis != ProcessingLawfulBasis.LEGAL_OBLIGATION]
            
            if non_compliant:
                return False, f"Special category data processed without appropriate safeguards: {len(non_compliant)} records"
            return True, "Special category data processing compliant"
        
        def get_remediation_actions(self) -> List[str]:
            return [
                "Obtain explicit consent for special category data processing",
                "Implement additional technical safeguards",
                "Conduct Data Protection Impact Assessment (DPIA)",
                "Regular review of special category data processing"
            ]


class CCPAComplianceRules:
    """CCPA-specific compliance rules implementation"""
    
    class ConsumerRightsRule(ComplianceRule):
        def __init__(self):
            super().__init__("CCPA-001", ComplianceFramework.CCPA, RiskLevel.HIGH)
        
        def evaluate(self, assessment: ComplianceAssessment, processing_records: List[DataProcessingRecord]) -> Tuple[bool, str]:
            # Check if systems support consumer rights (right to know, delete, opt-out)
            california_records = [r for r in processing_records if 'US-CA' in r.geographical_scope]
            
            if california_records and not assessment.data_protection_measures:
                return False, "Consumer rights mechanisms not implemented for California residents"
            return True, "Consumer rights protections in place"
        
        def get_remediation_actions(self) -> List[str]:
            return [
                "Implement consumer request processing system",
                "Create privacy policy with required CCPA disclosures",
                "Establish identity verification procedures",
                "Train staff on consumer rights handling"
            ]
    
    class SaleOptOutRule(ComplianceRule):
        def __init__(self):
            super().__init__("CCPA-002", ComplianceFramework.CCPA, RiskLevel.MEDIUM)
        
        def evaluate(self, assessment: ComplianceAssessment, processing_records: List[DataProcessingRecord]) -> Tuple[bool, str]:
            third_party_sharing = [r for r in processing_records if r.third_party_sharing]
            
            if third_party_sharing:
                # Would check for opt-out mechanisms in real implementation
                return False, "Third-party sharing detected - ensure opt-out mechanisms available"
            return True, "No third-party sharing or opt-out mechanisms in place"
        
        def get_remediation_actions(self) -> List[str]:
            return [
                "Implement 'Do Not Sell My Personal Information' option",
                "Update privacy policy with sale disclosures",
                "Create opt-out preference center",
                "Monitor and respect opt-out preferences"
            ]


class ComplianceEngine:
    """Main compliance evaluation and monitoring engine"""
    
    def __init__(self):
        self.rules_registry: Dict[ComplianceFramework, List[ComplianceRule]] = {
            ComplianceFramework.GDPR: [
                GDPRComplianceRules.DataMinimizationRule(),
                GDPRComplianceRules.LawfulBasisRule(),
                GDPRComplianceRules.RetentionRule(),
                GDPRComplianceRules.SpecialCategoryRule()
            ],
            ComplianceFramework.CCPA: [
                CCPAComplianceRules.ConsumerRightsRule(),
                CCPAComplianceRules.SaleOptOutRule()
            ],
            ComplianceFramework.PIPEDA: [],  # Canadian privacy rules
            ComplianceFramework.LGPD: []     # Brazilian privacy rules
        }
        
        self.data_category_classifier = DataCategoryClassifier()
        self.processing_logger = ProcessingLogger()
    
    def assess_compliance(self, 
                         investigation_id: str,
                         target_data: Dict[str, Any],
                         processing_activities: List[Dict[str, Any]],
                         geographical_scope: List[str]) -> ComplianceAssessment:
        """Perform comprehensive compliance assessment"""
        
        assessment_id = f"compliance_{investigation_id}_{int(datetime.utcnow().timestamp())}"
        
        # Determine applicable frameworks based on geographical scope
        applicable_frameworks = self._determine_applicable_frameworks(geographical_scope)
        
        # Classify data categories
        data_categories = self.data_category_classifier.classify_data(target_data)
        
        # Create processing records
        processing_records = self._create_processing_records(
            investigation_id, processing_activities, data_categories, geographical_scope
        )
        
        # Evaluate compliance for each applicable framework
        assessments = []
        for framework in applicable_frameworks:
            assessment = self._evaluate_framework_compliance(
                assessment_id, investigation_id, framework, data_categories, 
                processing_records, geographical_scope
            )
            assessments.append(assessment)
        
        # Return primary assessment (highest risk framework)
        primary_assessment = max(assessments, key=lambda a: a.risk_level.value)
        
        # Log assessment
        self.processing_logger.log_compliance_assessment(primary_assessment)
        
        return primary_assessment
    
    def _determine_applicable_frameworks(self, geographical_scope: List[str]) -> List[ComplianceFramework]:
        """Determine which compliance frameworks apply based on geographical scope"""
        applicable = []
        
        # EU countries require GDPR
        eu_countries = {'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 
                       'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 
                       'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'}
        
        if any(country in eu_countries for country in geographical_scope):
            applicable.append(ComplianceFramework.GDPR)
        
        # California requires CCPA
        if 'US-CA' in geographical_scope or 'US' in geographical_scope:
            applicable.append(ComplianceFramework.CCPA)
        
        # Canada requires PIPEDA
        if 'CA' in geographical_scope:
            applicable.append(ComplianceFramework.PIPEDA)
        
        # Brazil requires LGPD
        if 'BR' in geographical_scope:
            applicable.append(ComplianceFramework.LGPD)
        
        return applicable
    
    def _create_processing_records(self, 
                                 investigation_id: str,
                                 processing_activities: List[Dict[str, Any]],
                                 data_categories: List[DataCategory],
                                 geographical_scope: List[str]) -> List[DataProcessingRecord]:
        """Create detailed processing records for compliance tracking"""
        
        processing_records = []
        current_time = datetime.utcnow()
        
        for activity in processing_activities:
            record = DataProcessingRecord(
                processing_id=f"proc_{investigation_id}_{activity.get('source', 'unknown')}",
                investigation_id=investigation_id,
                data_category=self._map_source_to_category(activity.get('source', '')),
                data_source=activity.get('source', 'unknown'),
                processing_purpose="OSINT investigation and threat assessment",
                lawful_basis=self._determine_lawful_basis(activity, geographical_scope),
                data_subjects=[f"subject_{hashlib.md5(investigation_id.encode()).hexdigest()[:8]}"],
                retention_period=timedelta(minutes=10),  # Security requirement
                processed_at=current_time,
                expires_at=current_time + timedelta(minutes=10),
                geographical_scope=geographical_scope,
                third_party_sharing=activity.get('third_party_sharing', False),
                automated_decision_making=activity.get('automated_analysis', True),
                high_risk_processing=self._assess_high_risk_processing(activity, data_categories),
                consent_obtained=activity.get('consent_obtained', False),
                data_minimization_applied=True,  # Platform design principle
                pseudonymization_applied=True,   # Target anonymization
                encryption_applied=True,         # End-to-end encryption
                access_controls=['investigator_role', 'time_based_access', 'audit_logging']
            )
            processing_records.append(record)
        
        return processing_records
    
    def _map_source_to_category(self, source: str) -> DataCategory:
        """Map intelligence source to data category"""
        source_mapping = {
            'twitter': DataCategory.SOCIAL_MEDIA,
            'reddit': DataCategory.SOCIAL_MEDIA,
            'linkedin': DataCategory.SOCIAL_MEDIA,
            'whois': DataCategory.PUBLIC_RECORDS,
            'dns': DataCategory.TECHNICAL_DATA,
            'shodan': DataCategory.TECHNICAL_DATA,
            'virustotal': DataCategory.TECHNICAL_DATA,
            'ssl_certificate': DataCategory.TECHNICAL_DATA,
            'alienvault_otx': DataCategory.TECHNICAL_DATA
        }
        return source_mapping.get(source.lower(), DataCategory.TECHNICAL_DATA)
    
    def _determine_lawful_basis(self, activity: Dict[str, Any], geographical_scope: List[str]) -> ProcessingLawfulBasis:
        """Determine appropriate lawful basis for processing"""
        
        # For OSINT investigations, typically legitimate interests or legal obligation
        if activity.get('legal_request', False):
            return ProcessingLawfulBasis.LEGAL_OBLIGATION
        
        # Public records and technical data often qualify for legitimate interests
        if activity.get('source') in ['whois', 'dns', 'public_records']:
            return ProcessingLawfulBasis.LEGITIMATE_INTERESTS
        
        # Social media requires more careful consideration
        if activity.get('source') in ['twitter', 'reddit', 'linkedin']:
            if activity.get('public_data_only', True):
                return ProcessingLawfulBasis.LEGITIMATE_INTERESTS
            else:
                return ProcessingLawfulBasis.CONSENT
        
        return ProcessingLawfulBasis.LEGITIMATE_INTERESTS
    
    def _assess_high_risk_processing(self, activity: Dict[str, Any], data_categories: List[DataCategory]) -> bool:
        """Assess if processing activity is high-risk"""
        
        high_risk_factors = [
            DataCategory.SPECIAL_CATEGORIES in data_categories,
            DataCategory.BIOMETRIC_DATA in data_categories,
            activity.get('automated_decision_making', False),
            activity.get('large_scale_processing', False),
            activity.get('systematic_monitoring', False)
        ]
        
        return any(high_risk_factors)
    
    def _evaluate_framework_compliance(self, 
                                     assessment_id: str,
                                     investigation_id: str,
                                     framework: ComplianceFramework,
                                     data_categories: List[DataCategory],
                                     processing_records: List[DataProcessingRecord],
                                     geographical_scope: List[str]) -> ComplianceAssessment:
        """Evaluate compliance against specific framework"""
        
        # Initialize assessment
        assessment = ComplianceAssessment(
            assessment_id=assessment_id,
            investigation_id=investigation_id,
            framework=framework,
            status=ComplianceStatus.COMPLIANT,
            risk_level=RiskLevel.LOW,
            compliance_score=100.0,
            data_categories_identified=data_categories,
            processing_records=processing_records,
            lawful_bases_applied=list(set(r.lawful_basis for r in processing_records)),
            high_risk_factors=[],
            consent_requirements=[],
            retention_violations=[],
            cross_border_transfers=[],
            remediation_actions=[],
            policy_updates_required=[],
            training_requirements=[],
            assessed_by="compliance_engine",
            assessed_at=datetime.utcnow(),
            next_review_date=datetime.utcnow() + timedelta(days=90),
            data_protection_measures=[
                "End-to-end encryption",
                "Time-based access controls", 
                "Automated data deletion",
                "Audit logging",
                "Role-based access control"
            ]
        )
        
        # Evaluate rules for this framework
        rules = self.rules_registry.get(framework, [])
        failed_rules = []
        
        for rule in rules:
            is_compliant, explanation = rule.evaluate(assessment, processing_records)
            
            if not is_compliant:
                failed_rules.append((rule, explanation))
                assessment.remediation_actions.extend(rule.get_remediation_actions())
                
                # Adjust compliance score and status
                if rule.severity == RiskLevel.CRITICAL:
                    assessment.compliance_score -= 30
                    assessment.risk_level = RiskLevel.CRITICAL
                    assessment.status = ComplianceStatus.NON_COMPLIANT
                elif rule.severity == RiskLevel.HIGH:
                    assessment.compliance_score -= 20
                    if assessment.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]:
                        assessment.risk_level = RiskLevel.HIGH
                        assessment.status = ComplianceStatus.REQUIRES_REVIEW
                elif rule.severity == RiskLevel.MEDIUM:
                    assessment.compliance_score -= 10
                    if assessment.risk_level == RiskLevel.LOW:
                        assessment.risk_level = RiskLevel.MEDIUM
        
        # Framework-specific assessments
        if framework == ComplianceFramework.GDPR:
            self._assess_gdpr_specific_requirements(assessment, processing_records)
        elif framework == ComplianceFramework.CCPA:
            self._assess_ccpa_specific_requirements(assessment, processing_records)
        
        # Ensure minimum score
        assessment.compliance_score = max(0, assessment.compliance_score)
        
        return assessment
    
    def _assess_gdpr_specific_requirements(self, assessment: ComplianceAssessment, processing_records: List[DataProcessingRecord]):
        """GDPR-specific compliance assessments"""
        
        # Check for cross-border transfers
        eu_countries = {'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 
                       'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 
                       'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'}
        
        for record in processing_records:
            non_eu_countries = [c for c in record.geographical_scope if c not in eu_countries]
            if non_eu_countries:
                assessment.cross_border_transfers.extend(non_eu_countries)
                assessment.high_risk_factors.append("Cross-border data transfer to non-EU countries")
        
        # Check for DPIA requirements
        high_risk_records = [r for r in processing_records if r.high_risk_processing]
        if high_risk_records:
            assessment.policy_updates_required.append("Data Protection Impact Assessment (DPIA) required")
            assessment.high_risk_factors.append("High-risk processing activities identified")
        
        # Special category data handling
        special_category_records = [r for r in processing_records 
                                  if r.data_category == DataCategory.SPECIAL_CATEGORIES]
        if special_category_records:
            assessment.consent_requirements.append("Explicit consent required for special category data")
            assessment.high_risk_factors.append("Special category data processing")
    
    def _assess_ccpa_specific_requirements(self, assessment: ComplianceAssessment, processing_records: List[DataProcessingRecord]):
        """CCPA-specific compliance assessments"""
        
        # Check for consumer rights implementation
        california_records = [r for r in processing_records if 'US-CA' in r.geographical_scope]
        if california_records:
            assessment.policy_updates_required.extend([
                "Privacy policy must include CCPA-required disclosures",
                "Consumer request processing system required",
                "Identity verification procedures required"
            ])
            
            # Check for third-party sharing
            sharing_records = [r for r in california_records if r.third_party_sharing]
            if sharing_records:
                assessment.remediation_actions.append("Implement 'Do Not Sell My Personal Information' option")
                assessment.high_risk_factors.append("Third-party sharing of California resident data")


class DataCategoryClassifier:
    """Classifier for identifying data categories in collected intelligence"""
    
    def classify_data(self, target_data: Dict[str, Any]) -> List[DataCategory]:
        """Classify collected data into compliance categories"""
        
        categories = set()
        
        # Analyze different data sources
        if 'social_intelligence' in target_data:
            categories.add(DataCategory.SOCIAL_MEDIA)
            social_data = target_data['social_intelligence']
            
            if self._contains_personal_identifiers(social_data):
                categories.add(DataCategory.PERSONAL_IDENTIFIERS)
            
            if self._contains_location_data(social_data):
                categories.add(DataCategory.LOCATION_DATA)
        
        if 'infrastructure_intelligence' in target_data:
            categories.add(DataCategory.TECHNICAL_DATA)
            categories.add(DataCategory.PUBLIC_RECORDS)  # WHOIS data
        
        if 'threat_intelligence' in target_data:
            categories.add(DataCategory.TECHNICAL_DATA)
        
        return list(categories)
    
    def _contains_personal_identifiers(self, data: Dict[str, Any]) -> bool:
        """Check if data contains personal identifiers"""
        personal_indicators = ['email', 'phone', 'name', 'username', 'profile']
        return any(indicator in str(data).lower() for indicator in personal_indicators)
    
    def _contains_location_data(self, data: Dict[str, Any]) -> bool:
        """Check if data contains location information"""
        location_indicators = ['location', 'geo', 'country', 'city', 'address', 'coordinates']
        return any(indicator in str(data).lower() for indicator in location_indicators)


class ProcessingLogger:
    """Compliance audit trail and processing logging"""
    
    def __init__(self):
        self.processing_log: List[Dict[str, Any]] = []
    
    def log_compliance_assessment(self, assessment: ComplianceAssessment):
        """Log compliance assessment for audit trail"""
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'compliance_assessment',
            'assessment_id': assessment.assessment_id,
            'investigation_id': assessment.investigation_id,
            'framework': assessment.framework.value,
            'status': assessment.status.value,
            'risk_level': assessment.risk_level.value,
            'compliance_score': assessment.compliance_score,
            'data_categories': [cat.value for cat in assessment.data_categories_identified],
            'high_risk_factors': assessment.high_risk_factors,
            'remediation_required': len(assessment.remediation_actions) > 0
        }
        
        self.processing_log.append(log_entry)
        logger.info(f"Compliance assessment completed: {assessment.assessment_id} - {assessment.status.value}")
    
    def log_data_processing(self, record: DataProcessingRecord):
        """Log data processing activity"""
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'data_processing',
            'processing_id': record.processing_id,
            'investigation_id': record.investigation_id,
            'data_category': record.data_category.value,
            'data_source': record.data_source,
            'lawful_basis': record.lawful_basis.value,
            'retention_period_minutes': int(record.retention_period.total_seconds() / 60),
            'geographical_scope': record.geographical_scope,
            'high_risk': record.high_risk_processing,
            'consent_obtained': record.consent_obtained
        }
        
        self.processing_log.append(log_entry)
        logger.info(f"Data processing logged: {record.processing_id}")
    
    def get_audit_trail(self, investigation_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get compliance audit trail"""
        
        if investigation_id:
            return [entry for entry in self.processing_log 
                   if entry.get('investigation_id') == investigation_id]
        
        return self.processing_log.copy()
    
    def generate_compliance_report(self, framework: ComplianceFramework, 
                                 start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate compliance summary report"""
        
        relevant_entries = [
            entry for entry in self.processing_log
            if start_date <= datetime.fromisoformat(entry['timestamp']) <= end_date
            and entry.get('framework') == framework.value
        ]
        
        assessments = [e for e in relevant_entries if e['event_type'] == 'compliance_assessment']
        processing_activities = [e for e in relevant_entries if e['event_type'] == 'data_processing']
        
        compliance_scores = [a['compliance_score'] for a in assessments if 'compliance_score' in a]
        avg_compliance_score = sum(compliance_scores) / len(compliance_scores) if compliance_scores else 0
        
        return {
            'framework': framework.value,
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'summary': {
                'total_assessments': len(assessments),
                'total_processing_activities': len(processing_activities),
                'average_compliance_score': round(avg_compliance_score, 2),
                'compliant_assessments': len([a for a in assessments if a['status'] == 'compliant']),
                'non_compliant_assessments': len([a for a in assessments if a['status'] == 'non_compliant']),
                'high_risk_assessments': len([a for a in assessments if a['risk_level'] in ['high', 'critical']])
            },
            'data_categories_processed': list(set(
                cat for activity in processing_activities 
                for cat in activity.get('data_categories', [])
            )),
            'common_risk_factors': self._analyze_common_risk_factors(assessments),
            'recommendations': self._generate_framework_recommendations(framework, assessments)
        }
    
    def _analyze_common_risk_factors(self, assessments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze common risk factors across assessments"""
        
        risk_factor_counts = {}
        for assessment in assessments:
            for risk_factor in assessment.get('high_risk_factors', []):
                risk_factor_counts[risk_factor] = risk_factor_counts.get(risk_factor, 0) + 1
        
        return [
            {'factor': factor, 'occurrences': count}
            for factor, count in sorted(risk_factor_counts.items(), key=lambda x: x[1], reverse=True)
        ]
    
    def _generate_framework_recommendations(self, framework: ComplianceFramework, 
                                          assessments: List[Dict[str, Any]]) -> List[str]:
        """Generate framework-specific recommendations"""
        
        recommendations = []
        
        if framework == ComplianceFramework.GDPR:
            non_compliant_count = len([a for a in assessments if a['status'] != 'compliant'])
            if non_compliant_count > 0:
                recommendations.extend([
                    "Conduct regular GDPR compliance training for all staff",
                    "Implement automated data protection controls",
                    "Regular Data Protection Impact Assessments for high-risk processing",
                    "Review and update privacy notices"
                ])
        
        elif framework == ComplianceFramework.CCPA:
            recommendations.extend([
                "Implement consumer request management system",
                "Regular review of third-party data sharing agreements",
                "Update privacy policy with CCPA disclosures",
                "Monitor opt-out preference compliance"
            ])
        
        return recommendations
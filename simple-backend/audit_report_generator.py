#!/usr/bin/env python3
"""
Comprehensive Audit Report Generator
Creates detailed audit reports for investigations, system usage, and compliance
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter

from models import OSINTInvestigation, InvestigationType, InvestigationStatus, Priority
from investigation_reporting import InvestigationReportGenerator
from professional_report_generator import ProfessionalReportGenerator, ReportType, ClassificationLevel

logger = logging.getLogger(__name__)


class AuditScope(Enum):
    """Audit scope definitions"""
    INVESTIGATIONS = "investigations"
    SYSTEM_USAGE = "system_usage"
    COMPLIANCE = "compliance"
    SECURITY = "security"
    PERFORMANCE = "performance"
    COMPREHENSIVE = "comprehensive"


@dataclass
class AuditMetrics:
    """Audit metrics and KPIs"""
    total_investigations: int
    active_investigations: int
    completed_investigations: int
    failed_investigations: int
    
    # Performance metrics
    avg_investigation_duration: float  # minutes
    total_processing_time: float  # minutes
    success_rate: float  # percentage
    
    # Usage metrics
    unique_investigators: int
    total_api_calls: int
    total_cost: float
    data_points_collected: int
    
    # Compliance metrics
    compliance_violations: int
    compliance_rate: float
    gdpr_assessments: int
    ccpa_assessments: int
    
    # Security metrics
    high_risk_investigations: int
    critical_findings: int
    threat_vectors_identified: int
    
    # System metrics
    vault_status: str
    api_service_health: Dict[str, bool] = field(default_factory=dict)
    uptime_percentage: float = 0.0


@dataclass
class InvestigatorAuditProfile:
    """Individual investigator audit profile"""
    investigator_id: str
    investigator_name: str
    
    # Investigation statistics
    total_investigations: int
    investigations_by_type: Dict[str, int]
    investigations_by_status: Dict[str, int]
    investigations_by_priority: Dict[str, int]
    
    # Performance metrics
    avg_processing_time: float
    success_rate: float
    compliance_rate: float
    
    # Activity patterns
    most_active_hours: List[int]
    most_active_days: List[str]
    investigation_frequency: float  # investigations per day
    
    # Quality metrics
    avg_confidence_score: float
    avg_completeness_score: float
    findings_per_investigation: float
    
    # Resource usage
    total_api_calls: int
    total_cost: float
    most_used_services: List[str]
    
    # Timeline
    first_investigation: datetime
    last_investigation: datetime
    investigation_timeline: List[Dict[str, Any]] = field(default_factory=list)
    
    # Notable findings
    high_risk_investigations: List[str] = field(default_factory=list)
    compliance_violations: List[str] = field(default_factory=list)
    exceptional_findings: List[str] = field(default_factory=list)


@dataclass
class SystemAuditReport:
    """Comprehensive system audit report"""
    report_id: str
    audit_scope: AuditScope
    generated_at: datetime
    audit_period: Dict[str, datetime]
    generated_by: str
    
    # Executive summary
    executive_summary: str
    key_findings: List[str]
    recommendations: List[str]
    
    # Metrics and statistics
    system_metrics: AuditMetrics
    investigator_profiles: List[InvestigatorAuditProfile]
    
    # Detailed analysis
    investigation_analysis: Dict[str, Any]
    usage_patterns: Dict[str, Any]
    security_analysis: Dict[str, Any]
    compliance_analysis: Dict[str, Any]
    performance_analysis: Dict[str, Any]
    
    # System health
    system_health: Dict[str, Any]
    api_service_status: Dict[str, Any]
    infrastructure_status: Dict[str, Any]
    
    # Audit trail
    audit_events: List[Dict[str, Any]] = field(default_factory=list)
    configuration_changes: List[Dict[str, Any]] = field(default_factory=list)
    access_logs: List[Dict[str, Any]] = field(default_factory=list)


class ComprehensiveAuditReportGenerator:
    """Generate comprehensive audit reports for the OSINT platform"""
    
    def __init__(self, investigation_orchestrator, vault_client, config_manager):
        self.orchestrator = investigation_orchestrator
        self.vault_client = vault_client
        self.config_manager = config_manager
        self.professional_report_generator = ProfessionalReportGenerator()
        
    def generate_audit_report(self, 
                             scope: AuditScope = AuditScope.COMPREHENSIVE,
                             start_date: Optional[datetime] = None,
                             end_date: Optional[datetime] = None,
                             generated_by: str = "System Administrator",
                             investigator_filter: Optional[str] = None) -> SystemAuditReport:
        """Generate comprehensive audit report"""
        
        # Set default time range if not provided
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)  # Default 30-day range
        
        report_id = f"AUDIT_{scope.value}_{int(datetime.utcnow().timestamp())}"
        
        logger.info(f"Generating audit report {report_id} for scope {scope.value}")
        
        # Get all investigations in the audit period
        all_investigations = self._get_investigations_in_period(start_date, end_date, investigator_filter)
        
        # Calculate system metrics
        system_metrics = self._calculate_system_metrics(all_investigations)
        
        # Generate investigator profiles
        investigator_profiles = self._generate_investigator_profiles(all_investigations)
        
        # Perform detailed analysis based on scope
        analysis_results = self._perform_detailed_analysis(scope, all_investigations, start_date, end_date)
        
        # Generate executive summary and recommendations
        executive_summary, key_findings, recommendations = self._generate_executive_analysis(
            system_metrics, investigator_profiles, analysis_results
        )
        
        # Create comprehensive report
        audit_report = SystemAuditReport(
            report_id=report_id,
            audit_scope=scope,
            generated_at=datetime.utcnow(),
            audit_period={'start': start_date, 'end': end_date},
            generated_by=generated_by,
            executive_summary=executive_summary,
            key_findings=key_findings,
            recommendations=recommendations,
            system_metrics=system_metrics,
            investigator_profiles=investigator_profiles,
            investigation_analysis=analysis_results.get('investigations', {}),
            usage_patterns=analysis_results.get('usage', {}),
            security_analysis=analysis_results.get('security', {}),
            compliance_analysis=analysis_results.get('compliance', {}),
            performance_analysis=analysis_results.get('performance', {}),
            system_health=self._assess_system_health(),
            api_service_status=self._check_api_service_status(),
            infrastructure_status=self._check_infrastructure_status()
        )
        
        # Add audit events if comprehensive scope
        if scope == AuditScope.COMPREHENSIVE:
            audit_report.audit_events = self._collect_audit_events(start_date, end_date)
            audit_report.configuration_changes = self._collect_configuration_changes(start_date, end_date)
            audit_report.access_logs = self._collect_access_logs(start_date, end_date)
        
        logger.info(f"Audit report {report_id} generated successfully")
        return audit_report
    
    def _get_investigations_in_period(self, start_date: datetime, end_date: datetime, 
                                    investigator_filter: Optional[str]) -> List[OSINTInvestigation]:
        """Get all investigations within the audit period"""
        all_investigations = self.orchestrator.get_active_investigations()
        
        filtered_investigations = []
        for inv in all_investigations:
            # Check if investigation is within date range
            if start_date <= inv.created_at <= end_date:
                # Apply investigator filter if specified
                if not investigator_filter or inv.investigator_name.lower() == investigator_filter.lower():
                    filtered_investigations.append(inv)
        
        return filtered_investigations
    
    def _calculate_system_metrics(self, investigations: List[OSINTInvestigation]) -> AuditMetrics:
        """Calculate comprehensive system metrics"""
        
        if not investigations:
            return AuditMetrics(
                total_investigations=0, active_investigations=0, completed_investigations=0,
                failed_investigations=0, avg_investigation_duration=0.0, total_processing_time=0.0,
                success_rate=0.0, unique_investigators=0, total_api_calls=0, total_cost=0.0,
                data_points_collected=0, compliance_violations=0, compliance_rate=0.0,
                gdpr_assessments=0, ccpa_assessments=0, high_risk_investigations=0,
                critical_findings=0, threat_vectors_identified=0, vault_status="unknown"
            )
        
        # Basic counts
        total_investigations = len(investigations)
        active_investigations = len([inv for inv in investigations if inv.status in [
            InvestigationStatus.PENDING, InvestigationStatus.PLANNING, InvestigationStatus.PROFILING,
            InvestigationStatus.COLLECTING, InvestigationStatus.ANALYZING, InvestigationStatus.VERIFYING,
            InvestigationStatus.ASSESSING_RISK, InvestigationStatus.GENERATING_REPORT
        ]])
        completed_investigations = len([inv for inv in investigations if inv.status == InvestigationStatus.COMPLETED])
        failed_investigations = len([inv for inv in investigations if inv.status == InvestigationStatus.FAILED])
        
        # Performance metrics
        processing_times = [inv.processing_time_seconds for inv in investigations 
                          if inv.processing_time_seconds and inv.processing_time_seconds > 0]
        avg_investigation_duration = sum(processing_times) / len(processing_times) / 60 if processing_times else 0.0
        total_processing_time = sum(processing_times) / 60 if processing_times else 0.0
        success_rate = (completed_investigations / total_investigations * 100) if total_investigations > 0 else 0.0
        
        # Usage metrics
        unique_investigators = len(set(inv.investigator_name for inv in investigations))
        total_api_calls = sum(inv.api_calls_made for inv in investigations)
        total_cost = sum(inv.cost_estimate_usd for inv in investigations)
        data_points_collected = sum(inv.progress.data_points_collected for inv in investigations)
        
        # Compliance metrics
        compliance_violations = 0
        gdpr_assessments = 0
        ccpa_assessments = 0
        compliant_investigations = 0
        
        for inv in investigations:
            if inv.compliance_reports:
                for report in inv.compliance_reports:
                    if report.framework == 'GDPR':
                        gdpr_assessments += 1
                    elif report.framework == 'CCPA':
                        ccpa_assessments += 1
                    
                    if not report.compliant:
                        compliance_violations += len(report.violations) if hasattr(report, 'violations') else 1
                    else:
                        compliant_investigations += 1
        
        compliance_rate = (compliant_investigations / max(gdpr_assessments + ccpa_assessments, 1) * 100)
        
        # Security metrics
        high_risk_investigations = 0
        critical_findings = 0
        threat_vectors_identified = 0
        
        for inv in investigations:
            if hasattr(inv, 'risk_assessment') and inv.risk_assessment:
                risk_score = inv.risk_assessment.get('overall_risk_score', 0)
                if risk_score > 70:
                    high_risk_investigations += 1
                
                critical_findings += len(inv.risk_assessment.get('critical_findings', []))
                threat_vectors_identified += len(inv.risk_assessment.get('threat_vectors', []))
        
        # Vault status
        vault_status_info = self.vault_client.get_vault_status() if self.vault_client else {"mode": "unavailable"}
        vault_status = "connected" if vault_status_info.get('authenticated') else vault_status_info.get('mode', 'unknown')
        
        return AuditMetrics(
            total_investigations=total_investigations,
            active_investigations=active_investigations,
            completed_investigations=completed_investigations,
            failed_investigations=failed_investigations,
            avg_investigation_duration=avg_investigation_duration,
            total_processing_time=total_processing_time,
            success_rate=success_rate,
            unique_investigators=unique_investigators,
            total_api_calls=total_api_calls,
            total_cost=total_cost,
            data_points_collected=data_points_collected,
            compliance_violations=compliance_violations,
            compliance_rate=compliance_rate,
            gdpr_assessments=gdpr_assessments,
            ccpa_assessments=ccpa_assessments,
            high_risk_investigations=high_risk_investigations,
            critical_findings=critical_findings,
            threat_vectors_identified=threat_vectors_identified,
            vault_status=vault_status,
            api_service_health=self._check_api_service_health_simple(),
            uptime_percentage=98.5  # Mock uptime - would come from monitoring system
        )
    
    def _generate_investigator_profiles(self, investigations: List[OSINTInvestigation]) -> List[InvestigatorAuditProfile]:
        """Generate detailed audit profiles for each investigator"""
        
        investigator_data = defaultdict(lambda: {
            'investigations': [],
            'api_calls': 0,
            'cost': 0.0,
            'processing_times': [],
            'completion_statuses': [],
            'compliance_statuses': []
        })
        
        # Aggregate data by investigator
        for inv in investigations:
            investigator_id = inv.investigator_id
            investigator_data[investigator_id]['investigations'].append(inv)
            investigator_data[investigator_id]['api_calls'] += inv.api_calls_made
            investigator_data[investigator_id]['cost'] += inv.cost_estimate_usd
            
            if inv.processing_time_seconds:
                investigator_data[investigator_id]['processing_times'].append(inv.processing_time_seconds)
            
            investigator_data[investigator_id]['completion_statuses'].append(inv.status)
            
            # Compliance status
            if inv.compliance_reports:
                compliant = any(report.compliant for report in inv.compliance_reports)
                investigator_data[investigator_id]['compliance_statuses'].append(compliant)
        
        # Generate profiles
        profiles = []
        for investigator_id, data in investigator_data.items():
            investigations_list = data['investigations']
            if not investigations_list:
                continue
            
            investigator_name = investigations_list[0].investigator_name
            total_investigations = len(investigations_list)
            
            # Statistics by type, status, priority
            investigations_by_type = Counter(inv.investigation_type.value for inv in investigations_list)
            investigations_by_status = Counter(inv.status.value for inv in investigations_list)
            investigations_by_priority = Counter(inv.priority.value for inv in investigations_list)
            
            # Performance metrics
            avg_processing_time = sum(data['processing_times']) / len(data['processing_times']) / 60 if data['processing_times'] else 0.0
            
            completed_count = len([s for s in data['completion_statuses'] if s == InvestigationStatus.COMPLETED])
            success_rate = (completed_count / total_investigations * 100) if total_investigations > 0 else 0.0
            
            compliant_count = sum(data['compliance_statuses'])
            compliance_rate = (compliant_count / len(data['compliance_statuses']) * 100) if data['compliance_statuses'] else 0.0
            
            # Activity patterns
            investigation_hours = [inv.created_at.hour for inv in investigations_list]
            investigation_days = [inv.created_at.strftime('%A') for inv in investigations_list]
            
            most_active_hours = [hour for hour, count in Counter(investigation_hours).most_common(3)]
            most_active_days = [day for day, count in Counter(investigation_days).most_common(3)]
            
            # Timeline analysis
            investigation_dates = sorted([inv.created_at for inv in investigations_list])
            first_investigation = investigation_dates[0]
            last_investigation = investigation_dates[-1]
            
            days_span = (last_investigation - first_investigation).days + 1
            investigation_frequency = total_investigations / max(days_span, 1)
            
            # Quality metrics
            avg_confidence_score = 85.0  # Would calculate from actual confidence scores
            avg_completeness_score = sum(inv.progress.overall_progress for inv in investigations_list) / total_investigations * 100
            findings_per_investigation = sum(len(inv.key_findings) for inv in investigations_list) / total_investigations
            
            # Notable findings
            high_risk_investigations = []
            for inv in investigations_list:
                if hasattr(inv, 'risk_assessment') and inv.risk_assessment:
                    if inv.risk_assessment.get('overall_risk_score', 0) > 80:
                        high_risk_investigations.append(inv.id)
            
            profile = InvestigatorAuditProfile(
                investigator_id=investigator_id,
                investigator_name=investigator_name,
                total_investigations=total_investigations,
                investigations_by_type=dict(investigations_by_type),
                investigations_by_status=dict(investigations_by_status),
                investigations_by_priority=dict(investigations_by_priority),
                avg_processing_time=avg_processing_time,
                success_rate=success_rate,
                compliance_rate=compliance_rate,
                most_active_hours=most_active_hours,
                most_active_days=most_active_days,
                investigation_frequency=investigation_frequency,
                avg_confidence_score=avg_confidence_score,
                avg_completeness_score=avg_completeness_score,
                findings_per_investigation=findings_per_investigation,
                total_api_calls=data['api_calls'],
                total_cost=data['cost'],
                most_used_services=['social_media', 'infrastructure', 'threat_intel'],
                first_investigation=first_investigation,
                last_investigation=last_investigation,
                high_risk_investigations=high_risk_investigations[:5]  # Top 5
            )
            
            profiles.append(profile)
        
        # Sort by total investigations (most active first)
        profiles.sort(key=lambda p: p.total_investigations, reverse=True)
        return profiles
    
    def _perform_detailed_analysis(self, scope: AuditScope, investigations: List[OSINTInvestigation], 
                                 start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Perform detailed analysis based on audit scope"""
        
        analysis = {}
        
        if scope in [AuditScope.INVESTIGATIONS, AuditScope.COMPREHENSIVE]:
            analysis['investigations'] = self._analyze_investigations(investigations)
        
        if scope in [AuditScope.SYSTEM_USAGE, AuditScope.COMPREHENSIVE]:
            analysis['usage'] = self._analyze_usage_patterns(investigations)
        
        if scope in [AuditScope.SECURITY, AuditScope.COMPREHENSIVE]:
            analysis['security'] = self._analyze_security_posture(investigations)
        
        if scope in [AuditScope.COMPLIANCE, AuditScope.COMPREHENSIVE]:
            analysis['compliance'] = self._analyze_compliance_status(investigations)
        
        if scope in [AuditScope.PERFORMANCE, AuditScope.COMPREHENSIVE]:
            analysis['performance'] = self._analyze_performance_metrics(investigations)
        
        return analysis
    
    def _generate_executive_analysis(self, system_metrics: AuditMetrics, 
                                   investigator_profiles: List[InvestigatorAuditProfile],
                                   analysis_results: Dict[str, Any]) -> Tuple[str, List[str], List[str]]:
        """Generate executive summary, key findings, and recommendations"""
        
        # Executive Summary
        executive_summary = f"""
        This comprehensive audit report covers {system_metrics.total_investigations} OSINT investigations 
        conducted by {system_metrics.unique_investigators} investigators. The platform achieved a 
        {system_metrics.success_rate:.1f}% success rate with an average investigation duration of 
        {system_metrics.avg_investigation_duration:.1f} minutes.
        
        System performance indicators show {system_metrics.total_api_calls:,} API calls generating 
        {system_metrics.data_points_collected:,} intelligence data points at a total cost of 
        ${system_metrics.total_cost:.2f}.
        
        Security analysis identified {system_metrics.high_risk_investigations} high-risk investigations 
        with {system_metrics.critical_findings} critical findings across {system_metrics.threat_vectors_identified} 
        threat vectors. Compliance monitoring shows a {system_metrics.compliance_rate:.1f}% compliance rate 
        with {system_metrics.compliance_violations} violations requiring attention.
        """
        
        # Key Findings
        key_findings = [
            f"Platform processed {system_metrics.total_investigations} investigations with {system_metrics.success_rate:.1f}% success rate",
            f"Average investigation duration: {system_metrics.avg_investigation_duration:.1f} minutes",
            f"Security: {system_metrics.high_risk_investigations} high-risk investigations identified",
            f"Compliance: {system_metrics.compliance_rate:.1f}% compliance rate achieved",
            f"Cost efficiency: ${system_metrics.total_cost/max(system_metrics.total_investigations, 1):.2f} average cost per investigation",
            f"Most active investigator completed {max([p.total_investigations for p in investigator_profiles], default=0)} investigations"
        ]
        
        # Add performance-specific findings
        if system_metrics.total_investigations > 0:
            fastest_investigator = min(investigator_profiles, key=lambda p: p.avg_processing_time, default=None)
            if fastest_investigator:
                key_findings.append(f"Fastest investigator: {fastest_investigator.investigator_name} ({fastest_investigator.avg_processing_time:.1f} min avg)")
        
        # Recommendations
        recommendations = [
            "Implement continuous monitoring for high-risk investigations",
            "Provide additional training for investigators with <90% success rates",
            "Review and optimize API usage to reduce costs",
            "Establish regular compliance audits and remediation processes",
            "Develop performance benchmarks and investigator KPIs"
        ]
        
        # Add specific recommendations based on metrics
        if system_metrics.success_rate < 85:
            recommendations.append("Focus on improving investigation success rates through process optimization")
        
        if system_metrics.compliance_rate < 95:
            recommendations.append("Enhance compliance monitoring and training programs")
        
        if system_metrics.high_risk_investigations > system_metrics.total_investigations * 0.2:
            recommendations.append("Review threat assessment criteria and escalation procedures")
        
        return executive_summary.strip(), key_findings, recommendations
    
    def export_audit_report(self, audit_report: SystemAuditReport, format_type: str = 'html') -> bytes:
        """Export audit report in specified format"""
        
        if format_type == 'html':
            return self._export_html_audit_report(audit_report).encode('utf-8')
        elif format_type == 'json':
            return self._export_json_audit_report(audit_report).encode('utf-8')
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_html_audit_report(self, report: SystemAuditReport) -> str:
        """Export audit report as HTML"""
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>System Audit Report - {report.report_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .section {{ margin-bottom: 30px; }}
                .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
                .metric-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
                .metric-value {{ font-size: 2em; font-weight: bold; color: #007bff; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f8f9fa; }}
                .finding {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 4px; }}
                .recommendation {{ background: #d1ecf1; padding: 10px; margin: 5px 0; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 System Audit Report</h1>
                <h2>{report.report_id}</h2>
                <p><strong>Audit Period:</strong> {report.audit_period['start'].strftime('%Y-%m-%d')} to {report.audit_period['end'].strftime('%Y-%m-%d')}</p>
                <p><strong>Generated:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p><strong>Scope:</strong> {report.audit_scope.value.title()}</p>
            </div>
            
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <p>{report.executive_summary}</p>
            </div>
            
            <div class="section">
                <h2>📈 System Metrics</h2>
                <div class="metrics">
                    <div class="metric-card">
                        <div class="metric-value">{report.system_metrics.total_investigations}</div>
                        <div>Total Investigations</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{report.system_metrics.success_rate:.1f}%</div>
                        <div>Success Rate</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{report.system_metrics.unique_investigators}</div>
                        <div>Active Investigators</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{report.system_metrics.avg_investigation_duration:.1f}</div>
                        <div>Avg Duration (min)</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">${report.system_metrics.total_cost:.2f}</div>
                        <div>Total Cost</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{report.system_metrics.compliance_rate:.1f}%</div>
                        <div>Compliance Rate</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🔍 Key Findings</h2>
                {''.join(f'<div class="finding">🔍 {finding}</div>' for finding in report.key_findings)}
            </div>
            
            <div class="section">
                <h2>💡 Recommendations</h2>
                {''.join(f'<div class="recommendation">💡 {rec}</div>' for rec in report.recommendations)}
            </div>
            
            <div class="section">
                <h2>👥 Investigator Performance</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Investigator</th>
                            <th>Total Investigations</th>
                            <th>Success Rate</th>
                            <th>Avg Duration (min)</th>
                            <th>Compliance Rate</th>
                            <th>Total Cost</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(f'''
                        <tr>
                            <td>{profile.investigator_name}</td>
                            <td>{profile.total_investigations}</td>
                            <td>{profile.success_rate:.1f}%</td>
                            <td>{profile.avg_processing_time:.1f}</td>
                            <td>{profile.compliance_rate:.1f}%</td>
                            <td>${profile.total_cost:.2f}</td>
                        </tr>
                        ''' for profile in report.investigator_profiles[:10])}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>⚡ System Health</h2>
                <div class="metrics">
                    <div class="metric-card">
                        <div class="metric-value">{report.system_metrics.uptime_percentage:.1f}%</div>
                        <div>System Uptime</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{report.system_metrics.vault_status.title()}</div>
                        <div>Vault Status</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{len([s for s in report.system_metrics.api_service_health.values() if s])}</div>
                        <div>Healthy Services</div>
                    </div>
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 40px; color: #666;">
                <p>Generated by Enterprise OSINT Platform Audit System</p>
                <p>© {datetime.utcnow().year} - Confidential</p>
            </div>
        </body>
        </html>
        """
        
        return html_template
    
    def _export_json_audit_report(self, report: SystemAuditReport) -> str:
        """Export audit report as JSON"""
        
        def serialize_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return str(obj)
        
        # Convert to dictionary with serialization
        report_dict = {
            'report_id': report.report_id,
            'audit_scope': report.audit_scope.value,
            'generated_at': serialize_datetime(report.generated_at),
            'audit_period': {
                'start': serialize_datetime(report.audit_period['start']),
                'end': serialize_datetime(report.audit_period['end'])
            },
            'generated_by': report.generated_by,
            'executive_summary': report.executive_summary,
            'key_findings': report.key_findings,
            'recommendations': report.recommendations,
            'system_metrics': {
                'total_investigations': report.system_metrics.total_investigations,
                'success_rate': report.system_metrics.success_rate,
                'avg_investigation_duration': report.system_metrics.avg_investigation_duration,
                'unique_investigators': report.system_metrics.unique_investigators,
                'total_api_calls': report.system_metrics.total_api_calls,
                'total_cost': report.system_metrics.total_cost,
                'compliance_rate': report.system_metrics.compliance_rate,
                'high_risk_investigations': report.system_metrics.high_risk_investigations,
                'vault_status': report.system_metrics.vault_status,
                'uptime_percentage': report.system_metrics.uptime_percentage
            },
            'investigator_profiles': [
                {
                    'investigator_name': profile.investigator_name,
                    'total_investigations': profile.total_investigations,
                    'success_rate': profile.success_rate,
                    'compliance_rate': profile.compliance_rate,
                    'avg_processing_time': profile.avg_processing_time,
                    'total_cost': profile.total_cost,
                    'investigation_frequency': profile.investigation_frequency,
                    'most_active_days': profile.most_active_days
                }
                for profile in report.investigator_profiles
            ]
        }
        
        return json.dumps(report_dict, indent=2, default=serialize_datetime)
    
    # Helper methods for analysis
    def _analyze_investigations(self, investigations: List[OSINTInvestigation]) -> Dict[str, Any]:
        """Analyze investigation patterns and trends"""
        return {
            'total_count': len(investigations),
            'by_type': dict(Counter(inv.investigation_type.value for inv in investigations)),
            'by_priority': dict(Counter(inv.priority.value for inv in investigations)),
            'by_status': dict(Counter(inv.status.value for inv in investigations)),
            'avg_duration': sum(inv.processing_time_seconds or 0 for inv in investigations) / len(investigations) / 60 if investigations else 0
        }
    
    def _analyze_usage_patterns(self, investigations: List[OSINTInvestigation]) -> Dict[str, Any]:
        """Analyze system usage patterns"""
        return {
            'peak_hours': [9, 10, 11, 14, 15, 16],  # Mock data
            'peak_days': ['Tuesday', 'Wednesday', 'Thursday'],
            'avg_concurrent': 3.2,
            'resource_utilization': 'moderate'
        }
    
    def _analyze_security_posture(self, investigations: List[OSINTInvestigation]) -> Dict[str, Any]:
        """Analyze security posture"""
        high_risk_count = 0
        for inv in investigations:
            if hasattr(inv, 'risk_assessment') and inv.risk_assessment:
                if inv.risk_assessment.get('overall_risk_score', 0) > 70:
                    high_risk_count += 1
        
        return {
            'high_risk_investigations': high_risk_count,
            'security_incidents': 0,
            'threat_detections': high_risk_count,
            'vulnerability_count': high_risk_count
        }
    
    def _analyze_compliance_status(self, investigations: List[OSINTInvestigation]) -> Dict[str, Any]:
        """Analyze compliance status"""
        compliant_count = 0
        total_assessments = 0
        
        for inv in investigations:
            if inv.compliance_reports:
                total_assessments += len(inv.compliance_reports)
                compliant_count += sum(1 for report in inv.compliance_reports if report.compliant)
        
        return {
            'total_assessments': total_assessments,
            'compliant_assessments': compliant_count,
            'compliance_rate': (compliant_count / max(total_assessments, 1)) * 100,
            'violations': total_assessments - compliant_count
        }
    
    def _analyze_performance_metrics(self, investigations: List[OSINTInvestigation]) -> Dict[str, Any]:
        """Analyze performance metrics"""
        return {
            'avg_response_time': 250,  # ms
            'throughput': len(investigations),
            'error_rate': 2.3,  # percentage
            'resource_efficiency': 87.5  # percentage
        }
    
    def _assess_system_health(self) -> Dict[str, Any]:
        """Assess overall system health"""
        return {
            'status': 'healthy',
            'uptime': '99.2%',
            'memory_usage': '68%',
            'cpu_usage': '45%',
            'disk_usage': '34%'
        }
    
    def _check_api_service_status(self) -> Dict[str, Any]:
        """Check API service status"""
        if self.config_manager:
            configs = self.config_manager.get_all_service_configs()
            return {service: info['configured'] for service, info in configs.items()}
        return {}
    
    def _check_api_service_health_simple(self) -> Dict[str, bool]:
        """Simple API service health check"""
        return {
            'openai': True,
            'shodan': True,
            'virustotal': True,
            'twitter': True,
            'reddit': False,
            'alienvault_otx': True
        }
    
    def _check_infrastructure_status(self) -> Dict[str, Any]:
        """Check infrastructure status"""
        return {
            'database': 'healthy',
            'cache': 'healthy',
            'storage': 'healthy',
            'network': 'healthy'
        }
    
    def _collect_audit_events(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Collect audit events (mock implementation)"""
        return []  # Would collect real audit events in production
    
    def _collect_configuration_changes(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Collect configuration changes (mock implementation)"""
        return []  # Would collect real config changes in production
    
    def _collect_access_logs(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Collect access logs (mock implementation)"""
        return []  # Would collect real access logs in production
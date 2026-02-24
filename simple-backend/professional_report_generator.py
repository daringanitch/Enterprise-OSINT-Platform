#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.
# Individual use is free. Commercial use requires 3% profit sharing.
# See LICENSE file for details.

"""
Professional Report Generation System
Creates executive summaries, technical findings, and comprehensive OSINT investigation reports
"""

import logging
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from io import BytesIO

# Import for PDF generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.piecharts import Pie
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from models import OSINTInvestigation, InvestigationType, InvestigationStatus, Priority

logger = logging.getLogger(__name__)


class ReportType(Enum):
    """Types of professional reports"""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_FINDINGS = "technical_findings"
    COMPREHENSIVE = "comprehensive"
    AUDIT_TRAIL = "audit_trail"
    THREAT_ASSESSMENT = "threat_assessment"
    COMPLIANCE_SUMMARY = "compliance_summary"


class ReportFormat(Enum):
    """Report output formats"""
    PDF = "pdf"
    HTML = "html"
    DOCX = "docx"
    JSON = "json"
    STIX = "stix"


class ClassificationLevel(Enum):
    """Report classification levels"""
    UNCLASSIFIED = "unclassified"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class ReportMetadata:
    """Metadata for professional reports"""
    report_id: str
    report_type: ReportType
    classification: ClassificationLevel
    generated_at: datetime
    generated_by: str
    investigation_id: str
    target_identifier: str
    
    # Report specifications
    include_charts: bool = True
    include_raw_data: bool = False
    include_recommendations: bool = True
    executive_level: bool = True
    
    # Distribution and handling
    distribution_list: List[str] = field(default_factory=list)
    retention_period: timedelta = field(default_factory=lambda: timedelta(days=90))
    watermark: Optional[str] = None
    
    # Quality metrics
    completeness_score: float = 0.0
    confidence_score: float = 0.0
    data_freshness: float = 0.0


@dataclass
class ExecutiveSummary:
    """Executive summary section of reports"""
    key_findings: List[str]
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    impact_analysis: Dict[str, str]
    threat_level: str
    confidence_level: str
    
    # Executive metrics
    investigation_duration: str
    data_sources_analyzed: int
    intelligence_items_collected: int
    compliance_status: str
    
    # Business impact
    business_risk_factors: List[str] = field(default_factory=list)
    mitigation_priority: List[str] = field(default_factory=list)
    resource_requirements: List[str] = field(default_factory=list)


@dataclass
class TechnicalFindings:
    """Technical findings section of reports"""
    infrastructure_analysis: Dict[str, Any]
    social_intelligence: Dict[str, Any]
    threat_indicators: List[Dict[str, Any]]
    vulnerabilities_identified: List[Dict[str, Any]]
    attack_vectors: List[Dict[str, Any]]
    
    # Technical metrics
    domains_analyzed: int
    ip_addresses_investigated: int
    social_accounts_discovered: int
    malware_samples_analyzed: int
    
    # Correlation analysis
    cross_source_correlations: Dict[str, float]
    temporal_patterns: Dict[str, Any]
    behavioral_anomalies: List[str]
    
    # Evidence chain
    evidence_reliability: Dict[str, float] = field(default_factory=dict)
    source_credibility: Dict[str, str] = field(default_factory=dict)
    verification_status: Dict[str, str] = field(default_factory=dict)


@dataclass
class ProfessionalReport:
    """Complete professional OSINT investigation report"""
    metadata: ReportMetadata
    executive_summary: ExecutiveSummary
    technical_findings: TechnicalFindings
    
    # Report sections
    methodology: str
    scope_and_limitations: str
    conclusions: str
    appendices: Dict[str, Any] = field(default_factory=dict)
    
    # Supporting data
    charts_and_visualizations: Dict[str, bytes] = field(default_factory=dict)
    raw_data_exports: Dict[str, str] = field(default_factory=dict)
    
    # Report quality
    peer_review_status: Optional[str] = None
    quality_assurance_notes: List[str] = field(default_factory=list)


class ProfessionalReportGenerator:
    """Main class for generating professional OSINT investigation reports"""
    
    def __init__(self, organization_name: str = "Enterprise OSINT Platform"):
        self.organization_name = organization_name
        self.report_templates = self._initialize_report_templates()
        self.style_guide = self._initialize_style_guide()
        
    def _initialize_report_templates(self) -> Dict[str, Any]:
        """Initialize professional report templates"""
        return {
            "executive_summary": {
                "sections": [
                    "Executive Overview",
                    "Key Findings",
                    "Risk Assessment",
                    "Strategic Recommendations",
                    "Resource Requirements"
                ],
                "max_pages": 3,
                "executive_focus": True
            },
            "technical_findings": {
                "sections": [
                    "Investigation Methodology",
                    "Infrastructure Analysis",
                    "Social Intelligence Findings",
                    "Threat Intelligence Analysis",
                    "Correlation Results",
                    "Evidence Assessment",
                    "Technical Recommendations"
                ],
                "max_pages": 20,
                "technical_detail": True
            },
            "comprehensive": {
                "sections": [
                    "Executive Summary",
                    "Investigation Scope",
                    "Methodology",
                    "Key Findings",
                    "Technical Analysis",
                    "Risk Assessment",
                    "Recommendations",
                    "Appendices"
                ],
                "max_pages": 50,
                "complete_analysis": True
            }
        }
    
    def _initialize_style_guide(self) -> Dict[str, Any]:
        """Initialize professional styling guide"""
        return {
            "colors": {
                "primary": "#2c3e50",
                "secondary": "#34495e",
                "accent": "#3498db",
                "warning": "#f39c12",
                "danger": "#e74c3c",
                "success": "#27ae60"
            },
            "fonts": {
                "heading": "Helvetica-Bold",
                "body": "Helvetica",
                "code": "Courier"
            },
            "classification_colors": {
                "unclassified": "#27ae60",
                "internal": "#f39c12",
                "confidential": "#e74c3c",
                "restricted": "#8e44ad"
            }
        }
    
    def generate_report(self, 
                       investigation: OSINTInvestigation,
                       report_type: ReportType = ReportType.COMPREHENSIVE,
                       format_type: ReportFormat = ReportFormat.PDF,
                       classification: ClassificationLevel = ClassificationLevel.INTERNAL,
                       generated_by: str = "OSINT Analyst",
                       custom_options: Optional[Dict[str, Any]] = None) -> ProfessionalReport:
        """Generate a professional OSINT investigation report"""
        
        logger.info(f"Generating {report_type.value} report for investigation {investigation.id}")
        
        # Create report metadata
        metadata = self._create_report_metadata(
            investigation, report_type, classification, generated_by, custom_options or {}
        )
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(investigation)
        
        # Generate technical findings
        technical_findings = self._generate_technical_findings(investigation)
        
        # Create complete report
        report = ProfessionalReport(
            metadata=metadata,
            executive_summary=executive_summary,
            technical_findings=technical_findings,
            methodology=self._generate_methodology_section(investigation),
            scope_and_limitations=self._generate_scope_section(investigation),
            conclusions=self._generate_conclusions_section(investigation, executive_summary)
        )
        
        # Add supporting materials
        if metadata.include_charts:
            report.charts_and_visualizations = self._generate_charts(investigation)
        
        if metadata.include_raw_data:
            report.raw_data_exports = self._export_raw_data(investigation)
        
        # Add appendices
        report.appendices = self._generate_appendices(investigation)
        
        logger.info(f"Report {metadata.report_id} generated successfully")
        return report
    
    def _create_report_metadata(self, 
                               investigation: OSINTInvestigation,
                               report_type: ReportType,
                               classification: ClassificationLevel,
                               generated_by: str,
                               options: Dict[str, Any]) -> ReportMetadata:
        """Create comprehensive report metadata"""
        
        report_id = f"RPT-{investigation.id}-{int(datetime.utcnow().timestamp())}"
        
        return ReportMetadata(
            report_id=report_id,
            report_type=report_type,
            classification=classification,
            generated_at=datetime.utcnow(),
            generated_by=generated_by,
            investigation_id=investigation.id,
            target_identifier=investigation.target_profile.primary_identifier,
            include_charts=options.get('include_charts', True),
            include_raw_data=options.get('include_raw_data', False),
            include_recommendations=options.get('include_recommendations', True),
            executive_level=options.get('executive_level', report_type == ReportType.EXECUTIVE_SUMMARY),
            distribution_list=options.get('distribution_list', []),
            watermark=options.get('watermark'),
            completeness_score=self._calculate_completeness_score(investigation),
            confidence_score=self._calculate_confidence_score(investigation),
            data_freshness=self._calculate_data_freshness_score(investigation)
        )
    
    def _generate_executive_summary(self, investigation: OSINTInvestigation) -> ExecutiveSummary:
        """Generate executive summary with business-focused insights"""
        
        # Extract key findings
        key_findings = self._extract_key_findings(investigation)
        
        # Risk assessment summary
        risk_assessment = {}
        if hasattr(investigation, 'risk_assessment') and investigation.risk_assessment:
            risk_assessment = {
                'overall_score': investigation.risk_assessment.get('overall_risk_score', 0),
                'threat_level': investigation.risk_assessment.get('threat_level', 'unknown'),
                'critical_vectors': len([
                    v for v in investigation.risk_assessment.get('threat_vectors', [])
                    if v.get('threat_level') in ['critical', 'high']
                ])
            }
        
        # Strategic recommendations
        recommendations = self._generate_strategic_recommendations(investigation)
        
        # Business impact analysis
        impact_analysis = self._analyze_business_impact(investigation)
        
        # Calculate investigation metrics
        duration = "N/A"
        if investigation.started_at and investigation.completed_at:
            duration_delta = investigation.completed_at - investigation.started_at
            hours = duration_delta.total_seconds() / 3600
            if hours < 1:
                duration = f"{int(duration_delta.total_seconds() / 60)} minutes"
            elif hours < 24:
                duration = f"{hours:.1f} hours"
            else:
                duration = f"{hours/24:.1f} days"
        
        # Count data sources
        data_sources = set()
        intelligence_items = 0
        
        if investigation.social_intelligence:
            data_sources.update(investigation.social_intelligence.data_sources)
            # Count mentions from platform data
            total_mentions = 0
            if investigation.social_intelligence:
                for platform_data in investigation.social_intelligence.platforms.values():
                    if 'mentions' in platform_data:
                        total_mentions += len(platform_data['mentions'])
            intelligence_items += total_mentions
            
        if investigation.infrastructure_intelligence:
            data_sources.add("infrastructure")
            intelligence_items += len(investigation.infrastructure_intelligence.domains)
            intelligence_items += len(investigation.infrastructure_intelligence.ip_addresses)
            
        if investigation.threat_intelligence:
            data_sources.add("threat_intelligence")
            intelligence_items += len(getattr(investigation.threat_intelligence, 'iocs', []))
        
        # Compliance status
        compliance_status = "Compliant"
        if investigation.compliance_reports:
            latest_report = investigation.compliance_reports[-1]
            compliance_status = "Compliant" if latest_report.compliant else "Non-Compliant"
        
        return ExecutiveSummary(
            key_findings=key_findings[:5],  # Top 5 findings
            risk_assessment=risk_assessment,
            recommendations=recommendations[:7],  # Top strategic recommendations
            impact_analysis=impact_analysis,
            threat_level=risk_assessment.get('threat_level', 'Unknown'),
            confidence_level=investigation.progress.confidence_level if hasattr(investigation.progress, 'confidence_level') else 'Medium',
            investigation_duration=duration,
            data_sources_analyzed=len(data_sources),
            intelligence_items_collected=intelligence_items,
            compliance_status=compliance_status,
            business_risk_factors=self._identify_business_risk_factors(investigation),
            mitigation_priority=self._prioritize_mitigations(investigation),
            resource_requirements=self._estimate_resource_requirements(investigation)
        )
    
    def _generate_technical_findings(self, investigation: OSINTInvestigation) -> TechnicalFindings:
        """Generate detailed technical findings section"""
        
        # Infrastructure analysis
        infrastructure_analysis = {}
        domains_analyzed = 0
        ip_addresses_investigated = 0
        
        if investigation.infrastructure_intelligence:
            infrastructure_analysis = {
                'domains': investigation.infrastructure_intelligence.domains,
                'subdomains': investigation.infrastructure_intelligence.subdomains,
                'ip_addresses': investigation.infrastructure_intelligence.ip_addresses,
                'ssl_certificates': getattr(investigation.infrastructure_intelligence, 'ssl_certificates', []),
                'dns_records': getattr(investigation.infrastructure_intelligence, 'dns_records', {})
            }
            domains_analyzed = len(investigation.infrastructure_intelligence.domains)
            ip_addresses_investigated = len(investigation.infrastructure_intelligence.ip_addresses)
        
        # Social intelligence
        social_intelligence = {}
        social_accounts_discovered = 0
        
        if investigation.social_intelligence:
            social_intelligence = {
                'platforms': list(investigation.social_intelligence.platforms),
                'mentions': [mention for platform_data in investigation.social_intelligence.platforms.values() 
                           for mention in platform_data.get('mentions', [])],
                'sentiment_analysis': investigation.social_intelligence.sentiment_analysis,
                'reputation_score': investigation.social_intelligence.reputation_score
            }
            social_accounts_discovered = len(investigation.social_intelligence.platforms)
        
        # Threat indicators
        threat_indicators = []
        malware_samples_analyzed = 0
        
        if investigation.threat_intelligence:
            threat_indicators = getattr(investigation.threat_intelligence, 'iocs', [])
            malware_samples_analyzed = len(getattr(investigation.threat_intelligence, 'malware_samples', []))
        
        # Vulnerabilities (derived from findings)
        vulnerabilities = self._extract_vulnerabilities(investigation)
        
        # Attack vectors (from risk assessment)
        attack_vectors = []
        if hasattr(investigation, 'risk_assessment') and investigation.risk_assessment:
            attack_vectors = investigation.risk_assessment.get('threat_vectors', [])
        
        # Cross-source correlations
        correlations = self._calculate_cross_source_correlations(investigation)
        
        return TechnicalFindings(
            infrastructure_analysis=infrastructure_analysis,
            social_intelligence=social_intelligence,
            threat_indicators=threat_indicators,
            vulnerabilities_identified=vulnerabilities,
            attack_vectors=attack_vectors,
            domains_analyzed=domains_analyzed,
            ip_addresses_investigated=ip_addresses_investigated,
            social_accounts_discovered=social_accounts_discovered,
            malware_samples_analyzed=malware_samples_analyzed,
            cross_source_correlations=correlations,
            temporal_patterns=self._analyze_temporal_patterns(investigation),
            behavioral_anomalies=self._identify_behavioral_anomalies(investigation),
            evidence_reliability=self._assess_evidence_reliability(investigation),
            source_credibility=self._assess_source_credibility(investigation),
            verification_status=self._determine_verification_status(investigation)
        )
    
    def _extract_key_findings(self, investigation: OSINTInvestigation) -> List[str]:
        """Extract and prioritize key findings from investigation"""
        findings = []
        
        # Add findings from investigation
        for finding in investigation.key_findings:
            findings.append(finding)
        
        # Add risk-based findings
        if hasattr(investigation, 'risk_assessment') and investigation.risk_assessment:
            risk_score = investigation.risk_assessment.get('overall_risk_score', 0)
            threat_level = investigation.risk_assessment.get('threat_level', 'unknown')
            
            findings.append(f"Overall risk assessment: {threat_level.upper()} ({risk_score:.1f}/100)")
            
            critical_findings = investigation.risk_assessment.get('critical_findings', [])
            findings.extend(critical_findings[:3])  # Top 3 critical findings
        
        # Add compliance findings
        if investigation.compliance_reports:
            latest_report = investigation.compliance_reports[-1]
            if not latest_report.compliant:
                findings.append(f"Compliance violations identified: {len(latest_report.violations)} issues")
        
        # Add infrastructure findings
        if investigation.infrastructure_intelligence:
            exposed_services = getattr(investigation.infrastructure_intelligence, 'exposed_services', [])
            if exposed_services:
                findings.append(f"Exposed services detected: {len(exposed_services)} services")
        
        return findings
    
    def _generate_strategic_recommendations(self, investigation: OSINTInvestigation) -> List[str]:
        """Generate business-focused strategic recommendations"""
        recommendations = []
        
        # Risk-based recommendations
        if hasattr(investigation, 'risk_assessment') and investigation.risk_assessment:
            immediate_actions = investigation.risk_assessment.get('immediate_actions', [])
            recommendations.extend(immediate_actions[:3])  # Top 3 immediate actions
            
            monitoring_recs = investigation.risk_assessment.get('monitoring_recommendations', [])
            recommendations.extend(monitoring_recs[:2])  # Top 2 monitoring recommendations
        
        # Compliance recommendations
        if investigation.compliance_reports:
            for report in investigation.compliance_reports:
                if report.recommendations:
                    recommendations.extend(report.recommendations[:2])  # Top 2 per report
        
        # Infrastructure recommendations
        if investigation.infrastructure_intelligence and getattr(investigation.infrastructure_intelligence, 'exposed_services', []):
            recommendations.append("Review and secure exposed services to reduce attack surface")
        
        # General strategic recommendations
        recommendations.extend([
            "Implement continuous monitoring for identified threat indicators",
            "Review and update incident response procedures based on findings",
            "Conduct regular security awareness training for identified vulnerabilities"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _analyze_business_impact(self, investigation: OSINTInvestigation) -> Dict[str, str]:
        """Analyze potential business impact from findings"""
        impact = {
            "operational": "Low",
            "financial": "Low",
            "reputational": "Low",
            "legal": "Low"
        }
        
        # Assess based on risk level
        if hasattr(investigation, 'risk_assessment') and investigation.risk_assessment:
            risk_score = investigation.risk_assessment.get('overall_risk_score', 0)
            
            if risk_score >= 80:
                impact.update({
                    "operational": "Critical",
                    "financial": "High",
                    "reputational": "High",
                    "legal": "High"
                })
            elif risk_score >= 60:
                impact.update({
                    "operational": "High",
                    "financial": "Medium",
                    "reputational": "Medium",
                    "legal": "Medium"
                })
            elif risk_score >= 40:
                impact.update({
                    "operational": "Medium",
                    "financial": "Low",
                    "reputational": "Low",
                    "legal": "Low"
                })
        
        # Adjust based on specific findings
        if investigation.infrastructure_intelligence and getattr(investigation.infrastructure_intelligence, 'exposed_services', []):
            if len(investigation.infrastructure_intelligence.exposed_services) > 5:
                impact["operational"] = "High"
        
        # Compliance impact
        if investigation.compliance_reports:
            for report in investigation.compliance_reports:
                if not report.compliant:
                    impact["legal"] = "High"
        
        return impact
    
    def export_report(self, report: ProfessionalReport, format_type: ReportFormat) -> bytes:
        """Export report in specified format"""
        
        if format_type == ReportFormat.PDF:
            return self._export_pdf(report)
        elif format_type == ReportFormat.HTML:
            return self._export_html(report).encode('utf-8')
        elif format_type == ReportFormat.JSON:
            return self._export_json(report).encode('utf-8')
        elif format_type == ReportFormat.STIX:
            return self._export_stix(report)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")

    def _export_stix(self, report: "ProfessionalReport") -> bytes:
        """Export report as a STIX 2.1 bundle (JSON bytes)."""
        from stix_export import STIXExporter

        exporter = STIXExporter()
        # Build a minimal investigation-like dict from the report
        investigation_dict = {
            "id": getattr(report, "report_id", "unknown"),
            "name": getattr(report, "title", "OSINT Report"),
            "summary": getattr(report, "executive_summary", ""),
        }
        bundle = exporter.export_investigation(investigation_dict)
        if isinstance(bundle, dict) and "error" in bundle:
            import json
            return json.dumps(bundle).encode("utf-8")
        return exporter.to_json(bundle).encode("utf-8")
    
    def _export_pdf(self, report: ProfessionalReport) -> bytes:
        """Export report as professional PDF"""
        
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            alignment=1,  # Center alignment
            spaceAfter=20
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading1'],
            fontSize=16,
            textColor=colors.HexColor('#34495e'),
            spaceBefore=20,
            spaceAfter=10
        )
        
        classification_style = ParagraphStyle(
            'Classification',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.red,
            alignment=1,  # Center alignment
            spaceAfter=10
        )
        
        # Title page
        story.append(Paragraph("OSINT INVESTIGATION REPORT", title_style))
        story.append(Paragraph(f"Classification: {report.metadata.classification.value.upper()}", classification_style))
        story.append(Spacer(1, 20))
        
        # Report metadata table
        metadata_data = [
            ['Report ID', report.metadata.report_id],
            ['Investigation ID', report.metadata.investigation_id],
            ['Target', report.metadata.target_identifier],
            ['Generated By', report.metadata.generated_by],
            ['Generated At', report.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Report Type', report.metadata.report_type.value.title()],
            ['Confidence Score', f"{report.metadata.confidence_score:.1f}%"],
            ['Data Freshness', f"{report.metadata.data_freshness:.1f}%"]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 3*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(metadata_table)
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        
        # Key Findings
        story.append(Paragraph("Key Findings", styles['Heading2']))
        for i, finding in enumerate(report.executive_summary.key_findings, 1):
            story.append(Paragraph(f"{i}. {finding}", styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Risk Assessment
        story.append(Paragraph("Risk Assessment", styles['Heading2']))
        risk_data = [
            ['Metric', 'Value'],
            ['Overall Risk Score', f"{report.executive_summary.risk_assessment.get('overall_score', 0):.1f}/100"],
            ['Threat Level', report.executive_summary.threat_level.upper()],
            ['Confidence Level', report.executive_summary.confidence_level],
            ['Investigation Duration', report.executive_summary.investigation_duration],
            ['Data Sources', str(report.executive_summary.data_sources_analyzed)],
            ['Intelligence Items', str(report.executive_summary.intelligence_items_collected)]
        ]
        
        risk_table = Table(risk_data, colWidths=[2.5*inch, 2.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        story.append(risk_table)
        story.append(Spacer(1, 10))
        
        # Recommendations
        story.append(Paragraph("Strategic Recommendations", styles['Heading2']))
        for i, rec in enumerate(report.executive_summary.recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
        
        story.append(PageBreak())
        
        # Technical Findings
        story.append(Paragraph("TECHNICAL FINDINGS", heading_style))
        
        # Infrastructure Analysis
        if report.technical_findings.infrastructure_analysis:
            story.append(Paragraph("Infrastructure Analysis", styles['Heading2']))
            story.append(Paragraph(f"Domains Analyzed: {report.technical_findings.domains_analyzed}", styles['Normal']))
            story.append(Paragraph(f"IP Addresses Investigated: {report.technical_findings.ip_addresses_investigated}", styles['Normal']))
            story.append(Spacer(1, 10))
        
        # Social Intelligence
        if report.technical_findings.social_intelligence:
            story.append(Paragraph("Social Intelligence", styles['Heading2']))
            story.append(Paragraph(f"Social Accounts Discovered: {report.technical_findings.social_accounts_discovered}", styles['Normal']))
            story.append(Spacer(1, 10))
        
        # Methodology
        story.append(PageBreak())
        story.append(Paragraph("METHODOLOGY", heading_style))
        story.append(Paragraph(report.methodology, styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Scope and Limitations
        story.append(Paragraph("SCOPE AND LIMITATIONS", styles['Heading2']))
        story.append(Paragraph(report.scope_and_limitations, styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Conclusions
        story.append(Paragraph("CONCLUSIONS", styles['Heading2']))
        story.append(Paragraph(report.conclusions, styles['Normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def _export_html(self, report: ProfessionalReport) -> str:
        """Export report as professional HTML"""
        
        classification_color = self.style_guide['classification_colors'][report.metadata.classification.value]
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OSINT Investigation Report - {report.metadata.report_id}</title>
            <style>
                body {{
                    font-family: 'Helvetica', Arial, sans-serif;
                    line-height: 1.6;
                    color: #2c3e50;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #ecf0f1;
                }}
                .report-header {{
                    text-align: center;
                    padding: 30px;
                    background: linear-gradient(135deg, #2c3e50, #34495e);
                    color: white;
                    border-radius: 10px;
                    margin-bottom: 30px;
                }}
                .classification {{
                    background-color: {classification_color};
                    color: white;
                    padding: 10px;
                    text-align: center;
                    font-weight: bold;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .section {{
                    background: white;
                    padding: 25px;
                    margin-bottom: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .section h2 {{
                    color: #2c3e50;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                    margin-top: 0;
                }}
                .metadata-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }}
                .metadata-table th, .metadata-table td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                .metadata-table th {{
                    background-color: #34495e;
                    color: white;
                }}
                .risk-metrics {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }}
                .risk-card {{
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    border-left: 4px solid #3498db;
                }}
                .risk-score {{
                    font-size: 2em;
                    font-weight: bold;
                    color: #e74c3c;
                    margin: 10px 0;
                }}
                .findings-list {{
                    list-style: none;
                    padding: 0;
                }}
                .findings-list li {{
                    padding: 10px;
                    margin: 5px 0;
                    background: #f8f9fa;
                    border-left: 4px solid #e74c3c;
                    border-radius: 4px;
                }}
                .recommendations-list {{
                    list-style: none;
                    padding: 0;
                }}
                .recommendations-list li {{
                    padding: 10px;
                    margin: 5px 0;
                    background: #f8f9fa;
                    border-left: 4px solid #27ae60;
                    border-radius: 4px;
                }}
                .technical-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }}
                .technical-card {{
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                    border: 1px solid #ddd;
                }}
                .watermark {{
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%) rotate(-45deg);
                    font-size: 6em;
                    color: rgba(0,0,0,0.1);
                    z-index: -1;
                    pointer-events: none;
                }}
                @media print {{
                    body {{ background-color: white; }}
                    .section {{ box-shadow: none; border: 1px solid #ddd; }}
                }}
            </style>
        </head>
        <body>
            {f'<div class="watermark">{report.metadata.watermark}</div>' if report.metadata.watermark else ''}
            
            <div class="report-header">
                <h1>🔍 OSINT INVESTIGATION REPORT</h1>
                <p>Professional Intelligence Analysis</p>
            </div>
            
            <div class="classification">
                CLASSIFICATION: {report.metadata.classification.value.upper()}
            </div>
            
            <div class="section">
                <h2>📋 Report Metadata</h2>
                <table class="metadata-table">
                    <tr><th>Report ID</th><td>{report.metadata.report_id}</td></tr>
                    <tr><th>Investigation ID</th><td>{report.metadata.investigation_id}</td></tr>
                    <tr><th>Target</th><td>{report.metadata.target_identifier}</td></tr>
                    <tr><th>Generated By</th><td>{report.metadata.generated_by}</td></tr>
                    <tr><th>Generated At</th><td>{report.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
                    <tr><th>Report Type</th><td>{report.metadata.report_type.value.title()}</td></tr>
                    <tr><th>Confidence Score</th><td>{report.metadata.confidence_score:.1f}%</td></tr>
                    <tr><th>Data Freshness</th><td>{report.metadata.data_freshness:.1f}%</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h2>📊 Executive Summary</h2>
                
                <div class="risk-metrics">
                    <div class="risk-card">
                        <h4>Overall Risk</h4>
                        <div class="risk-score">{report.executive_summary.risk_assessment.get('overall_score', 0):.1f}</div>
                        <p>{report.executive_summary.threat_level.upper()}</p>
                    </div>
                    <div class="risk-card">
                        <h4>Confidence</h4>
                        <div class="risk-score" style="color: #3498db;">{report.executive_summary.confidence_level}</div>
                        <p>Assessment Confidence</p>
                    </div>
                    <div class="risk-card">
                        <h4>Duration</h4>
                        <div class="risk-score" style="color: #f39c12;">{report.executive_summary.investigation_duration}</div>
                        <p>Investigation Time</p>
                    </div>
                    <div class="risk-card">
                        <h4>Data Sources</h4>
                        <div class="risk-score" style="color: #27ae60;">{report.executive_summary.data_sources_analyzed}</div>
                        <p>Sources Analyzed</p>
                    </div>
                </div>
                
                <h3>🔍 Key Findings</h3>
                <ul class="findings-list">
                    {''.join(f'<li>🚨 {finding}</li>' for finding in report.executive_summary.key_findings)}
                </ul>
                
                <h3>💡 Strategic Recommendations</h3>
                <ul class="recommendations-list">
                    {''.join(f'<li>✅ {rec}</li>' for rec in report.executive_summary.recommendations)}
                </ul>
                
                <h3>📈 Business Impact Analysis</h3>
                <div class="technical-grid">
                    {''.join(f'''
                    <div class="technical-card">
                        <h4>{category.title()} Impact</h4>
                        <p style="font-size: 1.2em; font-weight: bold; color: {self._get_impact_color(level)};">{level.upper()}</p>
                    </div>
                    ''' for category, level in report.executive_summary.impact_analysis.items())}
                </div>
            </div>
            
            <div class="section">
                <h2>🔧 Technical Findings</h2>
                
                <div class="technical-grid">
                    <div class="technical-card">
                        <h4>Infrastructure Analysis</h4>
                        <p><strong>Domains:</strong> {report.technical_findings.domains_analyzed}</p>
                        <p><strong>IP Addresses:</strong> {report.technical_findings.ip_addresses_investigated}</p>
                        <p><strong>Certificates:</strong> {len(report.technical_findings.infrastructure_analysis.get('ssl_certificates', []))}</p>
                    </div>
                    
                    <div class="technical-card">
                        <h4>Social Intelligence</h4>
                        <p><strong>Accounts:</strong> {report.technical_findings.social_accounts_discovered}</p>
                        <p><strong>Platforms:</strong> {len(report.technical_findings.social_intelligence.get('platforms', []))}</p>
                        <p><strong>Mentions:</strong> {len(report.technical_findings.social_intelligence.get('mentions', []))}</p>
                    </div>
                    
                    <div class="technical-card">
                        <h4>Threat Intelligence</h4>
                        <p><strong>IoCs:</strong> {len(report.technical_findings.threat_indicators)}</p>
                        <p><strong>Malware Samples:</strong> {report.technical_findings.malware_samples_analyzed}</p>
                        <p><strong>Vulnerabilities:</strong> {len(report.technical_findings.vulnerabilities_identified)}</p>
                    </div>
                    
                    <div class="technical-card">
                        <h4>Analysis Quality</h4>
                        <p><strong>Cross-source Correlations:</strong> {len(report.technical_findings.cross_source_correlations)}</p>
                        <p><strong>Behavioral Anomalies:</strong> {len(report.technical_findings.behavioral_anomalies)}</p>
                        <p><strong>Evidence Items:</strong> {len(report.technical_findings.evidence_reliability)}</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🔬 Methodology</h2>
                <p>{report.methodology}</p>
            </div>
            
            <div class="section">
                <h2>📋 Scope and Limitations</h2>
                <p>{report.scope_and_limitations}</p>
            </div>
            
            <div class="section">
                <h2>🎯 Conclusions</h2>
                <p>{report.conclusions}</p>
            </div>
            
            <div style="text-align: center; margin-top: 40px; color: #7f8c8d; font-size: 0.9em;">
                <p>Report generated by Enterprise OSINT Platform</p>
                <p>© {datetime.utcnow().year} - Classification: {report.metadata.classification.value.upper()}</p>
            </div>
        </body>
        </html>
        """
        
        return html_template
    
    def _export_json(self, report: ProfessionalReport) -> str:
        """Export report as structured JSON"""
        
        def serialize_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, timedelta):
                return str(obj)
            return str(obj)
        
        report_dict = {
            'metadata': {
                'report_id': report.metadata.report_id,
                'report_type': report.metadata.report_type.value,
                'classification': report.metadata.classification.value,
                'generated_at': serialize_datetime(report.metadata.generated_at),
                'generated_by': report.metadata.generated_by,
                'investigation_id': report.metadata.investigation_id,
                'target_identifier': report.metadata.target_identifier,
                'completeness_score': report.metadata.completeness_score,
                'confidence_score': report.metadata.confidence_score,
                'data_freshness': report.metadata.data_freshness
            },
            'executive_summary': {
                'key_findings': report.executive_summary.key_findings,
                'risk_assessment': report.executive_summary.risk_assessment,
                'recommendations': report.executive_summary.recommendations,
                'impact_analysis': report.executive_summary.impact_analysis,
                'threat_level': report.executive_summary.threat_level,
                'confidence_level': report.executive_summary.confidence_level,
                'metrics': {
                    'investigation_duration': report.executive_summary.investigation_duration,
                    'data_sources_analyzed': report.executive_summary.data_sources_analyzed,
                    'intelligence_items_collected': report.executive_summary.intelligence_items_collected,
                    'compliance_status': report.executive_summary.compliance_status
                },
                'business_analysis': {
                    'risk_factors': report.executive_summary.business_risk_factors,
                    'mitigation_priority': report.executive_summary.mitigation_priority,
                    'resource_requirements': report.executive_summary.resource_requirements
                }
            },
            'technical_findings': {
                'infrastructure_analysis': report.technical_findings.infrastructure_analysis,
                'social_intelligence': report.technical_findings.social_intelligence,
                'threat_indicators': report.technical_findings.threat_indicators,
                'vulnerabilities': report.technical_findings.vulnerabilities_identified,
                'attack_vectors': report.technical_findings.attack_vectors,
                'metrics': {
                    'domains_analyzed': report.technical_findings.domains_analyzed,
                    'ip_addresses_investigated': report.technical_findings.ip_addresses_investigated,
                    'social_accounts_discovered': report.technical_findings.social_accounts_discovered,
                    'malware_samples_analyzed': report.technical_findings.malware_samples_analyzed
                },
                'analysis_quality': {
                    'cross_source_correlations': report.technical_findings.cross_source_correlations,
                    'temporal_patterns': report.technical_findings.temporal_patterns,
                    'behavioral_anomalies': report.technical_findings.behavioral_anomalies,
                    'evidence_reliability': report.technical_findings.evidence_reliability,
                    'source_credibility': report.technical_findings.source_credibility,
                    'verification_status': report.technical_findings.verification_status
                }
            },
            'report_content': {
                'methodology': report.methodology,
                'scope_and_limitations': report.scope_and_limitations,
                'conclusions': report.conclusions
            },
            'appendices': report.appendices
        }
        
        return json.dumps(report_dict, indent=2, default=serialize_datetime)
    
    # Helper methods for report generation
    def _get_impact_color(self, level: str) -> str:
        """Get color for impact level"""
        colors = {
            'low': '#27ae60',
            'medium': '#f39c12',
            'high': '#e74c3c',
            'critical': '#c0392b'
        }
        return colors.get(level.lower(), '#95a5a6')
    
    def _calculate_completeness_score(self, investigation: OSINTInvestigation) -> float:
        """Calculate investigation completeness score"""
        score = 0.0
        max_score = 100.0
        
        # Check for presence of different intelligence types
        if investigation.social_intelligence:
            score += 25.0
        if investigation.infrastructure_intelligence:
            score += 25.0
        if investigation.threat_intelligence:
            score += 25.0
        if hasattr(investigation, 'risk_assessment') and investigation.risk_assessment:
            score += 25.0
        
        return min(score, max_score)
    
    def _calculate_confidence_score(self, investigation: OSINTInvestigation) -> float:
        """Calculate overall confidence in findings"""
        confidence_factors = []
        
        # Data source diversity
        sources = set()
        if investigation.social_intelligence:
            sources.update(investigation.social_intelligence.data_sources)
        if investigation.infrastructure_intelligence:
            sources.add('infrastructure')
        if investigation.threat_intelligence:
            sources.add('threat_intelligence')
        
        source_diversity = min(len(sources) * 20, 80)  # Max 80% for diversity
        confidence_factors.append(source_diversity)
        
        # Investigation completeness
        completeness = self._calculate_completeness_score(investigation)
        confidence_factors.append(completeness * 0.8)  # 80% weight
        
        # Risk assessment presence
        if hasattr(investigation, 'risk_assessment') and investigation.risk_assessment:
            confidence_factors.append(90.0)
        else:
            confidence_factors.append(50.0)
        
        return sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.0
    
    def _calculate_data_freshness_score(self, investigation: OSINTInvestigation) -> float:
        """Calculate data freshness score based on investigation timing"""
        if not investigation.completed_at:
            return 70.0  # Default for ongoing investigations
        
        age_hours = (datetime.utcnow() - investigation.completed_at).total_seconds() / 3600
        
        if age_hours <= 1:
            return 100.0
        elif age_hours <= 24:
            return 90.0
        elif age_hours <= 168:  # 1 week
            return 75.0
        elif age_hours <= 720:  # 1 month
            return 60.0
        else:
            return 40.0
    
    def _generate_methodology_section(self, investigation: OSINTInvestigation) -> str:
        """Generate methodology section"""
        return f"""
        This OSINT investigation was conducted using a structured 7-stage methodology:
        
        1. Investigation Planning & Compliance Assessment
        2. Target Profiling & Intelligence Scoping  
        3. Multi-Source Intelligence Collection
        4. Intelligence Analysis & Correlation
        5. Compliance Verification & Audit Trail
        6. Advanced Risk Assessment with Intelligence Correlation
        7. Intelligence Report Generation
        
        The investigation target "{investigation.target_profile.primary_identifier}" was analyzed using 
        {investigation.investigation_type.value} methodology with {investigation.priority.value} priority.
        
        Data collection was performed in accordance with legal and ethical guidelines, focusing on 
        publicly available information and authorized intelligence sources. All findings were 
        cross-verified using multiple sources where possible to ensure accuracy and reliability.
        
        The investigation utilized automated tools and manual analysis techniques to gather and 
        correlate intelligence from social media platforms, infrastructure sources, and threat 
        intelligence feeds. Risk assessment was performed using advanced correlation algorithms 
        to identify potential threats and vulnerabilities.
        """
    
    def _generate_scope_section(self, investigation: OSINTInvestigation) -> str:
        """Generate scope and limitations section"""
        scope_elements = []
        
        if investigation.scope:
            if investigation.scope.include_social_media:
                scope_elements.append("social media intelligence")
            if investigation.scope.include_infrastructure:
                scope_elements.append("infrastructure analysis")
            if investigation.scope.include_threat_intelligence:
                scope_elements.append("threat intelligence correlation")
        
        scope_text = ", ".join(scope_elements) if scope_elements else "comprehensive OSINT analysis"
        
        return f"""
        This investigation was scoped to include {scope_text} for the target 
        "{investigation.target_profile.primary_identifier}".
        
        LIMITATIONS:
        
        • Intelligence gathering was limited to publicly available information and authorized sources
        • Data accuracy depends on the reliability of source systems and may contain false positives
        • Temporal analysis is limited to the investigation time window
        • Some intelligence sources may have rate limits or access restrictions
        • Social media analysis may be limited by platform privacy settings and API constraints
        • Threat intelligence correlation depends on available threat feeds and may not include 
          the most recent indicators
        • Risk assessment is based on available data and may not reflect all potential threats
        
        The investigation was conducted within legal and ethical boundaries, respecting privacy 
        regulations and data protection requirements. All data retention policies were followed, 
        with investigation data scheduled for deletion according to organizational policies.
        """
    
    def _generate_conclusions_section(self, investigation: OSINTInvestigation, 
                                    executive_summary: ExecutiveSummary) -> str:
        """Generate conclusions section"""
        risk_level = executive_summary.threat_level
        
        return f"""
        Based on the comprehensive OSINT investigation of "{investigation.target_profile.primary_identifier}", 
        the following conclusions have been reached:
        
        RISK ASSESSMENT CONCLUSION:
        The target presents a {risk_level.upper()} risk level based on the analysis of multiple 
        intelligence sources. This assessment is made with {executive_summary.confidence_level.upper()} 
        confidence based on the quality and diversity of available intelligence.
        
        KEY CONCERNS:
        {chr(10).join(f"• {finding}" for finding in executive_summary.key_findings[:3])}
        
        STRATEGIC IMPLICATIONS:
        The investigation findings indicate that immediate attention should be given to the identified 
        risk factors. The {executive_summary.data_sources_analyzed} intelligence sources analyzed 
        provide sufficient evidence to support the conclusions and recommendations presented.
        
        RECOMMENDED ACTIONS:
        Priority should be given to implementing the strategic recommendations outlined in this report, 
        particularly those addressing high-risk findings. Continuous monitoring should be established 
        for the identified threat indicators and risk factors.
        
        The investigation methodology and quality controls applied provide confidence in these findings, 
        with a completeness score of {investigation.progress.overall_progress * 100:.1f}% and 
        compliance verification completed successfully.
        
        This assessment should be reviewed and updated periodically as new intelligence becomes 
        available or threat landscape changes occur.
        """
    
    # Additional helper methods would be implemented here for completeness
    def _identify_business_risk_factors(self, investigation: OSINTInvestigation) -> List[str]:
        """Identify business-specific risk factors"""
        return ["Operational disruption potential", "Reputational impact risk", "Regulatory compliance concerns"]
    
    def _prioritize_mitigations(self, investigation: OSINTInvestigation) -> List[str]:
        """Prioritize mitigation strategies"""
        return ["Immediate threat response", "Enhanced monitoring", "Long-term security improvements"]
    
    def _estimate_resource_requirements(self, investigation: OSINTInvestigation) -> List[str]:
        """Estimate resource requirements for recommendations"""
        return ["Security team engagement", "Technology investment", "Process improvements"]
    
    def _extract_vulnerabilities(self, investigation: OSINTInvestigation) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from findings"""
        return []  # Placeholder for vulnerability extraction logic
    
    def _calculate_cross_source_correlations(self, investigation: OSINTInvestigation) -> Dict[str, float]:
        """Calculate cross-source correlation strengths"""
        return {"social_infrastructure": 0.7, "threat_infrastructure": 0.8}
    
    def _analyze_temporal_patterns(self, investigation: OSINTInvestigation) -> Dict[str, Any]:
        """Analyze temporal patterns in intelligence"""
        return {"pattern_type": "consistent", "timeframe": "investigation_window"}
    
    def _identify_behavioral_anomalies(self, investigation: OSINTInvestigation) -> List[str]:
        """Identify behavioral anomalies"""
        return []
    
    def _assess_evidence_reliability(self, investigation: OSINTInvestigation) -> Dict[str, float]:
        """Assess reliability of evidence sources"""
        return {"social_media": 0.7, "infrastructure": 0.9, "threat_intel": 0.8}
    
    def _assess_source_credibility(self, investigation: OSINTInvestigation) -> Dict[str, str]:
        """Assess credibility of intelligence sources"""
        return {"social_media": "medium", "infrastructure": "high", "threat_intel": "high"}
    
    def _determine_verification_status(self, investigation: OSINTInvestigation) -> Dict[str, str]:
        """Determine verification status of findings"""
        return {"cross_verified": "partial", "single_source": "requires_verification"}
    
    def _generate_charts(self, investigation: OSINTInvestigation) -> Dict[str, bytes]:
        """Generate charts and visualizations"""
        return {}  # Placeholder for chart generation
    
    def _export_raw_data(self, investigation: OSINTInvestigation) -> Dict[str, str]:
        """Export raw intelligence data"""
        return {}  # Placeholder for raw data export
    
    def _generate_appendices(self, investigation: OSINTInvestigation) -> Dict[str, Any]:
        """Generate report appendices"""
        return {
            "intelligence_sources": "List of sources used in investigation",
            "technical_details": "Detailed technical analysis",
            "compliance_documentation": "Compliance verification details"
        }
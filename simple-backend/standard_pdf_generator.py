#!/usr/bin/env python3
"""
Standardized PDF Report Generator for Enterprise OSINT Operations

This is the single source of truth for all PDF report generation across:
- Production code
- Local demos  
- Kubernetes demos
- Web applications
- Examples

All other PDF generation should import and use this standardized generator.
"""
import io
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
import uuid

# PDF generation libraries with fallback
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.piecharts import Pie
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class StandardOSINTPDFGenerator:
    """
    Standardized PDF report generator for all Enterprise OSINT applications.
    
    This class provides consistent formatting, styling, and structure across
    all demos, web apps, and production code.
    """
    
    def __init__(self):
        """Initialize the PDF generator with standard styles"""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab>=4.0.0")
        
        # Standard colors (define first)
        self.colors = {
            'primary': colors.HexColor('#1f4e79'),      # Navy blue
            'secondary': colors.HexColor('#2c5f85'),    # Lighter blue  
            'accent': colors.HexColor('#0066cc'),       # Bright blue
            'text': colors.HexColor('#333333'),         # Dark gray
            'light_gray': colors.HexColor('#f8f9fa'),   # Light background
            'border': colors.HexColor('#dee2e6'),       # Border gray
            'success': colors.HexColor('#28a745'),      # Green
            'warning': colors.HexColor('#ffc107'),      # Yellow
            'danger': colors.HexColor('#dc3545')        # Red
        }
        
        self.styles = getSampleStyleSheet()
        self.setup_standard_styles()
    
    def setup_standard_styles(self):
        """Setup standardized paragraph styles for all reports"""
        
        # Report Title
        self.styles.add(ParagraphStyle(
            name='StandardTitle',
            parent=self.styles['Title'],
            fontSize=22,
            textColor=self.colors['primary'],
            spaceAfter=30,
            spaceBefore=20,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section Header
        self.styles.add(ParagraphStyle(
            name='StandardSectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            textColor=self.colors['secondary'],
            spaceBefore=25,
            spaceAfter=12,
            fontName='Helvetica-Bold',
            borderWidth=0,
            borderPadding=0,
            leftIndent=0
        ))
        
        # Subsection Header
        self.styles.add(ParagraphStyle(
            name='StandardSubsectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self.colors['secondary'],
            spaceBefore=18,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
        
        # Body Text
        self.styles.add(ParagraphStyle(
            name='StandardBody',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=self.colors['text'],
            spaceBefore=6,
            spaceAfter=6,
            alignment=TA_JUSTIFY,
            fontName='Helvetica'
        ))
        
        # Key-Value Text
        self.styles.add(ParagraphStyle(
            name='StandardKeyValue',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=self.colors['text'],
            spaceBefore=3,
            spaceAfter=3,
            fontName='Helvetica',
            leftIndent=20
        ))
        
        # Executive Summary
        self.styles.add(ParagraphStyle(
            name='StandardExecutive',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=self.colors['text'],
            spaceBefore=8,
            spaceAfter=8,
            alignment=TA_JUSTIFY,
            fontName='Helvetica',
            borderWidth=1,
            borderColor=self.colors['border'],
            borderPadding=10,
            backColor=self.colors['light_gray']
        ))
        
        # Footer Text  
        self.styles.add(ParagraphStyle(
            name='StandardFooter',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.gray,
            alignment=TA_CENTER,
            fontName='Helvetica'
        ))
        
        # Classification Text
        self.styles.add(ParagraphStyle(
            name='StandardClassification',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.colors['danger'],
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            spaceBefore=10,
            spaceAfter=10
        ))

    def generate_standard_pdf_report(self, investigation_data: Dict[str, Any], report_type: str = "comprehensive") -> bytes:
        """
        Generate a standardized PDF report from OSINT investigation data.
        
        Args:
            investigation_data: Dictionary containing investigation results
            report_type: Type of report ('comprehensive', 'executive', 'technical')
            
        Returns:
            bytes: PDF document as bytes
        """
        buffer = io.BytesIO()
        
        # Create PDF document with standard settings
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=A4,
            rightMargin=72,
            leftMargin=72, 
            topMargin=72,
            bottomMargin=72,
            title=f"OSINT Report - {investigation_data.get('target', 'Unknown')}",
            author="Enterprise OSINT Research Agent",
            subject="Open Source Intelligence Report",
            creator="Enterprise OSINT Platform"
        )
        
        # Build document story
        story = []
        
        # Header
        story.extend(self._build_standard_header(investigation_data))
        
        # Investigation Details
        story.extend(self._build_investigation_details(investigation_data))
        
        # Executive Summary
        story.extend(self._build_executive_summary(investigation_data))
        
        # Main Content based on report type
        if report_type == "comprehensive":
            story.extend(self._build_comprehensive_content(investigation_data))
        elif report_type == "executive":
            story.extend(self._build_executive_content(investigation_data))
        elif report_type == "technical":
            story.extend(self._build_technical_content(investigation_data))
        
        # Recommendations
        story.extend(self._build_recommendations(investigation_data))
        
        # Footer
        story.extend(self._build_standard_footer(investigation_data))
        
        # Build PDF
        doc.build(story)
        
        buffer.seek(0)
        return buffer.getvalue()

    def _build_standard_header(self, investigation_data: Dict[str, Any]) -> List:
        """Build standardized report header"""
        story = []
        
        # Classification (if applicable)
        classification = investigation_data.get('classification', 'INTERNAL USE ONLY')
        story.append(Paragraph(classification, self.styles['StandardClassification']))
        
        # Main title
        story.append(Paragraph("ENTERPRISE OSINT INTELLIGENCE REPORT", self.styles['StandardTitle']))
        story.append(Spacer(1, 20))
        
        return story

    def _build_investigation_details(self, investigation_data: Dict[str, Any]) -> List:
        """Build investigation details section"""
        story = []
        
        story.append(Paragraph("Investigation Details", self.styles['StandardSectionHeader']))
        
        # Create details table
        details_data = [
            ['Investigation ID:', investigation_data.get('id', 'N/A')],
            ['Target Entity:', investigation_data.get('target', 'N/A')],
            ['Investigation Type:', investigation_data.get('type', 'N/A')],
            ['Priority Level:', investigation_data.get('priority', 'Normal')],
            ['Jurisdiction:', investigation_data.get('jurisdiction', 'Global')],
            ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M UTC')],
            ['Platform:', investigation_data.get('platform', 'Enterprise OSINT Agent')],
            ['Status:', investigation_data.get('status', 'Completed')]
        ]
        
        details_table = Table(details_data, colWidths=[2.5*inch, 4*inch])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.colors['light_gray']),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.colors['text']),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(details_table)
        story.append(Spacer(1, 20))
        
        return story

    def _build_executive_summary(self, investigation_data: Dict[str, Any]) -> List:
        """Build executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['StandardSectionHeader']))
        
        # Default summary or use provided one
        summary = investigation_data.get('executive_summary', 
            "This comprehensive OSINT intelligence report provides detailed analysis of the target entity "
            "based on publicly available information. The investigation covers corporate intelligence, "
            "infrastructure assessment, social media analysis, and threat intelligence to provide a "
            "complete risk and opportunity assessment."
        )
        
        story.append(Paragraph(summary, self.styles['StandardExecutive']))
        story.append(Spacer(1, 20))
        
        return story

    def _build_comprehensive_content(self, investigation_data: Dict[str, Any]) -> List:
        """Build comprehensive report content"""
        story = []
        
        results = investigation_data.get('results', {})
        
        # Corporate Intelligence
        if 'corporate' in results:
            story.extend(self._build_corporate_section(results['corporate']))
        
        # Infrastructure Assessment
        if 'infrastructure' in results:
            story.extend(self._build_infrastructure_section(results['infrastructure']))
        
        # Social Media Analysis
        if 'social' in results:
            story.extend(self._build_social_section(results['social']))
        
        # Threat Intelligence
        if 'threats' in results:
            story.extend(self._build_threat_section(results['threats']))
        
        return story

    def _build_executive_content(self, investigation_data: Dict[str, Any]) -> List:
        """Build executive-focused content (high-level only)"""
        story = []
        
        results = investigation_data.get('results', {})
        
        # Key Findings
        story.append(Paragraph("Key Findings", self.styles['StandardSectionHeader']))
        
        findings = []
        
        if 'corporate' in results:
            corp = results['corporate']
            findings.append(f"Corporate Status: {corp.get('legal_status', 'N/A')}")
            findings.append(f"Industry: {corp.get('industry', 'N/A')}")
        
        if 'threats' in results:
            threats = results['threats']
            findings.append(f"Threat Level: {threats.get('threat_level', 'N/A')}")
        
        if 'social' in results:
            social = results['social']
            findings.append(f"Reputation Score: {social.get('reputation_score', 'N/A')}/100")
        
        for finding in findings:
            story.append(Paragraph(f"• {finding}", self.styles['StandardKeyValue']))
        
        story.append(Spacer(1, 20))
        
        return story

    def _build_technical_content(self, investigation_data: Dict[str, Any]) -> List:
        """Build technical-focused content"""
        story = []
        
        results = investigation_data.get('results', {})
        
        # Focus on infrastructure and technical details
        if 'infrastructure' in results:
            story.extend(self._build_infrastructure_section(results['infrastructure'], detailed=True))
        
        if 'threats' in results:
            story.extend(self._build_threat_section(results['threats'], detailed=True))
        
        return story

    def _build_corporate_section(self, corporate_data: Dict[str, Any]) -> List:
        """Build corporate intelligence section"""
        story = []
        
        story.append(Paragraph("Corporate Intelligence", self.styles['StandardSectionHeader']))
        
        # Key corporate information
        corp_items = [
            ('Company Name', corporate_data.get('company_name', 'N/A')),
            ('Industry', corporate_data.get('industry', 'N/A')),
            ('Legal Status', corporate_data.get('legal_status', 'N/A')),
            ('Headquarters', corporate_data.get('headquarters', 'N/A')),
            ('Employee Count', corporate_data.get('employees', 'N/A')),
            ('Revenue', corporate_data.get('revenue', 'N/A')),
            ('Funding', corporate_data.get('funding', 'N/A'))
        ]
        
        for label, value in corp_items:
            story.append(Paragraph(f"<b>{label}:</b> {value}", self.styles['StandardKeyValue']))
        
        # Executives
        if 'executives' in corporate_data and corporate_data['executives']:
            story.append(Paragraph("Key Executives", self.styles['StandardSubsectionHeader']))
            for exec in corporate_data['executives']:
                story.append(Paragraph(
                    f"• {exec.get('name', 'N/A')} - {exec.get('title', 'N/A')}", 
                    self.styles['StandardKeyValue']
                ))
        
        story.append(Spacer(1, 15))
        return story

    def _build_infrastructure_section(self, infra_data: Dict[str, Any], detailed: bool = False) -> List:
        """Build infrastructure assessment section"""
        story = []
        
        story.append(Paragraph("Infrastructure Assessment", self.styles['StandardSectionHeader']))
        
        # Key infrastructure information
        infra_items = [
            ('Domain', infra_data.get('domain', 'N/A')),
            ('Hosting Provider', infra_data.get('hosting_provider', 'N/A')),
            ('SSL Grade', infra_data.get('ssl_certificate', {}).get('grade', 'N/A')),
            ('CDN', infra_data.get('cdn', 'N/A')),
            ('Vulnerabilities', infra_data.get('vulnerabilities', 'N/A'))
        ]
        
        for label, value in infra_items:
            story.append(Paragraph(f"<b>{label}:</b> {value}", self.styles['StandardKeyValue']))
        
        if detailed:
            # Add technical details for technical reports
            if 'ip_addresses' in infra_data:
                story.append(Paragraph("IP Addresses", self.styles['StandardSubsectionHeader']))
                for ip in infra_data['ip_addresses']:
                    story.append(Paragraph(f"• {ip}", self.styles['StandardKeyValue']))
        
        story.append(Spacer(1, 15))
        return story

    def _build_social_section(self, social_data: Dict[str, Any]) -> List:
        """Build social media analysis section"""
        story = []
        
        story.append(Paragraph("Social Media Analysis", self.styles['StandardSectionHeader']))
        
        # Reputation score
        rep_score = social_data.get('reputation_score', 'N/A')
        story.append(Paragraph(f"<b>Reputation Score:</b> {rep_score}/100", self.styles['StandardKeyValue']))
        
        # Twitter presence
        if 'twitter_presence' in social_data:
            twitter = social_data['twitter_presence']
            story.append(Paragraph("Twitter Analysis", self.styles['StandardSubsectionHeader']))
            twitter_items = [
                ('Handle', twitter.get('handle', 'N/A')),
                ('Followers', twitter.get('followers', 'N/A')),
                ('Sentiment', twitter.get('sentiment', 'N/A')),
                ('Activity Level', twitter.get('recent_activity', 'N/A'))
            ]
            
            for label, value in twitter_items:
                story.append(Paragraph(f"<b>{label}:</b> {value}", self.styles['StandardKeyValue']))
        
        story.append(Spacer(1, 15))
        return story

    def _build_threat_section(self, threat_data: Dict[str, Any], detailed: bool = False) -> List:
        """Build threat intelligence section"""
        story = []
        
        story.append(Paragraph("Threat Intelligence", self.styles['StandardSectionHeader']))
        
        # Key threat information
        threat_items = [
            ('Threat Level', threat_data.get('threat_level', 'N/A')),
            ('Domain Reputation', threat_data.get('domain_reputation', 'N/A')),
            ('IP Reputation', threat_data.get('ip_reputation', 'N/A')),
            ('Malware Associations', threat_data.get('malware_associations', 'N/A')),
            ('Data Breaches', threat_data.get('data_breaches', 'N/A')),
            ('Security Incidents', threat_data.get('security_incidents', 'N/A'))
        ]
        
        for label, value in threat_items:
            story.append(Paragraph(f"<b>{label}:</b> {value}", self.styles['StandardKeyValue']))
        
        if detailed:
            # Add detailed threat analysis for technical reports
            if 'dark_web_mentions' in threat_data:
                story.append(Paragraph(f"<b>Dark Web Mentions:</b> {threat_data['dark_web_mentions']}", self.styles['StandardKeyValue']))
        
        story.append(Spacer(1, 15))
        return story

    def _build_recommendations(self, investigation_data: Dict[str, Any]) -> List:
        """Build recommendations section"""
        story = []
        
        story.append(Paragraph("Recommendations", self.styles['StandardSectionHeader']))
        
        # Use provided recommendations or default ones
        recommendations = investigation_data.get('recommendations', [
            "Continue routine monitoring of digital assets and brand mentions",
            "Maintain current security posture and implement additional hardening measures",
            "Establish regular reputation monitoring and social media oversight",
            "Update threat intelligence feeds and security monitoring tools",
            "Consider implementing advanced threat detection capabilities",
            "Review and update incident response procedures based on current threat landscape"
        ])
        
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['StandardBody']))
        
        story.append(Spacer(1, 20))
        
        return story

    def _build_standard_footer(self, investigation_data: Dict[str, Any]) -> List:
        """Build standardized report footer"""
        story = []
        
        # Disclaimer
        story.append(Paragraph("Disclaimer", self.styles['StandardSectionHeader']))
        
        disclaimer_text = (
            "This report contains information gathered from publicly available sources and is intended "
            "for legitimate business intelligence purposes only. The analysis and recommendations "
            "provided are based on available data and should be considered alongside other intelligence "
            "sources. This report is confidential and intended solely for the authorized recipient."
        )
        
        story.append(Paragraph(disclaimer_text, self.styles['StandardBody']))
        story.append(Spacer(1, 20))
        
        # Report metadata
        story.append(Paragraph(
            f"Generated by: Enterprise OSINT Research Agent v1.0.0", 
            self.styles['StandardFooter']
        ))
        story.append(Paragraph(
            f"Report ID: {investigation_data.get('id', 'N/A')}", 
            self.styles['StandardFooter']
        ))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", 
            self.styles['StandardFooter']
        ))
        
        # Classification
        classification = investigation_data.get('classification', 'INTERNAL USE ONLY')
        story.append(Spacer(1, 15))
        story.append(Paragraph(classification, self.styles['StandardClassification']))
        
        return story


def generate_standard_osint_pdf(investigation_data: Dict[str, Any], report_type: str = "comprehensive") -> bytes:
    """
    Convenience function for generating standardized OSINT PDF reports.
    
    This function should be imported and used by all demos and production code
    to ensure consistent PDF formatting.
    
    Args:
        investigation_data: Investigation results dictionary
        report_type: 'comprehensive', 'executive', or 'technical'
        
    Returns:
        bytes: PDF document as bytes
    """
    generator = StandardOSINTPDFGenerator()
    return generator.generate_standard_pdf_report(investigation_data, report_type)


# Backward compatibility function names
def generate_pdf_report(investigation_data: Dict[str, Any]) -> bytes:
    """Backward compatibility wrapper"""
    return generate_standard_osint_pdf(investigation_data, "comprehensive")


def generate_mock_pdf_report(investigation_data: Dict[str, Any]) -> bytes:
    """Backward compatibility wrapper for demo code"""
    return generate_standard_osint_pdf(investigation_data, "comprehensive")
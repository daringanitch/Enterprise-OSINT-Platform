"""
Professional PDF Report Generation Service
"""
import io
import os
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

import structlog
from weasyprint import HTML, CSS
from jinja2 import Environment, FileSystemLoader
from fastapi.responses import Response

logger = structlog.get_logger()


class OSINTReportGenerator:
    """Professional OSINT investigation report generator"""
    
    def __init__(self):
        # Setup Jinja2 template environment
        template_dir = Path(__file__).parent.parent / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True
        )
        
        # Custom CSS for better PDF formatting
        self.report_css = CSS(string="""
            @page {
                size: A4;
                margin: 2cm 1.5cm;
            }
            
            body {
                font-family: 'DejaVu Sans', Arial, sans-serif;
                font-size: 11pt;
                line-height: 1.4;
            }
            
            .page-break {
                page-break-before: always;
            }
            
            .avoid-break {
                break-inside: avoid;
            }
            
            table {
                border-collapse: collapse;
                width: 100%;
                margin-bottom: 1em;
            }
            
            th, td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }
            
            th {
                background-color: #f2f2f2;
                font-weight: bold;
            }
        """)
    
    def format_duration(self, duration_seconds: float) -> str:
        """Format duration in a human-readable way"""
        if duration_seconds < 1:
            return f"{duration_seconds*1000:.0f}ms"
        elif duration_seconds < 60:
            return f"{duration_seconds:.1f}s"
        elif duration_seconds < 3600:
            minutes = int(duration_seconds // 60)
            seconds = duration_seconds % 60
            return f"{minutes}m {seconds:.0f}s"
        else:
            hours = int(duration_seconds // 3600)
            minutes = int((duration_seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    def determine_risk_level(self, risk_score: Optional[int]) -> str:
        """Determine risk level CSS class from risk score"""
        if risk_score is None:
            return "minimal"
        
        if risk_score <= 20:
            return "minimal"
        elif risk_score <= 40:
            return "low"
        elif risk_score <= 60:
            return "medium"
        elif risk_score <= 80:
            return "high"
        else:
            return "critical"
    
    def count_findings(self, findings: Dict[str, Any]) -> int:
        """Count total number of findings across all categories"""
        if not findings:
            return 0
            
        count = 0
        for category_data in findings.values():
            if isinstance(category_data, dict):
                count += len([v for v in category_data.values() if v])
        return count
    
    async def generate_investigation_report(
        self, 
        investigation: Dict[str, Any], 
        user_email: str,
        format: str = "pdf"
    ) -> Response:
        """Generate a professional investigation report"""
        
        try:
            # Prepare template data
            template_data = {
                "investigation": investigation,
                "user_email": user_email,
                "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "created_date": datetime.fromtimestamp(
                    investigation.get("created_at", 0)
                ).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "completed_date": None,
                "duration": "N/A",
                "risk_level": self.determine_risk_level(investigation.get("risk_score")),
                "findings_count": self.count_findings(investigation.get("findings", {})),
                "error_count": len(investigation.get("errors", []))
            }
            
            # Handle completion data if available
            if investigation.get("completed_at"):
                template_data["completed_date"] = datetime.fromtimestamp(
                    investigation["completed_at"]
                ).strftime("%Y-%m-%d %H:%M:%S UTC")
            
            # Format duration
            if investigation.get("duration_seconds"):
                template_data["duration"] = self.format_duration(
                    investigation["duration_seconds"]
                )
            
            logger.info(
                "Generating investigation report",
                investigation_id=investigation.get("id"),
                target=investigation.get("target"),
                format=format,
                findings_count=template_data["findings_count"],
                risk_score=investigation.get("risk_score")
            )
            
            if format.lower() == "html":
                # Return HTML for preview/debugging
                template = self.jinja_env.get_template("investigation_report.html")
                html_content = template.render(**template_data)
                
                return Response(
                    content=html_content,
                    media_type="text/html"
                )
            
            else:
                # Generate PDF
                template = self.jinja_env.get_template("investigation_report.html")
                html_content = template.render(**template_data)
                
                # Convert HTML to PDF
                html = HTML(string=html_content)
                pdf_bytes = html.write_pdf(stylesheets=[self.report_css])
                
                filename = f"osint_report_{investigation.get('target', 'unknown')}_{investigation.get('id', 'unknown')[:8]}.pdf"
                # Sanitize filename
                filename = "".join(c for c in filename if c.isalnum() or c in "._-")
                
                logger.info(
                    "PDF report generated successfully",
                    investigation_id=investigation.get("id"),
                    pdf_size_bytes=len(pdf_bytes),
                    filename=filename
                )
                
                return Response(
                    content=pdf_bytes,
                    media_type="application/pdf",
                    headers={
                        "Content-Disposition": f"attachment; filename={filename}",
                        "Content-Length": str(len(pdf_bytes))
                    }
                )
                
        except Exception as e:
            logger.error(
                "Failed to generate investigation report",
                investigation_id=investigation.get("id"),
                error=str(e),
                exc_info=True
            )
            
            # Fallback to text report
            return await self.generate_text_report(investigation, user_email)
    
    async def generate_text_report(
        self, 
        investigation: Dict[str, Any], 
        user_email: str
    ) -> Response:
        """Fallback text report generation"""
        
        created_date = datetime.fromtimestamp(investigation.get("created_at", 0))
        
        report_lines = [
            "OSINT INVESTIGATION REPORT",
            "=" * 50,
            "",
            f"Target: {investigation.get('target', 'N/A')}",
            f"Investigation Type: {investigation.get('investigation_type', 'N/A')}",
            f"Status: {investigation.get('status', 'N/A')}",
            f"Risk Score: {investigation.get('risk_score', 'N/A')}/100",
            f"Created: {created_date.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Investigator: {user_email}",
            "",
            "SUMMARY",
            "-" * 20,
            investigation.get('summary', 'No summary available'),
            ""
        ]
        
        # Add findings
        findings = investigation.get('findings', {})
        if findings:
            report_lines.extend([
                "FINDINGS",
                "-" * 20
            ])
            for category, data in findings.items():
                report_lines.append(f"\n{category.upper().replace('_', ' ')}:")
                if data:
                    for key, value in data.items():
                        report_lines.append(f"  {key}: {value}")
                else:
                    report_lines.append("  No findings in this category")
        
        # Add errors
        errors = investigation.get('errors', [])
        if errors:
            report_lines.extend([
                "",
                "COLLECTION ERRORS",
                "-" * 20
            ])
            for error in errors:
                report_lines.append(f"• {error}")
        
        report_lines.extend([
            "",
            "=" * 50,
            f"Generated by Enterprise OSINT Platform on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "This report contains sensitive information. Handle appropriately."
        ])
        
        report_content = "\n".join(report_lines)
        filename = f"investigation-report-{investigation.get('id', 'unknown')[:8]}.txt"
        
        return Response(
            content=report_content,
            media_type="text/plain",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )


# Global report generator instance
report_generator = OSINTReportGenerator()
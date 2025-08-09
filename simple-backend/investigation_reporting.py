#!/usr/bin/env python3
"""
Investigation Activity Reporting System
Comprehensive tracking and reporting of investigator activities, targets, and investigation patterns
"""

import logging
import csv
import io
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from enum import Enum

from models import OSINTInvestigation, InvestigationType, InvestigationStatus, Priority

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report output formats"""
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    HTML = "html"


class TimeRange(Enum):
    """Predefined time ranges for reports"""
    LAST_24_HOURS = "24h"
    LAST_7_DAYS = "7d"
    LAST_30_DAYS = "30d"
    LAST_90_DAYS = "90d"
    CUSTOM = "custom"


@dataclass
class InvestigationSummary:
    """Summary information for a single investigation"""
    investigation_id: str
    target: str
    investigator_name: str
    investigator_id: str
    investigation_type: str
    priority: str
    status: str
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    processing_time_seconds: float
    data_points_collected: int
    api_calls_made: int
    cost_estimate_usd: float
    risk_score: float
    compliance_status: str
    classification_level: str
    geographical_scope: List[str] = field(default_factory=list)
    key_findings_count: int = 0
    warnings_count: int = 0


@dataclass
class InvestigatorProfile:
    """Profile information for an investigator"""
    investigator_id: str
    investigator_name: str
    total_investigations: int
    investigations_by_type: Dict[str, int]
    investigations_by_priority: Dict[str, int]
    investigations_by_status: Dict[str, int]
    avg_processing_time: float
    total_data_points: int
    total_api_calls: int
    total_cost: float
    success_rate: float
    compliance_rate: float
    first_investigation: datetime
    last_investigation: datetime
    most_investigated_targets: List[Tuple[str, int]]
    preferred_investigation_types: List[str]


@dataclass
class InvestigationActivityReport:
    """Comprehensive investigation activity report"""
    report_id: str
    generated_at: datetime
    time_range: Dict[str, str]
    total_investigations: int
    
    # Summary statistics
    investigators: List[InvestigatorProfile]
    investigation_summaries: List[InvestigationSummary]
    
    # Analytics
    investigations_by_type: Dict[str, int]
    investigations_by_priority: Dict[str, int]
    investigations_by_status: Dict[str, int]
    investigations_by_day: Dict[str, int]
    top_targets: List[Tuple[str, int]]
    top_investigators: List[Tuple[str, int]]
    
    # Performance metrics
    avg_processing_time: float
    total_data_points: int
    total_api_calls: int
    total_cost: float
    success_rate: float
    compliance_rate: float
    
    # Risk and security
    high_risk_investigations: int
    classified_investigations: int
    cross_border_investigations: int
    
    # Operational insights
    peak_activity_hours: List[int]
    busiest_days: List[str]
    investigation_trends: Dict[str, Any]


class InvestigationReportGenerator:
    """Main class for generating investigation activity reports"""
    
    def __init__(self, investigation_orchestrator):
        self.orchestrator = investigation_orchestrator
        self.report_cache = {}
    
    def generate_activity_report(self, 
                               start_date: Optional[datetime] = None,
                               end_date: Optional[datetime] = None,
                               time_range: TimeRange = TimeRange.LAST_30_DAYS,
                               investigator_filter: Optional[str] = None,
                               investigation_type_filter: Optional[InvestigationType] = None,
                               priority_filter: Optional[Priority] = None,
                               include_detailed_summaries: bool = True) -> InvestigationActivityReport:
        """Generate comprehensive investigation activity report"""
        
        # Determine time range
        if time_range != TimeRange.CUSTOM:
            end_date = datetime.utcnow()
            if time_range == TimeRange.LAST_24_HOURS:
                start_date = end_date - timedelta(hours=24)
            elif time_range == TimeRange.LAST_7_DAYS:
                start_date = end_date - timedelta(days=7)
            elif time_range == TimeRange.LAST_30_DAYS:
                start_date = end_date - timedelta(days=30)
            elif time_range == TimeRange.LAST_90_DAYS:
                start_date = end_date - timedelta(days=90)
        
        if not start_date or not end_date:
            raise ValueError("Start and end dates must be provided for custom time range")
        
        # Get all investigations in time range
        all_investigations = self.orchestrator.get_active_investigations()
        filtered_investigations = self._filter_investigations(
            all_investigations, start_date, end_date, 
            investigator_filter, investigation_type_filter, priority_filter
        )
        
        # Generate report ID
        report_id = f"activity_report_{int(datetime.utcnow().timestamp())}"
        
        # Create investigation summaries
        investigation_summaries = []
        if include_detailed_summaries:
            investigation_summaries = [
                self._create_investigation_summary(inv) for inv in filtered_investigations
            ]
        
        # Generate investigator profiles
        investigator_profiles = self._generate_investigator_profiles(filtered_investigations)
        
        # Calculate analytics
        analytics = self._calculate_investigation_analytics(filtered_investigations)
        
        # Generate performance metrics
        performance_metrics = self._calculate_performance_metrics(filtered_investigations)
        
        # Generate operational insights
        operational_insights = self._generate_operational_insights(filtered_investigations)
        
        # Create comprehensive report
        report = InvestigationActivityReport(
            report_id=report_id,
            generated_at=datetime.utcnow(),
            time_range={
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
                'range_type': time_range.value
            },
            total_investigations=len(filtered_investigations),
            investigators=investigator_profiles,
            investigation_summaries=investigation_summaries,
            **analytics,
            **performance_metrics,
            **operational_insights
        )
        
        # Cache report
        self.report_cache[report_id] = report
        
        logger.info(f"Generated investigation activity report {report_id} covering {len(filtered_investigations)} investigations")
        
        return report
    
    def _filter_investigations(self, 
                             investigations: List[OSINTInvestigation],
                             start_date: datetime,
                             end_date: datetime,
                             investigator_filter: Optional[str],
                             investigation_type_filter: Optional[InvestigationType],
                             priority_filter: Optional[Priority]) -> List[OSINTInvestigation]:
        """Filter investigations based on criteria"""
        
        filtered = []
        
        for inv in investigations:
            # Time range filter
            if not (start_date <= inv.created_at <= end_date):
                continue
            
            # Investigator filter
            if investigator_filter and inv.investigator_name.lower() != investigator_filter.lower():
                continue
            
            # Investigation type filter
            if investigation_type_filter and inv.investigation_type != investigation_type_filter:
                continue
            
            # Priority filter
            if priority_filter and inv.priority != priority_filter:
                continue
            
            filtered.append(inv)
        
        return filtered
    
    def _create_investigation_summary(self, investigation: OSINTInvestigation) -> InvestigationSummary:
        """Create detailed summary for a single investigation"""
        
        # Calculate processing time
        processing_time = 0.0
        if investigation.started_at and investigation.completed_at:
            processing_time = (investigation.completed_at - investigation.started_at).total_seconds()
        elif investigation.processing_time_seconds:
            processing_time = investigation.processing_time_seconds
        
        # Determine geographical scope
        geographical_scope = []
        if investigation.infrastructure_intelligence and investigation.infrastructure_intelligence.ip_addresses:
            for ip_info in investigation.infrastructure_intelligence.ip_addresses:
                location = ip_info.get('location')
                if location and location not in geographical_scope:
                    geographical_scope.append(location)
        
        # Calculate risk score
        risk_score = 0.0
        if investigation.risk_assessment:
            risk_score = investigation.risk_assessment.get('overall_risk_score', 0.0)
        
        # Determine compliance status
        compliance_status = "unknown"
        if investigation.compliance_reports:
            latest_report = investigation.compliance_reports[-1]
            compliance_status = "compliant" if latest_report.compliant else "non_compliant"
        
        return InvestigationSummary(
            investigation_id=investigation.id,
            target=investigation.target_profile.primary_identifier,
            investigator_name=investigation.investigator_name,
            investigator_id=investigation.investigator_id,
            investigation_type=investigation.investigation_type.value,
            priority=investigation.priority.value,
            status=investigation.status.value,
            created_at=investigation.created_at,
            started_at=investigation.started_at,
            completed_at=investigation.completed_at,
            processing_time_seconds=processing_time,
            data_points_collected=investigation.progress.data_points_collected,
            api_calls_made=investigation.api_calls_made,
            cost_estimate_usd=investigation.cost_estimate_usd,
            risk_score=risk_score,
            compliance_status=compliance_status,
            classification_level=investigation.classification_level,
            geographical_scope=geographical_scope,
            key_findings_count=len(investigation.key_findings),
            warnings_count=len(investigation.progress.warnings)
        )
    
    def _generate_investigator_profiles(self, investigations: List[OSINTInvestigation]) -> List[InvestigatorProfile]:
        """Generate detailed profiles for each investigator"""
        
        investigator_data = defaultdict(lambda: {
            'investigations': [],
            'total_processing_time': 0.0,
            'total_data_points': 0,
            'total_api_calls': 0,
            'total_cost': 0.0,
            'successful_investigations': 0,
            'compliant_investigations': 0,
            'targets': []
        })
        
        # Aggregate data by investigator
        for inv in investigations:
            investigator_id = inv.investigator_id
            investigator_data[investigator_id]['investigations'].append(inv)
            investigator_data[investigator_id]['total_processing_time'] += inv.processing_time_seconds or 0
            investigator_data[investigator_id]['total_data_points'] += inv.progress.data_points_collected
            investigator_data[investigator_id]['total_api_calls'] += inv.api_calls_made
            investigator_data[investigator_id]['total_cost'] += inv.cost_estimate_usd
            investigator_data[investigator_id]['targets'].append(inv.target_profile.primary_identifier)
            
            if inv.status == InvestigationStatus.COMPLETED:
                investigator_data[investigator_id]['successful_investigations'] += 1
            
            if inv.compliance_reports and any(report.compliant for report in inv.compliance_reports):
                investigator_data[investigator_id]['compliant_investigations'] += 1
        
        # Generate profiles
        profiles = []
        for investigator_id, data in investigator_data.items():
            investigations_list = data['investigations']
            total_investigations = len(investigations_list)
            
            if total_investigations == 0:
                continue
            
            # Calculate statistics
            investigations_by_type = Counter(inv.investigation_type.value for inv in investigations_list)
            investigations_by_priority = Counter(inv.priority.value for inv in investigations_list)
            investigations_by_status = Counter(inv.status.value for inv in investigations_list)
            
            avg_processing_time = data['total_processing_time'] / total_investigations
            success_rate = (data['successful_investigations'] / total_investigations) * 100
            compliance_rate = (data['compliant_investigations'] / total_investigations) * 100
            
            # Most investigated targets
            target_counts = Counter(data['targets'])
            most_investigated_targets = target_counts.most_common(10)
            
            # Preferred investigation types
            preferred_types = [type_name for type_name, _ in investigations_by_type.most_common(3)]
            
            # Timeline
            investigation_dates = [inv.created_at for inv in investigations_list]
            first_investigation = min(investigation_dates)
            last_investigation = max(investigation_dates)
            
            profile = InvestigatorProfile(
                investigator_id=investigator_id,
                investigator_name=investigations_list[0].investigator_name,
                total_investigations=total_investigations,
                investigations_by_type=dict(investigations_by_type),
                investigations_by_priority=dict(investigations_by_priority),
                investigations_by_status=dict(investigations_by_status),
                avg_processing_time=avg_processing_time,
                total_data_points=data['total_data_points'],
                total_api_calls=data['total_api_calls'],
                total_cost=data['total_cost'],
                success_rate=round(success_rate, 1),
                compliance_rate=round(compliance_rate, 1),
                first_investigation=first_investigation,
                last_investigation=last_investigation,
                most_investigated_targets=most_investigated_targets,
                preferred_investigation_types=preferred_types
            )
            
            profiles.append(profile)
        
        # Sort by total investigations (most active first)
        profiles.sort(key=lambda p: p.total_investigations, reverse=True)
        
        return profiles
    
    def _calculate_investigation_analytics(self, investigations: List[OSINTInvestigation]) -> Dict[str, Any]:
        """Calculate investigation analytics and breakdowns"""
        
        # Basic breakdowns
        investigations_by_type = Counter(inv.investigation_type.value for inv in investigations)
        investigations_by_priority = Counter(inv.priority.value for inv in investigations)
        investigations_by_status = Counter(inv.status.value for inv in investigations)
        
        # Daily investigation counts
        investigations_by_day = Counter()
        for inv in investigations:
            day_key = inv.created_at.strftime('%Y-%m-%d')
            investigations_by_day[day_key] += 1
        
        # Top targets (most investigated)
        target_counts = Counter(inv.target_profile.primary_identifier for inv in investigations)
        top_targets = target_counts.most_common(20)
        
        # Top investigators (by volume)
        investigator_counts = Counter(inv.investigator_name for inv in investigations)
        top_investigators = investigator_counts.most_common(10)
        
        return {
            'investigations_by_type': dict(investigations_by_type),
            'investigations_by_priority': dict(investigations_by_priority),
            'investigations_by_status': dict(investigations_by_status),
            'investigations_by_day': dict(investigations_by_day),
            'top_targets': top_targets,
            'top_investigators': top_investigators
        }
    
    def _calculate_performance_metrics(self, investigations: List[OSINTInvestigation]) -> Dict[str, Any]:
        """Calculate performance and efficiency metrics"""
        
        if not investigations:
            return {
                'avg_processing_time': 0.0,
                'total_data_points': 0,
                'total_api_calls': 0,
                'total_cost': 0.0,
                'success_rate': 0.0,
                'compliance_rate': 0.0
            }
        
        # Processing time metrics
        processing_times = [inv.processing_time_seconds for inv in investigations if inv.processing_time_seconds]
        avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0.0
        
        # Data collection metrics
        total_data_points = sum(inv.progress.data_points_collected for inv in investigations)
        total_api_calls = sum(inv.api_calls_made for inv in investigations)
        total_cost = sum(inv.cost_estimate_usd for inv in investigations)
        
        # Success rate
        completed_investigations = len([inv for inv in investigations if inv.status == InvestigationStatus.COMPLETED])
        success_rate = (completed_investigations / len(investigations)) * 100
        
        # Compliance rate
        compliant_investigations = len([
            inv for inv in investigations 
            if inv.compliance_reports and any(report.compliant for report in inv.compliance_reports)
        ])
        compliance_rate = (compliant_investigations / len(investigations)) * 100
        
        return {
            'avg_processing_time': round(avg_processing_time, 2),
            'total_data_points': total_data_points,
            'total_api_calls': total_api_calls,
            'total_cost': round(total_cost, 2),
            'success_rate': round(success_rate, 1),
            'compliance_rate': round(compliance_rate, 1)
        }
    
    def _generate_operational_insights(self, investigations: List[OSINTInvestigation]) -> Dict[str, Any]:
        """Generate operational insights and patterns"""
        
        # Risk and security metrics
        high_risk_investigations = len([
            inv for inv in investigations 
            if inv.risk_assessment and inv.risk_assessment.get('overall_risk_score', 0) > 70
        ])
        
        classified_investigations = len([
            inv for inv in investigations 
            if inv.classification_level in ['confidential', 'restricted']
        ])
        
        cross_border_investigations = len([
            inv for inv in investigations
            if inv.infrastructure_intelligence and inv.infrastructure_intelligence.ip_addresses
            and len(set(ip.get('location', 'US') for ip in inv.infrastructure_intelligence.ip_addresses)) > 1
        ])
        
        # Activity patterns
        hourly_activity = Counter()
        daily_activity = Counter()
        
        for inv in investigations:
            hour = inv.created_at.hour
            day = inv.created_at.strftime('%A')
            hourly_activity[hour] += 1
            daily_activity[day] += 1
        
        peak_activity_hours = [hour for hour, _ in hourly_activity.most_common(3)]
        busiest_days = [day for day, _ in daily_activity.most_common(3)]
        
        # Investigation trends (simplified)
        investigation_trends = {
            'most_common_type': Counter(inv.investigation_type.value for inv in investigations).most_common(1)[0] if investigations else ("none", 0),
            'most_common_priority': Counter(inv.priority.value for inv in investigations).most_common(1)[0] if investigations else ("none", 0),
            'average_findings_per_investigation': round(sum(len(inv.key_findings) for inv in investigations) / len(investigations), 1) if investigations else 0.0
        }
        
        return {
            'high_risk_investigations': high_risk_investigations,
            'classified_investigations': classified_investigations,
            'cross_border_investigations': cross_border_investigations,
            'peak_activity_hours': peak_activity_hours,
            'busiest_days': busiest_days,
            'investigation_trends': investigation_trends
        }
    
    def export_report(self, report: InvestigationActivityReport, format_type: ReportFormat) -> str:
        """Export report in specified format"""
        
        if format_type == ReportFormat.JSON:
            return self._export_json(report)
        elif format_type == ReportFormat.CSV:
            return self._export_csv(report)
        elif format_type == ReportFormat.HTML:
            return self._export_html(report)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_json(self, report: InvestigationActivityReport) -> str:
        """Export report as JSON"""
        
        def serialize_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj
        
        # Convert dataclass to dict with datetime serialization
        report_dict = {
            'report_id': report.report_id,
            'generated_at': serialize_datetime(report.generated_at),
            'time_range': report.time_range,
            'total_investigations': report.total_investigations,
            'summary_statistics': {
                'investigations_by_type': report.investigations_by_type,
                'investigations_by_priority': report.investigations_by_priority,
                'investigations_by_status': report.investigations_by_status,
                'top_targets': report.top_targets[:10],
                'top_investigators': report.top_investigators[:10]
            },
            'performance_metrics': {
                'avg_processing_time': report.avg_processing_time,
                'total_data_points': report.total_data_points,
                'total_api_calls': report.total_api_calls,
                'total_cost': report.total_cost,
                'success_rate': report.success_rate,
                'compliance_rate': report.compliance_rate
            },
            'security_metrics': {
                'high_risk_investigations': report.high_risk_investigations,
                'classified_investigations': report.classified_investigations,
                'cross_border_investigations': report.cross_border_investigations
            },
            'investigators': [
                {
                    'investigator_name': inv.investigator_name,
                    'total_investigations': inv.total_investigations,
                    'investigations_by_type': inv.investigations_by_type,
                    'success_rate': inv.success_rate,
                    'compliance_rate': inv.compliance_rate,
                    'most_investigated_targets': inv.most_investigated_targets[:5]
                }
                for inv in report.investigators
            ],
            'investigations': [
                {
                    'investigation_id': inv.investigation_id,
                    'target': inv.target,
                    'investigator': inv.investigator_name,
                    'type': inv.investigation_type,
                    'priority': inv.priority,
                    'status': inv.status,
                    'created_at': serialize_datetime(inv.created_at),
                    'processing_time': inv.processing_time_seconds,
                    'risk_score': inv.risk_score,
                    'compliance_status': inv.compliance_status
                }
                for inv in report.investigation_summaries
            ]
        }
        
        return json.dumps(report_dict, indent=2, default=str)
    
    def _export_csv(self, report: InvestigationActivityReport) -> str:
        """Export investigation summaries as CSV"""
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        headers = [
            'Investigation ID', 'Target', 'Investigator', 'Type', 'Priority', 'Status',
            'Created At', 'Started At', 'Completed At', 'Processing Time (s)',
            'Data Points', 'API Calls', 'Cost (USD)', 'Risk Score',
            'Compliance Status', 'Classification', 'Findings Count', 'Warnings Count'
        ]
        writer.writerow(headers)
        
        # Write investigation data
        for inv in report.investigation_summaries:
            row = [
                inv.investigation_id,
                inv.target,
                inv.investigator_name,
                inv.investigation_type,
                inv.priority,
                inv.status,
                inv.created_at.isoformat() if inv.created_at else '',
                inv.started_at.isoformat() if inv.started_at else '',
                inv.completed_at.isoformat() if inv.completed_at else '',
                inv.processing_time_seconds,
                inv.data_points_collected,
                inv.api_calls_made,
                inv.cost_estimate_usd,
                inv.risk_score,
                inv.compliance_status,
                inv.classification_level,
                inv.key_findings_count,
                inv.warnings_count
            ]
            writer.writerow(row)
        
        return output.getvalue()
    
    def _export_html(self, report: InvestigationActivityReport) -> str:
        """Export report as HTML"""
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Investigation Activity Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .section {{ margin-bottom: 30px; }}
                .metrics {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .metric {{ text-align: center; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .summary {{ background-color: #f9f9f9; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 Investigation Activity Report</h1>
                <p>Report ID: {report_id}</p>
                <p>Generated: {generated_at}</p>
                <p>Time Range: {time_range}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="summary">
                    <div class="metrics">
                        <div class="metric">
                            <h3>{total_investigations}</h3>
                            <p>Total Investigations</p>
                        </div>
                        <div class="metric">
                            <h3>{success_rate}%</h3>
                            <p>Success Rate</p>
                        </div>
                        <div class="metric">
                            <h3>{compliance_rate}%</h3>
                            <p>Compliance Rate</p>
                        </div>
                        <div class="metric">
                            <h3>${total_cost}</h3>
                            <p>Total Cost</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Top Investigators</h2>
                <table>
                    <tr><th>Investigator</th><th>Investigations</th><th>Success Rate</th><th>Compliance Rate</th></tr>
                    {investigator_rows}
                </table>
            </div>
            
            <div class="section">
                <h2>Investigation Breakdown</h2>
                <h3>By Type:</h3>
                <ul>{type_breakdown}</ul>
                <h3>By Priority:</h3>
                <ul>{priority_breakdown}</ul>
            </div>
            
            <div class="section">
                <h2>Recent Investigations</h2>
                <table>
                    <tr><th>Target</th><th>Investigator</th><th>Type</th><th>Priority</th><th>Status</th><th>Created</th></tr>
                    {investigation_rows}
                </table>
            </div>
        </body>
        </html>
        """
        
        # Format investigator rows
        investigator_rows = ""
        for inv in report.investigators[:10]:
            investigator_rows += f"""
            <tr>
                <td>{inv.investigator_name}</td>
                <td>{inv.total_investigations}</td>
                <td>{inv.success_rate}%</td>
                <td>{inv.compliance_rate}%</td>
            </tr>
            """
        
        # Format type breakdown
        type_breakdown = ""
        for inv_type, count in report.investigations_by_type.items():
            type_breakdown += f"<li>{inv_type}: {count}</li>"
        
        # Format priority breakdown  
        priority_breakdown = ""
        for priority, count in report.investigations_by_priority.items():
            priority_breakdown += f"<li>{priority}: {count}</li>"
        
        # Format recent investigations
        investigation_rows = ""
        for inv in report.investigation_summaries[:20]:
            investigation_rows += f"""
            <tr>
                <td>{inv.target}</td>
                <td>{inv.investigator_name}</td>
                <td>{inv.investigation_type}</td>
                <td>{inv.priority}</td>
                <td>{inv.status}</td>
                <td>{inv.created_at.strftime('%Y-%m-%d %H:%M')}</td>
            </tr>
            """
        
        return html_template.format(
            report_id=report.report_id,
            generated_at=report.generated_at.strftime('%Y-%m-%d %H:%M:%S'),
            time_range=f"{report.time_range['start'][:10]} to {report.time_range['end'][:10]}",
            total_investigations=report.total_investigations,
            success_rate=report.success_rate,
            compliance_rate=report.compliance_rate,
            total_cost=report.total_cost,
            investigator_rows=investigator_rows,
            type_breakdown=type_breakdown,
            priority_breakdown=priority_breakdown,
            investigation_rows=investigation_rows
        )
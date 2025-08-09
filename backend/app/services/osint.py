"""
OSINT Investigation Service
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from app import db, socketio
from app.models.investigation import Investigation, InvestigationStatus
from app.services.mcp_client import MCPClient
from app.services.pdf_generator import PDFGenerator

logger = logging.getLogger(__name__)


class OSINTService:
    """Service for running OSINT investigations"""
    
    @staticmethod
    def emit_progress(investigation_id: str, progress: int, message: str, data: Dict = None):
        """Emit progress update via WebSocket"""
        socketio.emit('investigation_progress', {
            'investigation_id': investigation_id,
            'progress': progress,
            'message': message,
            'data': data or {},
            'timestamp': datetime.utcnow().isoformat()
        }, room=f'investigation_{investigation_id}')
    
    @staticmethod
    async def run_investigation(investigation_id: int) -> Dict[str, Any]:
        """Run a complete OSINT investigation"""
        investigation = Investigation.query.get(investigation_id)
        if not investigation:
            raise ValueError(f"Investigation {investigation_id} not found")
        
        try:
            # Start investigation
            investigation.start()
            db.session.commit()
            
            # Initialize results structure
            results = {
                'corporate': {},
                'infrastructure': {},
                'social': {},
                'threats': {},
                'summary': {},
                'metadata': {
                    'investigation_id': investigation.uuid,
                    'target': investigation.target,
                    'type': investigation.type.value,
                    'started_at': datetime.utcnow().isoformat()
                }
            }
            
            # Phase 1: Corporate Intelligence (20%)
            OSINTService.emit_progress(investigation.uuid, 10, 
                                     "Starting corporate intelligence gathering...")
            corporate_data = await OSINTService._gather_corporate_intelligence(
                investigation.target, investigation.type.value
            )
            results['corporate'] = corporate_data
            investigation.update_progress(20, "Corporate intelligence completed")
            OSINTService.emit_progress(investigation.uuid, 20, 
                                     "Corporate intelligence completed", 
                                     {'phase': 'corporate', 'data': corporate_data})
            
            # Phase 2: Infrastructure Assessment (40%)
            OSINTService.emit_progress(investigation.uuid, 30, 
                                     "Analyzing infrastructure...")
            async with MCPClient() as mcp:
                infra_results = await mcp.execute_investigation_tools(
                    investigation.target, 'infrastructure'
                )
                results['infrastructure'] = infra_results['infrastructure']
            investigation.update_progress(40, "Infrastructure assessment completed")
            OSINTService.emit_progress(investigation.uuid, 40, 
                                     "Infrastructure assessment completed",
                                     {'phase': 'infrastructure', 'data': results['infrastructure']})
            
            # Phase 3: Social Media Intelligence (60%)
            OSINTService.emit_progress(investigation.uuid, 50, 
                                     "Gathering social media intelligence...")
            async with MCPClient() as mcp:
                social_results = await mcp.execute_investigation_tools(
                    investigation.target, 'social_media'
                )
                results['social'] = social_results['social_media']
            investigation.update_progress(60, "Social media analysis completed")
            OSINTService.emit_progress(investigation.uuid, 60, 
                                     "Social media analysis completed",
                                     {'phase': 'social', 'data': results['social']})
            
            # Phase 4: Threat Intelligence (80%)
            OSINTService.emit_progress(investigation.uuid, 70, 
                                     "Assessing threats...")
            async with MCPClient() as mcp:
                threat_results = await mcp.execute_investigation_tools(
                    investigation.target, 'threat_assessment'
                )
                results['threats'] = threat_results['threat_intel']
            investigation.update_progress(80, "Threat assessment completed")
            OSINTService.emit_progress(investigation.uuid, 80, 
                                     "Threat assessment completed",
                                     {'phase': 'threats', 'data': results['threats']})
            
            # Phase 5: Analysis and Summary (100%)
            OSINTService.emit_progress(investigation.uuid, 90, 
                                     "Generating executive summary...")
            summary = OSINTService._generate_summary(results)
            results['summary'] = summary
            
            # Calculate threat level
            threat_level = OSINTService._calculate_threat_level(results)
            
            # Complete investigation
            investigation.complete(
                results=results,
                summary=summary['executive_summary'],
                threat_level=threat_level
            )
            db.session.commit()
            
            OSINTService.emit_progress(investigation.uuid, 100, 
                                     "Investigation completed successfully",
                                     {'phase': 'completed', 'threat_level': threat_level})
            
            # Emit completion event
            socketio.emit('investigation_completed', {
                'investigation_id': investigation.uuid,
                'status': 'completed',
                'threat_level': threat_level,
                'summary': summary['executive_summary']
            }, room=f'investigation_{investigation.uuid}')
            
            return results
            
        except Exception as e:
            logger.error(f"Investigation {investigation_id} failed: {str(e)}")
            investigation.fail(str(e))
            db.session.commit()
            
            # Emit failure event
            socketio.emit('investigation_failed', {
                'investigation_id': investigation.uuid,
                'error': str(e)
            }, room=f'investigation_{investigation.uuid}')
            
            raise
    
    @staticmethod
    async def _gather_corporate_intelligence(target: str, investigation_type: str) -> Dict[str, Any]:
        """Gather corporate intelligence data"""
        # This would integrate with corporate data sources
        # For now, return structured mock data
        return {
            'company_info': {
                'name': target.replace('.com', '').title() + ' Corporation',
                'industry': 'Technology',
                'founded': '2010',
                'employees': '100-500',
                'revenue': '$10M-$50M',
                'headquarters': 'San Francisco, CA',
                'website': f'https://{target}'
            },
            'executives': [
                {'name': 'John Doe', 'title': 'CEO', 'linkedin': '/in/johndoe'},
                {'name': 'Jane Smith', 'title': 'CTO', 'linkedin': '/in/janesmith'}
            ],
            'financials': {
                'funding_total': '$25M',
                'last_round': 'Series B - $15M (2023)',
                'investors': ['Venture Capital Fund', 'Angel Investors']
            },
            'compliance': {
                'gdpr_compliant': True,
                'iso_27001': False,
                'soc2': True
            }
        }
    
    @staticmethod
    def _generate_summary(results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary from investigation results"""
        summary = {
            'executive_summary': '',
            'key_findings': [],
            'risk_indicators': [],
            'recommendations': []
        }
        
        # Analyze corporate data
        if results.get('corporate', {}).get('company_info'):
            company = results['corporate']['company_info']['name']
            summary['executive_summary'] = f"Comprehensive OSINT investigation of {company} "
        
        # Analyze infrastructure
        if results.get('infrastructure', {}).get('ssl'):
            ssl_grade = results['infrastructure']['ssl'].get('grade', 'Unknown')
            if ssl_grade in ['A+', 'A']:
                summary['key_findings'].append('Strong SSL/TLS configuration detected')
            else:
                summary['risk_indicators'].append(f'SSL grade {ssl_grade} indicates potential security issues')
        
        # Analyze threats
        threat_assessment = results.get('threats', {}).get('assessment', {})
        if threat_assessment.get('high_risk_indicators', 0) > 0:
            summary['risk_indicators'].append('High-risk threat indicators detected')
            summary['recommendations'].append('Immediate security review recommended')
        
        # Compile executive summary
        risk_count = len(summary['risk_indicators'])
        if risk_count == 0:
            summary['executive_summary'] += "reveals a low-risk profile with strong security posture."
        elif risk_count <= 2:
            summary['executive_summary'] += "identifies moderate risk factors requiring attention."
        else:
            summary['executive_summary'] += "uncovers significant security concerns requiring immediate action."
        
        # Add standard recommendations
        summary['recommendations'].extend([
            'Continue regular security monitoring',
            'Implement automated threat detection',
            'Review and update security policies'
        ])
        
        return summary
    
    @staticmethod
    def _calculate_threat_level(results: Dict[str, Any]) -> str:
        """Calculate overall threat level from results"""
        threat_score = 0
        
        # Check infrastructure risks
        if results.get('infrastructure', {}).get('ssl', {}).get('grade', 'F') not in ['A+', 'A', 'B']:
            threat_score += 2
        
        if results.get('infrastructure', {}).get('subdomains', {}).get('vulnerable_count', 0) > 0:
            threat_score += 3
        
        # Check threat intelligence
        threat_data = results.get('threats', {})
        if threat_data.get('assessment', {}).get('malware_indicators', 0) > 0:
            threat_score += 5
        
        if threat_data.get('breaches', {}).get('breach_count', 0) > 0:
            threat_score += 3
        
        if threat_data.get('reputation', {}).get('blacklisted', False):
            threat_score += 4
        
        # Calculate level
        if threat_score >= 10:
            return 'critical'
        elif threat_score >= 6:
            return 'high'
        elif threat_score >= 3:
            return 'medium'
        else:
            return 'low'
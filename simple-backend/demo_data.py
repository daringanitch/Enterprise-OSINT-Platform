#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.
# Individual use is free. Commercial use requires 3% profit sharing.
# See LICENSE file for details.

"""
Demo Data System

Provides realistic demo data for investigations when in demo mode.
"""

import json
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import dataclass
import uuid

@dataclass
class DemoInvestigation:
    """Demo investigation data structure"""
    id: str
    target: str
    status: str
    investigation_type: str
    investigator_name: str
    created_at: str
    completed_at: str
    findings: Dict[str, Any]
    risk_score: float
    confidence_level: str

class DemoDataProvider:
    """Provides demo data for all platform features"""
    
    def __init__(self):
        self.demo_targets = [
            "example.com", "demo-company.org", "test-site.net", 
            "sample-corp.com", "mock-enterprise.io"
        ]
        self.investigators = [
            "Demo Analyst", "Sample Investigator", "Test User",
            "Training Account", "Demo Admin"
        ]
    
    def generate_demo_investigations(self, count: int = 5) -> List[Dict[str, Any]]:
        """Generate demo investigations"""
        investigations = []
        
        for i in range(count):
            target = random.choice(self.demo_targets)
            investigator = random.choice(self.investigators)
            
            # Create timestamps
            created = datetime.utcnow() - timedelta(days=random.randint(1, 30))
            completed = created + timedelta(hours=random.randint(1, 48))
            
            # Generate demo findings
            findings = self._generate_demo_findings(target)
            
            investigation = {
                'id': f'demo_{uuid.uuid4().hex[:12]}',
                'target_profile': {
                    'primary_identifier': target,
                    'target_type': 'domain',
                    'target_id': f'demo_target_{i}'
                },
                'status': random.choice(['completed', 'completed', 'completed', 'failed']),  # Mostly completed
                'investigation_type': 'comprehensive',
                'investigator_name': investigator,
                'investigator_id': investigator.lower().replace(' ', '_'),
                'priority': random.choice(['normal', 'high', 'low']),
                'created_at': created.isoformat(),
                'completed_at': completed.isoformat() if random.choice([True, True, False]) else None,
                'current_stage': 'completed',
                'current_activity': 'Demo investigation completed',
                'progress_percentage': 100,
                'stage_progress': 100,
                'can_generate_report': True,
                'report_available': False,  # Demo reports aren't actually generated
                'findings': findings,
                'risk_assessment': {
                    'score': round(random.uniform(0.1, 0.8), 2),
                    'level': random.choice(['low', 'low', 'medium', 'high'])
                },
                'cost_estimate_usd': round(random.uniform(0.50, 5.00), 2),
                'api_calls_made': random.randint(3, 15),
                'classification_level': 'confidential',
                'progress': {
                    'overall_progress': 100.0,
                    'data_points_collected': random.randint(5, 25),
                    'current_activity': 'Demo investigation completed',
                    'errors_encountered': 0
                }
            }
            
            investigations.append(investigation)
        
        return investigations
    
    def _generate_demo_findings(self, target: str) -> Dict[str, Any]:
        """Generate realistic demo findings for a target"""
        return {
            'infrastructure': [
                {
                    'type': 'domain_analysis',
                    'domain': target,
                    'status': 'active',
                    'registrar': random.choice(['GoDaddy', 'Namecheap', 'CloudFlare']),
                    'creation_date': (datetime.utcnow() - timedelta(days=random.randint(365, 2000))).isoformat()
                },
                {
                    'type': 'dns_records',
                    'records_found': random.randint(5, 20),
                    'mx_records': random.randint(1, 3),
                    'a_records': random.randint(1, 5)
                },
                {
                    'type': 'ssl_certificate',
                    'valid': True,
                    'issuer': random.choice(['Let\'s Encrypt', 'DigiCert', 'Comodo']),
                    'expires': (datetime.utcnow() + timedelta(days=random.randint(30, 365))).isoformat()
                }
            ],
            'threat_intelligence': [
                {
                    'type': 'reputation_check',
                    'score': random.randint(85, 100),
                    'status': random.choice(['clean', 'clean', 'clean', 'suspicious']),
                    'sources': random.choice([['VirusTotal'], ['AbuseIPDB'], ['VirusTotal', 'AbuseIPDB']])
                },
                {
                    'type': 'malware_scan',
                    'result': 'clean',
                    'last_scan': datetime.utcnow().isoformat()
                }
            ],
            'social_intelligence': [
                {
                    'type': 'social_media_presence',
                    'platforms': random.sample(['Twitter', 'LinkedIn', 'Facebook', 'Instagram'], random.randint(1, 3)),
                    'verified_accounts': random.randint(0, 2),
                    'total_followers': random.randint(100, 50000)
                },
                {
                    'type': 'company_info',
                    'employees': random.randint(10, 500),
                    'industry': random.choice(['Technology', 'Finance', 'Healthcare', 'Education', 'Retail'])
                }
            ],
            'summary': {
                'total_data_points': random.randint(8, 15),
                'risk_indicators': random.randint(0, 3),
                'confidence_score': random.randint(75, 95),
                'recommendation': random.choice([
                    'No immediate threats detected',
                    'Monitor for suspicious activity',
                    'Standard security posture observed',
                    'Follow up investigation recommended'
                ])
            }
        }
    
    def get_demo_system_status(self) -> Dict[str, Any]:
        """Get demo system status"""
        return {
            'mode': 'demo',
            'mcp_servers': {
                'infrastructure': {'status': 'healthy', 'response_time': '45ms', 'demo_mode': True},
                'threat': {'status': 'healthy', 'response_time': '32ms', 'demo_mode': True},
                'social': {'status': 'healthy', 'response_time': '58ms', 'demo_mode': True},
                'ai_analysis': {'status': 'healthy', 'response_time': '123ms', 'demo_mode': True}
            },
            'database': {'status': 'healthy', 'demo_data_loaded': True},
            'api_status': {
                'total_keys': 0,
                'active_keys': 0,
                'demo_mode_note': 'All data is simulated for demonstration purposes'
            }
        }
    
    def get_demo_api_status(self) -> Dict[str, Any]:
        """Get demo API status"""
        return {
            'available_apis': {
                'infrastructure': 1,  # Demo MCP server
                'threat_intelligence': 1,  # Demo MCP server
                'social_media': 1,  # Demo MCP server
                'ai_ml': 1  # Demo MCP server
            },
            'fallback_mode': False,  # Demo mode doesn't need fallback
            'investigation_capabilities': {
                'infrastructure_analysis': True,
                'threat_intelligence': True,
                'social_media_analysis': True,
                'ai_analysis': True
            },
            'warnings': [
                'Demo mode active: All data is simulated',
                'No real API calls are made in demo mode'
            ],
            'demo_features': [
                'Synthetic investigation data',
                'Mock threat intelligence',
                'Sample social media analysis',
                'Realistic progress simulation'
            ]
        }
    
    def generate_demo_report_data(self, investigation_id: str, target: str) -> Dict[str, Any]:
        """Generate demo report data"""
        return {
            'investigation_id': investigation_id,
            'target': target,
            'report_type': 'comprehensive',
            'generated_at': datetime.utcnow().isoformat(),
            'executive_summary': f'Demo investigation of {target} completed successfully. This is simulated data for demonstration purposes.',
            'key_findings': [
                f'{target} shows standard security posture',
                'No immediate threats detected in demo analysis',
                'Social media presence appears legitimate',
                'Infrastructure configuration follows best practices'
            ],
            'risk_assessment': {
                'overall_score': round(random.uniform(0.1, 0.4), 2),
                'category': 'Low Risk',
                'confidence': 'High'
            },
            'recommendations': [
                'Continue standard monitoring protocols',
                'No immediate action required',
                'Schedule routine follow-up in 90 days'
            ],
            'technical_details': {
                'data_points_analyzed': random.randint(15, 30),
                'sources_queried': random.randint(4, 8),
                'analysis_depth': 'Comprehensive',
                'demo_note': 'This report contains simulated data for demonstration'
            },
            'compliance': {
                'gdpr_compliant': True,
                'data_retention': '30 days',
                'privacy_level': 'Standard'
            }
        }

# Global demo data provider
demo_provider = DemoDataProvider()
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
        # Cache for demo investigations - generated once and reused
        self._cached_investigations: List[Dict[str, Any]] = []
        self._cache_generated = False

    def get_demo_investigations(self, count: int = 5) -> List[Dict[str, Any]]:
        """Get cached demo investigations (generates once, returns same data)"""
        if not self._cache_generated or len(self._cached_investigations) != count:
            self._cached_investigations = self._generate_demo_investigations(count)
            self._cache_generated = True
        return self._cached_investigations

    def get_demo_investigation(self, inv_id: str) -> Dict[str, Any]:
        """Get a specific demo investigation by ID"""
        # Ensure cache is populated
        if not self._cache_generated:
            self.get_demo_investigations()

        for inv in self._cached_investigations:
            if inv['id'] == inv_id:
                return inv
        return None

    def generate_demo_investigations(self, count: int = 5) -> List[Dict[str, Any]]:
        """Generate demo investigations - uses cache for consistency"""
        return self.get_demo_investigations(count)

    def _generate_demo_investigations(self, count: int = 5) -> List[Dict[str, Any]]:
        """Internal: Generate fresh demo investigations with deterministic IDs"""
        investigations = []

        # Deterministic data for consistent demo experience
        statuses = ['completed', 'completed', 'completed', 'completed', 'failed']
        priorities = ['high', 'normal', 'normal', 'low', 'high']
        risk_levels = ['low', 'medium', 'low', 'high', 'medium']
        risk_scores = [0.25, 0.45, 0.15, 0.72, 0.38]
        days_ago = [3, 7, 14, 21, 28]

        for i in range(count):
            target = self.demo_targets[i % len(self.demo_targets)]
            investigator = self.investigators[i % len(self.investigators)]

            # Create deterministic timestamps
            created = datetime.utcnow() - timedelta(days=days_ago[i % len(days_ago)])
            completed = created + timedelta(hours=2 + i * 3)

            # Generate demo findings
            findings = self._generate_demo_findings(target)

            investigation = {
                'id': f'demo_inv_{i + 1:03d}',  # Deterministic IDs: demo_inv_001, demo_inv_002, etc.
                'target_profile': {
                    'primary_identifier': target,
                    'target_type': 'domain',
                    'target_id': f'demo_target_{i}'
                },
                'status': statuses[i % len(statuses)],
                'investigation_type': 'comprehensive',
                'investigator_name': investigator,
                'investigator_id': investigator.lower().replace(' ', '_'),
                'priority': priorities[i % len(priorities)],
                'created_at': created.isoformat(),
                'completed_at': completed.isoformat() if statuses[i % len(statuses)] == 'completed' else None,
                'current_stage': 'completed' if statuses[i % len(statuses)] == 'completed' else 'failed',
                'current_activity': 'Demo investigation completed' if statuses[i % len(statuses)] == 'completed' else 'Demo investigation failed',
                'progress_percentage': 100 if statuses[i % len(statuses)] == 'completed' else 75,
                'stage_progress': 100 if statuses[i % len(statuses)] == 'completed' else 75,
                'can_generate_report': statuses[i % len(statuses)] == 'completed',
                'report_available': False,
                'findings': findings,
                'risk_assessment': {
                    'score': risk_scores[i % len(risk_scores)],
                    'level': risk_levels[i % len(risk_levels)]
                },
                'cost_estimate_usd': round(1.50 + i * 0.75, 2),
                'api_calls_made': 5 + i * 2,
                'classification_level': 'confidential',
                'progress': {
                    'overall_progress': 100.0 if statuses[i % len(statuses)] == 'completed' else 75.0,
                    'data_points_collected': 10 + i * 3,
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
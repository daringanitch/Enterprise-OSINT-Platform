#!/usr/bin/env python3
"""
Load synthetic OSINT data from the Amazon mock bundle
"""

import csv
import json
import os
from typing import Dict, List, Any
from datetime import datetime

class SyntheticDataLoader:
    """Load and manage synthetic OSINT data for demos"""
    
    def __init__(self, data_dir: str = "mock_data_fresh/datasets"):
        self.data_dir = data_dir
        self._load_all_data()
    
    def _load_all_data(self):
        """Load all synthetic data files"""
        try:
            # Load JSON files
            with open(os.path.join(self.data_dir, "dossier.json"), "r") as f:
                self.dossier = json.load(f)
            
            with open(os.path.join(self.data_dir, "graph.json"), "r") as f:
                self.graph = json.load(f)
            
            # Load CSV files
            self.domains = self._load_csv("domains.csv")
            self.dns_records = self._load_csv("dns_records.csv")
            self.subdomains = self._load_csv("subdomains.csv")
            self.certificates = self._load_csv("certificates.csv")
            self.brand_typosquats = self._load_csv("brand_typosquats.csv")
            self.security_headers = self._load_csv("security_headers.csv")
            self.policies = self._load_csv("policies.csv")
            self.infra_asns = self._load_csv("infra_asns.csv")
            self.oauth_saml = self._load_csv("oauth_saml.csv")
            self.findings = self._load_csv("findings.csv")
        except Exception as e:
            print(f"Warning: Could not load synthetic data: {e}")
            self._use_fallback_data()
    
    def _load_csv(self, filename: str) -> List[Dict[str, Any]]:
        """Load a CSV file and return as list of dicts"""
        filepath = os.path.join(self.data_dir, filename)
        data = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    data.append(row)
        except:
            pass
        return data
    
    def _use_fallback_data(self):
        """Use simple fallback data if files not found"""
        self.dossier = {
            "target": "example.com",
            "mode": "DEMO",
            "summary": {
                "highlights": ["Demo mode active", "Using synthetic data"],
                "risk_totals": {"high": 1, "medium": 2, "low": 3}
            }
        }
        self.domains = [{"domain": "example.com", "registrar": "Demo Registrar"}]
        self.dns_records = []
        self.subdomains = []
        self.findings = []
        self.graph = {"nodes": [], "edges": []}
    
    def get_corporate_intelligence(self, target: str) -> Dict[str, Any]:
        """Get corporate intelligence based on synthetic data"""
        # Check if we have Amazon data
        if self.dossier.get("target") == "amazon.com" and target.lower() in ["amazon", "amazon.com"]:
            return {
                "target": "amazon.com",
                "company_name": "Amazon.com, Inc.",
                "industry": "E-commerce / Cloud Computing",
                "founded": "1994",
                "headquarters": "Seattle, WA",
                "employees": "1,500,000+",
                "revenue": "$514 billion (2022)",
                "funding": "Public (NASDAQ: AMZN)",
                "executives": [
                    {"name": "Andy Jassy", "title": "CEO", "linkedin": "andy-jassy"},
                    {"name": "Brian Olsavsky", "title": "CFO", "linkedin": "brian-olsavsky"},
                    {"name": "Adam Selipsky", "title": "CEO AWS", "linkedin": "adam-selipsky"}
                ],
                "subsidiaries": ["AWS", "Whole Foods", "Twitch", "Audible", "IMDb"],
                "legal_status": "Active - Good Standing",
                "compliance_issues": "None identified (Mock Data)"
            }
        
        # Default for other targets
        return {
            "target": target,
            "company_name": f"{target.replace('.com', '').title()} Corporation",
            "industry": "Technology (Demo)",
            "founded": "2020",
            "headquarters": "Demo City, CA",
            "employees": "100-500",
            "revenue": "$10-50M (estimated)",
            "funding": "Series A",
            "executives": [
                {"name": "Demo CEO", "title": "CEO", "linkedin": "demo-ceo"},
                {"name": "Demo CTO", "title": "CTO", "linkedin": "demo-cto"}
            ],
            "subsidiaries": ["Demo Labs"],
            "legal_status": "Active - Demo Mode",
            "compliance_issues": "None (Synthetic Data)"
        }
    
    def get_infrastructure_intelligence(self, target: str) -> Dict[str, Any]:
        """Get infrastructure intelligence from synthetic data"""
        if self.dossier.get("target") == "amazon.com" and target.lower() in ["amazon", "amazon.com"]:
            # Use real Amazon synthetic data
            subdomains = [s["host"] for s in self.subdomains[:5]]
            
            return {
                "domain": "amazon.com",
                "ip_addresses": ["52.94.236.248", "54.239.28.85", "205.251.242.103"],
                "hosting_provider": "Amazon Web Services",
                "ssl_certificate": {
                    "issuer": "DigiCert Inc",
                    "valid_from": "2024-01-01",
                    "valid_until": "2025-01-01",
                    "grade": "A+"
                },
                "subdomains": subdomains,
                "open_ports": [80, 443],
                "security_headers": {
                    "hsts": True,
                    "csp": True,
                    "x_frame_options": True
                },
                "vulnerabilities": "None detected (Mock scan)",
                "cdn": "CloudFront, Akamai",
                "dns_records": {
                    "spf": "v=spf1 include:amazon.com ~all",
                    "dmarc": "p=reject; rua=mailto:dmarc@amazon.com",
                    "mx": ["amazon-smtp-inbound-1.us-east-1.amazonaws.com"]
                }
            }
        
        # Default infrastructure
        return {
            "domain": target,
            "ip_addresses": ["192.0.2.1", "192.0.2.2"],
            "hosting_provider": "Demo Hosting Provider",
            "ssl_certificate": {
                "issuer": "Demo CA",
                "valid_from": "2024-01-01",
                "valid_until": "2025-01-01",
                "grade": "A"
            },
            "open_ports": [80, 443, 22],
            "security_headers": {
                "hsts": True,
                "csp": False,
                "x_frame_options": True
            },
            "vulnerabilities": "None detected (Demo mode)",
            "cdn": "Demo CDN"
        }
    
    def get_social_intelligence(self, target: str) -> Dict[str, Any]:
        """Get social media intelligence"""
        if target.lower() in ["amazon", "amazon.com"]:
            return {
                "twitter_presence": {
                    "handle": "@amazon",
                    "followers": "5.8M",
                    "sentiment": "Mixed (72% positive)",
                    "recent_activity": "Active - 5 posts/day"
                },
                "linkedin_company": {
                    "followers": "29M",
                    "employees_on_platform": "1M+",
                    "recent_updates": "Hiring announcements, AWS updates"
                },
                "news_mentions": {
                    "last_30_days": 450,
                    "sentiment": "Mostly Positive",
                    "key_topics": ["AWS Growth", "E-commerce", "AI Services"]
                },
                "reputation_score": 82
            }
        
        return {
            "twitter_presence": {
                "handle": f"@{target.replace('.com', '')}",
                "followers": "10K",
                "sentiment": "Positive (85%)",
                "recent_activity": "Active - Demo posts"
            },
            "linkedin_company": {
                "followers": "5,000",
                "employees_on_platform": "100",
                "recent_updates": "Demo updates"
            },
            "news_mentions": {
                "last_30_days": 5,
                "sentiment": "Neutral",
                "key_topics": ["Demo", "Testing"]
            },
            "reputation_score": 75
        }
    
    def get_threat_intelligence(self, target: str) -> Dict[str, Any]:
        """Get threat intelligence from synthetic data"""
        if target.lower() in ["amazon", "amazon.com"] and self.findings:
            # Use actual findings from CSV
            high_findings = [f for f in self.findings if f.get("severity") == "high"]
            medium_findings = [f for f in self.findings if f.get("severity") == "medium"]
            
            typosquats = []
            for typo in self.brand_typosquats[:3]:
                typosquats.append(f"{typo['domain']} ({typo['risk']} risk)")
            
            return {
                "domain_reputation": "Clean",
                "ip_reputation": "No issues detected",
                "malware_associations": "None found",
                "phishing_reports": f"{len(high_findings)} high-risk typosquats detected",
                "data_breaches": "No recent breaches (Mock data)",
                "dark_web_mentions": "5 mentions (brand monitoring)",
                "security_incidents": "None reported",
                "threat_level": "Medium (due to brand abuse)",
                "typosquatting_domains": typosquats,
                "recommendations": [
                    "Monitor and takedown high-risk typosquatting domains",
                    "Implement brand protection monitoring",
                    "Regular security assessments of exposed services",
                    "Continue DMARC enforcement"
                ]
            }
        
        return {
            "domain_reputation": "Clean (Demo)",
            "ip_reputation": "No issues (Demo)",
            "malware_associations": "None (Demo)",
            "phishing_reports": "0 in demo mode",
            "data_breaches": "No breaches (Demo)",
            "dark_web_mentions": "0 mentions (Demo)",
            "security_incidents": "None (Demo)",
            "threat_level": "Low",
            "recommendations": [
                "Continue monitoring (Demo)",
                "Regular assessments (Demo)",
                "Maintain security posture (Demo)"
            ]
        }
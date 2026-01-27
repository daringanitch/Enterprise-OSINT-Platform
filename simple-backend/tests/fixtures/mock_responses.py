"""
Mock responses for MCP server and external API testing.
Provides consistent mock data for integration and unit tests.
"""
from datetime import datetime
from typing import Dict, Any, List


class MCPMockResponses:
    """Mock responses for MCP server interactions."""

    @staticmethod
    def infrastructure_health() -> Dict[str, Any]:
        """Mock infrastructure MCP health response."""
        return {
            "status": "healthy",
            "server": "infrastructure-advanced",
            "version": "1.0.0",
            "uptime_seconds": 3600,
            "last_check": datetime.utcnow().isoformat()
        }

    @staticmethod
    def threat_health() -> Dict[str, Any]:
        """Mock threat aggregator MCP health response."""
        return {
            "status": "healthy",
            "server": "threat-aggregator",
            "version": "1.0.0",
            "sources_available": ["virustotal", "shodan", "abuseipdb", "otx"],
            "uptime_seconds": 7200
        }

    @staticmethod
    def ai_health() -> Dict[str, Any]:
        """Mock AI analyzer MCP health response."""
        return {
            "status": "healthy",
            "server": "ai-analyzer",
            "version": "1.0.0",
            "model": "gpt-4",
            "capabilities": ["analysis", "threat_profiling", "summary"]
        }

    @staticmethod
    def infrastructure_intelligence(target: str = "example.com") -> Dict[str, Any]:
        """Mock infrastructure intelligence response."""
        return {
            "target": target,
            "dns_records": [
                {"type": "A", "value": "93.184.216.34", "ttl": 300},
                {"type": "MX", "value": "mail.example.com", "priority": 10, "ttl": 3600},
                {"type": "TXT", "value": "v=spf1 include:_spf.example.com ~all", "ttl": 300}
            ],
            "whois": {
                "registrar": "Example Registrar",
                "created_date": "1992-01-01",
                "expiry_date": "2025-12-31",
                "name_servers": ["ns1.example.com", "ns2.example.com"]
            },
            "certificates": [
                {
                    "issuer": "Let's Encrypt Authority X3",
                    "valid_from": "2024-01-01",
                    "valid_to": "2024-04-01",
                    "san": ["example.com", "www.example.com"]
                }
            ],
            "ports": [
                {"port": 80, "service": "http", "state": "open"},
                {"port": 443, "service": "https", "state": "open"}
            ],
            "asn": {
                "number": 15133,
                "name": "Example Networks",
                "country": "US"
            }
        }

    @staticmethod
    def threat_intelligence(target: str = "example.com") -> Dict[str, Any]:
        """Mock threat intelligence response."""
        return {
            "target": target,
            "reputation": {
                "score": 0,
                "category": "clean",
                "last_analysis": datetime.utcnow().isoformat()
            },
            "virustotal": {
                "positives": 0,
                "total": 87,
                "scan_date": datetime.utcnow().isoformat()
            },
            "shodan": {
                "ports_open": [80, 443],
                "vulns": [],
                "last_update": datetime.utcnow().isoformat()
            },
            "abuseipdb": {
                "confidence_score": 0,
                "total_reports": 0,
                "country": "US"
            },
            "blocklists": [],
            "malware_associations": []
        }

    @staticmethod
    def social_media_intelligence(target: str = "example.com") -> Dict[str, Any]:
        """Mock social media intelligence response."""
        return {
            "target": target,
            "twitter": {
                "mentions": 15,
                "sentiment": "neutral",
                "top_hashtags": ["#example", "#tech"],
                "influential_accounts": []
            },
            "linkedin": {
                "company_size": "1000-5000",
                "industry": "Technology",
                "employees_found": 45
            },
            "reddit": {
                "mentions": 8,
                "subreddits": ["technology", "programming"],
                "sentiment": "positive"
            }
        }

    @staticmethod
    def ai_analysis(target: str = "example.com") -> Dict[str, Any]:
        """Mock AI analysis response."""
        return {
            "target": target,
            "executive_summary": f"Analysis of {target} indicates a well-maintained domain with standard security practices.",
            "threat_profile": {
                "risk_level": "low",
                "threat_actors": [],
                "attack_surface": "minimal"
            },
            "recommendations": [
                "Continue monitoring for emerging threats",
                "Implement additional email security controls",
                "Consider bug bounty program"
            ],
            "confidence_score": 0.85,
            "analysis_timestamp": datetime.utcnow().isoformat()
        }

    @staticmethod
    def mcp_server_capabilities() -> Dict[str, Any]:
        """Mock MCP server capabilities response."""
        return {
            "version": "1.0.0",
            "capabilities": [
                "dns_analysis",
                "whois_lookup",
                "certificate_transparency",
                "port_scanning",
                "threat_intelligence",
                "reputation_check"
            ],
            "rate_limits": {
                "requests_per_minute": 60,
                "concurrent_requests": 10
            }
        }


class ExternalAPIMockResponses:
    """Mock responses for external API calls."""

    @staticmethod
    def virustotal_domain(domain: str = "example.com") -> Dict[str, Any]:
        """Mock VirusTotal API response."""
        return {
            "data": {
                "id": domain,
                "type": "domain",
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 85,
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 2
                    },
                    "reputation": 0,
                    "last_modification_date": int(datetime.utcnow().timestamp())
                }
            }
        }

    @staticmethod
    def shodan_host(ip: str = "93.184.216.34") -> Dict[str, Any]:
        """Mock Shodan API response."""
        return {
            "ip_str": ip,
            "ports": [80, 443],
            "hostnames": ["example.com"],
            "country_code": "US",
            "org": "Example Networks",
            "asn": "AS15133",
            "vulns": [],
            "data": [
                {
                    "port": 80,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.21.6"
                },
                {
                    "port": 443,
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.21.6",
                    "ssl": {"cert": {"fingerprint": {"sha256": "abc123..."}}}
                }
            ]
        }

    @staticmethod
    def abuseipdb_check(ip: str = "93.184.216.34") -> Dict[str, Any]:
        """Mock AbuseIPDB API response."""
        return {
            "data": {
                "ipAddress": ip,
                "isPublic": True,
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Example Networks",
                "domain": "example.com",
                "totalReports": 0,
                "numDistinctUsers": 0,
                "lastReportedAt": None
            }
        }

    @staticmethod
    def dns_lookup(domain: str = "example.com") -> Dict[str, Any]:
        """Mock DNS lookup response."""
        return {
            "domain": domain,
            "records": {
                "A": ["93.184.216.34"],
                "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
                "MX": [{"priority": 10, "host": "mail.example.com"}],
                "NS": ["ns1.example.com", "ns2.example.com"],
                "TXT": ["v=spf1 include:_spf.example.com ~all"]
            }
        }


class ErrorMockResponses:
    """Mock error responses for testing error handling."""

    @staticmethod
    def rate_limited() -> Dict[str, Any]:
        """Mock rate limit error response."""
        return {
            "error": "rate_limited",
            "message": "Rate limit exceeded. Please try again later.",
            "retry_after": 60
        }

    @staticmethod
    def authentication_failed() -> Dict[str, Any]:
        """Mock authentication error response."""
        return {
            "error": "authentication_failed",
            "message": "Invalid API key or credentials"
        }

    @staticmethod
    def not_found(resource: str = "investigation") -> Dict[str, Any]:
        """Mock not found error response."""
        return {
            "error": "not_found",
            "message": f"The requested {resource} was not found"
        }

    @staticmethod
    def server_error() -> Dict[str, Any]:
        """Mock internal server error response."""
        return {
            "error": "internal_error",
            "message": "An unexpected error occurred. Please try again later."
        }

    @staticmethod
    def mcp_timeout() -> Dict[str, Any]:
        """Mock MCP server timeout response."""
        return {
            "error": "timeout",
            "message": "MCP server did not respond within the expected time",
            "server": "unknown"
        }


# Convenience functions for common mock scenarios
def mock_healthy_mcp_servers() -> Dict[str, Dict[str, Any]]:
    """Return health status for all MCP servers."""
    return {
        "infrastructure": MCPMockResponses.infrastructure_health(),
        "threat": MCPMockResponses.threat_health(),
        "ai": MCPMockResponses.ai_health()
    }


def mock_full_investigation_intelligence(target: str = "example.com") -> Dict[str, Any]:
    """Return complete intelligence data for an investigation."""
    return {
        "infrastructure": MCPMockResponses.infrastructure_intelligence(target),
        "threat_intel": MCPMockResponses.threat_intelligence(target),
        "social_media": MCPMockResponses.social_media_intelligence(target),
        "ai_analysis": MCPMockResponses.ai_analysis(target)
    }

"""
Sample data factories for Enterprise OSINT Platform tests.
Provides consistent test data across all test modules.
"""
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional


class InvestigationFactory:
    """Factory for creating investigation test data."""

    @staticmethod
    def create_investigation_request(
        target: str = "example.com",
        investigation_type: str = "comprehensive",
        priority: str = "high",
        scope: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Create a valid investigation creation request."""
        return {
            "target": target,
            "investigation_type": investigation_type,
            "priority": priority,
            "scope": scope or {
                "include_infrastructure": True,
                "include_social_media": True,
                "include_threat_intel": True
            },
            "notes": "Test investigation"
        }

    @staticmethod
    def create_investigation_response(
        inv_id: Optional[str] = None,
        target: str = "example.com",
        status: str = "in_progress"
    ) -> Dict[str, Any]:
        """Create a sample investigation response."""
        return {
            "id": inv_id or str(uuid.uuid4()),
            "target": target,
            "status": status,
            "investigation_type": "comprehensive",
            "priority": "high",
            "created_at": datetime.utcnow().isoformat(),
            "started_at": datetime.utcnow().isoformat(),
            "progress": {
                "stage": "data_collection",
                "percentage": 25,
                "current_task": "Gathering infrastructure intelligence"
            },
            "findings": []
        }

    @staticmethod
    def create_completed_investigation(
        inv_id: Optional[str] = None,
        target: str = "example.com"
    ) -> Dict[str, Any]:
        """Create a completed investigation with findings."""
        return {
            "id": inv_id or str(uuid.uuid4()),
            "target": target,
            "status": "completed",
            "investigation_type": "comprehensive",
            "priority": "high",
            "created_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "started_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "completed_at": datetime.utcnow().isoformat(),
            "progress": {
                "stage": "completed",
                "percentage": 100,
                "current_task": "Investigation complete"
            },
            "findings": [
                {
                    "type": "infrastructure",
                    "severity": "medium",
                    "title": "Exposed Service Detected",
                    "description": "Port 22 (SSH) exposed to public internet",
                    "evidence": {"port": 22, "service": "OpenSSH 8.4"}
                },
                {
                    "type": "threat_intelligence",
                    "severity": "low",
                    "title": "Domain Reputation Clean",
                    "description": "No malicious activity associated with domain",
                    "evidence": {"threat_score": 0, "sources_checked": 5}
                }
            ],
            "risk_assessment": {
                "overall_score": 35,
                "risk_level": "low",
                "recommendations": ["Consider restricting SSH access to VPN only"]
            }
        }


class UserFactory:
    """Factory for creating user test data."""

    @staticmethod
    def create_login_request(
        username: str = "admin",
        password: str = "admin123"
    ) -> Dict[str, Any]:
        """Create a valid login request."""
        return {
            "username": username,
            "password": password
        }

    @staticmethod
    def create_user_profile(
        user_id: Optional[str] = None,
        username: str = "testuser",
        role: str = "analyst"
    ) -> Dict[str, Any]:
        """Create a user profile."""
        return {
            "user_id": user_id or str(uuid.uuid4()),
            "username": username,
            "full_name": f"Test {username.title()}",
            "email": f"{username}@example.com",
            "role": role,
            "clearance_level": "confidential",
            "created_at": datetime.utcnow().isoformat()
        }


class ComplianceFactory:
    """Factory for creating compliance test data."""

    @staticmethod
    def create_compliance_assessment_request(
        investigation_id: str,
        frameworks: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Create a compliance assessment request."""
        return {
            "investigation_id": investigation_id,
            "frameworks": frameworks or ["gdpr", "ccpa"],
            "include_recommendations": True
        }

    @staticmethod
    def create_compliance_result(
        framework: str = "gdpr",
        compliant: bool = True
    ) -> Dict[str, Any]:
        """Create a compliance assessment result."""
        return {
            "framework": framework,
            "compliant": compliant,
            "score": 85 if compliant else 45,
            "violations": [] if compliant else [
                {"rule": "data_retention", "severity": "medium", "description": "Audit log retention exceeds 30 days"}
            ],
            "recommendations": [
                {"category": "data_handling", "action": "Implement data minimization policies"}
            ],
            "assessed_at": datetime.utcnow().isoformat()
        }


class RiskAssessmentFactory:
    """Factory for creating risk assessment test data."""

    @staticmethod
    def create_risk_assessment_request(
        target: str = "example.com",
        investigation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a risk assessment request."""
        return {
            "target": target,
            "investigation_id": investigation_id,
            "include_recommendations": True,
            "depth": "comprehensive"
        }

    @staticmethod
    def create_risk_assessment_result(
        target: str = "example.com",
        risk_score: int = 45
    ) -> Dict[str, Any]:
        """Create a risk assessment result."""
        risk_level = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 40 else "low"
        return {
            "target": target,
            "overall_score": risk_score,
            "risk_level": risk_level,
            "confidence": 0.85,
            "factors": [
                {"category": "infrastructure", "score": risk_score - 10, "weight": 0.3},
                {"category": "reputation", "score": risk_score + 5, "weight": 0.2},
                {"category": "threat_intel", "score": risk_score, "weight": 0.3},
                {"category": "compliance", "score": risk_score - 5, "weight": 0.2}
            ],
            "recommendations": [
                "Implement network segmentation",
                "Enable logging and monitoring"
            ],
            "assessed_at": datetime.utcnow().isoformat()
        }


class ReportFactory:
    """Factory for creating report test data."""

    @staticmethod
    def create_report_request(
        investigation_id: str,
        format_type: str = "pdf",
        classification: str = "confidential"
    ) -> Dict[str, Any]:
        """Create a report generation request."""
        return {
            "investigation_id": investigation_id,
            "format": format_type,
            "classification_level": classification,
            "include_executive_summary": True,
            "include_technical_details": True,
            "include_recommendations": True
        }

    @staticmethod
    def create_report_metadata(
        report_id: Optional[str] = None,
        investigation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create report metadata."""
        return {
            "id": report_id or str(uuid.uuid4()),
            "investigation_id": investigation_id or str(uuid.uuid4()),
            "format": "pdf",
            "classification": "confidential",
            "generated_at": datetime.utcnow().isoformat(),
            "generated_by": "system",
            "page_count": 12,
            "file_size": 245678
        }


# Convenience aliases
def sample_investigation_request(**kwargs) -> Dict[str, Any]:
    """Create a sample investigation request."""
    return InvestigationFactory.create_investigation_request(**kwargs)


def sample_login_request(**kwargs) -> Dict[str, Any]:
    """Create a sample login request."""
    return UserFactory.create_login_request(**kwargs)


def sample_completed_investigation(**kwargs) -> Dict[str, Any]:
    """Create a sample completed investigation."""
    return InvestigationFactory.create_completed_investigation(**kwargs)


def sample_risk_assessment(**kwargs) -> Dict[str, Any]:
    """Create a sample risk assessment result."""
    return RiskAssessmentFactory.create_risk_assessment_result(**kwargs)

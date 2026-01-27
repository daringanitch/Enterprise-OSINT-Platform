"""
Unit tests for Enterprise OSINT Platform REST API endpoints.
Tests all /api/* endpoints with various scenarios.
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import jwt

# Import test fixtures
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from fixtures.sample_data import (
    InvestigationFactory, UserFactory, ComplianceFactory,
    RiskAssessmentFactory, ReportFactory
)
from fixtures.mock_responses import MCPMockResponses, ErrorMockResponses


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_endpoint_returns_ok(self, client):
        """Test /health endpoint returns healthy status."""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'

    def test_health_live_endpoint(self, client):
        """Test /health/live liveness probe."""
        response = client.get('/health/live')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'status' in data

    def test_health_ready_endpoint(self, client):
        """Test /health/ready readiness probe."""
        response = client.get('/health/ready')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'status' in data

    def test_ready_endpoint(self, client):
        """Test /ready endpoint."""
        response = client.get('/ready')
        assert response.status_code == 200


class TestAuthenticationEndpoints:
    """Tests for authentication endpoints."""

    def test_login_with_valid_credentials(self, client):
        """Test successful login with valid credentials."""
        login_data = UserFactory.create_login_request()
        response = client.post(
            '/api/auth/login',
            data=json.dumps(login_data),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'token' in data

    def test_login_with_invalid_credentials(self, client):
        """Test login failure with invalid credentials."""
        login_data = UserFactory.create_login_request(
            username="invalid",
            password="wrongpassword"
        )
        response = client.post(
            '/api/auth/login',
            data=json.dumps(login_data),
            content_type='application/json'
        )
        assert response.status_code == 401

    def test_login_missing_username(self, client):
        """Test login with missing username."""
        response = client.post(
            '/api/auth/login',
            data=json.dumps({"password": "test123"}),
            content_type='application/json'
        )
        assert response.status_code in [400, 401]

    def test_login_missing_password(self, client):
        """Test login with missing password."""
        response = client.post(
            '/api/auth/login',
            data=json.dumps({"username": "admin"}),
            content_type='application/json'
        )
        assert response.status_code in [400, 401]

    def test_logout_endpoint(self, client, auth_headers):
        """Test logout endpoint."""
        response = client.post('/api/auth/logout', headers=auth_headers)
        assert response.status_code == 200

    def test_me_endpoint_with_auth(self, client, auth_headers):
        """Test /api/auth/me returns user profile."""
        response = client.get('/api/auth/me', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'user_id' in data or 'username' in data

    def test_me_endpoint_without_auth(self, client):
        """Test /api/auth/me requires authentication."""
        response = client.get('/api/auth/me')
        assert response.status_code == 401


class TestInvestigationEndpoints:
    """Tests for investigation CRUD endpoints."""

    def test_list_investigations(self, client, auth_headers):
        """Test listing investigations."""
        response = client.get('/api/investigations', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, (list, dict))

    def test_list_investigations_without_auth(self, client):
        """Test listing investigations requires auth."""
        response = client.get('/api/investigations')
        assert response.status_code == 401

    def test_create_investigation(self, client, auth_headers):
        """Test creating a new investigation."""
        inv_data = InvestigationFactory.create_investigation_request()
        response = client.post(
            '/api/investigations',
            data=json.dumps(inv_data),
            content_type='application/json',
            headers=auth_headers
        )
        assert response.status_code in [200, 201, 202]
        data = json.loads(response.data)
        assert 'id' in data or 'investigation_id' in data

    def test_create_investigation_missing_target(self, client, auth_headers):
        """Test creating investigation without target fails."""
        response = client.post(
            '/api/investigations',
            data=json.dumps({"investigation_type": "comprehensive"}),
            content_type='application/json',
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_get_investigation_by_id(self, client, auth_headers, sample_investigation):
        """Test getting a specific investigation."""
        # First create an investigation
        inv_data = InvestigationFactory.create_investigation_request()
        create_response = client.post(
            '/api/investigations',
            data=json.dumps(inv_data),
            content_type='application/json',
            headers=auth_headers
        )
        if create_response.status_code in [200, 201, 202]:
            created = json.loads(create_response.data)
            inv_id = created.get('id') or created.get('investigation_id')
            if inv_id:
                response = client.get(
                    f'/api/investigations/{inv_id}',
                    headers=auth_headers
                )
                assert response.status_code in [200, 404]

    def test_get_nonexistent_investigation(self, client, auth_headers):
        """Test getting a non-existent investigation returns 404."""
        response = client.get(
            '/api/investigations/nonexistent-id-12345',
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_cancel_investigation(self, client, auth_headers):
        """Test canceling an investigation."""
        # Create then cancel
        inv_data = InvestigationFactory.create_investigation_request()
        create_response = client.post(
            '/api/investigations',
            data=json.dumps(inv_data),
            content_type='application/json',
            headers=auth_headers
        )
        if create_response.status_code in [200, 201, 202]:
            created = json.loads(create_response.data)
            inv_id = created.get('id') or created.get('investigation_id')
            if inv_id:
                response = client.post(
                    f'/api/investigations/{inv_id}/cancel',
                    headers=auth_headers
                )
                assert response.status_code in [200, 404]


class TestReportEndpoints:
    """Tests for report generation endpoints."""

    def test_list_reports(self, client, auth_headers):
        """Test listing reports."""
        response = client.get('/api/reports', headers=auth_headers)
        assert response.status_code == 200

    def test_generate_report_for_investigation(self, client, auth_headers):
        """Test generating a report for an investigation."""
        # Create investigation first
        inv_data = InvestigationFactory.create_investigation_request()
        create_response = client.post(
            '/api/investigations',
            data=json.dumps(inv_data),
            content_type='application/json',
            headers=auth_headers
        )
        if create_response.status_code in [200, 201, 202]:
            created = json.loads(create_response.data)
            inv_id = created.get('id') or created.get('investigation_id')
            if inv_id:
                response = client.post(
                    f'/api/investigations/{inv_id}/report',
                    data=json.dumps({"format": "pdf"}),
                    content_type='application/json',
                    headers=auth_headers
                )
                # May be 200, 202 (accepted), or 400/404 depending on state
                assert response.status_code in [200, 202, 400, 404]

    def test_get_report_audit_history(self, client, auth_headers):
        """Test getting report audit history."""
        response = client.get('/api/reports/audit-history', headers=auth_headers)
        assert response.status_code == 200


class TestMonitoringEndpoints:
    """Tests for API monitoring endpoints."""

    def test_get_api_monitoring_status(self, client, auth_headers):
        """Test getting API monitoring status."""
        response = client.get('/api/monitoring/apis', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, (list, dict))

    def test_get_specific_api_status(self, client, auth_headers):
        """Test getting status of a specific API."""
        response = client.get('/api/monitoring/apis/shodan', headers=auth_headers)
        # May return 200 or 404 if API not configured
        assert response.status_code in [200, 404]

    def test_check_api_connectivity(self, client, auth_headers):
        """Test checking API connectivity."""
        response = client.post(
            '/api/monitoring/apis/check',
            data=json.dumps({"api_name": "shodan"}),
            content_type='application/json',
            headers=auth_headers
        )
        assert response.status_code in [200, 400, 404]


class TestSystemStatusEndpoints:
    """Tests for system status and stats endpoints."""

    def test_system_status(self, client, auth_headers):
        """Test getting system status."""
        response = client.get('/api/system/status', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'status' in data or 'components' in data

    def test_stats_endpoint(self, client, auth_headers):
        """Test getting system statistics."""
        response = client.get('/api/stats', headers=auth_headers)
        assert response.status_code == 200

    def test_mcp_servers_status(self, client, auth_headers):
        """Test getting MCP servers status."""
        response = client.get('/api/mcp/servers', headers=auth_headers)
        assert response.status_code == 200

    def test_mcp_status_endpoint(self, client, auth_headers):
        """Test MCP status endpoint."""
        response = client.get('/api/mcp/status', headers=auth_headers)
        assert response.status_code == 200


class TestComplianceEndpoints:
    """Tests for compliance-related endpoints."""

    def test_list_compliance_frameworks(self, client, auth_headers):
        """Test listing available compliance frameworks."""
        response = client.get('/api/compliance/frameworks', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, (list, dict))

    def test_run_compliance_assessment(self, client, auth_headers):
        """Test running a compliance assessment."""
        # First create an investigation
        inv_data = InvestigationFactory.create_investigation_request()
        create_response = client.post(
            '/api/investigations',
            data=json.dumps(inv_data),
            content_type='application/json',
            headers=auth_headers
        )
        if create_response.status_code in [200, 201, 202]:
            created = json.loads(create_response.data)
            inv_id = created.get('id') or created.get('investigation_id')
            if inv_id:
                assessment_data = ComplianceFactory.create_compliance_assessment_request(inv_id)
                response = client.post(
                    '/api/compliance/assessment',
                    data=json.dumps(assessment_data),
                    content_type='application/json',
                    headers=auth_headers
                )
                assert response.status_code in [200, 400, 404]

    def test_get_audit_trail(self, client, auth_headers):
        """Test getting compliance audit trail."""
        response = client.get('/api/compliance/audit-trail', headers=auth_headers)
        assert response.status_code == 200

    def test_get_compliance_dashboard(self, client, auth_headers):
        """Test getting compliance dashboard."""
        response = client.get('/api/compliance/dashboard', headers=auth_headers)
        assert response.status_code == 200


class TestRiskAssessmentEndpoints:
    """Tests for risk assessment endpoints."""

    def test_run_risk_assessment(self, client, auth_headers):
        """Test running a risk assessment."""
        risk_data = RiskAssessmentFactory.create_risk_assessment_request()
        response = client.post(
            '/api/risk/assess',
            data=json.dumps(risk_data),
            content_type='application/json',
            headers=auth_headers
        )
        assert response.status_code in [200, 400]

    def test_get_investigation_risk_assessment(self, client, auth_headers):
        """Test getting risk assessment for an investigation."""
        # Create investigation first
        inv_data = InvestigationFactory.create_investigation_request()
        create_response = client.post(
            '/api/investigations',
            data=json.dumps(inv_data),
            content_type='application/json',
            headers=auth_headers
        )
        if create_response.status_code in [200, 201, 202]:
            created = json.loads(create_response.data)
            inv_id = created.get('id') or created.get('investigation_id')
            if inv_id:
                response = client.get(
                    f'/api/risk/investigations/{inv_id}',
                    headers=auth_headers
                )
                assert response.status_code in [200, 404]

    def test_correlate_risks(self, client, auth_headers):
        """Test risk correlation endpoint."""
        response = client.post(
            '/api/risk/correlate',
            data=json.dumps({"targets": ["example.com", "test.com"]}),
            content_type='application/json',
            headers=auth_headers
        )
        assert response.status_code in [200, 400]


class TestAdminEndpoints:
    """Tests for admin endpoints."""

    def test_vault_status(self, client, auth_headers):
        """Test getting Vault status."""
        response = client.get('/api/admin/vault/status', headers=auth_headers)
        assert response.status_code == 200

    def test_get_service_configs(self, client, auth_headers):
        """Test getting service configurations."""
        response = client.get('/api/admin/services/configs', headers=auth_headers)
        assert response.status_code == 200

    def test_configure_service(self, client, auth_headers):
        """Test configuring a service."""
        config_data = {
            "service_name": "test_service",
            "api_key": "test-api-key",
            "enabled": True
        }
        response = client.post(
            '/api/admin/services/configure',
            data=json.dumps(config_data),
            content_type='application/json',
            headers=auth_headers
        )
        assert response.status_code in [200, 400]

    def test_get_admin_audit_logs(self, client, auth_headers):
        """Test getting admin audit logs."""
        response = client.get('/api/admin/audit/logs', headers=auth_headers)
        assert response.status_code == 200


class TestJobQueueEndpoints:
    """Tests for job queue endpoints."""

    def test_get_queue_stats(self, client, auth_headers):
        """Test getting job queue statistics."""
        response = client.get('/api/jobs/queue/stats', headers=auth_headers)
        assert response.status_code == 200

    def test_get_job_status(self, client, auth_headers):
        """Test getting job status by ID."""
        response = client.get('/api/jobs/test-job-id/status', headers=auth_headers)
        assert response.status_code in [200, 404]

    def test_cancel_job(self, client, auth_headers):
        """Test canceling a job."""
        response = client.post(
            '/api/jobs/test-job-id/cancel',
            headers=auth_headers
        )
        assert response.status_code in [200, 404]


class TestReportingEndpoints:
    """Tests for advanced reporting endpoints."""

    def test_investigation_activity_report(self, client, auth_headers):
        """Test getting investigation activity report."""
        response = client.get(
            '/api/reports/investigations/activity',
            headers=auth_headers
        )
        assert response.status_code == 200

    def test_export_activity_report(self, client, auth_headers):
        """Test exporting activity report."""
        response = client.post(
            '/api/reports/investigations/activity/export',
            data=json.dumps({"format": "csv", "date_range": "last_30_days"}),
            content_type='application/json',
            headers=auth_headers
        )
        assert response.status_code in [200, 400]

    def test_investigators_report(self, client, auth_headers):
        """Test getting investigators report."""
        response = client.get('/api/reports/investigators', headers=auth_headers)
        assert response.status_code == 200

    def test_targets_report(self, client, auth_headers):
        """Test getting targets report."""
        response = client.get('/api/reports/targets', headers=auth_headers)
        assert response.status_code == 200


class TestProfessionalReportEndpoints:
    """Tests for professional report generation."""

    def test_generate_professional_report(self, client, auth_headers):
        """Test generating a professional report."""
        report_request = {
            "investigation_id": "test-inv-id",
            "report_type": "executive_summary",
            "classification": "confidential"
        }
        response = client.post(
            '/api/reports/professional/generate',
            data=json.dumps(report_request),
            content_type='application/json',
            headers=auth_headers
        )
        assert response.status_code in [200, 400, 404]


class TestMetricsEndpoint:
    """Tests for metrics/observability endpoints."""

    def test_metrics_endpoint(self, client):
        """Test Prometheus metrics endpoint."""
        response = client.get('/metrics')
        assert response.status_code == 200


class TestErrorHandling:
    """Tests for error handling across endpoints."""

    def test_invalid_json_body(self, client, auth_headers):
        """Test handling of invalid JSON in request body."""
        response = client.post(
            '/api/investigations',
            data='invalid json{',
            content_type='application/json',
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_unsupported_content_type(self, client, auth_headers):
        """Test handling of unsupported content type."""
        response = client.post(
            '/api/investigations',
            data='target=example.com',
            content_type='text/plain',
            headers=auth_headers
        )
        assert response.status_code in [400, 415]

    def test_expired_token(self, client):
        """Test handling of expired JWT token."""
        expired_payload = {
            'user_id': 'test_user',
            'username': 'testuser',
            'exp': datetime.utcnow() - timedelta(hours=1),
            'iat': datetime.utcnow() - timedelta(hours=2)
        }
        expired_token = jwt.encode(expired_payload, 'test-secret-key', algorithm='HS256')
        headers = {'Authorization': f'Bearer {expired_token}'}

        response = client.get('/api/investigations', headers=headers)
        assert response.status_code == 401

    def test_malformed_token(self, client):
        """Test handling of malformed JWT token."""
        headers = {'Authorization': 'Bearer not.a.valid.token'}
        response = client.get('/api/investigations', headers=headers)
        assert response.status_code == 401

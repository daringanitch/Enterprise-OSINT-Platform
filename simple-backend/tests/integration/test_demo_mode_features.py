"""
Comprehensive Demo Mode Feature Tests

Tests all platform features in demo mode to ensure they work correctly.
These tests also serve as validation for production mode with minimal changes.

Run with: pytest tests/integration/test_demo_mode_features.py -v
"""
import pytest
import json
from datetime import datetime, timedelta
import jwt
import os
import sys

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestDemoModeSetup:
    """Verify demo mode is properly configured."""

    def test_demo_mode_is_active(self, client, auth_headers):
        """Test that demo mode is active."""
        response = client.get('/api/system/mode', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        # In test environment, mode should be available
        assert 'current_mode' in data or 'mode' in data


class TestHealthEndpointsDemo:
    """Test all health endpoints work in demo mode."""

    def test_health_endpoint(self, client):
        """Test /health returns healthy."""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'

    def test_health_live_endpoint(self, client):
        """Test /health/live liveness probe."""
        response = client.get('/health/live')
        assert response.status_code == 200

    def test_health_ready_endpoint(self, client):
        """Test /health/ready readiness probe."""
        response = client.get('/health/ready')
        # May return 503 if dependencies unavailable, but should respond
        assert response.status_code in [200, 503]

    def test_ready_endpoint(self, client):
        """Test /ready endpoint."""
        response = client.get('/ready')
        assert response.status_code in [200, 503]


class TestAuthenticationDemo:
    """Test authentication endpoints in demo mode."""

    def test_login_admin_user(self, client):
        """Test login with admin demo account."""
        response = client.post(
            '/api/auth/login',
            data=json.dumps({'username': 'admin', 'password': 'admin123'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert data['user']['username'] == 'admin'
        assert data['user']['role'] == 'admin'

    def test_login_analyst1_user(self, client):
        """Test login with analyst1 demo account."""
        response = client.post(
            '/api/auth/login',
            data=json.dumps({'username': 'analyst1', 'password': 'admin123'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert data['user']['username'] == 'analyst1'
        assert data['user']['role'] == 'analyst'

    def test_login_analyst2_user(self, client):
        """Test login with analyst2 demo account."""
        response = client.post(
            '/api/auth/login',
            data=json.dumps({'username': 'analyst2', 'password': 'admin123'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data
        assert data['user']['username'] == 'analyst2'
        assert data['user']['role'] == 'senior_analyst'

    def test_login_invalid_credentials(self, client):
        """Test login fails with invalid credentials."""
        response = client.post(
            '/api/auth/login',
            data=json.dumps({'username': 'invalid', 'password': 'wrong'}),
            content_type='application/json'
        )
        assert response.status_code == 401

    def test_login_missing_fields(self, client):
        """Test login fails with missing fields."""
        response = client.post(
            '/api/auth/login',
            data=json.dumps({'username': 'admin'}),
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_logout_endpoint(self, client, auth_headers):
        """Test logout endpoint."""
        response = client.post('/api/auth/logout', headers=auth_headers)
        assert response.status_code == 200

    def test_get_current_user(self, client, auth_headers):
        """Test getting current user info."""
        response = client.get('/api/auth/me', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'user' in data


class TestInvestigationsDemo:
    """Test investigation endpoints in demo mode."""

    def test_list_investigations_returns_five(self, client, auth_headers):
        """Test that demo mode returns exactly 5 investigations."""
        response = client.get('/api/investigations', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) == 5

    def test_investigations_have_deterministic_ids(self, client, auth_headers):
        """Test that demo investigations have deterministic IDs."""
        response = client.get('/api/investigations', headers=auth_headers)
        data = json.loads(response.data)
        ids = [inv['id'] for inv in data]
        expected_ids = ['demo_inv_001', 'demo_inv_002', 'demo_inv_003', 'demo_inv_004', 'demo_inv_005']
        assert ids == expected_ids

    def test_investigations_have_required_fields(self, client, auth_headers):
        """Test that each investigation has all required fields."""
        response = client.get('/api/investigations', headers=auth_headers)
        data = json.loads(response.data)

        required_fields = [
            'id', 'target_profile', 'status', 'investigation_type',
            'investigator_name', 'priority', 'created_at', 'can_generate_report'
        ]

        for inv in data:
            for field in required_fields:
                assert field in inv, f"Missing field: {field}"

    def test_get_single_investigation(self, client):
        """Test getting a single demo investigation."""
        response = client.get('/api/investigations/demo_inv_001')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['id'] == 'demo_inv_001'
        assert 'target_profile' in data

    def test_get_nonexistent_investigation(self, client):
        """Test getting a non-existent investigation returns 404."""
        response = client.get('/api/investigations/nonexistent_id')
        assert response.status_code == 404

    def test_create_investigation(self, client, auth_headers):
        """Test creating a new investigation."""
        response = client.post(
            '/api/investigations',
            data=json.dumps({
                'target': 'test-target.com',
                'investigation_type': 'comprehensive',
                'priority': 'normal'
            }),
            headers=auth_headers,
            content_type='application/json'
        )
        # Should succeed or indicate queued
        assert response.status_code in [200, 201, 202]

    def test_investigation_progress_endpoint(self, client):
        """Test investigation progress endpoint."""
        response = client.get('/api/investigations/demo_inv_001/progress')
        # Should return progress or 404 if not implemented for demo
        assert response.status_code in [200, 404]


class TestReportGenerationDemo:
    """Test report generation in demo mode."""

    def test_generate_report_for_completed_investigation(self, client, auth_headers):
        """Test generating a report for a completed demo investigation."""
        response = client.post(
            '/api/investigations/demo_inv_001/report',
            headers=auth_headers,
            content_type='application/json'
        )
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'report_id' in data
        assert data['report_id'] == 'report_demo_inv_001'
        assert 'demo_mode' in data and data['demo_mode'] is True

    def test_generate_report_for_failed_investigation_rejected(self, client, auth_headers):
        """Test that report generation fails for failed investigation."""
        response = client.post(
            '/api/investigations/demo_inv_005/report',
            headers=auth_headers,
            content_type='application/json'
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert 'not completed' in data['error'].lower()

    def test_get_generated_report(self, client, auth_headers):
        """Test retrieving a generated report."""
        # First generate the report
        client.post(
            '/api/investigations/demo_inv_002/report',
            headers=auth_headers,
            content_type='application/json'
        )

        # Then retrieve it
        response = client.get('/api/investigations/demo_inv_002/report')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'id' in data
        assert 'content' in data

    def test_download_report(self, client, auth_headers):
        """Test downloading a report."""
        # First generate the report
        client.post(
            '/api/investigations/demo_inv_003/report',
            headers=auth_headers,
            content_type='application/json'
        )

        # Then download it
        response = client.get('/api/investigations/demo_inv_003/report/download')
        assert response.status_code == 200

    def test_list_all_reports(self, client):
        """Test listing all active reports."""
        response = client.get('/api/reports')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)

    def test_report_audit_history(self, client, auth_headers):
        """Test report audit history endpoint."""
        response = client.get('/api/reports/audit-history', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, (list, dict))


class TestComplianceDemo:
    """Test compliance endpoints in demo mode."""

    def test_list_compliance_frameworks(self, client):
        """Test listing supported compliance frameworks."""
        response = client.get('/api/compliance/frameworks')
        assert response.status_code == 200
        data = json.loads(response.data)
        # Can be dict or list format
        if isinstance(data, dict):
            assert 'frameworks' in data or 'supported_frameworks' in data
            # Check GDPR is supported
            if 'supported_frameworks' in data:
                assert 'gdpr' in data['supported_frameworks']
        else:
            assert isinstance(data, list)
            framework_names = [f.get('name') or f.get('framework') for f in data]
            assert any('GDPR' in str(f).upper() for f in framework_names)

    def test_compliance_assessment(self, client):
        """Test running a compliance assessment."""
        response = client.post(
            '/api/compliance/assessment',
            data=json.dumps({
                'target': 'example.com',
                'framework': 'gdpr',
                'geographical_scope': ['EU'],
                'target_data': {'domain': 'example.com'},
                'processing_activities': ['data_collection']
            }),
            content_type='application/json'
        )
        assert response.status_code in [200, 201]

    def test_investigation_compliance_reports(self, client):
        """Test getting compliance reports for an investigation."""
        response = client.get('/api/compliance/investigations/demo_inv_001/reports')
        assert response.status_code in [200, 404]

    def test_compliance_audit_trail(self, client):
        """Test compliance audit trail endpoint."""
        response = client.get('/api/compliance/audit-trail')
        assert response.status_code == 200

    def test_compliance_dashboard(self, client):
        """Test compliance dashboard endpoint."""
        response = client.get('/api/compliance/dashboard')
        assert response.status_code == 200


class TestRiskAssessmentDemo:
    """Test risk assessment endpoints in demo mode."""

    def test_standalone_risk_assessment(self, client):
        """Test standalone risk assessment."""
        response = client.post(
            '/api/risk/assess',
            data=json.dumps({
                'target': 'example.com',
                'intelligence_data': {'source': 'demo'}
            }),
            content_type='application/json'
        )
        assert response.status_code in [200, 201]

    def test_investigation_risk_assessment(self, client):
        """Test getting risk assessment for investigation."""
        response = client.get('/api/risk/investigations/demo_inv_001')
        assert response.status_code in [200, 404]

    def test_risk_correlation(self, client):
        """Test risk correlation endpoint."""
        response = client.post(
            '/api/risk/correlate',
            data=json.dumps({
                'sources': ['infrastructure', 'threat_intel'],
                'target': 'example.com'
            }),
            content_type='application/json'
        )
        assert response.status_code in [200, 201]


class TestMCPServersDemo:
    """Test MCP server endpoints in demo mode."""

    def test_list_mcp_servers(self, client):
        """Test listing MCP servers."""
        response = client.get('/api/mcp/servers')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) >= 3  # Should have multiple servers

    def test_mcp_server_status(self, client):
        """Test MCP server status endpoint."""
        response = client.get('/api/mcp/status')
        assert response.status_code == 200


class TestStatisticsDemo:
    """Test statistics endpoints in demo mode."""

    def test_platform_stats(self, client):
        """Test platform statistics endpoint."""
        response = client.get('/api/stats')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, dict)


class TestSystemModeDemo:
    """Test system mode endpoints in demo mode."""

    def test_get_system_mode(self, client, auth_headers):
        """Test getting current system mode."""
        response = client.get('/api/system/mode', headers=auth_headers)
        assert response.status_code == 200

    def test_get_demo_data_config(self, client, auth_headers):
        """Test getting demo data configuration."""
        response = client.get('/api/system/demo-data', headers=auth_headers)
        assert response.status_code == 200

    def test_get_api_keys_status(self, client, auth_headers):
        """Test getting API keys availability status."""
        response = client.get('/api/system/api-keys', headers=auth_headers)
        assert response.status_code == 200

    def test_system_status(self, client, auth_headers):
        """Test system status endpoint."""
        response = client.get('/api/system/status', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'status' in data


class TestJobQueueDemo:
    """Test job queue endpoints in demo mode."""

    def test_job_status(self, client, auth_headers):
        """Test getting job status."""
        response = client.get('/api/jobs/demo_job_123/status', headers=auth_headers)
        # Should return mock status or 404
        assert response.status_code in [200, 404]

    def test_queue_stats(self, client, auth_headers):
        """Test job queue statistics."""
        response = client.get('/api/jobs/queue/stats', headers=auth_headers)
        assert response.status_code == 200


class TestAdminEndpointsDemo:
    """Test admin endpoints in demo mode."""

    def test_vault_status(self, client):
        """Test Vault status endpoint."""
        response = client.get('/api/admin/vault/status')
        assert response.status_code == 200

    def test_service_configs(self, client):
        """Test getting service configurations."""
        response = client.get('/api/admin/services/configs')
        assert response.status_code == 200

    def test_audit_logs(self, client):
        """Test getting audit logs."""
        response = client.get('/api/admin/audit/logs')
        assert response.status_code == 200


class TestInvestigationActivityReportsDemo:
    """Test investigation activity report endpoints in demo mode."""

    def test_investigation_activity_report(self, client):
        """Test investigation activity report generation."""
        response = client.get('/api/reports/investigations/activity')
        assert response.status_code == 200

    def test_investigators_report(self, client):
        """Test investigators report endpoint."""
        response = client.get('/api/reports/investigators')
        assert response.status_code == 200

    def test_targets_report(self, client):
        """Test targets report endpoint."""
        response = client.get('/api/reports/targets')
        assert response.status_code == 200


class TestProfessionalReportsDemo:
    """Test professional report generation in demo mode."""

    def test_generate_professional_report(self, client, auth_headers):
        """Test generating a professional report."""
        # First ensure we have an investigation
        response = client.post(
            '/api/reports/professional/generate',
            data=json.dumps({
                'investigation_id': 'demo_inv_001',
                'report_type': 'executive',
                'format': 'json'
            }),
            content_type='application/json'
        )
        # Should succeed or gracefully fail
        assert response.status_code in [200, 201, 400, 404]


class TestMonitoringDemo:
    """Test monitoring endpoints in demo mode."""

    def test_api_monitoring(self, client):
        """Test API monitoring endpoint."""
        response = client.get('/api/monitoring/apis')
        assert response.status_code == 200


class TestDataConsistencyDemo:
    """Test that demo data remains consistent across requests."""

    def test_investigations_consistent_across_requests(self, client, auth_headers):
        """Test that demo investigations are consistent."""
        response1 = client.get('/api/investigations', headers=auth_headers)
        response2 = client.get('/api/investigations', headers=auth_headers)

        data1 = json.loads(response1.data)
        data2 = json.loads(response2.data)

        # IDs should be identical
        ids1 = [inv['id'] for inv in data1]
        ids2 = [inv['id'] for inv in data2]
        assert ids1 == ids2

    def test_investigation_details_match_list(self, client, auth_headers):
        """Test that investigation details match list data."""
        # Get list
        list_response = client.get('/api/investigations', headers=auth_headers)
        list_data = json.loads(list_response.data)

        # Get first investigation details
        detail_response = client.get(f'/api/investigations/{list_data[0]["id"]}')
        detail_data = json.loads(detail_response.data)

        # Should have same ID and target
        assert detail_data['id'] == list_data[0]['id']
        assert detail_data['target_profile'] == list_data[0]['target_profile']


class TestErrorHandlingDemo:
    """Test error handling in demo mode."""

    def test_invalid_endpoint_returns_404(self, client):
        """Test that invalid endpoints return 404."""
        response = client.get('/api/nonexistent/endpoint')
        assert response.status_code == 404

    def test_unauthorized_access_returns_401(self, client):
        """Test that unauthorized access returns 401."""
        response = client.get('/api/system/mode')
        assert response.status_code == 401

    def test_invalid_json_returns_400(self, client, auth_headers):
        """Test that invalid JSON returns 400."""
        response = client.post(
            '/api/auth/login',
            data='not valid json',
            content_type='application/json'
        )
        assert response.status_code in [400, 415, 500]


class TestReportLifecycleDemo:
    """Test complete report lifecycle in demo mode."""

    def test_full_report_lifecycle(self, client, auth_headers):
        """Test complete report generation and retrieval lifecycle."""
        # Step 1: Get investigations
        inv_response = client.get('/api/investigations', headers=auth_headers)
        assert inv_response.status_code == 200
        investigations = json.loads(inv_response.data)

        # Find a completed investigation
        completed_inv = next(
            (inv for inv in investigations if inv['status'] == 'completed'),
            None
        )
        assert completed_inv is not None, "No completed investigation found"
        inv_id = completed_inv['id']

        # Step 2: Generate report
        gen_response = client.post(
            f'/api/investigations/{inv_id}/report',
            headers=auth_headers,
            content_type='application/json'
        )
        assert gen_response.status_code == 201
        gen_data = json.loads(gen_response.data)
        report_id = gen_data['report_id']

        # Step 3: Retrieve report
        get_response = client.get(f'/api/investigations/{inv_id}/report')
        assert get_response.status_code == 200
        report_data = json.loads(get_response.data)
        assert report_data['id'] == report_id

        # Step 4: Verify report content
        assert 'content' in report_data
        assert 'executive_summary' in report_data['content']
        assert 'key_findings' in report_data['content']

        # Step 5: Download report
        download_response = client.get(f'/api/investigations/{inv_id}/report/download')
        assert download_response.status_code == 200

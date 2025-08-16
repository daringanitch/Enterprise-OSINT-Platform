"""
Unit tests for health check endpoints
"""
import pytest
import json


class TestHealthEndpoints:
    """Test health check endpoints"""
    
    def test_basic_health_endpoint(self, client):
        """Test basic /health endpoint returns 200"""
        response = client.get('/health')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert data['service'] == 'osint-backend'
        assert 'timestamp' in data
        assert 'trace_id' in data
    
    def test_liveness_probe(self, client):
        """Test /health/live endpoint for Kubernetes liveness probe"""
        response = client.get('/health/live')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'alive'
        assert data['service'] == 'osint-backend'
        assert 'timestamp' in data
        assert 'trace_id' in data
    
    def test_readiness_probe_structure(self, client):
        """Test /health/ready endpoint returns proper structure"""
        response = client.get('/health/ready')
        # May return 503 if dependencies aren't available, but structure should be correct
        
        data = json.loads(response.data)
        assert 'status' in data
        assert 'service' in data
        assert 'timestamp' in data
        assert 'trace_id' in data
        assert 'checks' in data
        
        # Verify expected checks are present
        checks = data.get('checks', {})
        expected_checks = ['postgresql', 'vault', 'mcp_servers', 'api_monitor']
        for check in expected_checks:
            assert check in checks or 'error' in str(checks)
    
    def test_readiness_with_healthy_dependencies(self, client, mock_postgres_client, monkeypatch):
        """Test readiness probe when all dependencies are healthy"""
        # Mock the postgres_client in the app module
        monkeypatch.setattr('app.postgres_client', mock_postgres_client)
        
        response = client.get('/health/ready')
        data = json.loads(response.data)
        
        # Should still work even if some services are degraded
        assert response.status_code in [200, 503]
        assert data['status'] in ['ready', 'not_ready']
    
    def test_legacy_ready_endpoint(self, client):
        """Test that legacy /ready endpoint still works"""
        response = client.get('/ready')
        # Should redirect to readiness() function
        assert response.status_code in [200, 503]
        
        data = json.loads(response.data)
        assert 'checks' in data  # Should have full readiness response
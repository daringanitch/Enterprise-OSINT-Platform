"""
Integration tests for investigation workflow
"""
import pytest
import json
from unittest.mock import patch, Mock


@pytest.mark.integration
class TestInvestigationFlow:
    """Test complete investigation workflow"""
    
    def test_create_investigation_flow(self, client, auth_headers, mock_external_apis):
        """Test creating and starting an investigation"""
        # Create investigation
        investigation_data = {
            "target": "example.com",
            "investigation_type": "comprehensive",
            "priority": "high"
        }
        
        response = client.post('/api/investigations',
                              data=json.dumps(investigation_data),
                              content_type='application/json',
                              headers=auth_headers)
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'investigation_id' in data
        assert 'status' in data
        
        investigation_id = data['investigation_id']
        
        # Get investigation status
        response = client.get(f'/api/investigations/{investigation_id}',
                             headers=auth_headers)
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['id'] == investigation_id
        assert data['target'] == 'example.com'
    
    def test_investigation_list_pagination(self, client, auth_headers):
        """Test investigation listing with pagination"""
        response = client.get('/api/investigations?page=1&limit=10',
                             headers=auth_headers)
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Check pagination structure
        assert 'investigations' in data
        assert 'total' in data
        assert 'page' in data
        assert 'limit' in data
        assert isinstance(data['investigations'], list)
    
    @patch('mcp_clients.MCPClientManager')
    def test_mcp_integration_health(self, mock_mcp_manager, client, auth_headers):
        """Test MCP server integration and health checks"""
        # Mock MCP server health check
        mock_instance = Mock()
        mock_instance.health_check.return_value = {
            'infrastructure': {'status': 'healthy', 'capabilities': ['whois', 'dns']},
            'social_media': {'status': 'healthy', 'capabilities': ['twitter', 'linkedin']},
            'threat_intel': {'status': 'healthy', 'capabilities': ['virustotal', 'shodan']}
        }
        mock_mcp_manager.return_value = mock_instance
        
        response = client.get('/api/mcp/servers', headers=auth_headers)
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'servers' in data
        
        # Check expected MCP servers
        expected_servers = ['infrastructure', 'social_media', 'threat_intel']
        for server in expected_servers:
            assert server in data['servers'] or 'error' in str(data)
    
    @patch('investigation_orchestrator.InvestigationOrchestrator')
    def test_investigation_execution(self, mock_orchestrator, client, auth_headers):
        """Test investigation execution with mocked orchestrator"""
        mock_instance = Mock()
        mock_instance.execute_investigation.return_value = {
            'status': 'completed',
            'results': {
                'infrastructure_intelligence': [
                    {
                        'source': 'whois',
                        'data': {'domain': 'example.com', 'registrar': 'Test Registrar'},
                        'confidence': 0.95
                    }
                ],
                'social_intelligence': [],
                'threat_intelligence': []
            }
        }
        mock_orchestrator.return_value = mock_instance
        
        # Start investigation
        investigation_data = {
            "target": "example.com",
            "investigation_type": "comprehensive",
            "priority": "high"
        }
        
        response = client.post('/api/investigations',
                              data=json.dumps(investigation_data),
                              content_type='application/json',
                              headers=auth_headers)
        
        assert response.status_code == 201
        data = json.loads(response.data)
        investigation_id = data['investigation_id']
        
        # Get results
        response = client.get(f'/api/investigations/{investigation_id}/results',
                             headers=auth_headers)
        
        # Should return results or indicate processing
        assert response.status_code in [200, 202]
    
    def test_error_handling_integration(self, client, auth_headers):
        """Test error handling across API endpoints"""
        # Test invalid investigation ID
        response = client.get('/api/investigations/invalid-id',
                             headers=auth_headers)
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
        
        # Test malformed request data
        response = client.post('/api/investigations',
                              data='invalid json',
                              content_type='application/json',
                              headers=auth_headers)
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
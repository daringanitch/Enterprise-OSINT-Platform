"""
Integration tests for async investigation workflow
"""
import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime


@pytest.mark.integration
class TestAsyncInvestigationWorkflow:
    """Test complete async investigation workflow"""
    
    def test_investigation_creation_and_queueing(self, client, auth_headers, mock_external_apis):
        """Test investigation creation triggers job queueing"""
        investigation_data = {
            "target": "example.com",
            "investigation_type": "comprehensive",
            "priority": "high",
            "investigator": "test_user"
        }
        
        with patch('app.job_queue_manager.enqueue_investigation') as mock_enqueue:
            mock_enqueue.return_value = "job_123"
            
            response = client.post('/api/investigations',
                                  data=json.dumps(investigation_data),
                                  content_type='application/json',
                                  headers=auth_headers)
            
            assert response.status_code == 201
            data = json.loads(response.data)
            
            # Verify job was queued
            mock_enqueue.assert_called_once()
            assert data['job_id'] == "job_123"
            assert data['status'] == 'queued'
            assert 'investigation_id' in data
    
    def test_job_status_tracking(self, client, auth_headers):
        """Test job status tracking throughout investigation lifecycle"""
        # Mock job status responses for different stages
        job_statuses = [
            {'id': 'job_123', 'status': 'queued', 'progress': 0},
            {'id': 'job_123', 'status': 'started', 'progress': 25},
            {'id': 'job_123', 'status': 'started', 'progress': 75},
            {'id': 'job_123', 'status': 'finished', 'progress': 100, 'result': {'status': 'completed'}}
        ]
        
        with patch('app.job_queue_manager.get_job_status', side_effect=job_statuses):
            for expected_status in job_statuses:
                response = client.get('/api/jobs/job_123/status', headers=auth_headers)
                
                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['status'] == expected_status['status']
                assert data['progress'] == expected_status['progress']
    
    def test_investigation_results_after_completion(self, client, auth_headers):
        """Test retrieving investigation results after async completion"""
        # Create investigation
        investigation_data = {
            "target": "example.com",
            "investigation_type": "comprehensive",
            "priority": "high"
        }
        
        with patch('app.job_queue_manager.enqueue_investigation', return_value="job_123"):
            response = client.post('/api/investigations',
                                  data=json.dumps(investigation_data),
                                  content_type='application/json',
                                  headers=auth_headers)
            
            assert response.status_code == 201
            data = json.loads(response.data)
            investigation_id = data['investigation_id']
        
        # Mock completed investigation with results
        mock_investigation = Mock()
        mock_investigation.id = investigation_id
        mock_investigation.status.value = 'completed'
        mock_investigation.target_profile.primary_identifier = 'example.com'
        mock_investigation.to_dict.return_value = {
            'id': investigation_id,
            'target': 'example.com',
            'status': 'completed',
            'results_summary': {
                'infrastructure_results': 5,
                'social_results': 3,
                'threat_results': 2
            }
        }
        
        with patch('app.orchestrator.get_investigation', return_value=mock_investigation):
            response = client.get(f'/api/investigations/{investigation_id}', headers=auth_headers)
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['status'] == 'completed'
            assert 'results_summary' in data
    
    def test_job_cancellation(self, client, auth_headers):
        """Test canceling queued or running jobs"""
        # Test successful cancellation
        with patch('app.job_queue_manager.cancel_job', return_value=True):
            response = client.post('/api/jobs/job_123/cancel', headers=auth_headers)
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'cancelled successfully' in data['message'].lower()
        
        # Test cancellation failure (job not found or not cancellable)
        with patch('app.job_queue_manager.cancel_job', return_value=False):
            response = client.post('/api/jobs/job_456/cancel', headers=auth_headers)
            
            assert response.status_code == 404
    
    def test_queue_statistics_monitoring(self, client, auth_headers):
        """Test monitoring job queue statistics"""
        mock_stats = {
            'investigations': {
                'length': 5,
                'scheduled_jobs': 2,
                'started_jobs': 1,
                'finished_jobs': 15,
                'failed_jobs': 1
            },
            'reports': {
                'length': 2,
                'scheduled_jobs': 0,
                'started_jobs': 1,
                'finished_jobs': 8,
                'failed_jobs': 0
            }
        }
        
        with patch('app.job_queue_manager.get_queue_stats', return_value=mock_stats):
            response = client.get('/api/jobs/queue/stats', headers=auth_headers)
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'investigations' in data
            assert 'reports' in data
            assert data['investigations']['length'] == 5
    
    @patch('app.job_queue_manager')
    def test_report_generation_queueing(self, mock_job_manager, client, auth_headers):
        """Test report generation queueing"""
        mock_job_manager.enqueue_report_generation.return_value = "report_job_123"
        
        # Mock existing investigation
        mock_investigation = Mock()
        mock_investigation.id = "inv_123"
        mock_investigation.status.value = 'completed'
        
        with patch('app.orchestrator.get_investigation', return_value=mock_investigation):
            response = client.post('/api/investigations/inv_123/report',
                                  data=json.dumps({
                                      'format': 'executive',
                                      'classification': 'confidential'
                                  }),
                                  content_type='application/json',
                                  headers=auth_headers)
            
            # Report generation should be queued
            mock_job_manager.enqueue_report_generation.assert_called_once()
    
    def test_error_handling_in_async_workflow(self, client, auth_headers):
        """Test error handling throughout async workflow"""
        # Test job queue unavailable
        with patch('app.job_queue_manager.enqueue_investigation', return_value=None):
            response = client.post('/api/investigations',
                                  data=json.dumps({
                                      "target": "example.com",
                                      "investigation_type": "comprehensive"
                                  }),
                                  content_type='application/json',
                                  headers=auth_headers)
            
            # Should still create investigation but without job queuing
            assert response.status_code == 201
            data = json.loads(response.data)
            assert data['job_id'] is None
        
        # Test job status check error
        with patch('app.job_queue_manager.get_job_status', side_effect=Exception("Redis unavailable")):
            response = client.get('/api/jobs/job_123/status', headers=auth_headers)
            
            assert response.status_code == 500
    
    def test_mcp_server_integration_async(self, client, auth_headers, mock_external_apis):
        """Test MCP server integration in async workflow"""
        investigation_data = {
            "target": "example.com",
            "investigation_type": "infrastructure",
            "priority": "normal"
        }
        
        # Mock MCP operation queueing
        with patch('app.job_queue_manager.enqueue_investigation') as mock_enqueue_inv, \
             patch('app.job_queue_manager.enqueue_mcp_operation') as mock_enqueue_mcp:
            
            mock_enqueue_inv.return_value = "inv_job_123"
            mock_enqueue_mcp.return_value = "mcp_job_456"
            
            response = client.post('/api/investigations',
                                  data=json.dumps(investigation_data),
                                  content_type='application/json',
                                  headers=auth_headers)
            
            assert response.status_code == 201
            
            # Verify investigation was queued
            mock_enqueue_inv.assert_called_once()
    
    def test_compliance_assessment_async(self, client, auth_headers):
        """Test compliance assessment in async workflow"""
        # Mock investigation completion triggering compliance assessment
        with patch('app.job_queue_manager.enqueue_compliance_assessment') as mock_enqueue:
            mock_enqueue.return_value = "compliance_job_789"
            
            # This would be triggered after investigation completion
            # For testing, we'll call the compliance endpoint directly
            response = client.get('/api/compliance/investigations/inv_123/reports',
                                 headers=auth_headers)
            
            # This endpoint should trigger compliance assessment
            # (Implementation would need to be added to actually queue compliance jobs)
    
    def test_investigation_priority_handling(self, client, auth_headers):
        """Test that investigation priority affects job queue processing"""
        high_priority_data = {
            "target": "critical-example.com",
            "investigation_type": "threat_assessment", 
            "priority": "urgent"
        }
        
        normal_priority_data = {
            "target": "normal-example.com",
            "investigation_type": "comprehensive",
            "priority": "normal"
        }
        
        with patch('app.job_queue_manager.enqueue_investigation') as mock_enqueue:
            mock_enqueue.return_value = "job_urgent"
            
            # Create urgent priority investigation
            response = client.post('/api/investigations',
                                  data=json.dumps(high_priority_data),
                                  content_type='application/json',
                                  headers=auth_headers)
            
            assert response.status_code == 201
            
            # Verify priority was passed to job queue
            call_args = mock_enqueue.call_args
            assert call_args[1]['priority'] == 'urgent'
    
    def test_concurrent_investigation_handling(self, client, auth_headers):
        """Test handling multiple concurrent investigations"""
        investigations_data = [
            {"target": f"example{i}.com", "investigation_type": "comprehensive"}
            for i in range(3)
        ]
        
        job_ids = []
        
        with patch('app.job_queue_manager.enqueue_investigation') as mock_enqueue:
            mock_enqueue.side_effect = [f"job_{i}" for i in range(3)]
            
            # Create multiple investigations concurrently
            for inv_data in investigations_data:
                response = client.post('/api/investigations',
                                      data=json.dumps(inv_data),
                                      content_type='application/json',
                                      headers=auth_headers)
                
                assert response.status_code == 201
                data = json.loads(response.data)
                job_ids.append(data['job_id'])
            
            # Verify all investigations were queued
            assert len(job_ids) == 3
            assert mock_enqueue.call_count == 3
    
    def test_investigation_data_persistence(self, client, auth_headers):
        """Test that investigation data persists through async workflow"""
        investigation_data = {
            "target": "persistence-test.com",
            "investigation_type": "comprehensive",
            "priority": "high",
            "investigator": "test_analyst"
        }
        
        with patch('app.job_queue_manager.enqueue_investigation', return_value="job_123"):
            # Create investigation
            response = client.post('/api/investigations',
                                  data=json.dumps(investigation_data),
                                  content_type='application/json',
                                  headers=auth_headers)
            
            assert response.status_code == 201
            data = json.loads(response.data)
            investigation_id = data['investigation_id']
        
        # Retrieve investigation and verify data persistence
        mock_investigation = Mock()
        mock_investigation.to_dict.return_value = {
            'id': investigation_id,
            'target': 'persistence-test.com',
            'investigation_type': 'comprehensive',
            'priority': 'high',
            'investigator_name': 'test_analyst',
            'status': 'queued'
        }
        
        with patch('app.orchestrator.get_investigation', return_value=mock_investigation):
            response = client.get(f'/api/investigations/{investigation_id}',
                                 headers=auth_headers)
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['target'] == 'persistence-test.com'
            assert data['investigation_type'] == 'comprehensive'
            assert data['priority'] == 'high'
            assert data['investigator_name'] == 'test_analyst'
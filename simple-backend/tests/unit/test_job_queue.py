"""
Unit tests for job queue functionality
"""
import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from job_queue import JobQueueManager, update_job_progress, mark_job_failed


class TestJobQueueManager:
    """Test job queue management functionality"""
    
    @patch('job_queue.Redis')
    def test_job_queue_manager_init(self, mock_redis):
        """Test JobQueueManager initialization"""
        mock_redis_instance = Mock()
        mock_redis.return_value = mock_redis_instance
        mock_redis_instance.ping.return_value = True
        
        manager = JobQueueManager()
        
        assert manager.redis_conn == mock_redis_instance
        assert 'investigations' in manager.queues
        assert 'reports' in manager.queues
        assert 'mcp_operations' in manager.queues
        assert 'compliance' in manager.queues
        mock_redis_instance.ping.assert_called_once()
    
    @patch('job_queue.Redis')
    def test_redis_connection_failure(self, mock_redis):
        """Test handling of Redis connection failure"""
        mock_redis_instance = Mock()
        mock_redis.return_value = mock_redis_instance
        mock_redis_instance.ping.side_effect = ConnectionError("Redis not available")
        
        # Should not raise exception, just log error
        manager = JobQueueManager()
        assert manager.redis_conn == mock_redis_instance
    
    @patch('job_queue.job_queue_manager')
    def test_enqueue_investigation(self, mock_manager):
        """Test investigation queueing"""
        mock_queue = Mock()
        mock_job = Mock()
        mock_job.id = "job_123"
        mock_queue.enqueue.return_value = mock_job
        
        mock_manager.queues = {'investigations': mock_queue}
        
        with patch('job_queue.TraceContextManager.get_current_trace_id', return_value='trace_123'):
            job_id = mock_manager.enqueue_investigation(
                investigation_id='inv_123',
                target='example.com',
                investigation_type='comprehensive'
            )
        
        assert job_id == "job_123"
        mock_queue.enqueue.assert_called_once()
    
    @patch('job_queue.job_queue_manager')
    def test_enqueue_report_generation(self, mock_manager):
        """Test report generation queueing"""
        mock_queue = Mock()
        mock_job = Mock()
        mock_job.id = "report_job_123"
        mock_queue.enqueue.return_value = mock_job
        
        mock_manager.queues = {'reports': mock_queue}
        
        with patch('job_queue.TraceContextManager.get_current_trace_id', return_value='trace_123'):
            job_id = mock_manager.enqueue_report_generation(
                investigation_id='inv_123',
                report_type='executive'
            )
        
        assert job_id == "report_job_123"
        mock_queue.enqueue.assert_called_once()
    
    @patch('job_queue.job_queue_manager')
    def test_enqueue_mcp_operation(self, mock_manager):
        """Test MCP operation queueing"""
        mock_queue = Mock()
        mock_job = Mock()
        mock_job.id = "mcp_job_123"
        mock_queue.enqueue.return_value = mock_job
        
        mock_manager.queues = {'mcp_operations': mock_queue}
        
        with patch('job_queue.TraceContextManager.get_current_trace_id', return_value='trace_123'):
            job_id = mock_manager.enqueue_mcp_operation(
                operation_type='whois_lookup',
                target='example.com',
                tools=['whois', 'dns']
            )
        
        assert job_id == "mcp_job_123"
        mock_queue.enqueue.assert_called_once()
    
    @patch('job_queue.Job')
    @patch('job_queue.job_queue_manager')
    def test_get_job_status(self, mock_manager, mock_job_class):
        """Test getting job status"""
        mock_job = Mock()
        mock_job.id = "job_123"
        mock_job.get_status.return_value = "finished"
        mock_job.created_at = datetime.utcnow()
        mock_job.started_at = datetime.utcnow()
        mock_job.ended_at = datetime.utcnow()
        mock_job.meta = {'trace_id': 'trace_123', 'type': 'investigation', 'progress': 100}
        mock_job.is_finished = True
        mock_job.is_failed = False
        mock_job.result = {'status': 'completed'}
        mock_job.func_name = 'execute_investigation'
        
        mock_job_class.fetch.return_value = mock_job
        mock_manager.redis_conn = Mock()
        
        status = mock_manager.get_job_status("job_123")
        
        assert status['id'] == "job_123"
        assert status['status'] == "finished"
        assert status['progress'] == 100
        assert status['trace_id'] == 'trace_123'
        assert status['type'] == 'investigation'
        assert 'result' in status
    
    @patch('job_queue.Job')
    @patch('job_queue.job_queue_manager')
    def test_cancel_job(self, mock_manager, mock_job_class):
        """Test job cancellation"""
        mock_job = Mock()
        mock_job.get_status.return_value = "started"
        mock_job.cancel.return_value = None
        mock_job.meta = {'trace_id': 'trace_123'}
        
        mock_job_class.fetch.return_value = mock_job
        mock_manager.redis_conn = Mock()
        
        result = mock_manager.cancel_job("job_123")
        
        assert result is True
        mock_job.cancel.assert_called_once()
    
    @patch('job_queue.job_queue_manager')
    def test_get_queue_stats(self, mock_manager):
        """Test getting queue statistics"""
        mock_queue = Mock()
        mock_queue.__len__ = Mock(return_value=5)
        mock_queue.scheduled_job_registry.count = 2
        mock_queue.started_job_registry.count = 1
        mock_queue.finished_job_registry.count = 10
        mock_queue.failed_job_registry.count = 0
        mock_queue.deferred_job_registry.count = 0
        
        mock_manager.queues = {'investigations': mock_queue}
        
        stats = mock_manager.get_queue_stats()
        
        assert 'investigations' in stats
        assert stats['investigations']['length'] == 5
        assert stats['investigations']['scheduled_jobs'] == 2
        assert stats['investigations']['started_jobs'] == 1
    
    @patch('job_queue.job_queue_manager')
    def test_health_check_healthy(self, mock_manager):
        """Test health check when system is healthy"""
        mock_redis = Mock()
        mock_redis.ping.return_value = True
        mock_manager.redis_conn = mock_redis
        
        mock_queue = Mock()
        mock_queue.__len__ = Mock(return_value=0)
        mock_queue.workers = []
        mock_manager.queues = {'investigations': mock_queue}
        
        with patch('job_queue.Worker.all', return_value=[]):
            health = mock_manager.health_check()
        
        assert health['status'] == 'healthy'
        assert health['redis_connection'] is True
        assert 'investigations' in health['queues']
    
    @patch('job_queue.job_queue_manager')
    def test_health_check_unhealthy(self, mock_manager):
        """Test health check when Redis is unhealthy"""
        mock_redis = Mock()
        mock_redis.ping.side_effect = ConnectionError("Redis down")
        mock_manager.redis_conn = mock_redis
        
        health = mock_manager.health_check()
        
        assert health['status'] == 'unhealthy'
        assert 'error' in health


class TestJobUtilities:
    """Test job utility functions"""
    
    @patch('job_queue.Job')
    @patch('job_queue.job_queue_manager')
    def test_update_job_progress(self, mock_manager, mock_job_class):
        """Test updating job progress"""
        mock_job = Mock()
        mock_job.meta = {}
        mock_job.save_meta.return_value = None
        
        mock_job_class.fetch.return_value = mock_job
        mock_manager.redis_conn = Mock()
        
        update_job_progress("job_123", 50, "Halfway done")
        
        assert mock_job.meta['progress'] == 50
        assert mock_job.meta['current_message'] == "Halfway done"
        assert 'last_update' in mock_job.meta
        mock_job.save_meta.assert_called_once()
    
    @patch('job_queue.Job')
    @patch('job_queue.job_queue_manager')
    def test_mark_job_failed(self, mock_manager, mock_job_class):
        """Test marking job as failed"""
        mock_job = Mock()
        mock_job.meta = {}
        mock_job.save_meta.return_value = None
        
        mock_job_class.fetch.return_value = mock_job
        mock_manager.redis_conn = Mock()
        
        mark_job_failed("job_123", "Something went wrong", "network_error")
        
        assert mock_job.meta['error_message'] == "Something went wrong"
        assert mock_job.meta['failure_reason'] == "network_error"
        assert 'failed_at' in mock_job.meta
        mock_job.save_meta.assert_called_once()
    
    @patch('job_queue.Job')
    @patch('job_queue.job_queue_manager')
    def test_update_job_progress_error_handling(self, mock_manager, mock_job_class):
        """Test error handling in job progress update"""
        mock_job_class.fetch.side_effect = Exception("Job not found")
        mock_manager.redis_conn = Mock()
        
        # Should not raise exception
        update_job_progress("nonexistent_job", 50, "Test message")
    
    @patch('job_queue.Job')
    @patch('job_queue.job_queue_manager')
    def test_mark_job_failed_error_handling(self, mock_manager, mock_job_class):
        """Test error handling in mark job failed"""
        mock_job_class.fetch.side_effect = Exception("Job not found")
        mock_manager.redis_conn = Mock()
        
        # Should not raise exception
        mark_job_failed("nonexistent_job", "Error message", "reason")


class TestJobQueueIntegration:
    """Integration tests for job queue operations"""
    
    @patch('job_queue.job_queue_manager')
    def test_investigation_workflow(self, mock_manager):
        """Test complete investigation workflow through job queue"""
        # Mock investigation queueing
        mock_queue = Mock()
        mock_job = Mock()
        mock_job.id = "inv_job_123"
        mock_queue.enqueue.return_value = mock_job
        mock_manager.queues = {'investigations': mock_queue}
        
        # Mock job status tracking
        mock_status_job = Mock()
        mock_status_job.id = "inv_job_123"
        mock_status_job.get_status.return_value = "finished"
        mock_status_job.meta = {'progress': 100, 'type': 'investigation'}
        mock_status_job.created_at = datetime.utcnow()
        mock_status_job.is_finished = True
        mock_status_job.is_failed = False
        mock_status_job.result = {'status': 'completed'}
        
        with patch('job_queue.TraceContextManager.get_current_trace_id', return_value='trace_123'), \
             patch('job_queue.Job.fetch', return_value=mock_status_job):
            
            # Queue investigation
            job_id = mock_manager.enqueue_investigation(
                investigation_id='inv_123',
                target='example.com',
                investigation_type='comprehensive'
            )
            
            # Check status
            status = mock_manager.get_job_status(job_id)
            
            assert job_id == "inv_job_123"
            assert status['status'] == "finished"
            assert status['progress'] == 100
    
    @patch('job_queue.job_queue_manager')
    def test_queue_error_handling(self, mock_manager):
        """Test error handling in queue operations"""
        mock_queue = Mock()
        mock_queue.enqueue.side_effect = Exception("Queue error")
        mock_manager.queues = {'investigations': mock_queue}
        
        with patch('job_queue.TraceContextManager.get_current_trace_id', return_value='trace_123'):
            job_id = mock_manager.enqueue_investigation(
                investigation_id='inv_123',
                target='example.com',
                investigation_type='comprehensive'
            )
        
        # Should return None on error
        assert job_id is None
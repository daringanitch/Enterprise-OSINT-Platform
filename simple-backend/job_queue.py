"""
Async Job Queue using RQ (Redis Queue) for OSINT Platform
Handles background processing of investigations, reports, and MCP operations
"""
import os
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from rq import Queue, Worker, Job
from rq.job import JobStatus
from redis import Redis
from trace_context import TraceContextManager, StructuredLogger

# Initialize logger
logger = StructuredLogger(__name__)

# Redis connection configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
REDIS_DB = int(os.getenv('REDIS_DB', '0'))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')

# Job timeouts (in seconds)
DEFAULT_TIMEOUT = 600  # 10 minutes
INVESTIGATION_TIMEOUT = 1800  # 30 minutes
REPORT_TIMEOUT = 300  # 5 minutes
MCP_TIMEOUT = 120  # 2 minutes


class JobQueueManager:
    """Manages async job queues for different types of operations"""
    
    def __init__(self):
        self.redis_conn = Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_PASSWORD,
            decode_responses=True,
            socket_timeout=30,
            socket_connect_timeout=30,
            retry_on_timeout=True
        )
        
        # Define separate queues for different job types
        self.queues = {
            'investigations': Queue('investigations', connection=self.redis_conn),
            'reports': Queue('reports', connection=self.redis_conn),
            'mcp_operations': Queue('mcp_operations', connection=self.redis_conn),
            'compliance': Queue('compliance', connection=self.redis_conn),
            'default': Queue('default', connection=self.redis_conn)
        }
        
        # Test Redis connection
        self._test_connection()
    
    def _test_connection(self) -> bool:
        """Test Redis connection and log status"""
        try:
            self.redis_conn.ping()
            logger.info("Redis connection established successfully", extra={
                'redis_host': REDIS_HOST,
                'redis_port': REDIS_PORT,
                'redis_db': REDIS_DB
            })
            return True
        except Exception as e:
            logger.error("Failed to connect to Redis", extra={
                'error': str(e),
                'redis_host': REDIS_HOST,
                'redis_port': REDIS_PORT
            })
            return False
    
    def enqueue_investigation(self, investigation_id: str, target: str, 
                            investigation_type: str, **kwargs) -> Optional[str]:
        """Queue an investigation for background processing"""
        try:
            trace_id = TraceContextManager.get_current_trace_id()
            
            job_data = {
                'investigation_id': investigation_id,
                'target': target,
                'investigation_type': investigation_type,
                'trace_id': trace_id,
                'created_at': datetime.utcnow().isoformat(),
                **kwargs
            }
            
            job = self.queues['investigations'].enqueue(
                'investigation_orchestrator.execute_investigation_async',
                investigation_id,
                job_data,
                timeout=INVESTIGATION_TIMEOUT,
                job_id=f"investigation_{investigation_id}",
                meta={'trace_id': trace_id, 'type': 'investigation'}
            )
            
            logger.info("Investigation queued for background processing", extra={
                'investigation_id': investigation_id,
                'job_id': job.id,
                'target': target,
                'investigation_type': investigation_type,
                'trace_id': trace_id
            })
            
            return job.id
            
        except Exception as e:
            logger.error("Failed to queue investigation", extra={
                'investigation_id': investigation_id,
                'error': str(e),
                'trace_id': TraceContextManager.get_current_trace_id()
            })
            return None
    
    def enqueue_report_generation(self, investigation_id: str, 
                                report_type: str = 'comprehensive') -> Optional[str]:
        """Queue report generation for background processing"""
        try:
            trace_id = TraceContextManager.get_current_trace_id()
            
            job_data = {
                'investigation_id': investigation_id,
                'report_type': report_type,
                'trace_id': trace_id,
                'created_at': datetime.utcnow().isoformat()
            }
            
            job = self.queues['reports'].enqueue(
                'professional_report_generator.generate_report_async',
                investigation_id,
                report_type,
                job_data,
                timeout=REPORT_TIMEOUT,
                job_id=f"report_{investigation_id}_{report_type}",
                meta={'trace_id': trace_id, 'type': 'report'}
            )
            
            logger.info("Report generation queued", extra={
                'investigation_id': investigation_id,
                'job_id': job.id,
                'report_type': report_type,
                'trace_id': trace_id
            })
            
            return job.id
            
        except Exception as e:
            logger.error("Failed to queue report generation", extra={
                'investigation_id': investigation_id,
                'error': str(e),
                'trace_id': TraceContextManager.get_current_trace_id()
            })
            return None
    
    def enqueue_mcp_operation(self, operation_type: str, target: str, 
                            tools: List[str], **kwargs) -> Optional[str]:
        """Queue MCP operation for background processing"""
        try:
            trace_id = TraceContextManager.get_current_trace_id()
            
            job_data = {
                'operation_type': operation_type,
                'target': target,
                'tools': tools,
                'trace_id': trace_id,
                'created_at': datetime.utcnow().isoformat(),
                **kwargs
            }
            
            job = self.queues['mcp_operations'].enqueue(
                'mcp_clients.execute_mcp_operation_async',
                operation_type,
                target,
                tools,
                job_data,
                timeout=MCP_TIMEOUT,
                job_id=f"mcp_{operation_type}_{hash(target)}",
                meta={'trace_id': trace_id, 'type': 'mcp_operation'}
            )
            
            logger.info("MCP operation queued", extra={
                'operation_type': operation_type,
                'job_id': job.id,
                'target': target,
                'tools': tools,
                'trace_id': trace_id
            })
            
            return job.id
            
        except Exception as e:
            logger.error("Failed to queue MCP operation", extra={
                'operation_type': operation_type,
                'error': str(e),
                'trace_id': TraceContextManager.get_current_trace_id()
            })
            return None
    
    def enqueue_compliance_assessment(self, investigation_id: str, 
                                    frameworks: List[str]) -> Optional[str]:
        """Queue compliance assessment for background processing"""
        try:
            trace_id = TraceContextManager.get_current_trace_id()
            
            job_data = {
                'investigation_id': investigation_id,
                'frameworks': frameworks,
                'trace_id': trace_id,
                'created_at': datetime.utcnow().isoformat()
            }
            
            job = self.queues['compliance'].enqueue(
                'compliance_framework.assess_compliance_async',
                investigation_id,
                frameworks,
                job_data,
                timeout=DEFAULT_TIMEOUT,
                job_id=f"compliance_{investigation_id}",
                meta={'trace_id': trace_id, 'type': 'compliance'}
            )
            
            logger.info("Compliance assessment queued", extra={
                'investigation_id': investigation_id,
                'job_id': job.id,
                'frameworks': frameworks,
                'trace_id': trace_id
            })
            
            return job.id
            
        except Exception as e:
            logger.error("Failed to queue compliance assessment", extra={
                'investigation_id': investigation_id,
                'error': str(e),
                'trace_id': TraceContextManager.get_current_trace_id()
            })
            return None
    
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get detailed status of a background job"""
        try:
            job = Job.fetch(job_id, connection=self.redis_conn)
            
            status_info = {
                'id': job.id,
                'status': job.get_status(),
                'created_at': job.created_at.isoformat() if job.created_at else None,
                'started_at': job.started_at.isoformat() if job.started_at else None,
                'ended_at': job.ended_at.isoformat() if job.ended_at else None,
                'progress': job.meta.get('progress', 0),
                'trace_id': job.meta.get('trace_id'),
                'type': job.meta.get('type'),
                'func_name': job.func_name if hasattr(job, 'func_name') else None
            }
            
            # Add result or error information
            if job.is_finished:
                status_info['result'] = job.result
            elif job.is_failed:
                status_info['error'] = str(job.exc_info) if job.exc_info else 'Unknown error'
                status_info['failure_reason'] = job.meta.get('failure_reason')
            
            return status_info
            
        except Exception as e:
            logger.error("Failed to get job status", extra={
                'job_id': job_id,
                'error': str(e)
            })
            return {
                'id': job_id,
                'status': 'error',
                'error': f'Failed to fetch job status: {str(e)}'
            }
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a background job"""
        try:
            job = Job.fetch(job_id, connection=self.redis_conn)
            
            if job.get_status() in [JobStatus.QUEUED, JobStatus.STARTED]:
                job.cancel()
                logger.info("Job cancelled successfully", extra={
                    'job_id': job_id,
                    'trace_id': job.meta.get('trace_id')
                })
                return True
            else:
                logger.warning("Cannot cancel job - not in cancellable state", extra={
                    'job_id': job_id,
                    'status': job.get_status()
                })
                return False
                
        except Exception as e:
            logger.error("Failed to cancel job", extra={
                'job_id': job_id,
                'error': str(e)
            })
            return False
    
    def get_queue_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all queues"""
        stats = {}
        
        for queue_name, queue in self.queues.items():
            try:
                stats[queue_name] = {
                    'length': len(queue),
                    'scheduled_jobs': queue.scheduled_job_registry.count,
                    'started_jobs': queue.started_job_registry.count,
                    'finished_jobs': queue.finished_job_registry.count,
                    'failed_jobs': queue.failed_job_registry.count,
                    'deferred_jobs': queue.deferred_job_registry.count
                }
            except Exception as e:
                stats[queue_name] = {'error': str(e)}
        
        return stats
    
    def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check for job queue system"""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'redis_connection': False,
            'queues': {},
            'workers': []
        }
        
        try:
            # Test Redis connection
            self.redis_conn.ping()
            health_status['redis_connection'] = True
            
            # Check queue health
            for queue_name, queue in self.queues.items():
                queue_health = {
                    'accessible': True,
                    'length': len(queue),
                    'workers': len(queue.workers)
                }
                health_status['queues'][queue_name] = queue_health
            
            # Check active workers
            workers = Worker.all(connection=self.redis_conn)
            for worker in workers:
                worker_info = {
                    'name': worker.name,
                    'state': worker.get_state(),
                    'current_job': worker.get_current_job_id(),
                    'queues': [q.name for q in worker.queues]
                }
                health_status['workers'].append(worker_info)
            
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['error'] = str(e)
            logger.error("Job queue health check failed", extra={'error': str(e)})
        
        return health_status


# Global job queue manager instance
job_queue_manager = JobQueueManager()


# Job progress tracking utilities
def update_job_progress(job_id: str, progress: int, message: str = None):
    """Update job progress for real-time monitoring"""
    try:
        job = Job.fetch(job_id, connection=job_queue_manager.redis_conn)
        meta = job.meta
        meta['progress'] = progress
        meta['last_update'] = datetime.utcnow().isoformat()
        if message:
            meta['current_message'] = message
        job.meta = meta
        job.save_meta()
        
        logger.debug("Job progress updated", extra={
            'job_id': job_id,
            'progress': progress,
            'message': message
        })
        
    except Exception as e:
        logger.error("Failed to update job progress", extra={
            'job_id': job_id,
            'error': str(e)
        })


def mark_job_failed(job_id: str, error_message: str, failure_reason: str = None):
    """Mark job as failed with detailed error information"""
    try:
        job = Job.fetch(job_id, connection=job_queue_manager.redis_conn)
        meta = job.meta
        meta['failed_at'] = datetime.utcnow().isoformat()
        meta['error_message'] = error_message
        if failure_reason:
            meta['failure_reason'] = failure_reason
        job.meta = meta
        job.save_meta()
        
        logger.error("Job marked as failed", extra={
            'job_id': job_id,
            'error_message': error_message,
            'failure_reason': failure_reason
        })
        
    except Exception as e:
        logger.error("Failed to mark job as failed", extra={
            'job_id': job_id,
            'error': str(e)
        })
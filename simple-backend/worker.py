#!/usr/bin/env python3
"""
RQ Worker for OSINT Platform Background Jobs
Runs background workers for processing investigations, reports, and MCP operations
"""
import os
import sys
import signal
import logging
from rq import Worker, Connection
from job_queue import job_queue_manager
from trace_context import StructuredLogger

# Configure logging
logger = StructuredLogger(__name__)

# Worker configuration
WORKER_TIMEOUT = int(os.getenv('WORKER_TIMEOUT', '1800'))  # 30 minutes
WORKER_TTL = int(os.getenv('WORKER_TTL', '3600'))  # 1 hour
WORKER_NAME = os.getenv('WORKER_NAME', f'osint-worker-{os.getpid()}')


class OSINTWorker(Worker):
    """Custom worker with enhanced logging and error handling"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setup_signal_handlers()
    
    def setup_signal_handlers(self):
        """Setup graceful shutdown signal handlers"""
        signal.signal(signal.SIGTERM, self.graceful_shutdown)
        signal.signal(signal.SIGINT, self.graceful_shutdown)
    
    def graceful_shutdown(self, signum, frame):
        """Handle graceful shutdown"""
        logger.info("Received shutdown signal, stopping worker gracefully", extra={
            'worker_name': self.name,
            'signal': signum,
            'current_job': self.get_current_job_id()
        })
        self.request_stop()
    
    def perform_job(self, job, queue):
        """Override to add enhanced logging and error handling"""
        trace_id = job.meta.get('trace_id', 'unknown')
        
        logger.info("Starting job execution", extra={
            'job_id': job.id,
            'job_type': job.meta.get('type'),
            'func_name': job.func_name,
            'trace_id': trace_id,
            'worker_name': self.name
        })
        
        try:
            # Set trace context for job execution
            if trace_id != 'unknown':
                os.environ['TRACE_ID'] = trace_id
            
            result = super().perform_job(job, queue)
            
            logger.info("Job completed successfully", extra={
                'job_id': job.id,
                'trace_id': trace_id,
                'worker_name': self.name
            })
            
            return result
            
        except Exception as e:
            logger.error("Job execution failed", extra={
                'job_id': job.id,
                'trace_id': trace_id,
                'error': str(e),
                'worker_name': self.name
            })
            raise
        finally:
            # Clean up trace context
            if 'TRACE_ID' in os.environ:
                del os.environ['TRACE_ID']
    
    def work(self, *args, **kwargs):
        """Override work method with startup logging"""
        logger.info("Worker starting", extra={
            'worker_name': self.name,
            'queues': [q.name for q in self.queues],
            'timeout': WORKER_TIMEOUT,
            'ttl': WORKER_TTL
        })
        
        try:
            return super().work(*args, **kwargs)
        except KeyboardInterrupt:
            logger.info("Worker stopped by user", extra={
                'worker_name': self.name
            })
        except Exception as e:
            logger.error("Worker error", extra={
                'worker_name': self.name,
                'error': str(e)
            })
            raise


def run_worker(queue_names=None):
    """Run worker for specified queues"""
    if queue_names is None:
        # Default to all queues
        queue_names = ['investigations', 'reports', 'mcp_operations', 'compliance', 'default']
    
    # Get queue objects
    queues = []
    for queue_name in queue_names:
        if queue_name in job_queue_manager.queues:
            queues.append(job_queue_manager.queues[queue_name])
        else:
            logger.warning(f"Unknown queue: {queue_name}")
    
    if not queues:
        logger.error("No valid queues specified")
        sys.exit(1)
    
    # Create and start worker
    with Connection(job_queue_manager.redis_conn):
        worker = OSINTWorker(
            queues,
            name=WORKER_NAME,
            default_timeout=WORKER_TIMEOUT,
            default_result_ttl=WORKER_TTL
        )
        
        # Perform health check before starting
        health = job_queue_manager.health_check()
        if health['status'] != 'healthy':
            logger.error("Job queue health check failed, cannot start worker", extra={
                'health_status': health
            })
            sys.exit(1)
        
        logger.info("Worker health check passed, starting worker", extra={
            'worker_name': WORKER_NAME,
            'queue_names': queue_names,
            'redis_host': job_queue_manager.redis_conn.connection_pool.connection_kwargs['host'],
            'redis_port': job_queue_manager.redis_conn.connection_pool.connection_kwargs['port']
        })
        
        try:
            worker.work(with_scheduler=True)
        except Exception as e:
            logger.error("Worker failed to start", extra={
                'error': str(e),
                'worker_name': WORKER_NAME
            })
            sys.exit(1)


def main():
    """Main entry point for worker script"""
    import argparse
    
    parser = argparse.ArgumentParser(description='OSINT Platform Background Worker')
    parser.add_argument('--queues', '-q', nargs='+', 
                       help='Queue names to process (default: all)',
                       choices=['investigations', 'reports', 'mcp_operations', 'compliance', 'default'])
    parser.add_argument('--name', '-n', 
                       help='Worker name (default: auto-generated)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Set worker name if provided
    if args.name:
        global WORKER_NAME
        WORKER_NAME = args.name
    
    # Start worker
    logger.info("Starting OSINT Platform worker", extra={
        'worker_name': WORKER_NAME,
        'queues': args.queues or ['all'],
        'verbose': args.verbose
    })
    
    run_worker(args.queues)


if __name__ == '__main__':
    main()
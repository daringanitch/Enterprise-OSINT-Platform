#!/usr/bin/env python3
"""
Enable Real Investigation Processing

This creates a simple background processor to handle investigations.
"""

import subprocess
import time

# Create a background processor script
processor_script = '''
import sys
import os
import asyncio
import time
import threading
sys.path.insert(0, '/app')

from investigation_orchestrator import InvestigationOrchestrator
from mcp_clients import MCPClientManager
import logging

logger = logging.getLogger(__name__)

class InvestigationProcessor:
    """Simple background processor for investigations"""
    
    def __init__(self):
        self.orchestrator = InvestigationOrchestrator()
        self.mcp_client = MCPClientManager()
        self.running = True
        
    async def process_investigation(self, inv_id):
        """Process a single investigation"""
        try:
            investigation = self.orchestrator.get_investigation(inv_id)
            if not investigation:
                logger.error(f"Investigation {inv_id} not found")
                return False
                
            target = investigation.target_profile.primary_identifier
            inv_type = investigation.investigation_type.value
            
            logger.info(f"Processing {inv_id}: {target} ({inv_type})")
            
            # Update status to processing
            investigation.status = models.InvestigationStatus.IN_PROGRESS
            investigation.current_stage = "data_collection"
            investigation.current_activity = "Gathering intelligence from MCP servers"
            
            # Gather intelligence
            try:
                results = await self.mcp_client.gather_all_intelligence(target, inv_type)
                
                if results:
                    # Process results
                    investigation.infrastructure_intelligence = results.get('infrastructure', [])
                    investigation.social_intelligence = results.get('social', [])
                    investigation.threat_intelligence = results.get('threat', [])
                    
                    # Update progress
                    investigation.progress['data_points_collected'] = sum(len(v) if isinstance(v, list) else 1 for v in results.values())
                    investigation.status = models.InvestigationStatus.COMPLETED
                    investigation.current_stage = "completed"
                    investigation.current_activity = "Investigation completed successfully"
                    investigation.completed_at = datetime.utcnow()
                    
                    logger.info(f"Completed {inv_id} with {investigation.progress['data_points_collected']} data points")
                else:
                    investigation.status = models.InvestigationStatus.COMPLETED
                    investigation.current_activity = "No data collected"
                    
            except Exception as e:
                logger.error(f"Error processing {inv_id}: {e}")
                investigation.status = models.InvestigationStatus.FAILED
                investigation.current_activity = f"Error: {str(e)[:100]}"
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to process {inv_id}: {e}")
            return False
    
    async def run_processor(self):
        """Main processing loop"""
        logger.info("Investigation processor started")
        
        while self.running:
            try:
                # Check for queued investigations
                queued = []
                for inv_id, inv in self.orchestrator.active_investigations.items():
                    if hasattr(inv, 'status') and inv.status.value in ['queued', 'pending']:
                        queued.append(inv_id)
                
                if queued:
                    logger.info(f"Found {len(queued)} queued investigations")
                    for inv_id in queued:
                        await self.process_investigation(inv_id)
                
                # Wait before next check
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Processor error: {e}")
                await asyncio.sleep(10)
    
    def start(self):
        """Start the processor in a thread"""
        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.run_processor())
            
        thread = threading.Thread(target=run, name="InvestigationProcessor")
        thread.daemon = True
        thread.start()
        logger.info("Processor thread started")

# Import required modules
import models
from datetime import datetime

# Start the processor
print("🚀 Starting investigation processor...")
processor = InvestigationProcessor()
processor.start()

print("✅ Processor started! Monitoring for queued investigations...")
print("   Check logs with: kubectl logs -n osint-platform -l app=osint-backend | grep -E 'Processing|Completed'")

# Keep the script running
while True:
    time.sleep(60)
    active_count = len(processor.orchestrator.active_investigations)
    print(f"⏰ Processor running... Active investigations: {active_count}")
'''

def deploy_processor():
    """Deploy the processor to backend"""
    print("🚀 Deploying investigation processor...")
    
    # Save script to a file first
    with open('/tmp/processor.py', 'w') as f:
        f.write(processor_script)
    
    # Get backend pod
    result = subprocess.run([
        'kubectl', 'get', 'pods', '-n', 'osint-platform',
        '-l', 'app=osint-backend', '-o', 'jsonpath={.items[0].metadata.name}'
    ], capture_output=True, text=True)
    
    pod_name = result.stdout.strip()
    print(f"📍 Using pod: {pod_name}")
    
    # Copy script to pod
    subprocess.run([
        'kubectl', 'cp', '/tmp/processor.py',
        f'osint-platform/{pod_name}:/tmp/processor.py'
    ])
    
    # Run the processor in background
    print("🔄 Starting processor in pod...")
    result = subprocess.run([
        'kubectl', 'exec', '-n', 'osint-platform', pod_name, '--',
        'bash', '-c', 'nohup python3 /tmp/processor.py > /tmp/processor.log 2>&1 &'
    ], capture_output=True, text=True)
    
    time.sleep(3)
    
    # Check if it started
    result = subprocess.run([
        'kubectl', 'exec', '-n', 'osint-platform', pod_name, '--',
        'cat', '/tmp/processor.log'
    ], capture_output=True, text=True)
    
    print("Processor output:")
    print(result.stdout)
    
    if "Processor started" in result.stdout:
        print("\n✅ Investigation processor deployed successfully!")
        print("🎯 Investigations should now process automatically")
        print("\n💡 Test it:")
        print("1. Create a new investigation")
        print("2. It should move from QUEUED → PROCESSING → COMPLETED")
        return True
    else:
        print("\n❌ Processor failed to start")
        return False

if __name__ == "__main__":
    # First, let me create a simpler immediate solution
    print("🔧 Creating immediate processing solution...")
    
    simple_fix = '''
kubectl exec -n osint-platform deployment/osint-backend -- python3 -c "
import sys
import os
import asyncio
sys.path.insert(0, '/app')

from investigation_orchestrator import InvestigationOrchestrator
from mcp_clients import MCPClientManager

async def process_all_queued():
    orchestrator = InvestigationOrchestrator()
    mcp_client = MCPClientManager()
    
    # Get all queued investigations
    queued = []
    for inv_id, inv in orchestrator.active_investigations.items():
        if hasattr(inv, 'status'):
            print(f'{inv_id}: {inv.status.value}')
            if inv.status.value in ['queued', 'pending']:
                queued.append((inv_id, inv))
    
    print(f'Found {len(queued)} queued investigations')
    
    for inv_id, inv in queued:
        print(f'Processing {inv_id}...')
        try:
            # Start the investigation
            result = await orchestrator.start_investigation(inv_id)
            print(f'Started: {result}')
        except Exception as e:
            print(f'Error: {e}')
            # Try direct processing
            try:
                target = inv.target_profile.primary_identifier
                results = await mcp_client.gather_all_intelligence(target, 'infrastructure')
                print(f'Got {len(results)} results for {target}')
            except Exception as e2:
                print(f'Direct processing error: {e2}')

asyncio.run(process_all_queued())
"
'''
    
    print("Running immediate fix...")
    result = subprocess.run(simple_fix, shell=True, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("Errors:", result.stderr)
    
    # Deploy the persistent processor
    # deploy_processor()
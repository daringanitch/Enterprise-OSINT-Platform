#!/usr/bin/env python3
"""
Background Investigation Processor

Creates a simple background processor that runs inside the backend pod.
"""

import subprocess
import time

# The background processor code
processor_code = '''
import sys
import os
import asyncio
import threading
import time
import json
import logging
from datetime import datetime, timedelta
sys.path.insert(0, '/app')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('background_processor')

class BackgroundInvestigationProcessor:
    """Simple background processor for OSINT investigations"""
    
    def __init__(self):
        self.running = True
        
    async def process_single_investigation(self, inv_id, target, inv_type):
        """Process a single investigation end-to-end"""
        try:
            from mcp_clients import MCPClientManager
            import models
            
            logger.info(f"🔍 Processing {inv_id}: {target} ({inv_type})")
            
            # Initialize MCP client
            mcp_client = MCPClientManager()
            
            # Gather intelligence
            results = await mcp_client.gather_all_intelligence(target, inv_type)
            
            if results:
                # Process and format results
                findings = {}
                data_points = 0
                
                for category, data in results.items():
                    if data:
                        findings[category] = data
                        data_points += len(data) if isinstance(data, list) else 1
                
                logger.info(f"✅ {inv_id}: Collected {data_points} data points across {len(findings)} categories")
                
                # Save to database
                try:
                    import psycopg2
                    conn = psycopg2.connect(os.environ['POSTGRES_URL'])
                    cur = conn.cursor()
                    
                    cur.execute("""
                        INSERT INTO investigations (
                            investigation_id, target, investigation_type, priority, status,
                            findings, progress_percentage, current_stage, current_activity,
                            completed_at, created_at, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (investigation_id) DO UPDATE SET
                            status = EXCLUDED.status,
                            findings = EXCLUDED.findings,
                            progress_percentage = EXCLUDED.progress_percentage,
                            current_stage = EXCLUDED.current_stage,
                            current_activity = EXCLUDED.current_activity,
                            completed_at = EXCLUDED.completed_at,
                            updated_at = EXCLUDED.updated_at;
                    """, (
                        inv_id, target, inv_type, 'normal', 'COMPLETED',
                        json.dumps(findings), 100, 'completed', 
                        f'Investigation completed with {data_points} findings',
                        datetime.utcnow(), datetime.utcnow(), datetime.utcnow()
                    ))
                    
                    conn.commit()
                    conn.close()
                    logger.info(f"💾 {inv_id}: Saved to database")
                    
                except Exception as db_error:
                    logger.error(f"Database save failed for {inv_id}: {db_error}")
                    
            else:
                logger.warning(f"⚠️  {inv_id}: No data collected")
                
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to process {inv_id}: {e}")
            return False
    
    async def check_and_process_investigations(self):
        """Check for new investigations and process them"""
        try:
            from investigation_orchestrator import InvestigationOrchestrator
            
            orchestrator = InvestigationOrchestrator()
            
            # Check active investigations in memory
            processed_count = 0
            
            for inv_id, investigation in list(orchestrator.active_investigations.items()):
                try:
                    status = investigation.status.value if hasattr(investigation, 'status') and hasattr(investigation.status, 'value') else 'unknown'
                    
                    if status in ['queued', 'pending', 'QUEUED', 'PENDING']:
                        target = investigation.target_profile.primary_identifier if hasattr(investigation, 'target_profile') else 'unknown'
                        inv_type = investigation.investigation_type.value if hasattr(investigation, 'investigation_type') and hasattr(investigation.investigation_type, 'value') else 'infrastructure'
                        
                        logger.info(f"🎯 Found queued investigation: {inv_id} ({target})")
                        
                        # Update status to processing
                        if hasattr(investigation, 'status'):
                            import models
                            investigation.status = models.InvestigationStatus.IN_PROGRESS
                            investigation.current_stage = "processing"
                            investigation.current_activity = "Processing with MCP servers"
                        
                        # Process it
                        success = await self.process_single_investigation(inv_id, target, inv_type)
                        
                        if success:
                            # Update status to completed
                            if hasattr(investigation, 'status'):
                                investigation.status = models.InvestigationStatus.COMPLETED
                                investigation.current_stage = "completed"
                                investigation.current_activity = "Investigation completed"
                                investigation.completed_at = datetime.utcnow()
                            processed_count += 1
                        
                except Exception as inv_error:
                    logger.error(f"Error processing investigation {inv_id}: {inv_error}")
            
            if processed_count > 0:
                logger.info(f"🎉 Processed {processed_count} investigations this cycle")
            
        except Exception as e:
            logger.error(f"Error in check cycle: {e}")
    
    async def run_processor_loop(self):
        """Main processing loop"""
        logger.info("🚀 Background Investigation Processor started")
        logger.info("   Checking for queued investigations every 10 seconds...")
        
        while self.running:
            try:
                await self.check_and_process_investigations()
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Processor loop error: {e}")
                await asyncio.sleep(30)  # Wait longer on error
    
    def start_background_thread(self):
        """Start the processor in a background thread"""
        def run():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self.run_processor_loop())
            except Exception as e:
                logger.error(f"Background thread error: {e}")
        
        thread = threading.Thread(target=run, name="InvestigationProcessor")
        thread.daemon = True
        thread.start()
        logger.info("✅ Background processor thread started")

# Start the processor
print("🚀 Starting Background Investigation Processor...")

processor = BackgroundInvestigationProcessor()
processor.start_background_thread()

# Keep the script running and show periodic status
start_time = time.time()
while True:
    time.sleep(60)  # Status update every minute
    runtime = int(time.time() - start_time)
    print(f"⏰ Processor running for {runtime//60}m {runtime%60}s")
    
    # Show investigation count
    try:
        from investigation_orchestrator import InvestigationOrchestrator
        orchestrator = InvestigationOrchestrator()
        active_count = len(orchestrator.active_investigations)
        print(f"   Active investigations in memory: {active_count}")
    except:
        pass
'''

def deploy_background_processor():
    """Deploy the background processor to the backend pod"""
    print("🚀 Deploying Background Investigation Processor...")
    
    # Get backend pod name
    result = subprocess.run([
        'kubectl', 'get', 'pods', '-n', 'osint-platform',
        '-l', 'app=osint-backend', '-o', 'jsonpath={.items[0].metadata.name}'
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ Failed to get pod name: {result.stderr}")
        return False
    
    pod_name = result.stdout.strip()
    print(f"📍 Using pod: {pod_name}")
    
    # Write processor to temp file
    with open('/tmp/bg_processor.py', 'w') as f:
        f.write(processor_code)
    
    # Copy to pod
    result = subprocess.run([
        'kubectl', 'cp', '/tmp/bg_processor.py',
        f'osint-platform/{pod_name}:/tmp/bg_processor.py'
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ Failed to copy processor: {result.stderr}")
        return False
    
    print("📁 Processor copied to pod")
    
    # Start the processor in background
    print("🔄 Starting background processor...")
    
    result = subprocess.run([
        'kubectl', 'exec', '-n', 'osint-platform', pod_name, '--',
        'bash', '-c', 'nohup python3 /tmp/bg_processor.py > /tmp/processor.log 2>&1 &'
    ], capture_output=True, text=True)
    
    # Wait a moment for it to start
    time.sleep(3)
    
    # Check if it started successfully
    result = subprocess.run([
        'kubectl', 'exec', '-n', 'osint-platform', pod_name, '--',
        'head', '-20', '/tmp/processor.log'
    ], capture_output=True, text=True)
    
    print("🔍 Processor startup log:")
    print(result.stdout)
    
    if "Background processor thread started" in result.stdout or "Background Investigation Processor started" in result.stdout:
        print("\n✅ Background processor deployed and started successfully!")
        print("🎯 Investigations should now process automatically")
        
        # Show monitoring command
        print("\n📊 Monitor processor status:")
        print(f"   kubectl exec -n osint-platform {pod_name} -- tail -f /tmp/processor.log")
        
        return True
    else:
        print("\n❌ Processor failed to start")
        print("📄 Check logs with:")
        print(f"   kubectl exec -n osint-platform {pod_name} -- cat /tmp/processor.log")
        return False

if __name__ == "__main__":
    success = deploy_background_processor()
    
    if success:
        print("\n🎉 Background processor is now running!")
        print("   It will automatically process any queued investigations")
        print("   and check for new ones every 10 seconds")
    else:
        print("\n❌ Failed to deploy background processor")
    
    # Clean up temp file
    import os
    try:
        os.remove('/tmp/bg_processor.py')
    except:
        pass
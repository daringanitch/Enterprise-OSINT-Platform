#!/usr/bin/env python3
"""
Process Stuck Investigations Script

This script manually processes investigations that are stuck in QUEUED status.
"""

# Script to run inside the backend pod
script_content = '''
import json
import asyncio
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, '/app')

try:
    from investigation_orchestrator import InvestigationOrchestrator
    from mcp_clients import MCPClientManager
    import psycopg2
    
    print("🚀 Processing stuck investigations...")
    
    # Connect to database
    conn = psycopg2.connect(os.environ['POSTGRES_URL'])
    cur = conn.cursor()
    
    # Find investigations in QUEUED status or similar
    cur.execute("""
        SELECT investigation_id, target, investigation_type, priority, status 
        FROM investigations 
        WHERE status IN ('QUEUED', 'PENDING', 'PROCESSING')
        ORDER BY created_at ASC
        LIMIT 10;
    """)
    
    stuck_investigations = cur.fetchall()
    print(f"📋 Found {len(stuck_investigations)} investigations to process")
    
    if not stuck_investigations:
        print("✅ No stuck investigations found!")
        sys.exit(0)
    
    # Initialize orchestrator
    orchestrator = InvestigationOrchestrator()
    
    for inv_id, target, inv_type, priority, status in stuck_investigations:
        print(f"\\n🔍 Processing: {inv_id} ({target})")
        
        try:
            # Update status to PROCESSING
            cur.execute("""
                UPDATE investigations 
                SET status = 'PROCESSING', 
                    current_stage = 'initializing',
                    current_activity = 'Starting investigation',
                    updated_at = CURRENT_TIMESTAMP
                WHERE investigation_id = %s;
            """, (inv_id,))
            conn.commit()
            
            # Start the investigation processing
            result = await orchestrator.start_investigation(
                investigation_id=inv_id,
                target=target,
                investigation_type=inv_type,
                priority=priority
            )
            
            if result:
                print(f"✅ Started processing {inv_id}")
            else:
                print(f"❌ Failed to start {inv_id}")
                
        except Exception as e:
            print(f"❌ Error processing {inv_id}: {e}")
            # Reset to PENDING on error
            cur.execute("""
                UPDATE investigations 
                SET status = 'PENDING',
                    current_activity = 'Error occurred, ready to retry'
                WHERE investigation_id = %s;
            """, (inv_id,))
            conn.commit()
    
    conn.close()
    print("\\n🎉 Investigation processing complete!")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Available modules:")
    import os
    for file in os.listdir("/app"):
        if file.endswith(".py"):
            print(f"   {file}")
            
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
'''

print("Running investigation processing script in backend pod...")

import subprocess
import tempfile
import os

# Write script to temp file
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write(script_content)
    temp_script = f.name

try:
    # Copy script to pod and run it
    result = subprocess.run([
        'kubectl', 'cp', temp_script, 
        'osint-platform/osint-backend-546d988c95-5f9kt:/tmp/process_investigations.py'
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ Failed to copy script: {result.stderr}")
    else:
        print("📁 Script copied to pod")
        
        # Run the script
        result = subprocess.run([
            'kubectl', 'exec', '-n', 'osint-platform', 
            'deployment/osint-backend', '--', 
            'python3', '/tmp/process_investigations.py'
        ], capture_output=True, text=True)
        
        print("Script output:")
        print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)

finally:
    # Clean up temp file
    os.unlink(temp_script)
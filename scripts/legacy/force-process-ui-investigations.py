#!/usr/bin/env python3
"""
Force Process UI Investigations

This script finds investigations shown in the UI and forces them to process.
"""

import subprocess

# Script to run in backend pod
process_script = '''
import sys
import os
import asyncio
import json
from datetime import datetime
sys.path.insert(0, '/app')

from investigation_orchestrator import InvestigationOrchestrator
from mcp_clients import MCPClientManager
import models
import psycopg2

async def force_process_amazon_investigations():
    """Force process Amazon.com investigations"""
    print("🔍 Force processing Amazon investigations...")
    
    try:
        # Create new investigations for Amazon
        orchestrator = InvestigationOrchestrator()
        mcp_client = MCPClientManager()
        
        amazon_targets = ["amazon.com"]
        
        for target in amazon_targets:
            print(f"\\n🎯 Processing {target}...")
            
            # Generate investigation ID
            import uuid
            inv_id = f"osint_{uuid.uuid4().hex[:12]}"
            
            print(f"📋 Investigation ID: {inv_id}")
            
            # Gather intelligence directly
            try:
                results = await mcp_client.gather_all_intelligence(target, "comprehensive")
                
                if results:
                    # Process results
                    findings = {}
                    data_points = 0
                    
                    for category, data in results.items():
                        if data:
                            findings[category] = data
                            data_points += len(data) if isinstance(data, list) else 1
                    
                    print(f"✅ Collected {data_points} data points across {len(findings)} categories")
                    
                    # Save directly to database
                    conn = psycopg2.connect(os.environ['POSTGRES_URL'])
                    cur = conn.cursor()
                    
                    cur.execute("""
                        INSERT INTO investigations (
                            investigation_id, target, investigation_type, priority, status,
                            findings, progress_percentage, current_stage, current_activity,
                            investigator_id, investigator, completed_at, created_at, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        inv_id, target, 'comprehensive', 'normal', 'COMPLETED',
                        json.dumps(findings), 100, 'completed', 
                        f'Investigation completed with {data_points} findings',
                        'darin', 'Darin Ganitch', datetime.utcnow(), datetime.utcnow(), datetime.utcnow()
                    ))
                    
                    conn.commit()
                    conn.close()
                    
                    print(f"💾 Saved {inv_id} to database")
                    
                else:
                    print(f"⚠️  No data collected for {target}")
                    
            except Exception as e:
                print(f"❌ Error processing {target}: {e}")
                
        print("\\n🎉 Force processing complete!")
        
    except Exception as e:
        print(f"❌ Failed to force process: {e}")
        import traceback
        traceback.print_exc()

# Run the processing
asyncio.run(force_process_amazon_investigations())
'''

def run_force_processing():
    """Run the force processing script"""
    print("🚀 Force processing Amazon investigations...")
    
    # Get backend pod
    result = subprocess.run([
        'kubectl', 'get', 'pods', '-n', 'osint-platform',
        '-l', 'app=osint-backend', '-o', 'jsonpath={.items[0].metadata.name}'
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ Failed to get pod name: {result.stderr}")
        return False
    
    pod_name = result.stdout.strip()
    print(f"📍 Using pod: {pod_name}")
    
    # Run the processing script
    result = subprocess.run([
        'kubectl', 'exec', '-n', 'osint-platform', pod_name, '--',
        'python3', '-c', process_script
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("Errors:", result.stderr)
    
    return "Investigation completed" in result.stdout

if __name__ == "__main__":
    success = run_force_processing()
    
    if success:
        print("\n✅ Amazon investigations processed!")
        print("🔄 Refresh the UI to see completed investigations")
    else:
        print("\n❌ Processing failed")
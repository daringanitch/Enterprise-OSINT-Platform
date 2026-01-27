#!/usr/bin/env python3
"""
Force Process Queued Investigations

This script manually processes investigations that are stuck in QUEUED status.
"""

import subprocess
import tempfile

# Script to run inside the backend pod
script_content = '''
import sys
import os
import asyncio
sys.path.insert(0, '/app')

async def force_process_investigations():
    """Force process all queued investigations"""
    try:
        from investigation_orchestrator import InvestigationOrchestrator
        from mcp_clients import MCPClientManager
        import psycopg2
        import json
        
        print("🚀 Force processing queued investigations...")
        
        # Connect to database to get queued investigations
        conn = psycopg2.connect(os.environ['POSTGRES_URL'])
        cur = conn.cursor()
        
        # Find all investigations and their status
        cur.execute("""
            SELECT target, status, investigation_type, id, priority
            FROM investigations 
            ORDER BY created_at DESC
            LIMIT 10;
        """)
        
        investigations = cur.fetchall()
        print(f"📋 Found {len(investigations)} total investigations")
        
        for target, status, inv_type, inv_id, priority in investigations:
            print(f"   {target} - {status} - {inv_type}")
        
        # Initialize the orchestrator and MCP client manager
        orchestrator = InvestigationOrchestrator()
        mcp_client = MCPClientManager()
        
        # Process each investigation that needs processing
        for target, status, inv_type, inv_id, priority in investigations:
            if status in ['QUEUED', 'PENDING']:
                print(f"\\n🔍 Processing {target} (ID: {inv_id})")
                
                try:
                    # Update status to PROCESSING
                    cur.execute("""
                        UPDATE investigations 
                        SET status = 'PROCESSING', 
                            current_stage = 'data_collection',
                            current_activity = 'Gathering intelligence',
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = %s;
                    """, (inv_id,))
                    conn.commit()
                    
                    # Gather intelligence using MCP clients
                    print(f"   Gathering intelligence for {target}...")
                    
                    # Call MCP servers directly
                    intelligence_results = await mcp_client.gather_all_intelligence(
                        target, inv_type or 'infrastructure'
                    )
                    
                    # Process the results
                    if intelligence_results:
                        findings = {}
                        total_findings = 0
                        
                        for category, results in intelligence_results.items():
                            if results:
                                findings[category] = results
                                total_findings += len(results)
                        
                        # Update investigation with results
                        cur.execute("""
                            UPDATE investigations 
                            SET status = 'COMPLETED',
                                findings = %s,
                                progress_percentage = 100,
                                current_stage = 'completed',
                                current_activity = 'Investigation completed',
                                completed_at = CURRENT_TIMESTAMP,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = %s;
                        """, (json.dumps(findings), inv_id))
                        conn.commit()
                        
                        print(f"   ✅ Completed {target} with {total_findings} findings")
                    else:
                        # Mark as completed with no findings
                        cur.execute("""
                            UPDATE investigations 
                            SET status = 'COMPLETED',
                                findings = %s,
                                progress_percentage = 100,
                                current_stage = 'completed',
                                current_activity = 'No intelligence gathered',
                                completed_at = CURRENT_TIMESTAMP,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = %s;
                        """, ('{"message": "No intelligence data available"}', inv_id))
                        conn.commit()
                        
                        print(f"   ⚠️  Completed {target} with no findings")
                
                except Exception as e:
                    print(f"   ❌ Error processing {target}: {e}")
                    
                    # Mark as failed
                    cur.execute("""
                        UPDATE investigations 
                        SET status = 'FAILED',
                            current_activity = %s,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = %s;
                    """, (f"Error: {str(e)[:200]}", inv_id))
                    conn.commit()
        
        conn.close()
        print("\\n🎉 Force processing complete!")
        
        # Show updated status
        conn = psycopg2.connect(os.environ['POSTGRES_URL'])
        cur = conn.cursor()
        cur.execute("SELECT target, status FROM investigations ORDER BY updated_at DESC LIMIT 5;")
        updated = cur.fetchall()
        print("\\n📊 Updated investigation status:")
        for target, status in updated:
            print(f"   {target}: {status}")
        conn.close()
        
    except Exception as e:
        print(f"❌ Force processing failed: {e}")
        import traceback
        traceback.print_exc()

# Run the async function
asyncio.run(force_process_investigations())
'''

def run_force_processing():
    """Run the force processing script in the backend pod"""
    print("🚀 Running force processing script in backend pod...")
    
    # Write script to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(script_content)
        temp_script = f.name
    
    try:
        # Get a backend pod name
        result = subprocess.run([
            'kubectl', 'get', 'pods', '-n', 'osint-platform', 
            '-l', 'app=osint-backend', '-o', 'name'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Failed to get pod names: {result.stderr}")
            return
        
        pod_name = result.stdout.strip().split('/')[-1]
        print(f"📁 Using pod: {pod_name}")
        
        # Copy script to pod
        result = subprocess.run([
            'kubectl', 'cp', temp_script, 
            f'osint-platform/{pod_name}:/tmp/force_process.py'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Failed to copy script: {result.stderr}")
            return
        
        # Run the script
        result = subprocess.run([
            'kubectl', 'exec', '-n', 'osint-platform', 
            pod_name, '--', 
            'python3', '/tmp/force_process.py'
        ], capture_output=True, text=True)
        
        print("🔍 Script output:")
        print(result.stdout)
        
        if result.stderr:
            print("⚠️  Errors:")
            print(result.stderr)
            
        if result.returncode == 0:
            print("✅ Force processing completed successfully!")
        else:
            print("❌ Force processing failed")
            
    except Exception as e:
        print(f"❌ Script execution error: {e}")
    finally:
        import os
        os.unlink(temp_script)

if __name__ == "__main__":
    run_force_processing()
#!/usr/bin/env python3
"""
Start Investigation Processing

This script starts processing for all queued investigations.
"""

import subprocess
import json

# Script to run inside the backend pod  
script_content = '''
import sys
import os
import asyncio
import json
sys.path.insert(0, '/app')

from investigation_orchestrator import InvestigationOrchestrator
import models

async def start_all_queued_investigations():
    """Start processing for all queued investigations"""
    try:
        orchestrator = InvestigationOrchestrator()
        
        print("🔍 Looking for queued investigations...")
        
        # Check active investigations in memory
        active_count = len(orchestrator.active_investigations)
        print(f"Active investigations in orchestrator: {active_count}")
        
        # List all investigations
        queued_count = 0
        for inv_id, inv in orchestrator.active_investigations.items():
            status = inv.status.value if hasattr(inv.status, 'value') else str(inv.status)
            target = inv.target_profile.primary_identifier if hasattr(inv, 'target_profile') else 'Unknown'
            print(f"  {inv_id}: {target} - Status: {status}")
            
            if status in ['queued', 'QUEUED', 'pending', 'PENDING']:
                queued_count += 1
                print(f"    🚀 Starting processing for {inv_id}...")
                
                try:
                    # Call the start_investigation method
                    result = await orchestrator.start_investigation(inv_id)
                    if result:
                        print(f"    ✅ Started processing for {inv_id}")
                    else:
                        print(f"    ❌ Failed to start {inv_id}")
                except Exception as e:
                    print(f"    ❌ Error starting {inv_id}: {e}")
        
        print(f"\\nTotal queued investigations started: {queued_count}")
        
        # If no investigations found in memory, check if there are any recent ones we can recreate
        if active_count == 0:
            print("\\n⚠️  No investigations in memory. They may need to be recreated.")
            print("   Please create new investigations through the UI.")
        
    except Exception as e:
        print(f"❌ Failed to start investigations: {e}")
        import traceback
        traceback.print_exc()

# Run the async function
asyncio.run(start_all_queued_investigations())

# Also check if we need to manually process with MCP clients
print("\\n🔧 Checking MCP client processing...")

from mcp_clients import MCPClientManager
import aiohttp

async def test_mcp_processing():
    """Test direct MCP processing"""
    try:
        mcp_client = MCPClientManager()
        
        # Test with a simple domain
        test_target = "example.com"
        print(f"Testing MCP processing for: {test_target}")
        
        # Try to gather intelligence
        results = await mcp_client.gather_all_intelligence(test_target, "infrastructure")
        
        if results:
            print(f"✅ MCP processing works! Got {len(results)} categories of results")
            for category, data in results.items():
                print(f"  - {category}: {len(data) if isinstance(data, list) else 1} results")
        else:
            print("❌ No results from MCP processing")
            
    except Exception as e:
        print(f"❌ MCP processing error: {e}")

asyncio.run(test_mcp_processing())
'''

def run_processing_script():
    """Run the processing script in backend pod"""
    print("🚀 Starting investigation processing script...")
    
    # Get backend pod
    result = subprocess.run([
        'kubectl', 'get', 'pods', '-n', 'osint-platform',
        '-l', 'app=osint-backend', '-o', 'jsonpath={.items[0].metadata.name}'
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ Failed to get pod name: {result.stderr}")
        return
        
    pod_name = result.stdout.strip()
    print(f"📍 Using pod: {pod_name}")
    
    # Run the script directly
    result = subprocess.run([
        'kubectl', 'exec', '-n', 'osint-platform', pod_name, '--',
        'python3', '-c', script_content
    ], capture_output=True, text=True)
    
    print("📄 Script output:")
    print(result.stdout)
    
    if result.stderr:
        print("⚠️  Errors:")
        print(result.stderr)

if __name__ == "__main__":
    run_processing_script()
    
    print("\n💡 Next steps:")
    print("1. If investigations are still queued, they need the background processing thread")
    print("2. Try creating a NEW investigation - it should process immediately")
    print("3. Check the logs: kubectl logs -n osint-platform -l app=osint-backend --tail=50")
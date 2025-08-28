#!/usr/bin/env python3
"""
Fix Investigation Processing

This script patches the backend to automatically start investigations after creation.
"""

import subprocess

# Patch to add to app.py after investigation creation
patch_content = '''
# PATCH: Auto-start investigation processing
import asyncio
import threading

def start_investigation_async(investigation_id):
    """Start investigation processing in background thread"""
    def run_async():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(orchestrator.start_investigation(investigation_id))
            print(f"Investigation {investigation_id} processing started: {result}")
            loop.close()
        except Exception as e:
            print(f"Failed to start investigation {investigation_id}: {e}")
    
    thread = threading.Thread(target=run_async, name=f"Investigation-{investigation_id}")
    thread.daemon = True
    thread.start()
    print(f"Started processing thread for {investigation_id}")

# Add this after line: investigation_id = orchestrator.create_investigation(
'''

# Script to run in backend pod
fix_script = '''
import sys
import os

print("🔧 Patching backend to auto-start investigations...")

# Read app.py
with open('/app/app.py', 'r') as f:
    content = f.read()

# Check if already patched
if 'start_investigation_async' in content:
    print("✅ Already patched!")
else:
    # Find where to insert the patch - after investigation creation
    create_inv_line = 'investigation_id = orchestrator.create_investigation('
    if create_inv_line in content:
        # Find the end of the create_investigation block
        start_index = content.find(create_inv_line)
        # Find the next empty line or return statement
        lines = content[start_index:].split('\\n')
        insert_index = start_index
        
        for i, line in enumerate(lines):
            if i > 0 and (line.strip() == '' or 'return' in line or 'except' in line):
                # Calculate actual insert position
                insert_index = start_index + len('\\n'.join(lines[:i]))
                break
        
        # Insert the auto-start code
        patch_code = """
        # Auto-start investigation processing
        try:
            import asyncio
            import threading
            
            def run_investigation_async():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(orchestrator.start_investigation(investigation_id))
                    logger.info(f"Investigation {investigation_id} started: {result}")
                except Exception as e:
                    logger.error(f"Failed to start investigation {investigation_id}: {e}")
                finally:
                    loop.close()
            
            thread = threading.Thread(target=run_investigation_async, name=f"Inv-{investigation_id[:8]}")
            thread.daemon = True
            thread.start()
            logger.info(f"Processing thread started for {investigation_id}")
        except Exception as e:
            logger.error(f"Failed to start investigation thread: {e}")
"""
        
        # Insert the patch
        new_content = content[:insert_index] + patch_code + content[insert_index:]
        
        # Write back
        with open('/app/app.py', 'w') as f:
            f.write(new_content)
        
        print("✅ Patched app.py to auto-start investigations!")
        print("📍 Patch location: After investigation creation")
    else:
        print("❌ Could not find investigation creation code to patch")

print("\\n🔄 Please restart the backend pod to apply changes:")
print("   kubectl rollout restart deployment/osint-backend -n osint-platform")
'''

def apply_patch():
    """Apply the patch to the backend"""
    print("🚀 Applying investigation processing fix...")
    
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
    
    # Run the patch script
    result = subprocess.run([
        'kubectl', 'exec', '-n', 'osint-platform', pod_name, '--',
        'python3', '-c', fix_script
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("Errors:", result.stderr)
    
    if "Patched app.py" in result.stdout:
        print("\n✅ Patch applied successfully!")
        print("🔄 Restarting backend to apply changes...")
        
        # Restart the backend
        restart_result = subprocess.run([
            'kubectl', 'rollout', 'restart', 
            'deployment/osint-backend', '-n', 'osint-platform'
        ], capture_output=True, text=True)
        
        if restart_result.returncode == 0:
            print("✅ Backend restart initiated")
            print("⏳ Wait for rollout to complete...")
            
            # Wait for rollout
            subprocess.run([
                'kubectl', 'rollout', 'status',
                'deployment/osint-backend', '-n', 'osint-platform'
            ])
            
            print("\n🎉 Fix applied! Investigations should now process automatically.")
            print("🧪 Test by creating a new investigation - it should move from QUEUED to PROCESSING")
            return True
        else:
            print(f"❌ Failed to restart: {restart_result.stderr}")
    else:
        print("❌ Patch failed to apply")
    
    return False

if __name__ == "__main__":
    success = apply_patch()
    
    if success:
        print("\n💡 Next steps:")
        print("1. Create a NEW investigation through the UI")  
        print("2. It should automatically start processing")
        print("3. Check status with: kubectl logs -n osint-platform -l app=osint-backend | grep 'Investigation.*started'")
    else:
        print("\n❌ Fix could not be applied. Manual intervention may be needed.")
#!/usr/bin/env python3
"""
Sync Memory with Database

Forces the orchestrator to load investigations from database into memory.
"""

import subprocess

sync_script = '''
import sys
import os
import json
from datetime import datetime
sys.path.insert(0, '/app')

from investigation_orchestrator import InvestigationOrchestrator
import models
import psycopg2

def sync_database_to_memory():
    """Load database investigations into memory"""
    print("🔄 Syncing database investigations to memory...")
    
    try:
        # Get orchestrator
        orchestrator = InvestigationOrchestrator()
        
        # Clear memory first
        orchestrator.active_investigations.clear()
        print("   Cleared memory investigations")
        
        # Load from database
        conn = psycopg2.connect(os.environ['POSTGRES_URL'])
        cur = conn.cursor()
        
        cur.execute("""
            SELECT investigation_id, target, investigation_type, status, 
                   investigator_id, investigator, findings, created_at, completed_at
            FROM investigations 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        
        rows = cur.fetchall()
        conn.close()
        
        print(f"   Found {len(rows)} investigations in database")
        
        # Create memory objects for each
        for row in rows:
            inv_id, target, inv_type, status, investigator_id, investigator, findings_json, created_at, completed_at = row
            
            try:
                # Create a basic investigation object
                from models import Investigation, InvestigationStatus, InvestigationType
                from models import TargetProfile, InvestigationProgress
                
                # Create target profile
                target_profile = TargetProfile(
                    target_id=f"target_{hash(target) % 10000000}",
                    primary_identifier=target,
                    target_type="domain"
                )
                
                # Create investigation
                investigation = Investigation(
                    investigation_id=inv_id,
                    target_profile=target_profile,
                    investigation_type=InvestigationType.COMPREHENSIVE,
                    investigator_id=investigator_id or "system",
                    investigator_name=investigator or "System"
                )
                
                # Set status
                if status.upper() == 'COMPLETED':
                    investigation.status = InvestigationStatus.COMPLETED
                    investigation.completed_at = completed_at
                    investigation.current_stage = "completed"
                    investigation.current_activity = "Investigation completed"
                    investigation.progress_percentage = 100
                elif status.upper() == 'QUEUED':
                    investigation.status = InvestigationStatus.QUEUED
                    investigation.current_stage = "queued"
                    investigation.current_activity = "Waiting to process"
                    investigation.progress_percentage = 0
                else:
                    investigation.status = InvestigationStatus.PENDING
                
                # Add findings if available
                if findings_json:
                    try:
                        findings = json.loads(findings_json)
                        investigation.progress = InvestigationProgress()
                        investigation.progress.data_points_collected = len(findings.get('summary', {}).get('data_points', 0)) if isinstance(findings.get('summary', {}), dict) else 0
                    except:
                        pass
                
                # Store in memory
                orchestrator.active_investigations[inv_id] = investigation
                
                print(f"   ✅ {inv_id}: {target} - {status}")
                
            except Exception as e:
                print(f"   ❌ Failed to load {inv_id}: {e}")
        
        print(f"\\n✅ Synced {len(orchestrator.active_investigations)} investigations to memory")
        
        return True
        
    except Exception as e:
        print(f"❌ Sync failed: {e}")
        import traceback
        traceback.print_exc()
        return False

# Run the sync
success = sync_database_to_memory()
if success:
    print("\\n🎉 Memory and database are now synchronized!")
    print("   API should now show completed investigations")
else:
    print("\\n❌ Sync failed")
'''

def run_sync():
    """Run the sync script"""
    print("🔄 Synchronizing memory with database...")
    
    result = subprocess.run([
        'kubectl', 'get', 'pods', '-n', 'osint-platform',
        '-l', 'app=osint-backend', '-o', 'jsonpath={.items[0].metadata.name}'
    ], capture_output=True, text=True)
    
    pod_name = result.stdout.strip()
    
    result = subprocess.run([
        'kubectl', 'exec', '-n', 'osint-platform', pod_name, '--',
        'python3', '-c', sync_script
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("Errors:", result.stderr)
    
    return "synchronized" in result.stdout.lower()

if __name__ == "__main__":
    success = run_sync()
    print("✅ Sync complete! UI should now show correct status" if success else "❌ Sync failed")
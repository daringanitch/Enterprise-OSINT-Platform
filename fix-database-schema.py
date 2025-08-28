#!/usr/bin/env python3
"""
Database Schema Fix Script for Enterprise OSINT Platform

This script fixes database schema issues causing investigation processing to fail.
"""

import psycopg2
import os
import sys

def fix_database_schema():
    """Fix the database schema issues"""
    try:
        # Connect to database
        conn = psycopg2.connect(os.environ.get('POSTGRES_URL'))
        cur = conn.cursor()
        
        print("🔧 Starting database schema fixes...")
        
        # First, let's check current schema
        cur.execute("""
            SELECT column_name, data_type, is_nullable 
            FROM information_schema.columns 
            WHERE table_name = 'investigations' 
            ORDER BY ordinal_position;
        """)
        current_columns = cur.fetchall()
        print(f"📊 Found {len(current_columns)} columns in investigations table")
        
        # Add missing columns if they don't exist
        missing_columns = [
            ("investigator_id", "VARCHAR(255)"),
            ("investigator", "VARCHAR(255)"),
            ("details", "JSONB"),
        ]
        
        for column_name, data_type in missing_columns:
            try:
                cur.execute(f"""
                    ALTER TABLE investigations 
                    ADD COLUMN IF NOT EXISTS {column_name} {data_type};
                """)
                print(f"✅ Added column: {column_name}")
            except Exception as e:
                print(f"⚠️  Column {column_name} already exists or error: {e}")
        
        # Update any NULL investigator fields with default values
        cur.execute("""
            UPDATE investigations 
            SET investigator_id = 'system', investigator = 'System User'
            WHERE investigator_id IS NULL OR investigator IS NULL;
        """)
        
        # Check for stuck investigations and reset them
        cur.execute("""
            SELECT COUNT(*) FROM investigations 
            WHERE status IN ('QUEUED', 'PROCESSING', 'IN_PROGRESS');
        """)
        stuck_count = cur.fetchone()[0]
        
        if stuck_count > 0:
            print(f"🔄 Found {stuck_count} stuck investigations, resetting to PENDING...")
            cur.execute("""
                UPDATE investigations 
                SET status = 'PENDING', 
                    current_stage = 'initialization',
                    current_activity = 'Preparing investigation',
                    updated_at = CURRENT_TIMESTAMP
                WHERE status IN ('QUEUED', 'PROCESSING', 'IN_PROGRESS');
            """)
            print(f"✅ Reset {stuck_count} investigations to PENDING status")
        
        # Create indexes for performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);",
            "CREATE INDEX IF NOT EXISTS idx_investigations_target ON investigations(target);",
            "CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations(created_at);",
        ]
        
        for index_sql in indexes:
            try:
                cur.execute(index_sql)
                print("✅ Created performance index")
            except Exception as e:
                print(f"⚠️  Index creation: {e}")
        
        # Commit all changes
        conn.commit()
        print("🎉 Database schema fixes completed successfully!")
        
        # Show current investigation status
        cur.execute("""
            SELECT target, status, created_at 
            FROM investigations 
            ORDER BY created_at DESC 
            LIMIT 5;
        """)
        investigations = cur.fetchall()
        print("\n📋 Recent investigations:")
        for inv in investigations:
            print(f"   {inv[0]} - {inv[1]} ({inv[2]})")
        
        return True
        
    except Exception as e:
        print(f"❌ Database schema fix failed: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def restart_backend_pods():
    """Restart backend pods to pick up schema changes"""
    import subprocess
    try:
        print("🔄 Restarting backend pods...")
        result = subprocess.run([
            'kubectl', 'rollout', 'restart', 
            'deployment/osint-backend', 
            '-n', 'osint-platform'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Backend pods restart initiated")
            return True
        else:
            print(f"❌ Failed to restart backend pods: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error restarting pods: {e}")
        return False

def main():
    """Main function"""
    print("🚀 Enterprise OSINT Platform - Database Schema Fix")
    print("=" * 60)
    
    # Check if we have database connection
    if not os.environ.get('POSTGRES_URL'):
        print("❌ POSTGRES_URL environment variable not set")
        print("Please set: export POSTGRES_URL='your-database-url'")
        sys.exit(1)
    
    # Fix database schema
    if fix_database_schema():
        # Restart backend to pick up changes
        restart_backend_pods()
        print("\n✅ All fixes applied! Investigations should now process correctly.")
        print("🔍 Try creating a new investigation to test.")
    else:
        print("❌ Schema fixes failed. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
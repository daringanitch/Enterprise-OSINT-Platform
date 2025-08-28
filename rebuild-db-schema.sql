-- Rebuild Database Schema for Enterprise OSINT Platform
-- This fixes the corrupted investigations table

-- Drop the corrupted table
DROP TABLE IF EXISTS investigations CASCADE;

-- Create clean investigations table
CREATE TABLE investigations (
    id SERIAL PRIMARY KEY,
    investigation_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(255) NOT NULL DEFAULT 'system',
    target VARCHAR(500) NOT NULL,
    investigation_type VARCHAR(100) NOT NULL,
    priority VARCHAR(50) NOT NULL DEFAULT 'normal',
    status VARCHAR(100) NOT NULL DEFAULT 'pending',
    description TEXT,
    
    -- Progress tracking
    current_stage VARCHAR(100) DEFAULT 'initialization',
    current_activity VARCHAR(255) DEFAULT 'Preparing investigation',
    progress_percentage INTEGER DEFAULT 0,
    
    -- Results
    findings JSONB DEFAULT '{}',
    key_findings JSONB DEFAULT '[]',
    executive_summary TEXT,
    technical_details JSONB DEFAULT '{}',
    risk_score DOUBLE PRECISION DEFAULT 0.0,
    threat_level VARCHAR(50),
    confidence_level VARCHAR(50),
    
    -- Metadata
    investigator_id VARCHAR(255) DEFAULT 'system',
    investigator VARCHAR(255) DEFAULT 'System User',
    workspace_id VARCHAR(255) DEFAULT 'default',
    classification_level VARCHAR(50) DEFAULT 'internal',
    
    -- Data tracking
    data_sources JSONB DEFAULT '{}',
    api_calls_made INTEGER DEFAULT 0,
    processing_time_seconds DOUBLE PRECISION DEFAULT 0.0,
    data_size_mb DOUBLE PRECISION DEFAULT 0.0,
    
    -- Compliance
    compliance_notes TEXT,
    data_retention_until TIMESTAMP WITH TIME ZONE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Reporting
    report_generated BOOLEAN DEFAULT FALSE,
    report_path VARCHAR(500),
    report_expires_at TIMESTAMP WITH TIME ZONE
);

-- Create indexes for performance
CREATE INDEX idx_investigations_target ON investigations(target);
CREATE INDEX idx_investigations_status ON investigations(status);
CREATE INDEX idx_investigations_user_id ON investigations(user_id);
CREATE INDEX idx_investigations_created_at ON investigations(created_at);
CREATE INDEX idx_investigations_investigation_id ON investigations(investigation_id);

-- Insert a test investigation to verify schema
INSERT INTO investigations (
    investigation_id, target, investigation_type, priority, status,
    investigator_id, investigator, findings
) VALUES (
    'test_schema_fix', 'schema-test.com', 'infrastructure', 'normal', 'completed',
    'admin', 'Administrator', '{"test": "schema fixed"}'
);

-- Verify the test insert worked
SELECT investigation_id, target, status, created_at FROM investigations;
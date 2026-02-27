-- Enterprise OSINT Platform — PostgreSQL Initialization
-- Run automatically by Docker on first container startup (empty volume)

-- ─── Investigations ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS investigations (
    id                      SERIAL PRIMARY KEY,
    investigation_id        VARCHAR(255)  UNIQUE NOT NULL,
    user_id                 VARCHAR(255)  NOT NULL DEFAULT 'system',
    target                  VARCHAR(500)  NOT NULL,
    investigation_type      VARCHAR(100)  NOT NULL,
    priority                VARCHAR(50)   NOT NULL DEFAULT 'normal',
    status                  VARCHAR(100)  NOT NULL DEFAULT 'pending',
    description             TEXT,

    -- Progress tracking
    current_stage           VARCHAR(100)  DEFAULT 'initialization',
    current_activity        VARCHAR(255)  DEFAULT 'Preparing investigation',
    progress_percentage     INTEGER       DEFAULT 0,

    -- Results
    findings                JSONB         DEFAULT '{}',
    key_findings            JSONB         DEFAULT '[]',
    executive_summary       TEXT,
    technical_details       JSONB         DEFAULT '{}',
    risk_score              DOUBLE PRECISION DEFAULT 0.0,
    threat_level            VARCHAR(50),
    confidence_level        VARCHAR(50),

    -- Metadata
    investigator_id         VARCHAR(255)  DEFAULT 'system',
    investigator            VARCHAR(255)  DEFAULT 'System User',
    workspace_id            VARCHAR(255)  DEFAULT 'default',
    classification_level    VARCHAR(50)   DEFAULT 'internal',

    -- Data tracking
    data_sources            JSONB         DEFAULT '{}',
    api_calls_made          INTEGER       DEFAULT 0,
    processing_time_seconds DOUBLE PRECISION DEFAULT 0.0,
    data_size_mb            DOUBLE PRECISION DEFAULT 0.0,

    -- Compliance
    compliance_notes        TEXT,
    data_retention_until    TIMESTAMP WITH TIME ZONE,

    -- Timestamps
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at              TIMESTAMP WITH TIME ZONE,
    completed_at            TIMESTAMP WITH TIME ZONE,

    -- Reporting
    report_generated        BOOLEAN       DEFAULT FALSE,
    report_path             VARCHAR(500),
    report_expires_at       TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_investigations_investigation_id ON investigations(investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigations_target           ON investigations(target);
CREATE INDEX IF NOT EXISTS idx_investigations_status          ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_investigations_user_id         ON investigations(user_id);
CREATE INDEX IF NOT EXISTS idx_investigations_created_at      ON investigations(created_at);

-- ─── Audit Log ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_log (
    id              SERIAL PRIMARY KEY,
    event_type      VARCHAR(100) NOT NULL,
    user_id         VARCHAR(255),
    resource_type   VARCHAR(100),
    resource_id     VARCHAR(255),
    action          VARCHAR(100),
    details         JSONB        DEFAULT '{}',
    ip_address      VARCHAR(45),
    user_agent      TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_log_event_type  ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id     ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at  ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource_id ON audit_log(resource_id);

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

-- ─── Users ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id                      SERIAL PRIMARY KEY,
    user_id                 VARCHAR(255)  UNIQUE NOT NULL,
    username                VARCHAR(100)  UNIQUE NOT NULL,
    email                   VARCHAR(255)  UNIQUE NOT NULL,
    password_hash           VARCHAR(255)  NOT NULL,
    full_name               VARCHAR(255),
    role                    VARCHAR(50)   NOT NULL DEFAULT 'analyst',
    clearance_level         VARCHAR(50)   DEFAULT 'internal',
    is_active               BOOLEAN       NOT NULL DEFAULT TRUE,
    failed_login_attempts   INTEGER       DEFAULT 0,
    last_login              TIMESTAMP WITH TIME ZONE,
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username  ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email     ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_user_id   ON users(user_id);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);

-- Default admin user  (password: admin123)
INSERT INTO users (user_id, username, email, password_hash, full_name, role, clearance_level)
VALUES (
    'admin-001',
    'admin',
    'admin@osint.local',
    '$2b$12$TIf4S/AlD6rWlqtGaJgtDeVuIS0AQSi8WzAVtMfeZOyi0pP5eg21q',
    'Platform Administrator',
    'admin',
    'top_secret'
) ON CONFLICT (username) DO NOTHING;

-- Default analyst user  (password: analyst123)
INSERT INTO users (user_id, username, email, password_hash, full_name, role, clearance_level)
VALUES (
    'analyst-001',
    'analyst',
    'analyst@osint.local',
    '$2b$12$pZ52FY9tRg2PYHDSQU8piO/RrOUQTs4VU/l89tLfGsCY.RW2tsUD.',
    'Senior Analyst',
    'senior_analyst',
    'confidential'
) ON CONFLICT (username) DO NOTHING;

-- ─── Audit Schema ───────────────────────────────────────────────────────────

CREATE SCHEMA IF NOT EXISTS audit;

-- audit.events — general audit log
CREATE TABLE IF NOT EXISTS audit.events (
    id                  SERIAL PRIMARY KEY,
    event_type          VARCHAR(100) NOT NULL,
    user_id             VARCHAR(255),
    user_name           VARCHAR(255),
    source_ip           VARCHAR(45),
    user_agent          TEXT,
    session_id          VARCHAR(255),
    endpoint            VARCHAR(500),
    method              VARCHAR(10),
    status_code         INTEGER,
    processing_time_ms  INTEGER,
    timestamp           TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    details             JSONB DEFAULT '{}',
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_events_event_type  ON audit.events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_user_id     ON audit.events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp   ON audit.events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at  ON audit.events(created_at);

-- audit.investigations — per-investigation audit trail
CREATE TABLE IF NOT EXISTS audit.investigations (
    id                          SERIAL PRIMARY KEY,
    investigation_id            VARCHAR(255) UNIQUE NOT NULL,
    investigator_id             VARCHAR(255),
    investigator_name           VARCHAR(255),
    target_identifier           VARCHAR(500),
    investigation_type          VARCHAR(100),
    priority                    VARCHAR(50),
    status                      VARCHAR(100),
    created_at                  TIMESTAMP WITH TIME ZONE,
    started_at                  TIMESTAMP WITH TIME ZONE,
    completed_at                TIMESTAMP WITH TIME ZONE,
    processing_time_seconds     DOUBLE PRECISION,
    data_points_collected       INTEGER DEFAULT 0,
    api_calls_made              INTEGER DEFAULT 0,
    cost_estimate_usd           DOUBLE PRECISION DEFAULT 0.0,
    risk_score                  DOUBLE PRECISION DEFAULT 0.0,
    threat_level                VARCHAR(50),
    compliance_status           VARCHAR(100),
    classification_level        VARCHAR(50) DEFAULT 'internal',
    key_findings                JSONB DEFAULT '[]',
    warnings                    JSONB DEFAULT '[]',
    errors                      JSONB DEFAULT '[]',
    metadata                    JSONB DEFAULT '{}',
    audit_updated_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_inv_investigation_id ON audit.investigations(investigation_id);
CREATE INDEX IF NOT EXISTS idx_audit_inv_status           ON audit.investigations(status);
CREATE INDEX IF NOT EXISTS idx_audit_inv_created_at       ON audit.investigations(created_at);

-- audit.api_key_usage — external API call tracking
CREATE TABLE IF NOT EXISTS audit.api_key_usage (
    id                  SERIAL PRIMARY KEY,
    service_name        VARCHAR(100) NOT NULL,
    operation           VARCHAR(100),
    user_id             VARCHAR(255),
    investigation_id    VARCHAR(255),
    request_timestamp   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    response_time_ms    INTEGER,
    success             BOOLEAN DEFAULT TRUE,
    rate_limited        BOOLEAN DEFAULT FALSE,
    quota_exceeded      BOOLEAN DEFAULT FALSE,
    request_size        INTEGER,
    response_size       INTEGER,
    cost_usd            DOUBLE PRECISION DEFAULT 0.0,
    error_type          VARCHAR(100),
    error_message       TEXT,
    request_metadata    JSONB DEFAULT '{}',
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_api_service_name     ON audit.api_key_usage(service_name);
CREATE INDEX IF NOT EXISTS idx_audit_api_investigation_id ON audit.api_key_usage(investigation_id);
CREATE INDEX IF NOT EXISTS idx_audit_api_created_at       ON audit.api_key_usage(created_at);

-- audit.system_metrics — periodic system health snapshots
CREATE TABLE IF NOT EXISTS audit.system_metrics (
    id              SERIAL PRIMARY KEY,
    metric_name     VARCHAR(100) NOT NULL,
    metric_value    DOUBLE PRECISION,
    metric_labels   JSONB DEFAULT '{}',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_metrics_name       ON audit.system_metrics(metric_name);
CREATE INDEX IF NOT EXISTS idx_audit_metrics_created_at ON audit.system_metrics(created_at);

-- ─── Legacy Audit Log (public schema) ───────────────────────────────────────

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

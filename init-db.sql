-- init-db.sql
-- This file runs automatically when PostgreSQL container starts

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create enum types
DO $$ BEGIN
    CREATE TYPE incidentseverity AS ENUM ('low', 'medium', 'high', 'critical');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE incidentstatus AS ENUM ('open', 'investigating', 'resolved', 'closed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE incidenttype AS ENUM ('system', 'security', 'performance', 'data_loss', 'llm', 'agent', 'other');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity incidentseverity DEFAULT 'medium',
    status incidentstatus DEFAULT 'open',
    incident_type incidenttype DEFAULT 'system',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    source_system VARCHAR(200),
    component VARCHAR(200),
    agent_id VARCHAR(100),
    llm_provider VARCHAR(100),
    tags JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    affected_users INTEGER DEFAULT 0,
    root_cause TEXT,
    resolution TEXT
);

-- Create indexes
CREATE INDEX IF NOT EXISTS ix_incidents_created_at ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS ix_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS ix_incidents_incident_type ON incidents (incident_type);
CREATE INDEX IF NOT EXISTS ix_incidents_agent_id ON incidents (agent_id);
CREATE INDEX IF NOT EXISTS ix_incidents_status_severity ON incidents (status, severity);

-- Insert sample data for testing
INSERT INTO incidents (id, title, description, severity, status, incident_type, agent_id, affected_users, tags)
SELECT 
    gen_random_uuid()::text,
    'LLM API Timeout - ' || ('GPT-' || (i%3 + 3)),
    'API calls timing out after 30 seconds for ' || ('GPT-' || (i%3 + 3)) || ' endpoints',
    CASE (i%4)
        WHEN 0 THEN 'low'::incidentseverity
        WHEN 1 THEN 'medium'::incidentseverity
        WHEN 2 THEN 'high'::incidentseverity
        ELSE 'critical'::incidentseverity
    END,
    CASE (i%4)
        WHEN 0 THEN 'open'::incidentstatus
        WHEN 1 THEN 'investigating'::incidentstatus
        WHEN 2 THEN 'resolved'::incidentstatus
        ELSE 'closed'::incidentstatus
    END,
    CASE (i%6)
        WHEN 0 THEN 'system'::incidenttype
        WHEN 1 THEN 'security'::incidenttype
        WHEN 2 THEN 'performance'::incidenttype
        WHEN 3 THEN 'data_loss'::incidenttype
        WHEN 4 THEN 'llm'::incidenttype
        ELSE 'agent'::incidenttype
    END,
    'agent-' || (i%10 + 1),
    (i%1000) + 50,
    ARRAY['llm', 'api', 'timeout']::jsonb
FROM generate_series(1, 50) i
ON CONFLICT (id) DO NOTHING;

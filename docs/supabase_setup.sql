-- ====================================================================
-- Adaptive Cyberattack Detection & Prevention System (Mini-SOC)
-- Supabase / PostgreSQL Schema Definition & RLS Configuration
-- Compatible with both Java Spring Boot JPA & Python ML Services
-- ====================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Simulation Runs Table
CREATE TABLE IF NOT EXISTS public.simulation_runs (
    id VARCHAR(64) PRIMARY KEY,
    scenario_name VARCHAR(50) NOT NULL,
    target_ip VARCHAR(45) NOT NULL,
    target_port INT,
    duration_seconds FLOAT NOT NULL DEFAULT 0.0,
    total_packets_injected INT NOT NULL DEFAULT 0,
    detected_alerts_count INT NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    error_message VARCHAR(500),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_simulation_runs_started ON public.simulation_runs (started_at DESC);

-- 2. Network Events / Flows Table (Time-Series & Provenance Tagged)
CREATE TABLE IF NOT EXISTS public.network_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    data_source VARCHAR(20) NOT NULL CHECK (data_source IN ('OBSERVED', 'SIMULATED', 'DATASET')),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip VARCHAR(45) NOT NULL,
    source_port INT NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    destination_port INT NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    flow_duration FLOAT DEFAULT 0.0,
    total_forward_packets INT DEFAULT 1,
    total_backward_packets INT DEFAULT 0,
    total_length_forward_packets FLOAT DEFAULT 64.0,
    total_length_backward_packets FLOAT DEFAULT 0.0,
    flow_bytes_per_second FLOAT DEFAULT 0.0,
    flow_packets_per_second FLOAT DEFAULT 0.0,
    syn_flag_count INT DEFAULT 0,
    ack_flag_count INT DEFAULT 0,
    fin_flag_count INT DEFAULT 0,
    rst_flag_count INT DEFAULT 0,
    psh_flag_count INT DEFAULT 0,
    urg_flag_count INT DEFAULT 0,
    down_up_ratio FLOAT DEFAULT 0.0,
    packet_length_mean FLOAT DEFAULT 0.0,
    packet_length_std FLOAT DEFAULT 0.0,
    packet_length_variance FLOAT DEFAULT 0.0,
    average_packet_size FLOAT DEFAULT 0.0,
    fwd_header_length INT DEFAULT 0,
    bwd_header_length INT DEFAULT 0,
    init_win_bytes_forward INT DEFAULT 0,
    init_win_bytes_backward INT DEFAULT 0,
    act_data_pkt_fwd INT DEFAULT 0,
    min_seg_size_forward INT DEFAULT 0,
    active_mean FLOAT DEFAULT 0.0,
    idle_mean FLOAT DEFAULT 0.0,
    simulation_run_id VARCHAR(64) REFERENCES public.simulation_runs(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_network_events_ts ON public.network_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_events_source ON public.network_events (data_source);
CREATE INDEX IF NOT EXISTS idx_network_events_ips ON public.network_events (source_ip, destination_ip);

-- 3. Incidents Table (Aggregated Alert Investigations)
CREATE TABLE IF NOT EXISTS public.incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(120) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED')),
    assigned_analyst VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    resolution_notes VARCHAR(2000)
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON public.incidents (status, created_at DESC);

-- 4. Threat Alerts Table
CREATE TABLE IF NOT EXISTS public.threat_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    data_source VARCHAR(20) NOT NULL CHECK (data_source IN ('OBSERVED', 'SIMULATED', 'DATASET')),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    risk_score FLOAT NOT NULL CHECK (risk_score >= 0.0 AND risk_score <= 100.0),
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    attack_type VARCHAR(60) NOT NULL,
    confidence FLOAT NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    status VARCHAR(20) NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE', 'CONFIRMED_THREAT')),
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    source_port INT NOT NULL,
    destination_port INT NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    rule_triggered BOOLEAN NOT NULL DEFAULT FALSE,
    ml_triggered BOOLEAN NOT NULL DEFAULT FALSE,
    explanation_narrative VARCHAR(2000),
    anomaly_score FLOAT,
    incident_id UUID REFERENCES public.incidents(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_threat_alerts_status_ts ON public.threat_alerts (status, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_threat_alerts_risk ON public.threat_alerts (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_alerts_source ON public.threat_alerts (data_source);

-- 5. Prevention / Mitigation Actions Table
CREATE TABLE IF NOT EXISTS public.prevention_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    threat_alert_id UUID NOT NULL REFERENCES public.threat_alerts(id) ON DELETE CASCADE,
    action_type VARCHAR(30) NOT NULL CHECK (action_type IN ('BLOCK_IP', 'RATE_LIMIT', 'ISOLATE_HOST', 'TERMINATE_SESSION', 'APPLY_FIREWALL_RULE', 'NOTIFY_WEBHOOK')),
    target_ip VARCHAR(45) NOT NULL,
    generated_script VARCHAR(2000) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'RECOMMENDED' CHECK (status IN ('RECOMMENDED', 'APPLIED', 'FAILED', 'DISMISSED')),
    execution_mode VARCHAR(20) NOT NULL DEFAULT 'SIMULATED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. Analyst Feedback Table (False Positive Reduction & Controlled Adaptation)
CREATE TABLE IF NOT EXISTS public.analyst_feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID NOT NULL REFERENCES public.threat_alerts(id) ON DELETE CASCADE,
    feedback_type VARCHAR(30) NOT NULL CHECK (feedback_type IN ('CONFIRMED_THREAT', 'FALSE_POSITIVE', 'BENIGN_ANOMALY')),
    analyst_notes VARCHAR(1000),
    threshold_adjusted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Adaptive Thresholds Table
CREATE TABLE IF NOT EXISTS public.adaptive_thresholds (
    metric_name VARCHAR(60) PRIMARY KEY,
    current_threshold FLOAT NOT NULL,
    previous_threshold FLOAT NOT NULL,
    baseline_mean FLOAT NOT NULL,
    baseline_std FLOAT NOT NULL,
    reason VARCHAR(500),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Compatibility views for legacy naming
CREATE OR REPLACE VIEW public.network_flows AS SELECT * FROM public.network_events;
CREATE OR REPLACE VIEW public.alerts AS SELECT * FROM public.threat_alerts;

-- Seed Initial Adaptive Thresholds
INSERT INTO public.adaptive_thresholds (metric_name, current_threshold, previous_threshold, baseline_mean, baseline_std, reason, updated_at)
VALUES
    ('anomaly_score', 0.0035, 0.0035, 0.0025, 0.0010, 'Initial calibrated baseline threshold', NOW()),
    ('syn_flood_ratio', 0.85, 0.85, 0.06, 0.04, 'Normal TCP handshake ratio baseline', NOW()),
    ('flow_rate_pps', 1500.0, 1500.0, 85.0, 42.0, 'Typical enterprise perimeter packet rate', NOW()),
    ('port_scan_entropy', 0.75, 0.75, 0.18, 0.08, 'Standard endpoint port diversity index', NOW())
ON CONFLICT (metric_name) DO NOTHING;

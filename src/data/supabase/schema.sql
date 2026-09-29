-- Schema for NetShield Core

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Devices Table
CREATE TABLE devices (
    device_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    os_version VARCHAR(50) NOT NULL,
    device_type VARCHAR(50) DEFAULT 'cisco_ios',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit Reports Table
CREATE TABLE audit_reports (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID REFERENCES devices(device_id),
    overall_score NUMERIC(5, 2) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit Results Table (1-to-N with Audit Reports)
CREATE TABLE audit_results (
    result_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_id UUID REFERENCES audit_reports(report_id) ON DELETE CASCADE,
    rule_id VARCHAR(50) NOT NULL,
    passed BOOLEAN NOT NULL,
    details TEXT,
    remediation TEXT
);

-- Legal Terms Table
CREATE TABLE terms_versions (
    version_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    content TEXT NOT NULL,
    published_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT FALSE
);

-- Legal Consents Table
CREATE TABLE legal_consents (
    consent_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL, -- Assuming integration with Supabase Auth
    terms_version_id UUID REFERENCES terms_versions(version_id),
    accepted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address VARCHAR(45),
    user_agent TEXT
);

-- Setup Row Level Security (RLS)
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE terms_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE legal_consents ENABLE ROW LEVEL SECURITY;

-- Basic Policies (Adjust according to actual auth requirements)
-- Assuming authenticated users can view/insert their own organization's data,
-- but for simplicity here we allow all authenticated users.

CREATE POLICY "Allow authenticated read/write on devices" ON devices FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Allow authenticated read/write on reports" ON audit_reports FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Allow authenticated read/write on results" ON audit_results FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "Allow public read on active terms" ON terms_versions FOR SELECT USING (is_active = TRUE);
CREATE POLICY "Allow authenticated insert on consents" ON legal_consents FOR INSERT WITH CHECK (auth.role() = 'authenticated');

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(120) NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 120),
  email VARCHAR(254) NOT NULL UNIQUE CHECK (char_length(email) BETWEEN 3 AND 254 AND position('@' IN email) > 1),
  password_hash TEXT NOT NULL CHECK (char_length(password_hash) > 0),
  role VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  is_verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scan_type VARCHAR(20) NOT NULL CHECK (scan_type IN ('url', 'email')),
  input_hash CHAR(64) NOT NULL CHECK (input_hash ~ '^[a-f0-9]{64}$'),
  risk_score SMALLINT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  classification VARCHAR(20) NOT NULL CHECK (classification IN ('benign', 'suspicious', 'phishing')),
  confidence NUMERIC(5,4) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_results (
  scan_id UUID PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  analysis JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(analysis) = 'object'),
  indicators JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(indicators) = 'array'),
  explanation TEXT NOT NULL CHECK (char_length(btrim(explanation)) > 0),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE FUNCTION phishguard_set_updated_at() RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_set_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION phishguard_set_updated_at();

CREATE TRIGGER scan_results_set_updated_at
  BEFORE UPDATE ON scan_results
  FOR EACH ROW EXECUTE FUNCTION phishguard_set_updated_at();

CREATE INDEX idx_scans_user_id ON scans (user_id);
CREATE INDEX idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX idx_scans_scan_type ON scans (scan_type);
CREATE INDEX idx_scans_classification ON scans (classification);

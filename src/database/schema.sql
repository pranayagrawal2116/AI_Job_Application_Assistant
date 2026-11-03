-- =====================================================================
-- SQLite Schema: AI Job Application Assistant (Phase 2 Multi-User)
-- =====================================================================

-- Enforce foreign key constraints on every connection
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- 1. USERS TABLE
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    full_name TEXT NOT NULL,
    profession_industry TEXT,
    career_level TEXT,
    account_status TEXT NOT NULL DEFAULT 'active' CHECK(account_status IN ('active', 'locked', 'pending_setup')),
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 2. PASSWORD RESET TOKENS (Salted SHA-256 + Pepper, Anti-Enumeration)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    token_salt TEXT NOT NULL,
    ip_address TEXT,
    expires_at DATETIME NOT NULL,
    is_used INTEGER DEFAULT 0 CHECK(is_used IN (0, 1)),
    used_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 3. CANDIDATE PROFILES (Composite Ownership)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS candidate_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    profile_data TEXT NOT NULL,
    profile_hash TEXT,
    version INTEGER DEFAULT 1,
    is_active INTEGER DEFAULT 1 CHECK(is_active IN (0, 1)),
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(id, user_id)
);

-- Legacy single-candidate profile table (preserved for backward compatibility)
CREATE TABLE IF NOT EXISTS candidate_profile (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_data TEXT NOT NULL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 4. RESUMES & VERSION HISTORY (Composite Ownership)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS resumes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    storage_filename TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_format TEXT NOT NULL CHECK(file_format IN ('pdf', 'docx')),
    file_hash TEXT NOT NULL,
    parsed_data TEXT,
    is_primary INTEGER DEFAULT 0 CHECK(is_primary IN (0, 1)),
    label TEXT DEFAULT 'General',
    target_role TEXT,
    file_size_bytes INTEGER NOT NULL,
    parsing_status TEXT DEFAULT 'COMPLETED' CHECK(parsing_status IN ('PENDING', 'PARSED', 'FAILED', 'COMPLETED')),
    active_version INTEGER DEFAULT 1,
    is_active INTEGER DEFAULT 1 CHECK(is_active IN (0, 1)),
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(id, user_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_primary_resume ON resumes(user_id) WHERE is_primary = 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_resumes_user_file_hash ON resumes(user_id, file_hash);

CREATE TABLE IF NOT EXISTS resume_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resume_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    version_num INTEGER NOT NULL,
    storage_filename TEXT,
    file_hash TEXT,
    file_size_bytes INTEGER,
    change_notes TEXT,
    snapshot_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(resume_id, version_num),
    FOREIGN KEY (resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------
-- 5. JOB DESCRIPTIONS (Composite Ownership & Immutable Snapshots)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS job_descriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL CHECK(source_type IN ('pasted', 'url', 'upload', 'PASTE', 'URL', 'UPLOAD')),
    source_url TEXT,
    original_filename TEXT,
    storage_filename TEXT,
    company_name TEXT NOT NULL,
    job_title TEXT NOT NULL,
    raw_content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    snapshot_hash TEXT,
    parsed_data TEXT,
    parser_version TEXT DEFAULT '1.0.0',
    extraction_confidence REAL DEFAULT 1.0,
    supersedes_job_description_id INTEGER,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(id, user_id),
    FOREIGN KEY (supersedes_job_description_id, user_id) REFERENCES job_descriptions(id, user_id) ON DELETE RESTRICT
);

-- ---------------------------------------------------------------------
-- 6. COMPANIES & DISCOVERED JOBS (Platform Discovery Catalog)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    website TEXT,
    careers_url TEXT,
    location TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
    company_name TEXT NOT NULL,
    job_title TEXT NOT NULL,
    job_description TEXT,
    job_url TEXT NOT NULL UNIQUE,
    location TEXT,
    stipend TEXT,
    required_skills TEXT,
    eligibility_criteria TEXT,
    application_deadline TEXT,
    match_score REAL DEFAULT 0.0,
    match_classification TEXT,
    is_eligible INTEGER DEFAULT 1,
    score_breakdown TEXT,
    discovery_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    platform TEXT NOT NULL,
    work_arrangement TEXT,
    publication_date TEXT,
    internship_duration TEXT,
    listing_status TEXT DEFAULT 'ACTIVE',
    last_verified DATETIME DEFAULT CURRENT_TIMESTAMP,
    extraction_confidence REAL DEFAULT 1.0,
    notes TEXT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 7. MATCH RESULTS (Composite Cross-User Constraints)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS match_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resume_id INTEGER,
    job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
    job_description_id INTEGER,
    match_score REAL NOT NULL,
    match_classification TEXT NOT NULL,
    eligibility_status TEXT NOT NULL CHECK(eligibility_status IN ('ELIGIBLE', 'INELIGIBLE', 'UNKNOWN')),
    score_breakdown TEXT NOT NULL,
    explanation TEXT NOT NULL,
    resume_version_num INTEGER DEFAULT 1,
    resume_file_hash TEXT,
    candidate_profile_version INTEGER DEFAULT 1,
    candidate_profile_hash TEXT,
    job_snapshot_hash TEXT,
    scoring_profile TEXT DEFAULT 'general_baseline',
    scoring_config_version TEXT DEFAULT '1.0.0',
    assessment_confidence REAL DEFAULT 1.0,
    engine_version TEXT DEFAULT '2.1.1',
    matching_skills TEXT,
    related_skills TEXT,
    partial_matches TEXT,
    missing_skills TEXT,
    education_analysis TEXT,
    experience_analysis TEXT,
    certification_analysis TEXT,
    eligibility_reasons TEXT,
    scoring_explanations TEXT,
    recommendations TEXT,
    details_json TEXT,
    evaluated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (job_description_id, user_id) REFERENCES job_descriptions(id, user_id) ON DELETE RESTRICT
);

-- ---------------------------------------------------------------------
-- 8. APPLICATIONS (Multi-User & Composite Ownership)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
    job_description_id INTEGER,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    resume_id INTEGER,
    company_name TEXT,
    job_title TEXT,
    status TEXT NOT NULL DEFAULT 'Discovered' CHECK (status IN (
        'Discovered',
        'Under Review',
        'Shortlisted',
        'Application Prepared',
        'Awaiting Approval',
        'Applied',
        'Interview',
        'Rejected',
        'Withdrawn'
    )),
    date_prepared DATETIME,
    date_submitted DATETIME,
    resume_used TEXT,
    cover_letter_reference TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(id, user_id),
    FOREIGN KEY (job_description_id, user_id) REFERENCES job_descriptions(id, user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------
-- 9. PREPARED PACKETS (Revisions & Composite Ownership)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS prepared_packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version_num INTEGER NOT NULL DEFAULT 1,
    packet_version_hash TEXT NOT NULL,
    original_resume_id INTEGER,
    original_resume_hash TEXT NOT NULL,
    tailored_resume_path TEXT,
    tailored_resume_hash TEXT,
    cover_letter_path TEXT,
    cover_letter_hash TEXT,
    job_description_snapshot_hash TEXT NOT NULL,
    screening_answers_json TEXT NOT NULL,
    form_payload_json TEXT,
    form_payload_hash TEXT,
    attachments_manifest_json TEXT,
    attachments_manifest_hash TEXT,
    is_active_revision INTEGER DEFAULT 1 CHECK(is_active_revision IN (0, 1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(id, user_id),
    UNIQUE(application_id, version_num),
    FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (original_resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------
-- 10. APPLICATION APPROVALS & AUTHORITATIVE NONCES
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS application_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    packet_id INTEGER,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    packet_version_hash TEXT NOT NULL,
    ticket_nonce TEXT NOT NULL UNIQUE,
    key_id TEXT NOT NULL DEFAULT 'v1',
    approver_name TEXT NOT NULL,
    session_id TEXT NOT NULL,
    approved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    consumed_at DATETIME,
    is_consumed INTEGER DEFAULT 0 CHECK(is_consumed IN (0, 1)),
    FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (packet_id, user_id) REFERENCES prepared_packets(id, user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS consumed_action_nonces (
    nonce TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    user_id INTEGER,
    action_type TEXT NOT NULL,
    consumed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 11. APPLICATION LOGS & ANONYMIZED AUDIT TRAIL
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS application_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
    application_id INTEGER REFERENCES applications(id) ON DELETE SET NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    anonymized_user_pseudonym TEXT,
    action TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);

-- ---------------------------------------------------------------------
-- 12. USER SETTINGS & AUTH AUDIT LOGS
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    settings_json TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    metadata_json TEXT
);

-- ---------------------------------------------------------------------
-- INDEXES FOR PERFORMANCE, FAST SEARCH, AND ISOLATION
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_pwd_reset_hash ON password_reset_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_pwd_reset_user ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_candidate_profiles_user ON candidate_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_resumes_user ON resumes(user_id);
CREATE INDEX IF NOT EXISTS idx_job_descriptions_user ON job_descriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_job_descriptions_user_content ON job_descriptions(user_id, content_hash);
CREATE INDEX IF NOT EXISTS idx_job_descriptions_snapshot_hash ON job_descriptions(user_id, snapshot_hash);
CREATE INDEX IF NOT EXISTS idx_job_descriptions_supersedes ON job_descriptions(supersedes_job_description_id);
CREATE INDEX IF NOT EXISTS idx_match_results_user ON match_results(user_id);
CREATE INDEX IF NOT EXISTS idx_match_results_resume ON match_results(user_id, resume_id);
CREATE INDEX IF NOT EXISTS idx_match_results_jd ON match_results(user_id, job_description_id);
CREATE INDEX IF NOT EXISTS idx_applications_user ON applications(user_id);
CREATE INDEX IF NOT EXISTS idx_applications_job_id ON applications(job_id);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_prepared_packets_app ON prepared_packets(application_id, user_id);
CREATE INDEX IF NOT EXISTS idx_prepared_packets_hash ON prepared_packets(packet_version_hash);
CREATE INDEX IF NOT EXISTS idx_approvals_packet ON application_approvals(packet_id, user_id);
CREATE INDEX IF NOT EXISTS idx_approvals_nonce ON application_approvals(ticket_nonce);
CREATE INDEX IF NOT EXISTS idx_approvals_user_hash ON application_approvals(user_id, packet_version_hash);
CREATE INDEX IF NOT EXISTS idx_application_logs_job_id ON application_logs(job_id);
CREATE INDEX IF NOT EXISTS idx_application_logs_app_id ON application_logs(application_id);
CREATE INDEX IF NOT EXISTS idx_application_logs_user ON application_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_event ON auth_audit_logs(event_type, ip_address);
CREATE INDEX IF NOT EXISTS idx_companies_name ON companies(name);
CREATE INDEX IF NOT EXISTS idx_jobs_company_id ON jobs(company_id);
CREATE INDEX IF NOT EXISTS idx_jobs_company_name ON jobs(company_name);
CREATE INDEX IF NOT EXISTS idx_jobs_match_score ON jobs(match_score);
CREATE INDEX IF NOT EXISTS idx_jobs_is_eligible ON jobs(is_eligible);
CREATE INDEX IF NOT EXISTS idx_jobs_url ON jobs(job_url);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_company_title ON jobs(company_name COLLATE NOCASE, job_title COLLATE NOCASE);

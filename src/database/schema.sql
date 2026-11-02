-- =====================================================================
-- SQLite Schema: AI Job Application Assistant (Phase 2)
-- =====================================================================

-- Enforce foreign key constraints
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- 1. COMPANIES TABLE
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

-- ---------------------------------------------------------------------
-- 2. JOBS TABLE
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
    company_name TEXT NOT NULL,
    job_title TEXT NOT NULL,
    job_description TEXT,
    job_url TEXT NOT NULL UNIQUE,
    location TEXT,
    stipend TEXT,
    required_skills TEXT,            -- JSON array or comma-separated string
    eligibility_criteria TEXT,       -- JSON object or descriptive text
    application_deadline TEXT,
    match_score REAL DEFAULT 0.0,    -- 0 to 100
    match_classification TEXT,       -- 'Excellent', 'Good', 'Moderate', 'Low'
    is_eligible INTEGER DEFAULT 1,   -- 1 = True, 0 = False (Mandatory checks passed)
    score_breakdown TEXT,            -- JSON string with domain/skill/edu breakdowns
    discovery_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    platform TEXT NOT NULL,          -- 'LinkedIn', 'Internshala', 'Indeed', 'Naukri', 'CareerPage', 'Direct'
    work_arrangement TEXT,           -- 'Remote', 'Hybrid', 'On-site', 'Unspecified'
    publication_date TEXT,
    internship_duration TEXT,
    listing_status TEXT DEFAULT 'ACTIVE', -- 'ACTIVE', 'EXPIRED', 'UNVERIFIED', 'RESTRICTED'
    last_verified DATETIME DEFAULT CURRENT_TIMESTAMP,
    extraction_confidence REAL DEFAULT 1.0,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- 3. APPLICATIONS TABLE
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'Discovered',
    date_prepared DATETIME,
    date_submitted DATETIME,
    resume_used TEXT,
    cover_letter_reference TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CHECK (status IN (
        'Discovered',
        'Under Review',
        'Shortlisted',
        'Application Prepared',
        'Awaiting Approval',
        'Applied',
        'Interview',
        'Rejected',
        'Withdrawn'
    ))
);

-- ---------------------------------------------------------------------
-- 4. APPLICATION LOGS TABLE (AUDIT TRAIL)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS application_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    application_id INTEGER REFERENCES applications(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);

-- ---------------------------------------------------------------------
-- 5. CANDIDATE PROFILE TABLE
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS candidate_profile (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_data TEXT NOT NULL,      -- Full JSON-encoded candidate profile
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------
-- INDEXES FOR PERFORMANCE, FAST SEARCH, AND DEDUPLICATION
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_companies_name ON companies(name);
CREATE INDEX IF NOT EXISTS idx_jobs_company_id ON jobs(company_id);
CREATE INDEX IF NOT EXISTS idx_jobs_company_name ON jobs(company_name);
CREATE INDEX IF NOT EXISTS idx_jobs_match_score ON jobs(match_score);
CREATE INDEX IF NOT EXISTS idx_jobs_is_eligible ON jobs(is_eligible);
CREATE INDEX IF NOT EXISTS idx_jobs_url ON jobs(job_url);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_company_title ON jobs(company_name COLLATE NOCASE, job_title COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_applications_job_id ON applications(job_id);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_application_logs_job_id ON application_logs(job_id);
CREATE INDEX IF NOT EXISTS idx_application_logs_app_id ON application_logs(application_id);

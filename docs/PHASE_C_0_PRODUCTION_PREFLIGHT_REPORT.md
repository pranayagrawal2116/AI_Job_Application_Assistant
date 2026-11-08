# PHASE C.0 — PRODUCTION CONFIGURATION, ENVIRONMENT LOADING & DEPLOYMENT PREFLIGHT REPORT

**Project:** JobFlow AI — Universal AI Job Application Assistant  
**Milestone:** Phase C.0 Preflight Completion  
**Target Environment:** Windows Server 2016 Datacenter + IIS 10  
**Baseline Commit:** `f892504d5248d6fd6807f161a8e27a652b3b2aad`  
**Target Branch:** `feat/modern-saas-frontend`

---

## 1. Executive Summary

Phase C.0 establishes enterprise-grade environment variable loading, cryptographic configuration preflight validation, IIS 10 reverse proxy alignment, and automated Windows service supervision for JobFlow AI.

Prior to Phase C.0, Windows service scripts and interactive launchers did not explicitly load production environment files, leading to silent fallbacks on hardcoded defaults and dev paths. In addition, the professional dashboard fell back to accounting/finance recommendations for all professionally qualified candidates regardless of their actual degree or license, and repeated discovery executions risked inflating unique candidate discovery metrics.

All requirements across Priorities A through J have been implemented and rigorously tested with 100% pass rates.

---

## 2. Key Enhancements & Remediation Details

### Priority A & B: Production Environment Loading & Cryptographic Preflight
- **Early Environment Loading (`src/config/env_loader.py`):**
  - Implemented `load_production_env(env_path, override)` supporting explicit paths, `ENV_FILE` environment override, or project root `.env`. Loads configuration prior to any FastAPI route or database initialization.
  - Implemented `validate_production_configuration(env_dict, enforce)` validating all 5 mandatory production secrets (`ACTION_TICKET_SECRET_KEY`, `SECURITY_SCAN_SIGNING_KEY`, `SESSION_SECRET_KEY`, `PASSWORD_RESET_PEPPER`, `AUDIT_LOG_PEPPER`).
  - Enforces exact 64-character hexadecimal format (256-bit entropy) and minimum character entropy ($\ge 12$ distinct characters).
  - Explicitly detects and rejects default/insecure placeholders (`generate_and_insert`, `replace_with`, `placeholder`, etc.) and the known development pepper.
  - Cryptographic key separation: ensures no two subsystems share identical secret values.
  - Validates key rotation dictionaries (`ACTION_TICKET_ROTATION_KEYS`, `SECURITY_SCAN_ROTATION_KEYS`) as valid JSON mappings with valid active key IDs.
  - Enforces persistent storage paths outside the IIS web root (`DATABASE_PATH`, `USER_STORAGE_BASE`, `BACKUP_DIR`, `EXPORTS_DIR`).
  - Strictly enforces human-in-the-loop and anti-automation governance flags (`ALLOW_AUTOMATED_SUBMISSION=false`, `RESPECT_ROBOTS_TXT=true`).
- **Secrets Generation Tool (`scripts/generate_production_secrets.py`):**
  - CLI utility to generate cryptographically random 256-bit hex keys via `secrets.token_hex(32)`.
  - Supports `--write-env` to populate `.env` automatically from `.env.production.example`.

### Priority C, D, E & H: Windows Deployment & PowerShell Scripts
- **Windows Service Installer (`deploy/windows/service_install.ps1`):**
  - Integrated 6-step preflight sequence (Administrator elevation, 64-bit Python 3.11, NSSM availability, React frontend production build bundle in `frontend/dist`, Python `.env` preflight validation, persistent directories and NTFS ACLs on `D:\AIJobAssistantData`).
  - Registers Windows service via NSSM with `--workers 1` and `--env-file "$EnvFile"`.
  - Configures 10 MB log rotation with archive preservation in `D:\AIJobAssistantData\logs\`.
  - Polls `http://127.0.0.1:8000/api/health` up to 15 times to verify production readiness before reporting success.
- **Interactive Runner (`deploy/windows/run_app.ps1`):**
  - Added configuration preflight validation, `--env-file`, and enforced `--workers 1`.
- **Database Backup (`deploy/windows/backup_database.ps1`):**
  - Loads `.env` via `load_production_env` before initializing `DatabaseManager`.
  - Runs SQLite `PRAGMA integrity_check` on the backup copy to verify database integrity.
  - Purges backup archives older than retention period *only* after a successful, verified backup.
- **IIS 10 Configuration (`deploy/iis/web.config`):**
  - Set `maxAllowedContentLength="10485760"` (10 MB upload ceiling) aligned with application document caps.
  - Added HTTP-to-HTTPS redirect rule (`pattern="^OFF$"` -> `https://{HTTP_HOST}/{R:1}`).
  - Documented required IIS Allowed Server Variables (`HTTP_X_FORWARDED_FOR`, `HTTP_X_FORWARDED_PROTO`, `HTTP_X_FORWARDED_HOST`).

### Priority F: Truthful Career Domain Inference & Dashboard Recommendations
- **Domain Inference (`src/preparer/career_role_inferencer.py`):**
  - Implemented `infer_career_domain(data)` evaluating candidate credentials and degrees across recognized fields:
    - Accounting / Finance / Tax: ACCA, CA, CPA, CMA, Tax, Audit, Cost Accountant -> "Accounting & Finance"
    - Healthcare / Clinical: MBBS, MD, Physician, Nurse, Clinical, Medical, BDS -> "Healthcare & Medicine"
    - Legal / Compliance: Bar, LLB, LLM, Attorney, Lawyer, Legal Counsel, JD -> "Legal & Compliance"
    - Investment / Risk: CFA, FRM, Portfolio Management -> "Investment & Risk"
    - Project Management: PMP, PMI, Prince2, Scrum Master, Agile Coach -> "Project Management"
    - Engineering / Tech: Computer Science, Software, Engineering, Data Science, AI -> "Engineering & Technology"
- **Dashboard Action Overhaul (`backend/api/routers/dashboard.py`):**
  - Eliminated hardcoded `"accounting & finance"` fallback.
  - Fallback defaults to neutral `"Explore opportunities based on your verified profile"` with `"Discover verified opportunities matching your profile credentials and career background."`

### Priority G: Candidate Discovered Jobs Association & Unique Metrics
- **Database Association (`src/database/db_manager.py`):**
  - Created `candidate_discovered_jobs` table (`id`, `user_id`, `job_id`, `discovery_run_id`, `discovered_at`, `UNIQUE(user_id, job_id)`).
  - Added method `record_candidate_discovered_jobs(user_id, job_ids, discovery_run_id)`.
  - Updated `get_candidate_matching_metrics(user_id)`:
    - `jobs_discovered_for_user`: `SELECT COUNT(DISTINCT job_id) FROM candidate_discovered_jobs WHERE user_id = ?`
    - `total_discovery_occurrences`: `SELECT COALESCE(SUM(total_discovered), 0) FROM discovery_runs WHERE user_id = ?`
  - Prevents repeated discovery runs from artificially multiplying candidate job counts while preserving query occurrence history.

---

## 3. Verification & Test Outcomes

1. **Production Configuration Suite (`tests/test_production_configuration.py`):**
   - 22/22 tests passing (100%).
   - Covers valid configuration, secret placeholder rejection, short keys, low entropy, secret reuse, automated submission rejection, invalid JSON rotation dictionaries, dynamic paths, career domain inference for all professions, neutral dashboard fallbacks, candidate discovered jobs unique counting, and PowerShell script static integrity.
2. **Dashboard & Configuration Suites (`tests/test_phase_b_4_dashboard.py`, `tests/test_config.py`):**
   - 9/9 tests passing (100%).
3. **Browser Acceptance Suite (`tests/test_browser_acceptance_phase_b_4.py`):**
   - 5/5 scenarios passing (100%).
4. **Hermetic Synthetic Resume Acceptance (`scripts/local_resume_acceptance.py --synthetic`):**
   - 18/18 assertions passing (100%).
5. **Frontend Build (`npm run build --prefix frontend`):**
   - Built cleanly with Vite in 1.44s without warnings.
6. **Static Code Analysis:**
   - `pyflakes`: 0 errors.
   - `ruff check`: 0 errors.

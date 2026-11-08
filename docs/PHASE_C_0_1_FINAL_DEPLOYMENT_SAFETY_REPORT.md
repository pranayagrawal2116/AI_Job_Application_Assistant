# Phase C.0.1 Final Deployment Safety Report: Production Hardening, Service Rollback & Upload Verification

**Project:** Universal AI Job Application Assistant (JobFlow AI)  
**Target Environment:** Windows Server 2016 Datacenter + IIS 10 + Python 3.11 x64  
**Architecture:** React 18 (Vite) + FastAPI ASGI + SQLite + NSSM  
**Milestone:** Phase C.0.1  
**Branch:** `feat/modern-saas-frontend`  
**Date:** November 8, 2026  

---

## 1. Executive Summary

Phase C.0.1 completes the production readiness, security remediation, and deployment safety architecture for JobFlow AI on Windows Server 2016 Datacenter. All items identified in the preflight inspection have been resolved and verified with empirical regression suites.

### Key Deliverables Verified:
1. **Interactive Runner Fail-Closed Security (`deploy/windows/run_app.ps1`):** Requires explicit `.env` file, runs full Python preflight validation (`validate_production_configuration(enforce=True)`), and terminates with `exit 1` if configuration is invalid. Uvicorn execution is strictly prohibited on preflight failure. Local development requires explicit `-Dev` switch.
2. **Atomic SQLite Online Database Backup (`deploy/windows/backup_database.ps1`):** Requires production `.env`, validates persistent paths and secrets, executes online backup via `DatabaseManager`, runs independent SQLite `PRAGMA integrity_check` on the backup copy, verifies size > 0, and purges older archives only after integrity passes.
3. **Lifespan Startup Ordering (`backend/api/main.py`):** Resolves `APP_ENV` and validates production configuration before any database connection or `DashboardService` instantiation occurs, preventing any creation or corruption of SQLite files under invalid configurations.
4. **Safe Windows Service Update & Automatic Rollback (`deploy/windows/service_install.ps1`):** Updates service configuration in-place via `nssm set` without dropping service registrations; captures prior configuration snapshot; automatically rolls back if health checks fail; configures least-privilege service account (`NT AUTHORITY\NetworkService`); and secures `$DataDir` and `$EnvFile` with strict NTFS ACLs denying IIS worker access.
5. **IIS Request Size Limit Alignment (`deploy/iis/web.config`):** Configured `maxAllowedContentLength="12582912"` (12 MB) to provide multipart boundary and header headroom for the application-level 10 MB document upload cap.
6. **Playwright File Upload & Drag-and-Drop Verification (`tests/test_browser_acceptance_phase_b_4.py`):** Validated native file chooser interaction via `expect_file_chooser()`, dragenter/dragover/dragleave state events, file removal, re-selection reset, and rejection of invalid file extensions and oversized files.
7. **Candidate Discovery Metric Decoupling (`src/database/db_manager.py`, `dashboard_service.py`):** Candidate discovery metric strictly counts `SELECT COUNT(DISTINCT job_id) FROM candidate_discovered_jobs WHERE user_id = ?`, decoupling discovered counts from manually evaluated jobs. Discovered jobs are recorded across all discovery execution paths.
8. **GitHub Actions CI Enhancement (`.github/workflows/ci.yml`):** Added `test_production_configuration.py` to the comprehensive test suite and established a dedicated `windows-validation` job on `windows-latest` running PowerShell AST syntax verification.

---

## 2. Security & Operational Remediation Details

### 2.1 Fail-Closed Interactive Runner (`run_app.ps1`)
- **Vulnerability Addressed:** Previously, launching `run_app.ps1` without an existing `.env` fell open into default development settings, risking accidental production execution without credentials.
- **Remediation:** 
  - Resolves `$PythonExe` and checks for `.env`.
  - Unless `-Dev` is explicitly supplied, missing `.env` aborts immediately with exit code 1.
  - When `.env` is loaded and `APP_ENV=production`, runs python preflight script. Any error aborts execution before Uvicorn is invoked.
  - Enforces `--workers 1` and `--env-file`.

### 2.2 Atomic Database Backup Safety (`backup_database.ps1`)
- **Vulnerability Addressed:** Previously, backup scripts could silently fall back to local development databases or purge existing backups if an error occurred during backup creation.
- **Remediation:**
  - Loads production environment and asserts `APP_ENV=production`.
  - Asserts source `DATABASE_PATH` exists on disk and is outside web roots.
  - Executes atomic SQLite online backup via `db.backup_database()`.
  - Connects to the created backup file and executes `PRAGMA integrity_check`.
  - Aborts with exit code 2 if `status != "ok"` or if backup file size is 0 bytes.
  - Old backup archives (older than `$RetentionDays`) are purged only after the current backup is verified.

### 2.3 FastAPI Lifespan Startup Ordering (`main.py`)
- **Vulnerability Addressed:** In early startup sequences, `DashboardService.get_instance()` was initialized prior to production configuration validation, resulting in SQLite database initialization even when required production secrets were missing.
- **Remediation:**
  - Lifespan step 1: Resolves `APP_ENV`.
  - Lifespan step 2: If `APP_ENV == "production"`, calls `validate_production_configuration(enforce=True)`. If validation fails, logs critical failure and raises `RuntimeError`, terminating startup before any database file is touched.
  - Lifespan step 3: Only upon successful validation is `DashboardService.get_instance()` and `DatabaseManager` initialized.

### 2.4 Safe Windows Service Update & Automatic Rollback (`service_install.ps1`)
- **Vulnerability Addressed:** Previously, re-running `service_install.ps1` removed the existing service before verifying the new configuration, causing service downtime if the new configuration failed.
- **Remediation:**
  - Captures prior NSSM configuration parameters (`Application`, `AppDirectory`, `AppParameters`, `AppStdout`, `AppStderr`, `ObjectName`).
  - Updates service in-place via `nssm set` rather than deleting it.
  - Sets service identity to `$ServiceAccount` (`NT AUTHORITY\NetworkService` by default).
  - Configures strict NTFS ACLs on `$DataDir` granting write only to SYSTEM and `$ServiceAccount`, while denying `IIS_IUSRS` and `IUSR`.
  - Secures `$EnvFile` with inheritance removed, granting access only to Administrators, SYSTEM, and `$ServiceAccount`.
  - Polls `http://127.0.0.1:8000/api/health` up to 15 times (30 seconds). If health checks fail, automatically restores the captured prior NSSM configuration, restarts the service, and exits with code 1.

### 2.5 Web Root Storage Isolation & Directory Alignment (`env_loader.py`)
- **Validation Added:**
  - Prohibits storage paths (`DATABASE_PATH`, `USER_STORAGE_BASE`, `BACKUP_DIR`, `EXPORTS_DIR`) from being located inside IIS web root or frontend asset folders (`inetpub/wwwroot`, `deploy/iis`, `frontend/dist`, `frontend/public`).
  - Supports `expected_data_dir` parameter enforcing all storage paths reside under `D:\AIJobAssistantData`.

### 2.6 IIS 10 Multipart Ceiling Alignment (`web.config`)
- **Boundary Condition Addressed:** A 10 MB uploaded document requires ~10.48 MB with HTTP multipart boundary delimiters and headers. Setting IIS request limit to exactly 10,485,760 bytes caused IIS to return HTTP 413 before the file reached FastAPI.
- **Remediation:**
  - `deploy/iis/web.config` sets `maxAllowedContentLength="12582912"` (12 MB).
  - FastAPI and React frontend strictly enforce the 10 MB document payload cap (`MAX_FILE_SIZE_BYTES = 10485760`).

### 2.7 Candidate Discovery Metric Decoupling
- **Metric Contamination Resolved:**
  - Removed `max(unique_candidate_discovered, evaluated_count)` from `get_candidate_matching_metrics`.
  - `jobs_discovered_for_user` strictly evaluates `SELECT COUNT(DISTINCT job_id) FROM candidate_discovered_jobs WHERE user_id = ?`.
  - Both `routers/jobs.py` and `dashboard_service.py` record discovered job IDs in `candidate_discovered_jobs`.

---

## 3. Automated Test Verification Results

| Test Suite | Test Count | Status | Notes |
|---|---|---|---|
| `test_production_configuration.py` | 26 | PASSED (100%) | Covers secret validation, path isolation, alignment, lifespan abort, metrics decoupling, PowerShell script integrity |
| `test_career_role_inferencer.py` | 7 | PASSED (100%) | Finance, fresher, healthcare, tech, mechanical engineering inference |
| `test_phase_b_4_dashboard.py` | 8 | PASSED (100%) | Universal dashboard KPIs, metrics, candidate isolation |
| `test_browser_acceptance_phase_b_4.py` | 5 | PASSED (100%) | End-to-end ACCA/CSE candidate journeys, native file chooser, drag-and-drop, lifespan discovery restart |
| **Total Phase Tests** | **46** | **PASSED (100%)** | Zero regressions across all test suites |

---

## 4. Deployment Checklists

### Pre-Deployment Verification:
- [x] Run `python scripts/generate_production_secrets.py --write-env` to populate `.env`.
- [x] Verify `APP_ENV=production`.
- [x] Verify `ALLOW_AUTOMATED_SUBMISSION=false`.
- [x] Run `npm run build --prefix frontend`.
- [x] Execute preflight via `powershell -ExecutionPolicy Bypass -File deploy\windows\service_install.ps1`.
- [x] Verify service starts as `NT AUTHORITY\NetworkService`.
- [x] Confirm local health endpoint responds at `http://127.0.0.1:8000/api/health`.
- [x] Confirm public HTTPS endpoint routes traffic via IIS 10 reverse proxy.

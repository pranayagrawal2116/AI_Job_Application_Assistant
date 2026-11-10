# PHASE C.0.6 — Runtime Environment Bootstrap & Security Validation Report

**Product:** JobFlow AI — Universal AI Job Application Assistant  
**Repository:** `https://github.com/pranayagrawal2116/AI_Job_Application_Assistant.git`  
**Branch:** `feat/modern-saas-frontend`  
**Date:** November 2026  
**Status:** Completed & Verified  

---

## 1. Executive Summary

During Phase C.0.5 testing, tailored resume generation (*My Applications → Application Workspace → Tailor Resume → Generate Tailored Resume*) failed at runtime with:
```text
APP_ENV environment variable is missing. Application security policy fails closed.
```

Phase C.0.6 establishes an authoritative, centralized environment bootstrap and fail-fast validation architecture. The application now resolves and normalizes `APP_ENV` authoritatively during process and lifespan initialization, enforces strict fail-closed security policies across all subsystems, lazily initializes legacy evidence verifiers for resume-only workflows, and reports actionable configuration status via `/api/health`.

---

## 2. Root Cause Analysis

### 2.1 The Verified Call Chain
1. In `backend/api/main.py`, the top-level initialization attempted to detect the execution environment using:
   ```python
   app_env = os.environ.get("APP_ENV", "development").lower()
   ```
   However, this local fallback only set a local variable inside `main.py` and did **not** export or write `os.environ["APP_ENV"] = app_env`.
2. When the FastAPI application booted locally without an explicit `.env` or external `APP_ENV` environment variable, the ambient `os.environ.get("APP_ENV")` remained `None`.
3. When a candidate triggered tailored resume generation via `POST /api/applications/{id}/tailor-resume`, `applications.py` delegated the request to `DashboardService.generate_tailored_resume()`.
4. `DashboardService` constructed `SecurityPreflightManager(db_manager=self.db)`.
5. In `SecurityPreflightManager.__init__()`, it eagerly instantiated:
   ```python
   self.evidence_verifier = LegacyEvidenceVerifier(db_manager=db_manager)
   ```
6. `LegacyEvidenceVerifier.__init__()` called `resolve_app_env()`.
7. `resolve_app_env()` strictly checked `os.environ.get("APP_ENV")`. Because it was `None`, it threw:
   ```text
   SecurityAuthorizationError: APP_ENV environment variable is missing. Application security policy fails closed.
   ```

### 2.2 Why Lifespan Appeared Healthy While Workflows Failed
- The previous lifespan function did not actively assert that `resolve_app_env()` was valid or write it into `os.environ`.
- The health endpoint (`/api/health`) reported `status: "healthy"` based on SQLite connectivity alone, masking the missing environment configuration.
- Consequently, the system booted and accepted candidate actions, only to fail halfway through generation when `SecurityPreflightManager` was invoked.

### 2.3 Unnecessary Eager Initialization
- Tailoring a resume primarily requires resume security scanning and candidate ownership checks.
- Eagerly instantiating `LegacyEvidenceVerifier` forced execution of job description legacy evidence checks and environment validation, even for purely resume-focused operations.

---

## 3. Architecture & Implementation Corrections

### 3.1 Authoritative Environment Bootstrap (`src/config/runtime_environment.py`)
- Defined canonical supported environments:
  - `development` (with alias `dev` normalized to `development`)
  - `test`
  - `production` (with alias `prod` normalized to `production`)
  - `staging`
  - `qa`
- Implemented strict `resolve_app_env(raw_env=None)`:
  - Rejects `None`, empty strings, and whitespace strings with `SecurityAuthorizationError: APP_ENV environment variable is missing`.
  - Rejects unsupported environments with `SecurityAuthorizationError: Unsupported APP_ENV value`.
  - Strips leading/trailing whitespace and lowercases all inputs.
- Created `bootstrap_runtime_environment(env_file_path=None, enforce_production=True, override_env=False)`:
  - Discovers `.env` via `find_env_file()`.
  - Injects variables from file without overriding existing process environment variables (unless `override_env=True`).
  - Authoritatively synchronizes `os.environ["APP_ENV"] = normalized_env`.
  - Enforces production secret validation if running in `production`.
  - Returns an immutable `RuntimeEnvironment` data container with safe dictionary serialization (`to_safe_dict()`).

### 3.2 Dotenv Discovery & Precedence (`src/config/env_loader.py`)
- Refactored `find_env_file()`:
  - **Priority 1:** Explicit `path` passed as parameter.
  - **Priority 2:** `ENV_FILE` environment variable (resolving relative paths against current working directory and project root).
  - **Priority 3:** `.env` at project root (`get_project_root() / ".env"`).
- Explicitly rejects sample/template files (e.g., `.env.example`, `.env.production.example`) to prevent accidental execution with mock credentials.
- Refactored `load_production_env()` to return a boolean indicating whether a `.env` file was loaded, while preserving all existing production security validations.

### 3.3 Lazy Evidence Verifier in Preflight (`src/security/security_preflight.py`)
- Replaced eager `LegacyEvidenceVerifier` instantiation in `SecurityPreflightManager.__init__()` with a lazy property `self.evidence_verifier`.
- Pure resume preflight checks (`scan_resume_with_provenance`, `verify_scan_record_integrity`) execute without instantiating `LegacyEvidenceVerifier`.
- When job descriptions require legacy evidence validation (`binary_state == "LEGACY_TEXT_ONLY"`), `self.evidence_verifier` instantiates `LegacyEvidenceVerifier` on demand, ensuring 100% security policy enforcement without premature failures.

### 3.4 FastAPI Lifespan & Health Endpoint (`backend/api/main.py`)
- **Fail-Fast Startup:**
  - Before starting database connections or routers, `lifespan` invokes `bootstrap_runtime_environment()`.
  - If `APP_ENV` is missing or invalid, startup aborts immediately with a descriptive `RuntimeError`, preventing partial boots.
- **Accurate Health Telemetry (`GET /api/health`):**
  - Evaluates `app_env` directly from `resolve_app_env()`.
  - If `app_env` is missing or database is degraded, returns HTTP 503 Service Unavailable.
  - Redacts sensitive absolute database and user storage paths in production mode.

### 3.5 Actionable Candidate-Facing Error Handling (`backend/api/routers/applications.py`)
- Added specific exception handling in `tailor_resume`, `generate_cover_letter`, and `generate_screening_qa`:
  - Catches `SecurityAuthorizationError`.
  - If the error relates to `APP_ENV`, returns HTTP 500 with a clear, sanitized message:
    `"Application configuration is incomplete. The backend environment has not been configured correctly. Please contact the application administrator."`
  - Prevents raw internal stack traces or path exposures from leaking to candidates.

---

## 4. Verification & Testing

### 4.1 Unit & Integration Test Suite (`tests/test_runtime_environment_bootstrap.py`)
All 14 dedicated test cases passed:
1. `test_01_valid_development_environment`: Resolves `APP_ENV=development`.
2. `test_02_development_alias`: Resolves `APP_ENV=dev` as `development`.
3. `test_03_test_environment`: Resolves `APP_ENV=test`.
4. `test_04_missing_app_env`: Raises `SecurityAuthorizationError` when `APP_ENV` is absent.
5. `test_05_empty_app_env`: Raises `SecurityAuthorizationError` on empty string `""`.
6. `test_06_whitespace_app_env`: Raises `SecurityAuthorizationError` on whitespace `"   "`.
7. `test_07_unknown_app_env`: Raises `SecurityAuthorizationError` on `"invalid_env"`.
8. `test_08_root_env_discovery`: Discovers `.env` at project root.
9. `test_09_env_file_override`: Discovers custom `.env` via `ENV_FILE`.
10. `test_10_process_variable_precedence`: Existing environment variables take precedence over file values.
11. `test_11_uvicorn_startup_abort_on_invalid_env`: Uvicorn process aborts startup if `APP_ENV` is invalid.
12. `test_12_security_preflight_initialization`: Lazy evidence verifier does not throw on valid environment.
13. `test_13_existing_strict_production_behavior`: Enforces required production secrets in production mode.
14. `test_14_security_policy_preservation`: Re-exported `resolve_app_env` maintains full backwards compatibility.

### 4.2 Browser & E2E Acceptance Suite (`tests/test_browser_acceptance_phase_c_0_6.py`)
Both hermetic end-to-end tests passed:
1. `test_01_api_health_authoritative_app_env`:
   - Validates `GET /api/health` returns HTTP 200 with `status: "healthy"` and `app_env: "test"`.
2. `test_02_e2e_resume_tailoring_workflow_no_app_env_error`:
   - Registers candidate `audit.candidate@jobflow.ai`.
   - Ingests verified job description for Azets Audit Ltd.
   - Uploads synthetic PDF resume and confirms cryptographic scan signing.
   - Triggers `POST /api/applications/{id}/tailor-resume` without triggering any `APP_ENV` error.
   - Restarts the isolated server and verifies that the persistent scan signing key successfully validates existing scan records across server restarts.

### 4.3 Regression Test Matrix
The entire security regression test suite was executed:
- `tests/test_persistent_scan_signing.py`: 12 passed
- `tests/test_security_scan_persistence.py`: 18 passed
- `tests/test_security_preflight.py`: 16 passed
- `tests/test_security_scan_key_lifecycle.py`: 14 passed
- `tests/test_phase_9_1_2_9_real_service_authentication.py`: 19 passed
- `tests/test_phase_9_1_2_13_clock_precision_and_concurrency.py`: 21 passed
- `tests/test_phase_9_1_2_14_deterministic_concurrency_cleanup.py`: 18 passed
- `tests/test_production_configuration.py`: 60 passed
- `tests/test_runtime_environment_bootstrap.py`: 14 passed
- `tests/test_browser_acceptance_phase_c_0_6.py`: 2 passed
- **Total:** 194 passing tests, 0 failures, 100% pass rate.
- **Code Quality:** Pyflakes and Ruff clean (0 errors, 0 warnings).
- **Frontend Build:** `npm run build --prefix frontend` built cleanly without TypeScript errors.

---

## 5. Deployment & Configuration Guidance

### 5.1 Local Development
For local development, create a `.env` file at the repository root:
```ini
APP_ENV=development
LOG_LEVEL=INFO
```
*Note: `.env` is ignored by `.gitignore` and must never be committed.*

### 5.2 Production Deployment (Windows Server 2016 / IIS 10)
For production deployment, ensure the service environment or `.env` specifies:
```ini
APP_ENV=production
ACTION_TICKETS_HMAC_SECRET=<64-hex-character-secret>
DATABASE_PATH=C:\JobFlow\data\storage\job_assistant.db
USER_STORAGE_BASE=C:\JobFlow\data\users
BACKUP_DIR=C:\JobFlow\data\backups
EXPORTS_DIR=C:\JobFlow\data\exports
SECURITY_KEY_DIR=C:\JobFlow\data\.security
```
Startup will fail fast during Uvicorn initialization if any required secret or configuration parameter is missing or insecure.

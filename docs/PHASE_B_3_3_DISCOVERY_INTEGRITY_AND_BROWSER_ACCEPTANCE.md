# Phase B.3.3 — Discovery Data Contract, Startup Recovery & Real Browser Acceptance

## 1. Executive Summary

Phase B.3.3 solidifies JobFlow AI's discovery data pipeline, background execution integrity, cross-tenant matching correctness, and end-to-end browser user experience. It closes all remaining architectural inconsistencies identified following Phase B.3.2:

1. **Authoritative Discovery Response Contract:** Aligned backend SQLite persistence, FastAPI serialization, and React TypeScript interfaces to eliminate discrepancy where discovery runs reported 0 jobs found despite saving new listings.
2. **FastAPI Lifespan Startup Recovery:** Safely recovers lingering `PENDING` and `RUNNING` discovery worker records on server startup without aborting active in-memory runs during runtime DB manager instantiations.
3. **Candidate-Specific Evaluation for Duplicate Catalog Jobs:** Extended `DiscoverySummary` to track duplicate job identifiers (`duplicate_job_ids`), ensuring previously cataloged opportunities are evaluated against the current candidate's primary resume without duplicating catalog rows or reusing previous candidates' scores.
4. **Strict Local Resume Acceptance Test Suite:** Upgraded `scripts/local_resume_acceptance.py` to enforce strict failure (exit code 1) on missing input files, added hermetic `--synthetic` persona validation, and verified all 32 real-resume assertions (16/16 ACCA, 16/16 CSE) with cryptographic SHA-256 provenance logging and zero hardcoded candidate PII.
5. **Real Playwright Browser Acceptance Testing:** Implemented automated headless browser test coverage verifying ACCA Candidate onboarding & discovery, CSE Candidate technical skill extraction, multi-browser Drag-and-Drop file dropzone handling (Chromium and WebKit), and resilient UI hydration under simulated interrupted discovery runs.

---

## 2. Key Architectural Improvements & Implementations

### 2.1 Unified Discovery Schema & Data Contract Alignment
- **Additive Database Migration:** Added `total_discovered INTEGER DEFAULT 0` column to the `discovery_runs` table in `src/database/schema.sql` and `src/database/db_manager.py` with idempotent migration verification (`_migrate_discovery_runs`).
- **Authoritative Serialization:** Implemented `DatabaseManager.serialize_discovery_run()` providing consistent field names across API endpoints:
  - Canonical metrics: `run_id`, `id`, `user_id`, `status`, `target_roles`, `target_locations`, `total_discovered`, `jobs_found`, `new_jobs_saved`, `jobs_saved`, `new_jobs_count`, `duplicates_skipped`, `restricted_count`, `query_count`, `source_outcomes`, `error_message`, `started_at`, `completed_at`, `created_at`.
- **Frontend Contract Integration:** Updated `DiscoveryRun` in `frontend/src/types/index.ts` and `api.triggerDiscovery` in `frontend/src/lib/api.ts` to consume the authoritative schema, eliminating UI count mismatches.

### 2.2 FastAPI Lifespan Startup Recovery
- **Startup Hook:** Integrated `service.db.recover_interrupted_discovery_runs()` directly into the `lifespan(app)` context manager in `backend/api/main.py`.
- **Safety Guarantee:** Removed legacy invocation from `DatabaseManager._init_db()`. This prevents ephemeral database connection creation during user requests or background tasks from mistakenly marking active in-flight worker tasks as failed.
- **Audit Trails:** Interrupted jobs transition cleanly to status `FAILED` with explicit timestamping (`completed_at = CURRENT_TIMESTAMP`) and informative candidate notifications indicating safe re-triggerability.

### 2.3 Candidate-Specific Match Evaluation for Duplicate Jobs
- **DiscoverySummary Tracking:** Added `duplicate_job_ids: List[int]` and `relevant_job_ids: List[int]` to `DiscoverySummary` in `src/scraper/discovery/search_coordinator.py`.
- **Multi-Tenant Fairness:** When Candidate B discovers an employer posting previously discovered by Candidate A:
  - The job is identified as a duplicate and skipped from insertion into the `jobs` catalog table (preserving URL and company/title deduplication invariants).
  - The existing `job_id` is appended to `duplicate_job_ids`.
  - The backend background evaluator evaluates the job directly against Candidate B's own primary resume. Candidate B gets their personalized match score, disqualification checks, and explainable breakdown without score reuse or cross-tenant contamination.

### 2.4 Strict Local Resume Acceptance CLI
- **Strict Verification:** `scripts/local_resume_acceptance.py` requires valid input paths or fails with exit code 1.
- **Dual Execution Modes:**
  - `--synthetic`: Generates in-memory PDFs using ReportLab and validates 18 explicit structural assertions across ACCA and CSE student personas.
  - `--acca-path` and `--cse-path`: Validates real candidate resumes against 32 rigorous domain assertions with SHA-256 provenance logging and zero hardcoded candidate PII.

### 2.5 Real Playwright Browser Acceptance Test Suite
- Automated end-to-end browser tests in `tests/test_browser_acceptance_phase_b_3_3.py`:
  - **Scenario A (ACCA Candidate):** Registration $\to$ Onboarding $\to$ Upload two-column ACCA resume $\to$ Verify profile (BBA, ACCA, Taxation) $\to$ Trigger background discovery $\to$ Verify non-blocking UI.
  - **Scenario B (CSE Candidate):** Registration $\to$ Onboarding $\to$ Upload B.Tech CSE resume $\to$ Verify profile (B.Tech, 2028 graduation, Flutter/Python skills) $\to$ Navigate to Opportunities.
  - **Scenario C (File Dropzone & Validation):** Evaluated in both Chromium and WebKit engines: click-to-upload, clear selection, unsupported file rejection (`.exe`), size threshold enforcement, and hidden input file attachment handling (`state="attached"`).
  - **Scenario D (Discovery Recovery & Safe Hydration):** Verifies discovery engine banner rendering, background polling resilience, and page reload hydration without permanent loading states.

---

## 3. Verification & Acceptance Evidence

### 3.1 Local Resume Acceptance CLI Results
```
MODE: Real Reference Resume Document Acceptance
  [PROVENANCE] ACCA Reference File: ACCA_REFERENCE_DOCUMENT | SHA-256: 9f996517398427fa...b2227490
  [PROVENANCE] CSE Reference File:  CSE_REFERENCE_DOCUMENT  | SHA-256: 823c5c666be6fe05...19fbde7d

[TEST A] Evaluating Real ACCA Reference Document...
  [PASS] 1. Candidate identity extracted
  [PASS] 2. Email extracted
  [PASS] 3. Phone extracted
  [PASS] 4. LinkedIn profile URL extracted
  [PASS] 5. Education extracted (>= 2 degrees/qualifications)
  [PASS] 6. BBA degree recognized
  [PASS] 7. BBA CGPA verified
  [PASS] 8. Secondary/HSC qualification percentage verified
  [PASS] 9. ACCA professional qualification recognized
  [PASS] 10. Work Experience entries extracted (>= 2)
  [PASS] 11. ACCA PER records extracted (>= 4)
  [PASS] 12. Tax domain skills extracted
  [PASS] 13. Audit domain skills extracted
  [PASS] 14. Accounting software tools recognized
  [PASS] 15. Multiple professional languages extracted
  [PASS] 16. Accounting/finance career recommendations without intern hallucination
  Result: 16/16 ACCA assertions passed.

[TEST B] Evaluating Real CSE Reference Document...
  [PASS] 1. Candidate identity extracted
  [PASS] 2. Email and phone extracted
  [PASS] 3. Academic institution recognized (MIT WPU / University)
  [PASS] 4. B.Tech Computer Science and Engineering degree recognized
  [PASS] 5. AI and Data Science specialization verified
  [PASS] 6. Academic CGPA verified (>= 7.5)
  [PASS] 7. Expected graduation year verified (2028)
  [PASS] 8. Work experience extracted
  [PASS] 9. Technical projects extracted
  [PASS] 10. Flutter framework skill recognized
  [PASS] 11. Python programming skill recognized
  [PASS] 12. Dart programming skill recognized
  [PASS] 13. Mobile / Android development evidence
  [PASS] 14. Healthcare software project evidence (ABDM / Chatbot)
  [PASS] 15. Profession-specific career recommendations (Software/AI/Mobile)
  [PASS] 16. No irrelevant finance or ACCA recommendations
  Result: 16/16 CSE assertions passed.

FINAL REAL RESUME ACCEPTANCE: ALL 32 ASSERTIONS PASSED (16/16 ACCA, 16/16 CSE)
```

### 3.2 Automated Pytest Suite Results
```
tests/test_phase_b_3_3_recovery_and_matching.py::TestPhaseB33RecoveryAndMatching::test_discovery_metrics_contract PASSED
tests/test_phase_b_3_3_recovery_and_matching.py::TestPhaseB33RecoveryAndMatching::test_duplicate_job_candidate_specific_evaluation PASSED
tests/test_phase_b_3_3_recovery_and_matching.py::TestPhaseB33RecoveryAndMatching::test_fastapi_lifespan_startup_recovery PASSED
tests/test_browser_acceptance_phase_b_3_3.py::TestBrowserAcceptancePhaseB33::test_scenario_a_acca_candidate_workflow PASSED
tests/test_browser_acceptance_phase_b_3_3.py::TestBrowserAcceptancePhaseB33::test_scenario_b_cse_candidate_workflow PASSED
tests/test_browser_acceptance_phase_b_3_3.py::TestBrowserAcceptancePhaseB33::test_scenario_c_file_dropzone_and_validation PASSED
tests/test_browser_acceptance_phase_b_3_3.py::TestBrowserAcceptancePhaseB33::test_scenario_d_discovery_recovery_and_persistence PASSED
======================= 49 passed, 5 warnings in 24.47s ========================
```

### 3.3 Static Analysis & Build Verification
- **Frontend Build (`npm run build --prefix frontend`):** Exited with code 0 (`tsc && vite build`), zero TypeScript or bundling errors.
- **Python Linter (`pyflakes`):** Exited with code 0 on all modified backend, database, scripts, and tests files.
- **Ruff Code Style (`ruff check`):** Exited with code 0, all checks passed.

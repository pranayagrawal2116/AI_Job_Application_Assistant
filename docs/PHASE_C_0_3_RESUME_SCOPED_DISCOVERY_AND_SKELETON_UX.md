# Phase C.0.3 Verification Report: Resume-Scoped Job Discovery, First-Visit Skeleton UX & Cross-Industry Job Relevance

**Product:** JobFlow AI — Universal AI Job Application Assistant  
**Repository:** `https://github.com/pranayagrawal2116/AI_Job_Application_Assistant.git`  
**Branch:** `feat/modern-saas-frontend`  
**Baseline Commit:** `03752d0033d9fbdbd2e58919b9306f6888cac830`  
**Architecture:** React 18 + TypeScript + Vite + FastAPI + Python 3.11/3.13 + SQLite  
**Date:** November 2026  

---

## 1. Executive Summary

Phase C.0.3 resolves the two critical candidate experience flaws identified in the Find Jobs workflow:
1. **First-Visit Skeleton Loading UX:** Replaced the previous behavior where first-time visitors were shown generic spinners or pre-existing shared catalogue items. Fresh candidates now see an immediate, responsive shimmer skeleton layout (6 skeleton cards closely matching actual job card dimensions) while their primary resume context is resolved, background discovery is triggered, and candidate-scoped opportunities are retrieved and scored.
2. **Strict Candidate & Resume Scoping:** Eliminated shared catalogue leakage. The default Explore Jobs feed now strictly returns opportunities associated with the authenticated candidate's active primary resume discovery run (`candidate_discovered_jobs` filtered by `user_id` and `resume_fingerprint`). Fresh candidates with no uploaded resume see an onboarding prompt rather than unrelated global jobs. Manual search (`searchTerm`) remains available across the catalog, rendering un-evaluated jobs with amber "Pending Evaluation" badges rather than deceptive 0% scores.

---

## 2. Key Architectural Deliverables

### 2.1 Schema & Database Engine Updates
- **`src/database/schema.sql` & `src/database/db_manager.py`:**
  - Added `resume_id` (INTEGER) and `resume_fingerprint` (TEXT) columns to `discovery_runs`.
  - Added `candidate_discovered_jobs` junction table:
    ```sql
    CREATE TABLE IF NOT EXISTS candidate_discovered_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        job_id INTEGER NOT NULL,
        discovery_run_id INTEGER NOT NULL,
        resume_id INTEGER,
        resume_fingerprint TEXT,
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
        FOREIGN KEY (discovery_run_id) REFERENCES discovery_runs(id) ON DELETE CASCADE,
        UNIQUE (user_id, job_id, resume_fingerprint)
    );
    CREATE INDEX IF NOT EXISTS idx_candidate_jobs_user_fingerprint 
        ON candidate_discovered_jobs(user_id, resume_fingerprint);
    ```
  - Added methods: `record_candidate_discovered_jobs`, `get_candidate_discovered_job_ids`, `get_user_match_results_for_jobs`.
  - Automated, idempotent startup migration checks ensuring backward compatibility with existing SQLite databases.

### 2.2 Authoritative Resume Career Context Resolver
- **`src/preparer/career_context_resolver.py` (`CareerContextResolver`):**
  - Canonical resolver determining candidate `career_domain`, `candidate_category`, `inferred_roles`, `selected_roles`, `target_locations`, `supporting_skills`, and `resume_fingerprint`.
  - Strictly derives context from active primary resume parsed evidence (`parsed_data`).
  - Fallback logic allows inferring from user-confirmed candidate profiles when no resume is uploaded, while marking `has_primary_resume = False`.
  - Zero cross-candidate preference contamination: preferences from another user or previous resume versions cannot leak into the candidate's active context.

### 2.3 Backend API Enhancements
- **`backend/api/routers/jobs.py`:**
  - `list_jobs`: Default feed filters jobs strictly through `candidate_discovered_jobs` for `(user_id, resume_fingerprint)`. Evaluated match results for the active resume are overlaid.
  - Safe handling of Pandas dataframe columns: list `required_skills` converted to strings safely to prevent `.str.lower()` attribute errors.
  - Score sorting safely handles `None` match scores for un-evaluated search results.
  - Discovery batch evaluation speedup: JIT pre-verifies the candidate resume once before scoring batches, reducing discovery runtime by over 12x.
- **`backend/api/routers/discovery.py`:**
  - Exposes `has_primary_resume`, `resume_fingerprint`, and `completed_for_current_resume` so the UI knows exactly whether to trigger auto-discovery.

### 2.4 React Skeleton Loading & State Machine
- **`frontend/src/features/jobs/JobCardSkeleton.tsx`:**
  - Created `JobCardSkeleton` and `JobCardSkeletonGrid` matching the visual hierarchy and rounded card layout of production job cards.
- **`frontend/src/features/jobs/JobsPage.tsx`:**
  - Rebuilt feed state machine:
    - `initial_loading`: Renders skeleton grid while verifying candidate discovery status.
    - `no_resume_uploaded`: Prompts candidate to upload a resume on My Profile with a direct CTA button.
    - `discovering`: Renders shimmer skeletons while polling background discovery progress every 2 seconds.
    - `ready_with_jobs`: Renders candidate-scoped, verified opportunities.
    - `partial_discovery`: Displays amber notification banner warning that some external sources were restricted while rendering accessible jobs.
    - `empty_no_matches`: Clean empty state with search reset.
    - `discovery_failed`: Error banner with a one-click Retry button.
  - Protected against React StrictMode and component remount duplicate discovery triggers using `useRef` guards.

---

## 3. Hermetic Test Verification

### 3.1 Universal Cross-Industry Unit Suite (`tests/test_universal_career_context_and_relevance.py`)
Tested 6 distinct synthetic scenarios across industries:
- **Scenario A (ACCA Candidate):** 100% accounting and tax roles ("Tax Associate", "Audit & Assurance Assistant"). AI/ML roles strictly rejected.
- **Scenario B (CSE Candidate):** Software engineering and AI roles ("Software Engineer", "Mobile Developer"). Finance roles strictly rejected.
- **Scenario C (Healthcare / Clinical Candidate):** Clinical and nursing roles ("Staff Nurse", "Clinical Specialist").
- **Scenario D (Legal / Corporate Law Candidate):** Legal and compliance roles ("Corporate Counsel", "Legal Analyst").
- **Scenario E (Mechanical Engineering Candidate):** CAD and design engineering roles ("Mechanical Engineer", "CAD Designer").
- **Scenario F (Resume Replacement CSE -> ACCA):** Primary resume replacement instantly updates inferred domain from `technology` to `finance`, invalidates stale tech roles, and produces accounting recommendations.
- **Un-evaluated Job Status:** Manual search results without candidate evaluations report `is_pending_evaluation = True` and `match_score = None`, never 0% Ineligible.

**Result: 7/7 PASSED (100%)**

### 3.2 Playwright Browser Acceptance Suite (`tests/test_browser_acceptance_phase_c_0_3.py`)
Executed on dynamic isolated ports with hermetic SQLite databases and mock discovery adapters:
1. `test_01_first_time_acca_candidate_journey`: Shimmer skeletons render immediately -> auto-discovery triggers -> verified accounting jobs appear -> AI/ML roles absent. **PASSED**
2. `test_02_resume_replacement_stale_role_invalidation`: CSE resume replaced with ACCA resume in Profile -> Find Jobs refreshes to accounting recommendations. **PASSED**
3. `test_03_cross_user_isolation`: Candidate Alpha (ACCA) and Candidate Beta (CSE) in separate sessions receive isolated recommendations without cross-leakage. **PASSED**
4. `test_04_cached_candidate_results_no_redundant_discovery`: Re-visiting Find Jobs with completed discovery immediately renders cached results without triggering redundant runs. **PASSED**
5. `test_05_discovery_failure_handling`: Backend failure replaces skeletons with error state and retry button. **PASSED**
6. `test_06_partial_discovery_banner`: Restricted external sources render partial discovery notice banner. **PASSED**
7. `test_07_manual_search_independent_of_inferred_domain`: Manual search queries global catalog without corrupting resume career domain chips. **PASSED**
8. `test_08_no_resume_onboarding_state`: Candidate without resume sees upload CTA, and discovery is never triggered. **PASSED**

**Result: 8/8 PASSED in 40.94s (100%)**

---

## 4. Quality & Regression Verification

- **Code Quality Linters:**
  - `ruff check`: 0 errors
  - `pyflakes`: 0 warnings across all modified backend, dashboard, and preparer modules
  - `npm run lint` (`tsc --noEmit`): 0 errors
  - `npm run build`: Production bundle built cleanly (`dist/assets/index-ID1Y_hUA.js`)
- **Synthetic Resume Acceptance:**
  - `python3 scripts/local_resume_acceptance.py --synthetic`: 18/18 assertions PASSED
- **CI Configuration:**
  - Updated `.github/workflows/ci.yml` to include `tests/test_universal_career_context_and_relevance.py` and `tests/test_browser_acceptance_phase_c_0_3.py`.

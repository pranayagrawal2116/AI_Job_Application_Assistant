# Phase B.3.2 — Real Resume Acceptance, Cross-Industry End-to-End Validation & Discovery Integration

## 1. Executive Summary

Phase B.3.2 hardens JobFlow AI's resume-first intelligence pipeline, connecting real resume parsing, multi-tenant profile synchronization, dynamic career inference, atomic discovery orchestration, and modern frontend UX into a unified, zero-hallucination workflow.

The phase resolves all identified integration gaps:
1. **Real Resume Acceptance:** 100% verified parsing and role inference against reference candidates (ACCA / UK Taxation and B.Tech CSE / AI & Mobile).
2. **Multi-Tenant Profile Isolation:** Eliminated disk-based profile fallback leakage across accounts.
3. **Dynamic Career Role Inference:** Fixed fresher/intern inference heuristic so credentialed and senior personas are never labeled as freshers or interns.
4. **Atomic Discovery Locking & Restart Recovery:** Introduced SQLite partial unique index (`uq_discovery_runs_active_user`) and server restart recovery routines.
5. **Unified Discovery APIs:** Replaced 2.5-second simulated timeouts with real async polling and terminal state transitions (`COMPLETED`, `PARTIAL`, `FAILED`).
6. **Job Deduplication with Location Differentiation:** Distinct locations for identical job titles at the same employer no longer collide.
7. **Honest Match Explanations:** Unevaluated jobs display `is_evaluated: false` and `Pending Evaluation` without fabricating catalog scores.
8. **File Dropzone & Upload Reliability:** Fixed double-click event cancellation and drag-and-drop bubbling in `FileDropzone.tsx`.

---

## 2. Key Architecture & Implementation Details

### 2.1 Universal Resume Parser Hardening (`src/preparer/resume_parser.py`)
- **Column Concurrency & Layout Ordering:** Concurrency tracking computes `col_concurrent_start_y` to ensure multi-column text does not interleave header rows with column body paragraphs.
- **Section Heading Mid-Sentence Guard:** Token-based boundary checks ensure trailing prepositions ("and", "with", "for", "to") or punctuation dashes trigger mid-sentence wrapping guards without false-positive matching on country or city names ending in 'a' (e.g. "India").
- **Section Heading Regex Hardening:** Enhanced `ACCA_PER` and `PROFESSIONAL_QUALIFICATIONS` patterns to accurately match multi-word headings.
- **Contact Info & Canvas Hyperlink Extraction:** Name extraction from header blocks; stripping icon font artifacts (`% `, `u `, `G `, `I `); extracting URI annotations (`page.get_links()`) to capture hyperlink destinations on stylized resumes.
- **Education Disentanglement:** Properly separates professional qualifications (ACCA Member) from academic degrees (BBA, HSC), preserving CGPAs and percentages.

### 2.2 Profile Synchronization & Multi-Tenant Isolation (`src/preparer/profile_updater.py`)
- `build_profile_dict(resume, existing_profile=None)` accepts either `ParsedResume` or dictionary payloads.
- Strictly derives inputs and preferences from the tenant's existing profile in SQLite; never reads `data/profile/candidate_profile.json` during database operations.
- Preserves the authenticated user's registered account email, preventing unverified resume emails from overriding account identity.

### 2.3 Career Role Inferencer Hardening (`src/preparer/career_role_inferencer.py`)
- Removed hardcoded current year (`2026`) in favor of dynamic UTC calendar calculations.
- Overhauled `_is_student_or_fresher`: candidate holding statutory or professional credentials (ACCA, CPA, CFA, Bar, MD, PhD), senior titles, or experience $\ge 12$ months are never classified as freshers.
- Zero intern title generation for senior or professional titles.
- Location inference respects international residency and does not default international candidates to "India".

### 2.4 Atomic Discovery Locking & Restart Recovery (`src/database/db_manager.py`)
- Partial Unique Index:
  ```sql
  CREATE UNIQUE INDEX IF NOT EXISTS uq_discovery_runs_active_user 
  ON discovery_runs(user_id) 
  WHERE status IN ('PENDING', 'RUNNING')
  ```
- Prevents concurrent discovery runs for the same candidate while allowing multiple candidates to run discovery simultaneously.
- `recover_interrupted_discovery_runs()` marks interrupted runs as `FAILED` with an informative restart recovery message on startup.
- `check_is_duplicate(job_url, company_name, job_title, location=None)` accounts for geographic location.

### 2.5 Unified Backend Discovery Routers (`backend/api/routers/jobs.py`, `discovery.py`)
- Removed generic fallback `["Associate", "Specialist"]` in favor of resume-inferred roles.
- `trigger_jobs_discovery` evaluates only newly discovered opportunities (`summary.saved_jobs`) against the candidate's primary resume.
- `get_job_match_explanation` returns honest `is_evaluated: false`, `match_score: None`, `is_eligible: None`, `eligibility_status: "UNKNOWN"` for unevaluated opportunities.

### 2.6 Frontend SaaS Enhancements (`frontend/src/`)
- `FileDropzone.tsx`: Hidden file input with programmatic trigger on container click, `pointer-events-none` on decorative children to prevent dragenter/dragleave flickering, and dedicated `pointer-events-auto` on clear action button.
- `JobsPage.tsx`: Real polling with `getDiscoveryRun(runId)` checking terminal statuses (`COMPLETED`, `PARTIAL`, `FAILED`), auto-recovery on page load for ongoing runs, and retry triggers.
- `OnboardingWizard.tsx`: Removed redundant duplicate profile sync call.
- `ProfilePage.tsx`: Displays honest provenance badges ("Candidate Confirmed" vs "Extracted from Resume — Needs Review").

---

## 3. Verification & Acceptance Results

1. **Local Real Resume Acceptance Suite (`scripts/local_resume_acceptance.py`):**
   - Test A (ACCA / Finance Resume): 16/16 assertions PASSED.
   - Test B (CSE / AI Resume): 16/16 assertions PASSED.
2. **Automated Unit & Regression Suite (`tests/test_phase_b_3_2_acceptance.py`):**
   - 19/19 tests PASSED (100% pass rate).
3. **Frontend Production Build:**
   - `npm run build --prefix frontend`: Exit code 0, 0 TypeScript errors, bundle generated cleanly.

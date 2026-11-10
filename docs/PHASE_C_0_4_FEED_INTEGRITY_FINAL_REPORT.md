# Phase C.0.4 — Critical Job Feed Integrity Hotfix: Final Engineering Report

## Executive Summary

Phase C.0.4 resolved the critical job feed integrity and scoring hallucination issues where an ACCA / BBA Finance candidate's "Find Opportunities" feed displayed irrelevant AI/ML engineering internships with inflated 75% match scores and "Eligible" statuses.

Through systematic root cause analysis, four distinct defects were identified and corrected across the matching engine, database schema, career context resolver, and API routers:
1. **Matcher Fallback Scoring Defect:** Fallback branches in `UniversalSkillMatcher` and `ResponsibilityAlignmentEvaluator` awarded maximum ratios (1.0) when job postings lacked structured skills or responsibilities, while `EducationCompatibilityEvaluator` failed to disqualify candidates for discipline mismatches.
2. **Missing Resume Fingerprint in Match Results:** Historical match evaluations lacked resume fingerprint binding, allowing evaluations from previous resumes or un-fingerprinted runs to contaminate subsequent candidate views.
3. **Overly Permissive Feed Scoping:** The `GET /api/jobs` feed previously pulled historical evaluations across all sessions without verifying relevance against the active candidate's inferred career domain.
4. **Token Collision in Relevance Filter:** Broad substring matching on terms like "office" (from "Microsoft Office") caused unrelated jobs such as "Founders Office" to pass relevance filtering.

All issues have been resolved with zero hallucination guarantees, complete cross-industry symmetry, 100% test pass rate across all suites, and verified Playwright browser acceptance tests.

---

## 1. Problem Diagnosis & Root Causes

### Problem A: Inflated Match Scores on Unrelated Jobs
- **Symptom:** AI/ML jobs scored ~75% and showed "Eligible" for an ACCA candidate with a Finance BBA degree.
- **Root Cause:**
  - `UniversalSkillMatcher.evaluate` previously returned default positive scores when `not all_job_skills`, without validating whether any of the candidate's actual skills aligned with the job title or domain keywords.
  - `ResponsibilityAlignmentEvaluator.evaluate` returned a default 1.0 ratio when `not reqs.responsibilities`.
  - `EducationCompatibilityEvaluator.evaluate` did not penalize candidates whose educational discipline (e.g. Finance) was completely unrelated to technical engineering roles.
- **Resolution:**
  - Hardened `UniversalSkillMatcher.evaluate` to extract domain keywords from job titles and descriptions when explicit skill tags are missing. If 0 candidate skills or qualifications match, it awards `score_ratio = 0.0`.
  - Hardened `ResponsibilityAlignmentEvaluator.evaluate` to cross-reference candidate experience and project deliverables against role title keywords. If zero overlap exists, it returns `0.0`.
  - Updated `EducationCompatibilityEvaluator.evaluate` to identify discipline mismatches, assigning `major_ratio = 0.20`, and flagging `UniversalEligibilityEvaluator` to classify eligibility strictly as `INELIGIBLE`.

### Problem B: Stale Match Results and Cross-Run Contamination
- **Symptom:** Evaluations generated during earlier discovery runs or under previous profiles lingered and appeared on the Explore Jobs page.
- **Root Cause:** The `match_results` table only recorded `user_id`, `resume_id`, and `resume_file_hash`, lacking `resume_fingerprint`. When querying historical evaluations, queries fell back to checking `resume_id` or blanket queries, pulling evaluations from runs performed under different resume versions.
- **Resolution:**
  - Added `resume_fingerprint TEXT` column to `match_results` and created `idx_match_results_fingerprint ON match_results(user_id, resume_fingerprint)`.
  - Automated migration in `_migrate_discovery_runs_table` to add the column and index idempotently.
  - Updated `save_match_result`, `get_user_match_results_for_jobs`, `get_user_match_results`, and `get_candidate_matching_metrics` to strictly require and enforce matching `resume_fingerprint`.

### Problem C: Feed Leakage on Find Opportunities
- **Symptom:** Even after clean runs, the feed displayed AI/ML listings, fiction writer postings, and unrelated counselor jobs.
- **Root Cause:**
  - `GET /api/jobs` retrieved all jobs without filtering out cross-domain items in the default feed.
  - Legacy code in `list_jobs` previously injected all evaluated job IDs from `match_results` without scoping to active fingerprint or career domain.
- **Resolution:**
  - Default feed in `GET /api/jobs` is strictly scoped to `candidate_discovered_jobs` matching `career_ctx.resume_fingerprint` plus match results evaluated specifically under that active fingerprint.
  - Each job in the feed is passed through `is_job_relevant_for_candidate`, discarding any jobs belonging to an unrelated discipline.

### Problem D: False Positive Relevance Matching
- **Symptom:** An ACCA candidate's feed contained "Founders Office Internship" and "Counselor" positions.
- **Root Cause:** The keyword "office" in candidate skills (from "Microsoft Office") matched "Founders Office", and generic words ("counselor", "associate") lacked strict stopword exclusions.
- **Resolution:**
  - Re-architected `CareerContextResolver.is_job_relevant`:
    - Canonical multi-domain classification: `accounting_finance`, `software_tech`, `creative_writing`, `education_training`, `healthcare`, `legal`, `mechanical_engineering`.
    - Cross-domain disqualification: Symmetrical disqualification when a job title belongs to an unrelated discipline (e.g. Finance candidate vs Software/Writing/Healthcare/Education).
    - Added extensive generic stopwords ("office", "female", "male", "suite", "skills", "tools", "system", "support", etc.) to prevent spurious token overlap.
    - Positive alignment requirement: The job title must align with candidate domain, target roles, or specialized skills.

---

## 2. Modified Files & Key Changes

| Component | File | Changes |
|-----------|------|---------|
| Database Schema | `src/database/schema.sql` | Added `resume_fingerprint TEXT` and `idx_match_results_fingerprint` index to `match_results`. |
| Database Engine | `src/database/db_manager.py` | Added migration logic, updated `save_match_result`, `_row_to_match_result`, `get_user_match_results_for_jobs`, `get_user_match_results`, and ensured `record_candidate_discovered_jobs` counts only newly inserted associations for idempotency. |
| Domain Models | `src/database/models.py` | Added `resume_fingerprint` to `MatchResult` and `UniversalMatchResult`. |
| Matching Engine | `src/matcher/universal_matcher.py` | Fixed fallback scoring for missing skills and responsibilities (zero ratio on zero match); added discipline mismatch check in `EducationCompatibilityEvaluator` and `UniversalEligibilityEvaluator`; safeguarded `facts.skills` iteration for dict/list formats. |
| Relevance Filter | `src/preparer/career_context_resolver.py` | Universal domain classification and symmetrical cross-domain disqualification; positive token matching with expanded stopword filtering. |
| API Router | `backend/api/routers/jobs.py` | Candidate-scoped feed filtering in `list_jobs`; scoped discovery recording and evaluation in `trigger_jobs_discovery` with explicit target role preservation. |
| Dashboard Service | `dashboard/services/dashboard_service.py` | Updated `get_candidate_dashboard_metrics` to scope candidate discovery metrics to active `resume_fingerprint`. |
| Test Suites | `tests/test_phase_c_0_4_feed_integrity.py` | 8 unit and integration tests verifying relevance gate, zero-hallucination scoring defense, fingerprint scoping, and live database integrity. |
| Browser Tests | `tests/test_browser_acceptance_phase_c_0_4.py` | 2 end-to-end Playwright browser acceptance tests verifying ACCA and CS candidate feeds in the React UI. |

---

## 3. Verification & Validation Evidence

### 3.1 Unit & Integration Test Results
```bash
APP_ENV=test pytest -v tests/test_phase_c_0_4_feed_integrity.py
# 8 passed in 1.16s (100% pass rate)

APP_ENV=test pytest -v tests/test_production_configuration.py tests/test_phase_b_3_3_recovery_and_matching.py tests/test_discovery.py
# 46 passed in 3.19s (100% pass rate)

APP_ENV=test pytest -v tests/test_personalized_discovery.py
# 5 passed in 16.68s (100% pass rate)
```

### 3.2 Playwright Browser Acceptance Results
```bash
APP_ENV=test pytest -v tests/test_browser_acceptance_phase_c_0_4.py
# tests/test_browser_acceptance_phase_c_0_4.py::TestBrowserAcceptancePhaseC04::test_01_acca_candidate_feed_integrity PASSED [ 50%]
# tests/test_browser_acceptance_phase_c_0_4.py::TestBrowserAcceptancePhaseC04::test_02_cs_candidate_feed_integrity PASSED [100%]
# 2 passed in 11.29s (100% pass rate)
```
- **Scenario 1 (ACCA / BBA Candidate):**
  - Logs into React dashboard as User #105.
  - Navigates to Explore Jobs (`/jobs`).
  - Verifies that zero AI, ML, or tech internships are present in the feed.
  - Verifies that authentic Tax, Audit, and Accounting opportunities are presented.
- **Scenario 2 (CS / AI Candidate):**
  - Creates a Computer Science candidate session.
  - Navigates to Explore Jobs (`/jobs`).
  - Verifies that AI/ML engineering internships are displayed with strong match scores and eligible statuses.

### 3.3 Code Quality & Build Verification
- **Ruff Check:** `ruff check` on all modified files passed with 0 errors.
- **Pyflakes:** Passed with 0 errors or unused imports.
- **Frontend Production Build:** `npm run build --prefix frontend` built successfully in 1.57s.

---

## 4. Conclusion & Next Steps

Phase C.0.4 has completely eliminated cross-industry feed leakage and hallucinated match scores. The Explore Jobs feed is now strictly candidate-specific, grounded in verifiable resume facts, and protected by universal multi-domain relevance filters.

The changes are fully verified, clean, and ready for commit on `feat/modern-saas-frontend`.

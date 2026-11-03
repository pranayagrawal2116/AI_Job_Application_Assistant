# AGENTS.md — Development Guidelines & Safety Protocol

> **Target Audience:** All AI agents, automated development assistants, and contributors working on the **AI Job Application Assistant** codebase.

---

## 1. Core Operating Principles

1. **Candidate Truthfulness (Zero Hallucination Policy):**
   - **NEVER** fabricate, infer, or embellish candidate experience, skills, certifications, degrees, grades, or project outcomes.
   - The candidate profile is rooted in verifiable data. If information is missing, leave the field empty or clearly flagged as pending user input.
   - **Crucial Rule:** Always prompt the candidate to provide their latest resume file (PDF or DOCX in `data/resumes/`) before extracting or utilizing personal details in application preparation.

2. **Strict Human-in-the-Loop Application Approval:**
   - **NEVER submit any job application automatically.**
   - All browser automation workflows MUST pause immediately prior to the final submission action (e.g., clicking "Submit Application", "Apply Now", or "Send").
   - The user must explicitly inspect the populated fields, review any generated cover letter, and manually authorize or execute the final submission.

3. **Browser Automation & Anti-Automation Ethics:**
   - Always leverage the connected **Playwright MCP Server** via MCP tool calls (`browser_navigate`, `browser_snapshot`, `browser_click`, `browser_fill_form`, etc.).
   - Do **NOT** spin up duplicate standalone browser automation systems or raw unmanaged driver processes unless specifically instructed.
   - **Respect Terms of Service, Robots Restrictions, and Anti-Automation Controls:**
     - Do **NOT** attempt to bypass CAPTCHAs, bot detections (Cloudflare, PerimeterX, Arkose), or two-factor authentication.
     - Implement human-like rate limiting (minimum 2–5 seconds between requests).
     - If a site blocks, rate-limits, or restricts automated access, cleanly abort the automated extraction, notify the user with an informative log message, and present the official job URL for manual inspection.

4. **Security, Secrets, and Privacy:**
   - **Zero Secrets in Code:** Never commit or hard-code API keys, credentials, session tokens, passwords, or cookies.
   - All credentials and environment flags belong in `.env` (referenced via `.env.example`).
   - Candidate resumes (`data/resumes/`), database records (`data/storage/`), and exports (`data/exports/`) are strictly kept local and git-ignored.
   - Never transmit candidate data or resume files to unapproved third-party servers.

---

## 2. Technical Stack & Conventions

- **Language:** Python 3.11+ (Python 3.13 compatible).
- **Dashboard:** Streamlit.
- **Data Persistence:** SQLite (`data/storage/job_assistant.db`) accessed via standard `sqlite3` or lightweight query managers.
- **Data Analysis:** Pandas for tabular manipulation, deduplication, and CSV export.
- **Configuration:** YAML (`config/config.yaml`, `config/scoring_rules.yaml`) and JSON (`config/search_criteria.json`, `data/profile/candidate_profile.json`).
- **Browser Automation:** Playwright MCP tools.

---

## 3. Matching & Scoring Rules (Phase 3 Spec)

- **Total Score:** 100 points
  - **Domain Relevance:** 30 pts (AI, ML, Deep Learning, GenAI, Data Science, NLP, CV, Python)
  - **Technical Skills:** 25 pts (Python, ML, Data Preprocessing, Data Visualization, Flutter/Dart)
  - **Educational Eligibility:** 20 pts (CS with AI & DS, 2028 graduation; candidate CGPA 7.6 evaluated strictly against explicit employer cutoff — no deduction if no cutoff specified)
  - **Experience Compatibility:** 10 pts (Student/Fresher roles: 10 pts; >1-2 years: penalty)
  - **Location Preference:** 10 pts (India / Remote / Work from Home: 10 pts)
  - **Duration Compatibility:** 5 pts (Standard summer/winter or flexible part-time)

- **Classifications:**
  - `85 – 100`: Excellent match
  - `70 – 84`: Good match
  - `50 – 69`: Moderate match
  - `< 50`: Low match

- **Mandatory Disqualification Override:**
  - If a mandatory requirement fails (e.g. requires 3+ years experience, requires graduation before 2026, employer explicitly mandates higher minimum CGPA, or mandates in-person work in an unsupported country), the engine **MUST** explicitly mark `is_eligible: false`, irrespective of high skill/keyword scores.
  - The evaluation output must always display the breakdown and specific reason behind every deduction or disqualification.
  - Mandatory eligibility checks operate independently of the 0-100 numerical matching score.

---

## 4. Application State Machine (Phase 2 & 6 Spec)

Every tracked job posting transitions through discrete statuses:
```
Discovered -> Under Review -> Shortlisted -> Application Prepared -> Awaiting Approval -> Applied -> (Interview | Rejected | Withdrawn)
```
- **Submission Safeguard:** An application status CANNOT be transitioned to `Applied` without explicit user confirmation.
- **Deduplication:** The database MUST enforce uniqueness on normalized job URLs and composite `(company_name, job_title)` to prevent duplicate listings or re-applying.

---

## 5. Playwright MCP Tooling Protocol

When interacting with the browser via Playwright MCP:
1. Call `browser_navigate` with the target URL.
2. Read the page accessibility tree or state using `browser_snapshot`.
3. Locate elements by ref or semantic selectors.
4. Interact using `browser_fill_form`, `browser_click`, or `browser_type`.
5. Capture visual evidence when helpful using `browser_take_screenshot`.
6. Always clean up tabs or close sessions with `browser_close` when operations conclude.

---

## 6. Phased Implementation Roadmap

- [x] **Phase 1: Project Initialization & Safety Architecture**
  - Workspace scaffolding, configs, candidate profile templates, Playwright MCP verification, README & AGENTS.md.
- [x] **Phase 2: SQLite Storage & Job Management Engine** (Complete)
  - Database schema, models, CRUD operations, deduplication logic, application status tracking, transactions, backup/restore, CSV export.
- [x] **Phase 3: Job Matching & Eligibility Evaluation Engine** (Complete)
  - Multi-factor scoring algorithm (100 pts), disqualification logic, transparent explanation generator, explicit human audit approval gate.
- [x] **Phase 4: Playwright MCP Automation Module** (Complete)
  - Robust navigation routines, accessibility tree interpretation, form inspection, anti-automation detection handler, agent-backend integration contract.
- [x] **Phase 5: Modular Job Discovery Scrapers** (Complete)
  - Modular adapters for LinkedIn, Internshala, Indeed, Naukri, and Company Career ATS (Greenhouse/Lever) feeds.
  - Anti-automation defense detection (Cloudflare Turnstile, login wall, Akamai) with graceful restriction logging and URL preservation.
  - Automated deduplication, real-time Phase 3 matching and eligibility evaluation, SQLite persistence, and CSV export.
- [x] **Phase 6: Streamlit Interactive Dashboard** (Complete)
  - Professional 8-page responsive UI: Overview, Explore Jobs, Shortlisted Jobs, Application Tracker, Job Matching Analytics, Discovery Management, Candidate Profile, Settings.
  - Multi-dimensional filtering, deep score inspection with 6-factor score breakdowns, shortlist management, status transitions with strict human-in-the-loop audit gate for 'Applied' status.
  - Interactive Plotly visualizations (score distribution, eligibility donut, location & platform charts, employer skill demand vs candidate gap analysis, application funnel).
  - SQLite database management with atomic live online backup, snapshot restore, and full CSV export.
  - Candidate profile editor with SQLite version history snapshots.
  - Verified with 7 automated unit tests (64 total suite tests passing) and Playwright MCP browser snapshot & screenshot verification.
- [x] **Phase 7: Application Preparation & Approval Workflow** (Complete)
  - Zero-hallucination resume parser supporting PDF and DOCX (`ResumeParser`).
  - Candidate profile synchronizer with immutable SQLite snapshots (`ProfileUpdater`, verified: 3 months at Sarita Infotech Pvt. Ltd. as Project Manager | Mobile App Development; Python, JavaScript, C/C++; Medical Chatbot; Sarita ABDM; CGPA 7.6, Class of 2028).
  - Resume-job alignment and transparent gap analyzer (`ResumeJobMatcher`).
  - Personalized, professional tailored cover letter generator saving individual markdown letters to disk (`CoverLetterGenerator`).
  - Screening question response drafter with strict `NEEDS CANDIDATE INPUT` tagging for unverified queries (`QuestionAnswerer`).
  - Playwright form pre-filling payload planner and anti-automation safeguard (`FormPrefiller`).
  - Strict human-in-the-loop review packet and authorization gate preventing automated submissions (`HumanApprovalGate`).
  - Interactive Streamlit Application Preparer interface (Resume Manager, Alignment Inspector, Cover Letter Editor, Screening QA, Human Approval Gate, and Prepared Application History).
  - Verified with 9 new automated unit tests (73 total suite tests passing) and Playwright MCP browser snapshot & screenshot verification.
- [x] **Architecture v2.1.1 Phase 4: Multi-User Job Description Ingestion & Parsing** (Complete)
  - Universal cross-industry job parser (`JobParser`) supporting Tech, Healthcare, Law, Finance, Engineering, Management, Creative, and Education with zero-hallucination guarantees and passive prompt injection resistance.
  - Three independent ingestion paths: pasted text (preserving bullets & Unicode), PDF/DOCX document upload (10 MB cap, magic bytes & zip-bomb protection, isolated user storage in `data/users/<user_id>/job_descriptions/`), and public job listing URL fetching (`URLJobFetcher`).
  - Advanced SSRF defense engine (`URLSafetyValidator`) blocking private IPv4/IPv6, carrier-grade NAT, cloud metadata endpoints, loopback, and DNS rebinding; redirect validation loop; response size capping (5 MB); anti-bot and restriction detection (Cloudflare, PerimeterX, LinkedIn authwalls, 403, 429) prompting clean manual text paste fallbacks.
  - SQLite immutable snapshot management with `supersedes_job_description_id` linking, per-user deduplication via content hash, cross-user duplicate independence, and composite ownership isolation (`UNIQUE(id, user_id)`).
  - Streamlit Job Analyzer & Ingestion interface (`Job Analyzer & Ingestion` view) with Paste Text, Document Upload, Safe URL Ingestion, Structured Requirements Inspector, Candidate Review & In-Place Correction Form, Version Lineage, and Deletion.
  - Verified with 29 new automated tests across 5 new test suites (192 total project suite tests passing, 100%), 0 pyflakes errors, and mypy/ruff clean.
- [x] **Architecture v2.1.1 Phase 5 & 5.1: Universal Resume-to-Job Matching Engine & Correctness Hardening** (Complete)
  - Explainable, deterministic, cross-industry resume-to-job matching engine (`UniversalMatcher`) computing multi-dimensional scores across 100 points with configurable scoring profiles (`SCORING_PROFILES`) and mathematical invariant `sum(weights) == 100.0`.
  - Strict three-state eligibility engine (`UniversalEligibilityEvaluator`): `ELIGIBLE`, `INELIGIBLE`, and `UNKNOWN` without defaulting unverified data or missing cutoffs to eligible.
  - Candidate fact provenance distinction (`USER_CONFIRMED` vs `EXTRACTED_UNVERIFIED`): unverified resume facts cannot satisfy mandatory statutory licenses, degree requirements, or minimum CGPA cutoffs, nor can they definitively disqualify without verification (`UNKNOWN`).
  - Strict experience requirement evaluation: non-overlapping interval date merging (`_merge_intervals`), ISO format `YYYY-MM-DD` and `Month Year` date parsing, missing date detection, and strict cutoff enforcement for all required years without arbitrary lower thresholds.
  - Statutory licensing precision: exact token and boundary-safe matching (`match_license_names`), preventing arbitrary substring collisions (e.g. "rn" in "intern"), with unconfirmed licenses flagged as `UNVERIFIED` and triggering `UNKNOWN` eligibility.
  - Project relevance scoring: related skills taxonomy expansion (`RELATED_SKILLS_MAP`), duty-word alignment, and fair weighting allowing candidates with relevant project deliverables to achieve full project points while strictly ensuring unrelated projects score lower (`relevant_score > unrelated_score`).
  - Version provenance and audit retention: `candidate_profile_hash` stored in `match_results`, linking each evaluation to the exact candidate profile version snapshot at evaluation time.
  - Immutable audit trail protection: deleting a resume (`delete_user_resume`) or job description (`delete_job_description`) referenced in historical matches safely archives the record (`is_active = 0`), preserving historical `match_results` evaluations intact with `ON DELETE RESTRICT` foreign keys.
  - Dashboard integration: authenticated user session resolution in `resume_match_analysis` view and automatic candidate profile loading via `db.get_user_candidate_profile(user_id)`.
  - Verified with 22 new comprehensive hardening regression tests in `test_phase5_1_hardening.py` (310 total project suite tests passing, 100%), 0 pyflakes errors, and clean ruff check.
- [x] **Architecture v2.1.1 Phase 5.1.1: Final Matching Pipeline & Database Migration Corrections** (Complete)
  - Actual candidate profile skill ingestion: comprehensive support for `technical_skills` (categorized dictionary or flat list), `professional_skills`, `soft_skills`, `tools_and_software`, `languages`, and `competencies`. Skill deduplication preserves highest confirmation status and provenance without upgrading unverified evidence. User-confirmed profile skills are matched even when omitted from the selected resume.
  - Explicit user-confirmation semantics: removed `from_profile` auto-verification assumption; empty provenance or unconfirmed items imported into `candidate_profiles` remain `EXTRACTED_UNVERIFIED`. Universal Candidate Profile editor updated to record section and item provenance (`USER_CONFIRMED`) for education, CGPA, work experience, technical skills, professional skills, certifications, and statutory licenses. Resume synchronization via `ProfileUpdater.diff_profile_with_resume` and `apply_approved_sync` prevents overwriting confirmed candidate information.
  - Experience date preservation: `split_date_range()` parses and separates date ranges (`Jan 2020 - Dec 2023`, `Jan 2020 - Present`, `2020-01 to 2024-01`, `2020-01-01 to 2024-01-01`, en/em dashes) so full range strings are never passed to both start and end parsers. `ProfileUpdater.build_profile_dict()` preserves `start_date`, `end_date`, `is_current`, `duration`, and `duration_months`. Non-overlapping interval merging (`_merge_intervals`) prevents double-counting concurrent roles. Duration uncertainty cleanly transitions to `experience_dates_missing = True`.
  - Mixed verified/unverified experience eligibility: conservative three-state logic in `UniversalEligibilityEvaluator`. Confirmed experience meeting or exceeding cutoff returns `ELIGIBLE`. Unverified records or duration months that could bridge the gap return `UNKNOWN` (e.g. 12m confirmed + 6m unverified vs 24m cutoff returns `UNKNOWN`, never `INELIGIBLE`). Incomplete history indicator (`employment_history_complete = False`) returns `UNKNOWN`. Confirmed complete employment history demonstrably below minimum returns `INELIGIBLE`.
  - Transactional SQLite database migration: automated 12-step table rebuild of `match_results` in `_migrate_match_results_foreign_keys()` updating foreign keys (`jobs`: `ON DELETE SET NULL`, `resumes` and `job_descriptions`: `ON DELETE RESTRICT`, `candidate_profile_hash` added). Catalog job deletions set `job_id = NULL` without cascading deletion to match evaluations. Direct resume/JD deletions blocked by `RESTRICT`. Idempotent repeated runs, verified zero foreign key violations (`PRAGMA foreign_key_check = 0`). Safe account deletion via `delete_user_account_data`.
  - Verified with 26 new automated unit/integration tests across 2 new test suites (`test_migration_phase5_1_1.py` with 9 tests, `test_profile_and_matching_pipeline.py` with 17 tests), totaling 336 passing tests across the entire repository (100% pass rate). 0 pyflakes errors, 0 ruff errors, and mypy clean.

- [x] **Architecture v2.1.1 Phase 6: Universal Application Preparation & Document Generation** (Complete)
  - Multi-user profile isolation: eliminated legacy single-candidate profile fallbacks (`config.candidate_profile`, `get_latest_candidate_profile()`). Newly created accounts start with empty profiles. Scoped saving via `save_user_candidate_profile` without swallowed exceptions.
  - Application preparation workspace: composite `(user_id, job_description_id)` workspace preventing duplicate applications on reopen (`get_or_create_application_workspace`).
  - Universal tailored resume generator (`UniversalTailoredResumeGenerator`): cross-industry support (Healthcare, Law, Finance, Engineering, Tech) with strict zero-hallucination guarantees, bullet relevance scoring, claim-level provenance metadata (`claim_id`, `source_type`, `evidence_status`), in-place editing, and unified diff inspection.
  - Universal cover letter generator (`CoverLetterGenerator`): career-level awareness (Student, Mid-Career, Executive, Career Changer) and 4 professional tones (`Professional & Direct`, `Enthusiastic & Modern`, `Executive & Formal`, `Academic & Rigorous`), with strict zero-fabrication and paragraph provenance.
  - Screening question answer assistant (`QuestionAnswerer`): 19-category classification, 5 review states (`GENERATED_DRAFT`, `NEEDS_CANDIDATE_INPUT`, `USER_EDITED`, `USER_APPROVED`, `REJECTED`), strict `NEEDS_CANDIDATE_INPUT` enforcement for missing data (salary, availability, relocation, STAR stories), and character limit counters.
  - Document generation & export engine (`UniversalDocumentGenerator`): ATS-optimized PDF and DOCX generation for Tailored Resume, Cover Letter, Screening QA, and Consolidated Application Packet across 7 professional templates (Modern, Minimal, Traditional, Executive, Technical, Healthcare, Academic) with structural integrity validation (PDF header/extractability, DOCX ZIP/XML validation) and isolated per-user directory storage.
  - Consolidated packet versioning & cryptographic approval gate (`HumanApprovalGate`): immutable revisions in `prepared_packets` with RFC 8785 canonical JSON hashing, revision incrementing/invalidation on edits, and single-use HMAC action ticket consumption (`application_approvals`).
  - Interactive Streamlit Application Preparer interface (`Application Preparer` view) with 8 tabs: Overview & Selection, Tailored Resume, Tailored Cover Letter, Screening Questions, Application Details, Attachments Manifest, Review & Approval Gate, and Packet History & Downloads.
  - Verified with 31 new automated tests across 6 new test suites (`test_profile_isolation.py`, `test_tailored_resume.py`, `test_cover_letter.py`, `test_screening_questions.py`, `test_document_generation.py`, `test_application_packet_integrity.py`), totaling 367 passing tests across the entire repository (100% pass rate). 0 ruff errors, 0 pyflakes errors, and clean git diff.

---

## 7. Approval Requirement

> **STOP:** Never jump to subsequent phases without explicit user instruction and approval of the completed phase deliverables.


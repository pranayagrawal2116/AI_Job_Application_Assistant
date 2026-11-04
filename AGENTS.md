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
- [x] **Architecture v2.1.1 Phase 6.1: Application Preparation Security, Provenance & Packet Integrity Hardening** (Complete)
  - Authenticated user resolution & session ownership: eliminated unauthenticated fallbacks to user ID 1 (`get_current_user_id()`), failing closed immediately. `HumanApprovalGate.authorize_universal_packet` validates session ownership against authenticated `user_id` and rejects cross-user authorizations. `DashboardService` session lookups isolated per user.
  - Workspace and resume ownership: `get_or_create_application_workspace` strictly validates resume ownership (`CrossUserAccessError`) and rejects inactive/archived resumes inside atomic transaction.
  - Database approval integrity: `DatabaseManager.record_packet_approval` validates application ownership, packet ownership, packet-to-application binding, packet version hash matching, and active revision status (`is_active_revision = 1`). Action ticket single-use consumption blocks replay attacks.
  - Truthful evidence & zero-fabrication: plain string certifications and statutory licenses, unconfirmed work experience, education, and projects remain `EXTRACTED_UNVERIFIED`. Synthesized summaries only claim verified status if all constituent elements are verified.
  - Complete elimination of hardcoded defaults: removed all hardcoded personal/educational defaults ("Pranay Anup Agrawal", "MIT World Peace University", "Medical Chatbot", "Sarita Infotech Pvt. Ltd.") across all generators and matchers (`CoverLetterGenerator`, `QuestionAnswerer`, `FormPrefiller`, `ResumeJobMatcher`). Eliminated implicit disk loading of `candidate_profile.json` in constructors.
  - Packet provenance & canonical snapshot persistence: added schema columns `canonical_snapshot_json`, `candidate_profile_version`, `candidate_profile_hash`, `matching_result_id`, `template_id`, `template_version` to `prepared_packets` with automatic idempotent migrations. RFC 8785 canonical JSON bytes stored directly in SQLite, guaranteeing cryptographic auditability. Real disk-inspected `attachments_manifest` with format checks, size, and SHA-256 hashes. PDF validation requires non-empty extractable text.
  - Streamlit cross-application state isolation: composite context keys including application ID, resume hash, JD snapshot hash, and candidate profile hash ensure fresh state and cache invalidation when switching applications.
  - Verified with 37 new targeted regression tests in `test_phase6_1_hardening.py`, totaling 404 passing tests across the entire repository (100% pass rate). 0 pyflakes errors, 0 ruff errors on modified files, and clean git diff.
- [x] **Architecture v2.1.1 Phase 6.1.1: Final Authenticated Session & Packet Hash Completeness** (Complete)
  - Actual login session requirement for approval: Streamlit Application Preparer workflow (Tab 7) strictly resolves active login session (`authenticated_session_id` / `session_id`). Ambiguous fallback session creation replaced with `DashboardService.get_authenticated_candidate_session(user_id, session_id)`, which fails closed on missing, invalid, expired, or cross-user sessions without ever auto-creating sessions.
  - Server-side session & user identity validation: `HumanApprovalGate.authorize_universal_packet` independently verifies active session validity and enforces `session.user_id == user_id` before consuming single-use HMAC action tickets.
  - Complete canonical packet snapshot payload: RFC 8785 canonical JSON schema expanded to include `user_id`, `application_id`, `packet_version`, `original_resume_id`, `original_resume_version_num`, `original_resume_file_hash`, `candidate_profile_version`, `candidate_profile_snapshot_hash`, `job_description_id`, `job_description_snapshot_hash`, `matching_result_id`, `matching_engine_version`, `scoring_configuration_version`, complete tailored resume content & provenance map, tailored resume document hash, cover letter text & provenance claims, cover letter document hash, screening QA items with review states & provenance, attachment manifest with file format, size & SHA-256 hashes, template metadata, rendering engine, and generation timestamp. File paths serve as reference locators only; integrity is verified by SHA-256 hashes.
  - Independent packet hash verification: `HumanApprovalGate.verify_packet_integrity` recomputes SHA-256 of canonical snapshot bytes and compares against `packet_version_hash`. Tampered snapshots or modified content are rejected during approval.
  - Legacy packet migration & handling: automated table rebuild `_migrate_prepared_packets_foreign_keys` updates `prepared_packets` foreign keys to `ON DELETE RESTRICT` on resumes. `PreparedPacket.is_legacy` property cleanly identifies legacy packets lacking canonical JSON snapshots (`canonical_snapshot_json is None`) without fabricating metadata or recalculating partial hashes.
  - Safe resume archival & packet retention: `DatabaseManager.delete_user_resume` safely archives resumes (`is_active = 0, is_primary = 0`) if linked to historical packets or match results, keeping physical files and version history intact. Explicit user privacy deletion (`delete_user_account_data`) cascades safely.
  - Verified with 20 new comprehensive hardening regression tests in `test_phase6_1_1_hardening.py` (424 total project suite tests passing, 100%), 0 pyflakes errors, and clean ruff check.
- [x] **Architecture v2.1.1 Phase 6.1.2: Approval Session Enforcement & Complete Canonical Packet Integrity** (Complete)
  - Approval session enforcement: Application approval workflow strictly reuses the authentic Phase 2 authenticated session; `get_or_create_candidate_session()` call eliminated from approval UI; missing/expired sessions show `"Your login session is missing or expired. Please sign in again before approving this packet."`; `authenticate_candidate()` and `create_user_session()` are never called during approval.
  - Complete canonical packet payload: RFC 8785 canonical JSON snapshot covers `user_id`, `application_id`, `packet_version`, `original_resume_id`, `original_resume_version_num`, `original_resume_file_hash`, `candidate_profile_version`, `candidate_profile_hash`, `job_description_id`, `job_description_snapshot_hash`, `matching_result_id`, `matching_engine_version`, `scoring_profile`, `scoring_config_version`, tailored resume data & claim provenance, `tailored_resume_pdf_hash`, `tailored_resume_docx_hash`, cover letter text & claims, `cover_letter_pdf_hash`, `cover_letter_docx_hash`, screening QA records with states, candidate edits, character limits, attachment manifest with file formats, byte sizes & SHA-256 hashes, template metadata, and rendering engine. Optional metadata is explicitly `null` when unavailable.
  - Exact byte-level hash invariant: `SHA256(canonical_snapshot_json.encode("utf-8")) == packet_version_hash` guaranteed across all new packets.
  - Independent pre-consumption verification: `verify_prepared_packet_integrity` independently validates packet ownership, active revision status, and hash integrity before consuming single-use HMAC action tickets; corrupted or tampered snapshots fail closed.
  - Legacy packet handling: Historical packets without canonical snapshots identified via `is_legacy = True` and preserved without fabricated metadata.
  - Verified with 24 new comprehensive hardening regression tests in `test_phase6_1_2_hardening.py` (448 total project suite tests passing, 100%), 0 pyflakes errors, and clean ruff check.

- [x] **Architecture v2.1.1 Phase 6.1.3: Strict User-Bound Session Identity & Actual Match Result Provenance** (Complete)
  - Strict session-to-user identity binding: `DashboardService.get_authenticated_candidate_session(user_id, session_id)` strictly requires `sess.user_id is not None and sess.user_id == user_id`, rejecting sessions missing database `user_id` or matching only on string `candidate_id`; `SecurityAuthorizationError` raised on unbound or cross-user sessions; legacy session creation helper deprecated and isolated strictly for backwards test compatibility.
  - Server-side independent session enforcement: `HumanApprovalGate.authorize_universal_packet` independently validates `session.user_id is not None and session.user_id == user_id` prior to packet integrity validation and prior to consuming single-use HMAC action tickets, preserving tickets upon session authorization failure.
  - Actual MatchResult provenance binding: Dashboard application preparer workflow passes the actual selected `latest_match.id` and its actual scoring metadata (`engine_version`, `scoring_profile`, `scoring_config_version`) into the canonical packet.
  - MatchResult ownership and source-version validation: `prepare_universal_packet` validates that MatchResult belongs to the authenticated user (`CrossUserAccessError`), matches the selected resume ID and file hash (`ValidationError`), and matches the selected job description ID and snapshot hash (`ValidationError`).
  - Explicit null metadata handling: applications without matching evaluations record explicit `null` metadata; candidates without profiles record explicit `null` profile version and hash; all hardcoded defaults eliminated.
  - Verified with 22 new comprehensive hardening regression tests in `test_phase6_1_3_hardening.py` (470 total project suite tests passing, 100%), 0 pyflakes errors, and clean ruff check.

- [x] **Architecture v2.1.1 Phase 7.1 & 7.1.1: Application Lifecycle Database Foundation & Integrity Hardening** (Complete)
  - Application lifecycle database foundation: Twelve universal statuses (`DRAFT`, `PREPARING`, `READY_FOR_REVIEW`, `APPROVED`, `SUBMITTED`, `IN_PROGRESS`, `ASSESSMENT`, `INTERVIEW`, `OFFER`, `REJECTED`, `WITHDRAWN`, `CLOSED`), composite candidate ownership (`UNIQUE(id, user_id)`), immutable timeline events (`application_events`), candidate-confirmed submissions (`submission_confirmations`), and follow-up tracking (`application_follow_ups`).
  - Approval migration query alignment: Uses real Phase 6.1.3 schema (`application_approvals.is_consumed = 0`, `ticket_nonce`, `session_id`) joined with `prepared_packets` where `is_active_revision = 1` and hashes match, conservatively mapping unconfirmed applications to `READY_FOR_REVIEW`.
  - Submission confirmation composite foreign key: `FOREIGN KEY (packet_id, user_id) REFERENCES prepared_packets(id, user_id) ON DELETE RESTRICT`, preventing packet deletion while referenced in active or historical submission records.
  - Approval-to-submission boundary: `transition_status=False` is storage-only, preserving candidate-confirmed details without mutating status; `transition_status=True` validates approved state, requires `packet_id`, validates active unconsumed human approval, atomically consumes ticket, advances status to `SUBMITTED`, and emits `SUBMISSION_CONFIRMED`.
  - Discovered catalogue job insertion vs user application tracking: `insert_job()` inserts jobs into catalog without guessing `SELECT id FROM users LIMIT 1` or creating placeholder system users (`system@localhost`). Backwards-compatible `insert_job(job, user_id=...)` creates an application and timeline event ONLY when an explicit, validated `user_id` is passed.
  - Append-only event hashing & deletion prevention: `DatabaseManager.compute_event_hash` upgraded to `hash_version="v2"`, binding UTC `created_at` timestamp directly into canonical JSON hash; `trg_prevent_application_events_delete` trigger blocks DELETE operations during normal usage; authorized GDPR privacy erasure uses ephemeral single-use tokens (`_privacy_erasure_tokens`); cryptographic tail-deletion limitation documented.
  - Fully transactional migration & rollback: `_migrate_phase7_lifecycle_tables` operates with explicit manual transaction management (`conn.isolation_level = None`), disabling foreign keys during table rebuild, running post-migration integrity checks (`PRAGMA foreign_key_check`, `PRAGMA integrity_check`), committing on success, and rolling back cleanly on any failure.
  - Verified with 44 new automated tests across 5 new test suites (`test_phase7_1_schema.py`, `test_phase7_1_migrations.py`, `test_phase7_1_ownership.py`, `test_phase7_1_event_integrity.py`, `test_phase7_1_1_integrity_corrections.py`), totaling 514 passing tests across the entire repository (100% pass rate). 0 pyflakes errors, 0 ruff errors on modified files, and clean git diff.

- [x] **Architecture v2.1.1 Phase 7.1.2: Final Database Safety & Migration Hardening** (Complete)
  - Generic event status immutability: Eliminated implicit application status mutation from `create_application_event()`. Event logging is strictly append-only audit tracking and cannot alter `applications.status`.
  - Submission confirmation preconditions & allowlist: Replaced blacklist status checking with a strict allowlist in `create_submission_confirmation(transition_status=True)` requiring applications to be in `APPROVED` or legacy `'Awaiting Approval'` status. Any other status (`DRAFT`, `PREPARING`, `READY_FOR_REVIEW`, `SUBMITTED`, `IN_PROGRESS`, `ASSESSMENT`, `INTERVIEW`, `OFFER`, `REJECTED`, `WITHDRAWN`, `CLOSED`) is rejected with `SecurityAuthorizationError`.
  - Unconditional consumed approval rejection: Active human approvals already consumed (`is_consumed = 1`) are unconditionally rejected on submission transition attempts. Added `correct_submission_confirmation()` allowing candidates to attach confirmation screenshots, reference identifiers, and notes to existing submissions without re-running submission or reusing consumed approvals.
  - Phase 7.1 existing database migration: Upgraded `_migrate_phase7_lifecycle_tables` to detect and rebuild `submission_confirmations` tables from earlier Phase 7.1 databases missing `ON DELETE RESTRICT` on `prepared_packets`, preserving all existing records, timestamps, active flags, and indexes.
  - Migration lock ordering: Enforces SQLite RESERVED write lock acquisition (`BEGIN IMMEDIATE TRANSACTION;`) prior to preflight verification and table snapshots, eliminating race conditions from concurrent writers. Preflight aborts roll back cleanly without leaving partial tables.
  - Hardened connection-scoped privacy erasure: Replaced table-based token authorizations (`_privacy_erasure_tokens`) with ephemeral, connection-scoped SQLite user-defined function `verify_privacy_erasure_authorization(OLD.user_id)` strictly authorized via context manager `_authorized_privacy_erasure_scope(conn, user_id)` during account deletion. Blocks unauthorized, concurrent, cross-user, or forged event deletions.
  - Verified with 13 new comprehensive hardening regression tests in `test_phase7_1_2_final_safety.py` (527 total project suite tests passing, 100%), 0 pyflakes errors, and clean ruff check.

- [x] **Architecture v2.1.1 Phase 7.1.3: Submission Confirmation Audit Consistency & Timestamp Integrity** (Complete)
  - Atomic confirmation corrections: Merged submission confirmation updates and `SUBMISSION_CONFIRMATION_UPDATED` timeline event logging into a single SQLite transaction. Failure at any point triggers atomic rollback of confirmation metadata and preserves original event chains intact without partial events.
  - Strict submission time vs audit event time separation: Separated candidate-reported external submission time (`submission_confirmations.submission_timestamp`, `applications.date_submitted`) from server UTC event recording time (`application_events.created_at`). Preserves historical submission dates while strictly binding actual server creation timestamps into RFC 8785 v2 event hashes.
  - Distinct audit event semantics: Enforced precise event type categorization across workflows: `SUBMISSION_CONFIRMATION_RECORDED` for storage-only records without state transition, `SUBMISSION_CONFIRMED` for transitions to `SUBMITTED`, and `SUBMISSION_CONFIRMATION_UPDATED` for metadata updates.
  - Centralized internal event helper: Added `_insert_application_event_internal(cursor, ...)` to encapsulate sequence numbering, RFC 8785 canonical hash computation, and event insertion on existing connections without transaction overhead or implicit status mutation.
  - Phase 7.2 service-layer security contract: Formulated explicit 10-point security contract in architecture documentation governing session-bound user resolution, action tickets, packet integrity, allowlist enforcement, and zero-automation final submission.
  - Verified with 11 new comprehensive automated tests in `test_phase7_1_3_audit_consistency.py` (538 total project suite tests passing, 100%), 0 pyflakes errors, 0 ruff errors, and clean git diff.

- [x] **Architecture v2.1.1 Phase 7.1.3.1: Transaction Failure-Injection Verification & Audit Review** (Complete)
  - Comprehensive failure-injection test coverage: Added deterministic test coverage for all five critical failure paths during submission confirmation corrections: Point A (canonicalization failure), Point B (event sequence/prev-hash lookup failure), Point C (event hash computation failure), Point D (SQLite trigger event insertion failure), and Point E (transaction commit failure via connection proxy seam).
  - Common rollback invariant assertions: Every failure point strictly verifies the 9 invariants: original confirmation reference unchanged, original candidate notes unchanged, original submission channel unchanged, original submission timestamp unchanged, no `SUBMISSION_CONFIRMATION_UPDATED` event appended, event sequence numbers remain contiguous, `verify_application_event_chain()` succeeds, original approval record unchanged, and exceptions propagate cleanly without swallowed errors or false success responses.
  - Before/after audit event provenance: Upgraded `correct_submission_confirmation()` payload to record both `updated_fields` and `previous_fields` alongside `confirmation_id`, providing complete before/after state provenance for all modified confirmation attributes.
  - Verified with 6 new deterministic failure-injection and audit review tests in `test_phase7_1_3_audit_consistency.py` (17 tests total in suite, 544 total project suite tests passing, 100%), 0 pyflakes errors, 0 ruff errors, and clean git diff.

- [x] **Architecture v2.1.1 Phase 7.2: Universal Application State Machine & Core Service Layer** (Complete)
  - Dedicated UI-independent state machine (`ApplicationStateMachine` in `src/lifecycle/`): formalizes all 12 universal application statuses (`DRAFT`, `PREPARING`, `READY_FOR_REVIEW`, `APPROVED`, `SUBMITTED`, `IN_PROGRESS`, `ASSESSMENT`, `INTERVIEW`, `OFFER`, `REJECTED`, `WITHDRAWN`, `CLOSED`) with bidirectional legacy aliases (`Discovered`, `Under Review`, `Shortlisted`, `Application Prepared`, `Awaiting Approval`, `Applied`).
  - Strict transition validation matrix: explicit allowed transitions matrix across all 12 states; gate-protected targets (`APPROVED` requires approved packet, `SUBMITTED` requires submission confirmation with active unconsumed human approval); terminal statuses (`REJECTED`, `WITHDRAWN`, `CLOSED`) restricted to re-opening only to `IN_PROGRESS` with mandatory rationale.
  - Transactional status transition engine: `DatabaseManager.transition_application_status()` executes under SQLite write lock, verifies candidate ownership (`CrossUserAccessError`), performs optimistic concurrency check via `expected_current_status`, validates transitions against `ApplicationStateMachine`, executes conditional `UPDATE`, and atomically records immutable audit timeline events (`STATUS_CHANGED`, `APPLICATION_REOPENED`) via `_insert_application_event_internal()`.
  - Secure core lifecycle service layer (`DashboardService`):
    - `resolve_authenticated_candidate(session_id, client_user_id)` strictly validates active session, enforces non-null `session.user_id`, and verifies `client_user_id == session.user_id`.
    - Session-bound candidate application management: `create_candidate_application()`, `get_candidate_application()`, `list_candidate_applications()` with filtering, searching, and sorting.
    - Protected manual submission workflow: 16-step verification sequence in `record_candidate_manual_submission()` verifying candidate session identity, application ownership, state machine transition validity, active packet integrity, unconsumed human approval, and single-use HMAC action ticket consumption.
    - External URL opening audit: `log_external_application_url_opened()` validates safe URLs via `URLSafetyValidator` and records `EXTERNAL_PORTAL_OPENED` timeline events without mutating application status.
    - Strict zero-automation boundary: zero browser automation or submission scripting in lifecycle modules; candidate retains complete control over external submissions.
  - Verified with 50 new automated tests across 3 new test suites (`test_application_state_machine.py` [11 tests], `test_application_lifecycle_service.py` [21 tests], `test_phase_7_2_submission_security.py` [18 tests]), totaling 594 passing tests across the entire repository (100% pass rate). 0 pyflakes errors, 0 ruff errors, and clean git diff.

- [x] **Architecture v2.1.1 Phase 7.2.1: State Transition Authorization & Lifecycle Security Hardening** (Complete)
  - Removal of boolean gate bypass: eliminated caller-supplied booleans (`is_gate_authorized=True`) as proof of authorization; generic database and service layer transitions to `APPROVED` and `SUBMITTED` unconditionally raise `SecurityAuthorizationError`; `APPROVED` transitions strictly routed through `HumanApprovalGate.authorize_universal_packet()`; `SUBMITTED` transitions strictly routed through manual submission confirmation with active unconsumed human approvals and action tickets.
  - Mandatory reopening rationale enforcement: transition from terminal states (`REJECTED`, `WITHDRAWN`, `CLOSED`) to `IN_PROGRESS` strictly requires a non-empty, non-whitespace rationale string passed via `reopen_rationale`; attempts to supply empty strings or bypass via metadata keys raise `ValidationError`; emits `APPLICATION_REOPENED` event with rationale and actor provenance.
  - Terminal transition matrix reconciliation: `REJECTED -> CLOSED` and `WITHDRAWN -> CLOSED` documented and validated as administrative finalization progressions without requiring reopening rationale; arbitrary non-reopening exits from terminal states rejected.
  - External URL safety & audit redaction: integrated `URLSafetyValidator` in `create_candidate_application()` and `log_external_application_url_opened()`, blocking SSRF, unsafe schemes (`javascript:`, `file:`), loopback/private IPs, and embedded credentials; `_redact_sensitive_url()` redacts tokens, secrets, API keys, passwords, and auth codes in timeline event payloads; status strictly preserved.
  - SQLite immediate write-lock & concurrency hardening: added `DatabaseManager.immediate_transaction()` acquiring SQLite's RESERVED write lock via `BEGIN IMMEDIATE` before reading application state, preventing concurrent write collisions; failure triggers complete atomic rollback.
  - Reserved audit payload protection: protected reserved fields (`previous_status`, `new_status`, `application_id`, `user_id`, `actor_type`, `session_reference`, `reopen_rationale`, `created_at`, `sequence_no`, `event_hash`, etc.) against caller override, raising `ValidationError` on conflict.
  - Verified with 19 new comprehensive automated hardening tests in `test_phase_7_2_1_security_hardening.py` (613 total project suite tests passing, 100%), 0 pyflakes errors, 0 ruff errors, and clean git diff.

- [x] **Architecture v2.1.1 Phase 7.2.2: Human Approval Atomicity, Ticket Provenance & URL Security** (Complete)
  - Atomic human approval workflow: refactored `HumanApprovalGate.authorize_universal_packet()` to delegate all 4 database writes (`application_approvals` insert, `application_logs` insert, `applications.status` update, and `application_events` insert with `PACKET_HUMAN_APPROVED`) to `DatabaseManager.authorize_application_packet_atomic()` within a single SQLite `immediate_transaction()`, eliminating partial write risks under RESERVED write locks.
  - Application pre-approval status enforcement: `authorize_application_packet_atomic()` asserts application is in `READY_FOR_REVIEW` (or legacy `APPLICATION_PREPARED`), rejecting approvals from `DRAFT`, `PREPARING`, `APPROVED`, `SUBMITTED`, `REJECTED`, `WITHDRAWN`, or `CLOSED` with `InvalidStatusTransitionError`.
  - Action ticket constituent parsing: centralized ticket parsing in `SessionManager.parse_action_ticket()` accurately extracting `(key_id, nonce, timestamp, signature)` from `TKT-{key_id}-{nonce}.{timestamp}.{signature}` with structure, non-empty segments, integer timestamp, and signature validation; legacy fallback defaults `key_id="v1"`.
  - Accurate ticket metadata persistence: `application_approvals.key_id` records the actual key ID rather than the timestamp integer; `application_approvals.ticket_nonce` records the exact 32-character hex nonce rather than composite prefixes; stored nonce matches the consumed nonce in `SessionManager`.
  - DNS resolution validation without bypass: eliminated `skip_dns=True` bypasses in `create_candidate_application()` and `log_external_application_url_opened()`; introduced injectable `url_resolver` in `DashboardService` for deterministic DNS testing without external network lookups while asserting all resolved IP addresses are public.
  - Complete URL audit redaction: `_redact_sensitive_url()` completely strips URL fragments (setting fragment to empty string `""`), preventing OAuth access tokens or private client state from leaking into audit events, and redacts sensitive query parameter values case-insensitively and unquoted.
  - Hardened `immediate_transaction()` error handling: added `txn_started` tracking ensuring `ROLLBACK` is only executed when a transaction is active, cleanly preserving the original `sqlite3.OperationalError: database is locked` on contention without masking it with invalid rollback errors.
  - Verified with 27 new automated tests across 4 dedicated test suites (`test_phase_7_2_2_approval_atomicity.py` [6 tests], `test_phase_7_2_2_ticket_metadata.py` [6 tests], `test_phase_7_2_2_url_security.py` [9 tests], `test_phase_7_2_2_transaction_failures.py` [6 tests]), totaling 640 passing tests across the entire repository (100% pass rate). 0 pyflakes errors, 0 ruff errors, and clean git diff.

- [x] **Architecture v2.1.1 Phase 7.2.2.1: Trusted Approval Boundary & Complete Atomicity Verification** (Complete)
  - Database approval authorization boundary closure: made atomic approval persistence internal (`_authorize_application_packet_atomic`) on `DatabaseManager`, eliminating public database-level approval bypasses; removed arbitrary `target_status` argument, strictly deriving target status from current status (`READY_FOR_REVIEW -> APPROVED`, legacy `Application Prepared -> Awaiting Approval`); introduced `VerifiedApprovalContext` in `src/database/models.py` as an internal trusted capability passed by `HumanApprovalGate.authorize_universal_packet()`.
  - Comprehensive 7-point failure-injection verification: implemented dedicated tests for all 7 potential failure points: Test A (approval row insert failure), Test B (application log insert failure), Test C (application status update failure), Test D (event canonicalization failure), Test E (event hash computation failure), Test F (event insertion failure), and Test G (transaction commit failure via connection wrapper).
  - 10-point common rollback invariant enforcement: each failure point rigorously verifies zero approvals, zero logs, status preserved at `READY_FOR_REVIEW`, zero approved events, pre-existing events unchanged, contiguous sequence numbers, valid cryptographic hash chain, no false success, consumed ticket cannot be replayed, and retry with freshly issued ticket succeeds.
  - Hyphenated key ID parsing & persistence: updated `SessionManager.parse_action_ticket()` to use `header_nonce.rsplit("-", 1)` and reject whitespace/empty segments, supporting hyphenated keys (e.g. `production-2026`, `auth-v2-prod-key`, `multi-part-cluster-key`); end-to-end tests verify ticket issuance, verification, replay prevention, and SQLite persistence of exact hyphenated key IDs and clean hex nonces; synchronized `SessionManager._rotation_keys` with `KeyRotationManager`.
  - Real SQLite lock-contention test: added `test_real_sqlite_write_lock_contention_between_connections` using two real connections to a file-backed SQLite database, proving lock contention detection with short timeouts without masking `OperationalError: database is locked`, clean connection cleanup, and subsequent transaction acquisition.
  - Verified with 13 new comprehensive automated tests across the test suites (totaling 653 passing tests across the entire repository, 100% pass rate), 0 pyflakes errors, 0 ruff errors on modified files, and clean git diff.

- [x] **Architecture v2.1.1 Phase 7.2.2.2: Verified Approval Grant Enforcement & Complete Rollback Verification** (Complete)
  - Elimination of raw-argument fallbacks: removed all raw fallback parameters (`application_id`, `user_id`, `packet_id`, `packet_version_hash`, `ticket_nonce`, `key_id`, `approver_name`, `session_id`) from `DatabaseManager._authorize_application_packet_atomic`; requires a cryptographically signed, single-use `VerifiedApprovalGrant` issued and verified by `SessionManager`; rejects raw kwargs, caller-supplied flags, or unverified grants with `SecurityAuthorizationError` before acquiring any write lock; deprecated and prohibited direct invocation of `record_packet_approval()` without verified grant evidence.
  - Verifiable approval authorization grants (`VerifiedApprovalGrant`): implemented `VerifiedApprovalGrant` dataclass in `src/database/models.py`; `SessionManager.verify_and_issue_approval_grant()` verifies ticket nonces, validates expiry, checks session ownership, registers grant in `_active_grants`, and computes HMAC-SHA256 signature (`_compute_grant_signature`) across canonical grant attributes; `SessionManager.verify_and_consume_approval_grant()` validates active registration, verifies cryptographic signature, checks expiration, enforces session user binding (`CrossUserAccessError`), verifies ticket nonce consumption, and transitions grant to `_consumed_grants` single-use, preventing replay attacks (`TicketAlreadyConsumedError`).
  - Upgraded rollback assertion helper with full event row snapshotting: enhanced `_assert_approval_rolled_back_and_verifiable` to capture and compare complete pre-existing event row attributes (`id`, `sequence_no`, `event_type`, `previous_status`, `new_status`, `event_payload_json`, `created_at`, `previous_event_hash`, `event_hash`) and independently verify cryptographic hash chain integrity via `DatabaseManager.verify_application_event_chain(raise_on_error=True)`.
  - Dedicated direct-bypass regression suite: implemented 10 comprehensive regression tests (Tests A through J in `test_phase_7_2_2_approval_atomicity.py`) covering raw field kwargs rejection, missing grant rejection, forged grant rejection, wrong user/session rejection, wrong application rejection, wrong packet/hash rejection, wrong action type rejection, grant replay rejection, legacy public method rejection, and valid single-use workflow preservation.
  - Action ticket parser character structure validation: enforced regex validation (`^[a-zA-Z0-9_\-]+$`) on `key_id`, `nonce`, and `signature` in `SessionManager.parse_action_ticket()`, with positive timestamp integer validation preceding signature structure checks.
  - Verified with 10 new comprehensive automated tests across the test suites (totaling 663 passing tests across the entire repository, 100% pass rate), 0 pyflakes errors, 0 ruff errors on modified files, and clean git diff.

- [x] **Architecture v2.1.1 Phase 7.2.2.3: Trusted Verifier Binding & Approval Grant Identity Integrity** (Complete)
  - Elimination of caller-controlled verifier injection: completely removed per-call `session_manager` parameter from `DatabaseManager._authorize_application_packet_atomic()`; rejects unexpected keyword arguments with `SecurityAuthorizationError`; wires trusted `SessionManager` through `DatabaseManager.__init__(..., session_manager=None)` with strict instance verification (`isinstance(sm, SessionManager) and type(sm).__name__ == "SessionManager"`) and property fallback to `SessionManager.get_instance()`; enforces explicit verification prior to opening SQLite write locks, failing closed on False or None verifier returns.
  - Cryptographic 12-attribute grant identity: included `approver_name` in server-side HMAC grant signatures; serialized grant payload using RFC 8785 canonical JSON bytes (`canonical_json_bytes`) across all 12 attributes (`action_type`, `application_id`, `approver_name`, `expires_at`, `grant_id`, `issued_at`, `key_id`, `packet_id`, `packet_version_hash`, `session_id`, `ticket_nonce`, `user_id`); verified submitted grant against complete active registered grant in `SessionManager._active_grants`, rejecting tampered attributes before consumption.
  - Process-level thread safety: added `threading.Lock()` (`_grant_lock`) protecting the active-to-consumed grant transition in `SessionManager.verify_and_consume_approval_grant()`, guaranteeing exactly one success under concurrent multi-threaded execution while secondary threads raise `TicketAlreadyConsumedError`.
  - Architecture constraints & in-memory limitation: accurately documented single-process deployment requirement, in-memory grant invalidation on process restarts, and sticky-session / centralized grant store requirements for multi-worker scaling.
  - Verified with 17 new comprehensive automated tests in `test_phase_7_2_2_3_trusted_verifier.py` (totaling 680 passing tests across the entire repository, 100% pass rate), 0 pyflakes errors, 0 ruff errors on modified files, and clean git diff.

- [x] **Architecture v2.1.1 Phase 7.2.2.4: Exact Trusted Verifier Type Enforcement & SessionManager Consistency** (Complete)
  - Exact SessionManager type identity enforcement: replaced loose inheritance and class-name checks with exact type identity (`type(session_manager) is SessionManager`) across `DatabaseManager.__init__()`, `DatabaseManager.session_manager` property, `DatabaseManager._authorize_application_packet_atomic()`, and `HumanApprovalGate.__init__()`; explicitly rejects all subclasses (even if named `SessionManager`), spoofed types, proxies, and duck-typed objects at both initialization and the verification boundary.
  - Shared SessionManager identity consistency: enforced invariant that `HumanApprovalGate.session_manager` and `DatabaseManager.session_manager` reference the exact same instance (`gate.session_manager is db.session_manager`); automatically wires the genuine instance if `DatabaseManager` initially lacks a verifier; rejects mismatched genuine instances with `SecurityAuthorizationError` ("SessionManager identity mismatch: DatabaseManager and HumanApprovalGate must share the exact same SessionManager instance.") to prevent dual-registry split-brain authorization bugs.
  - Verified with 10 new comprehensive automated tests in `test_phase_7_2_2_4_exact_verifier.py` (totaling 690 passing tests across the entire repository, 100% pass rate), 0 pyflakes errors, 0 ruff errors on modified files, and clean git diff.

---

## 7. Approval Requirement

> **STOP:** Never jump to subsequent phases without explicit user instruction and approval of the completed phase deliverables.


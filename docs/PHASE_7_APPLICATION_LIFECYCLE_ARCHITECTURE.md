# PHASE 7 — APPLICATION LIFECYCLE & TRACKING
## Architecture Audit, Security Review & Implementation Blueprint

**Architecture Version:** v2.1.1  
**Project:** Universal AI Job Application Assistant  
**Document:** `docs/PHASE_7_APPLICATION_LIFECYCLE_ARCHITECTURE.md`  
**Current Commit:** `89c4ebce71b8aa5bccf5d4665131c997b5788ea8` (Verified HEAD)  
**Branch:** `main`  
**Scope:** Stage 1 — Architecture Audit, Threat Model, Database Design & Implementation Blueprint.  
**Execution Mode:** Pure Architectural Blueprint (Zero production code changes; zero database modifications).

---

## 1. Executive Summary

The Universal AI Job Application Assistant has achieved complete, cryptographically verified multi-user application preparation up through Phase 6.1.3 (470 passing unit/integration tests, 100% pass rate). Registered candidates across professions, experience levels, and industries can securely ingest job descriptions, evaluate deterministic match scores, tailor resumes, draft cover letters, answer screening questions, export ATS-ready documents, assemble immutable canonical application packets, and grant verified human authorization under Phase 2 authenticated login sessions.

However, once an application packet is approved, the platform currently lacks a cohesive, multi-user application lifecycle tracking system. Today, candidates cannot track whether they have manually submitted an application, when they submitted it, what external confirmation details were received, when follow-ups are due, or how interviews, assessments, offers, or rejections unfold.

**Phase 7 — Application Lifecycle & Tracking** transforms the assistant into a comprehensive, candidate-controlled career management hub. It empowers candidates to track and manage their applications throughout their full real-world lifecycle while maintaining strict zero-hallucination, candidate privacy, and human-in-the-loop safeguards.

### Core Non-Negotiable Boundaries:
1. **Strict Candidate Control (Zero Automated Submission):** The platform **must never** automatically submit applications, log into third-party employer applicant tracking systems (ATS), bypass CAPTCHAs, evade anti-bot defenses, or store employer portal passwords.
2. **Decoupled Approval vs. Submission:** `APPROVED` (human authorization of internal application materials) and `SUBMITTED` (candidate confirmation of external submission on employer portal) are strictly independent states.
3. **Multi-User Isolation:** Every application, event, submission record, and follow-up is cryptographically and relationally bound to the candidate's authenticated database `user_id`.
4. **Append-Only Immutability:** Application history is preserved via an immutable, append-only event timeline.

---

## 2. Current Architecture Findings

A code-level inspection of the existing repository (`89c4ebc`) reveals the following architectural landscape across subsystems:

| Subsystem | Existing Implementation & State | Relevant Source Files |
| :--- | :--- | :--- |
| **Authentication & Multi-User Security** | Robust PBKDF2-HMAC-SHA256 password hashing, anti-enumeration tokens, account lockouts, candidate sessions with 256-bit entropy, 3600s TTL, strict non-null `session.user_id` validation in `DashboardService`, single-use HMAC action tickets (`KeyRotationManager`). | `src/security/auth.py`<br>`src/security/session_manager.py`<br>`dashboard/services/dashboard_service.py` |
| **Candidate Profiles & Resumes** | Multi-user profile management (`candidate_profiles`), isolated resume storage in `data/users/<user_id>/resumes/`, file security validation (magic bytes, PDF/DOCX format checks), content deduplication (`UNIQUE(user_id, file_hash)`), immutable resume version snapshots (`resume_versions`). | `src/database/db_manager.py`<br>`src/security/file_security.py`<br>`src/preparer/resume_parser.py` |
| **Job Description Ingestion** | Cross-industry universal parser, SSRF-hardened connection-pinned HTTP fetching, isolated user storage (`job_descriptions`), immutable snapshot hashes (`snapshot_hash`), superseding version lineage (`supersedes_job_description_id`). | `src/scraper/job_parser.py`<br>`src/scraper/url_fetcher.py`<br>`src/security/url_validator.py` |
| **Matching & Eligibility Engine** | Universal explainable matcher (100 pts), 3-state eligibility (`ELIGIBLE`, `INELIGIBLE`, `UNKNOWN`), strict candidate fact provenance (`USER_CONFIRMED` vs `EXTRACTED_UNVERIFIED`), immutable `match_results` rows linked with `ON DELETE RESTRICT` on resumes and job descriptions. | `src/engine/universal_matcher.py`<br>`src/engine/eligibility_engine.py`<br>`src/database/models.py` |
| **Application Preparation & Approval** | Application workspace `get_or_create_application_workspace(user_id, jd_id)`, tailored resume & cover letter generation, screening QA assistant, ATS document exports (7 templates), canonical JSON snapshot persistence, HMAC approval tickets, strict non-null `user_id` server-side authorization gate. | `src/preparer/approval_gate.py`<br>`src/preparer/document_generator.py`<br>`dashboard/views/application_preparer.py` |
| **Existing `applications` Table** | Multi-user composite table created in Phase 2/Phase 6. Stores `job_id`, `job_description_id`, `user_id`, `resume_id`, `company_name`, `job_title`, `status`, `date_prepared`, `date_submitted`, `resume_used`, `cover_letter_reference`, `notes`. | `src/database/schema.sql`<br>`src/database/models.py`<br>`src/database/db_manager.py` |
| **Existing Dashboard View** | `dashboard/views/application_tracker.py` is an older Phase 2 catalog job tracker querying `service.get_all_jobs_df()` (catalog scraper jobs), not user-specific applications from `job_descriptions`. | `dashboard/views/application_tracker.py`<br>`dashboard/app.py` |

---

## 3. Existing Reusable Components

Phase 7 does not need to reinvent existing foundational mechanisms:

1. **`get_or_create_application_workspace(user_id, job_description_id, resume_id)`:**
   - Already instantiates or fetches an `applications` record linking the candidate's `user_id` with `job_description_id` and selected `resume_id`.
   - Prevents duplicate workspace records on repeat visits.
2. **`HumanApprovalGate.authorize_universal_packet()`:**
   - Fully hardened in Phase 6.1.3 with strict server-side `session.user_id == user_id` identity binding, canonical RFC 8785 snapshot hash verification, and single-use HMAC action ticket consumption.
   - Advances `applications.status` to `Awaiting Approval` and writes an immutable audit record to `application_approvals`.
3. **`DashboardService.get_authenticated_candidate_session(user_id, session_id)`:**
   - Reliable server-side session resolver that validates session activity and non-null user ownership without creating new sessions or accepting legacy string IDs.
4. **`URLSafetyValidator` (`src/security/url_validator.py`):**
   - Comprehensive SSRF defense engine to safely validate external employer application URLs before storing or presenting them to candidates.
5. **`FileSecurityValidator` (`src/security/file_security.py`):**
   - High-assurance document validation (magic bytes, MIME type, zip-bomb protection) reusable for candidate-uploaded submission confirmation receipts or screenshots.
6. **`DatabaseManager.transaction()` & SQLite Composite Foreign Keys:**
   - Thread-safe context manager enforcing ACID transaction semantics and strict relational integrity across composite `(id, user_id)` constraints.

---

## 4. Identified Gaps

The audit identified five critical structural and functional gaps:

### Gap 1: Incomplete Lifecycle Statuses and Disconnected State Machine
- `applications.status` is currently restricted by a CHECK constraint to only 9 statuses:
  `'Discovered', 'Under Review', 'Shortlisted', 'Application Prepared', 'Awaiting Approval', 'Applied', 'Interview', 'Rejected', 'Withdrawn'`.
- Missing statuses: `DRAFT`, `PREPARING`, `READY_FOR_REVIEW`, `APPROVED`, `SUBMITTED`, `IN_PROGRESS`, `ASSESSMENT`, `OFFER`, `CLOSED`.
- In particular, `Awaiting Approval` and `Applied` conflate internal document authorization with real-world external job portal submission.

### Gap 2: Absence of Structured Submission Confirmation
- Currently, when an application is marked `Applied`, the only modification is setting `date_submitted = CURRENT_TIMESTAMP` and logging a string in `application_logs`.
- There is no mechanism to record:
  - Submission channel (Company Portal, LinkedIn, Email, Referral, Job Board).
  - External confirmation / reference number.
  - Candidate submission notes.
  - Optional uploaded confirmation receipt (PDF/screenshot).
- The legacy method `confirm_manual_submission` operates on `job_id` (catalog jobs) rather than `application_id` and uses legacy unauthenticated candidate strings.

### Gap 3: Lack of an Append-Only Application Event Timeline
- `application_logs` is tied to `job_id REFERENCES jobs(id)`. When an application is created from a user-ingested job description (`job_id is NULL`), logs fail foreign key checks or get orphaned.
- `application_logs` stores unstructured strings (`action`, `details`) without structured JSON payloads, actor provenance, event hashing, or sequence tracking.
- There is no queryable timeline to display when an application was created, when resumes were tailored, when packets were approved, when the external portal was opened, when submission was confirmed, or when interview milestones occurred.

### Gap 4: Zero Follow-Up Tracking Capability
- The database contains no table or entity for candidate follow-ups.
- Candidates have no way to record follow-up dates (e.g. 7-day status check-in, post-interview thank you note), follow-up types, outcome notes, or completion status.

### Gap 5: Dashboard View Disconnect
- `dashboard/views/application_tracker.py` queries `service.get_all_jobs_df()`—which reads from the global catalog `jobs` table scraped in Phase 5.
- It completely ignores private multi-user applications created via `job_descriptions` in the Application Preparer!
- An authenticated user looking at "Application Tracker" sees scraped jobs rather than their own prepared and approved applications.

---

## 5. Security & Threat-Model Review

A comprehensive threat assessment was conducted for Phase 7:

```
                                  THREAT MODEL MATRIX
+-----------------------------------+--------------------+-----------------------------------------------+
| Threat Scenario                   | Risk Classification| Architectural Mitigation                       |
+-----------------------------------+--------------------+-----------------------------------------------+
| T1. Cross-User IDOR Access        | Critical (P0)      | All service queries enforce composite keys:   |
|     (Guessing application_id)     |                    | WHERE id = :id AND user_id = :auth_user_id.   |
|                                   |                    | Composite FKs on all child tables.            |
+-----------------------------------+--------------------+-----------------------------------------------+
| T2. Automated External Submission | Critical (P0)      | Explicit architectural boundary: Zero browser  |
|     (Bot evasion / ATS login)     |                    | drivers or automated form-posting scripts.     |
|                                   |                    | Submission is strictly confirmed by candidate.|
+-----------------------------------+--------------------+-----------------------------------------------+
| T3. Premature/Unapproved          | High (P1)          | State machine prevents transition to SUBMITTED|
|     Submission Confirmation       |                    | without an active, approved packet hash.      |
+-----------------------------------+--------------------+-----------------------------------------------+
| T4. SSRF via External URLs        | High (P1)          | Validate all employer application URLs using   |
|     (Intranet/Metadata probe)     |                    | URLSafetyValidator; display only as outbound  |
|                                   |                    | rel="noopener noreferrer" links in browser.   |
+-----------------------------------+--------------------+-----------------------------------------------+
| T5. Timeline Rewriting / Audit    | Medium (P2)        | Append-only application_events table with     |
|     Tampering                     |                    | SHA-256 event hashing. Updates/deletes blocked|
+-----------------------------------+--------------------+-----------------------------------------------+
| T6. Malicious Confirmation File   | Medium (P2)        | FileSecurityValidator: magic byte inspection,  |
|     Upload (Malware/Polyglot)     |                    | PDF/PNG/JPG only, 5 MB limit, isolated paths. |
+-----------------------------------+--------------------+-----------------------------------------------+
| T7. Orphaned Applications upon    | Low (P3)           | ON DELETE SET NULL for resumes & JDs;         |
|     Resource Archival             |                    | preserve historical applications and packets. |
+-----------------------------------+--------------------+-----------------------------------------------+
```

---

## 6. Proposed Application Lifecycle & State Machine

The Phase 7 lifecycle cleanly decouples document preparation from real-world submission and subsequent recruitment milestones:

```
                                APPLICATION LIFECYCLE FLOW
                                
       [ Manual Creation ]           [ Job Ingestion / Match ]
                \                               /
                 v                             v
           +-----------+                 +-----------+
           |   DRAFT   | --------------> | PREPARING |
           +-----------+                 +-----------+
                                               |
                                               v
                                     +------------------+
                                     | READY_FOR_REVIEW |
                                     +------------------+
                                               |
                                     (Human Approval Gate)
                                               v
                                        +------------+
                                        |  APPROVED  |
                                        +------------+
                                               |
                               (Candidate Manual Submission)
                                               v
                                       +-------------+
                       +-------------> |  SUBMITTED  | <------------+
                       |               +-------------+              |
                       |                      |                     |
                       |                      v                     |
                       |              +---------------+             |
                       |              |  IN_PROGRESS  |             |
                       |              +---------------+             |
                       |                 /          \               |
                       |                v            v              |
                       |         +------------+ +------------+      |
                       |         | ASSESSMENT | | INTERVIEW  |      |
                       |         +------------+ +------------+      |
                       |                \            /              |
                       |                 v          v               |
                       |                 +----------+               |
                       |                 |  OFFER   |               |
                       |                 +----------+               |
                       |                      |                     |
                       |                      v                     |
                       |                 +----------+               |
                       |                 |  CLOSED  |               |
                       |                 +----------+               |
                       |                      ^                     |
                       |                      |                     |
                       |             +-----------------+            |
                       +------------ |    WITHDRAWN    | -----------+
                       |             +-----------------+            |
                       |                      ^                     |
                       |                      |                     |
                       |             +-----------------+            |
                       +------------ |    REJECTED     | -----------+
                                     +-----------------+
```

### Primary Lifecycle States:

1. **`DRAFT`:** Application stub created manually (e.g. candidate logs an opportunity before uploading a job description or running a match).
2. **`PREPARING`:** Application is actively being prepared (tailored resume being refined, cover letter drafted, or screening questions generated).
3. **`READY_FOR_REVIEW`:** All materials generated, screening questions reviewed, character limits satisfied, packet ready for human audit.
4. **`APPROVED`:** Human approver explicitly reviewed and approved the immutable packet via `HumanApprovalGate` with a valid login session and single-use HMAC action ticket.
5. **`SUBMITTED`:** Candidate has manually completed submission on the external employer site and confirmed submission in the assistant with submission metadata.
6. **`IN_PROGRESS`:** Employer has acknowledged receipt or application is actively under recruiter review.
7. **`ASSESSMENT`:** Candidate received a take-home project, coding test, or online assessment.
8. **`INTERVIEW`:** Candidate is participating in screening, technical, behavioral, or panel interviews.
9. **`OFFER`:** Candidate received a formal job offer.
10. **`REJECTED`:** Candidate was notified of rejection (or application expired/disqualified).
11. **`WITHDRAWN`:** Candidate voluntarily withdrew application from consideration.
12. **`CLOSED`:** Lifecycle concluded (offer accepted, position cancelled, or archive).

---

## 7. Status Transition Matrix

The state machine strictly enforces valid transitions, required preconditions, and mandatory confirmation gates:

| Previous State | Allowed Next States | Initiator | Validation & Preconditions | Mandatory Confirmation | Audit Event Emitted |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `DRAFT` | `PREPARING`, `WITHDRAWN`, `CLOSED` | Candidate | Title and company name non-empty. | No | `APPLICATION_PREPARATION_STARTED` |
| `PREPARING` | `READY_FOR_REVIEW`, `DRAFT`, `WITHDRAWN` | Candidate / System | Tailored resume and cover letter present. | No | `APPLICATION_READY_FOR_REVIEW` |
| `READY_FOR_REVIEW` | `APPROVED`, `PREPARING`, `WITHDRAWN` | Candidate | All screening questions confirmed; zero character-limit violations; authenticated session valid. | Yes (Human Approval Gate) | `PACKET_HUMAN_APPROVED` |
| `APPROVED` | `SUBMITTED`, `READY_FOR_REVIEW`, `WITHDRAWN` | Candidate | Valid approved packet hash must exist; candidate confirms manual submission details. | Yes (Manual Submission Modal) | `SUBMISSION_CONFIRMED` |
| `SUBMITTED` | `IN_PROGRESS`, `ASSESSMENT`, `INTERVIEW`, `REJECTED`, `WITHDRAWN` | Candidate | Submission date valid (not in future); submission channel specified. | Yes | `STATUS_CHANGED_TO_SUBMITTED` |
| `IN_PROGRESS` | `ASSESSMENT`, `INTERVIEW`, `OFFER`, `REJECTED`, `WITHDRAWN` | Candidate | None. | No | `STATUS_CHANGED_TO_IN_PROGRESS` |
| `ASSESSMENT` | `INTERVIEW`, `OFFER`, `REJECTED`, `WITHDRAWN` | Candidate | Assessment type / notes optional. | No | `ASSESSMENT_MILESTONE_LOGGED` |
| `INTERVIEW` | `ASSESSMENT`, `OFFER`, `REJECTED`, `WITHDRAWN` | Candidate | Interview stage / date notes optional. | No | `INTERVIEW_MILESTONE_LOGGED` |
| `OFFER` | `CLOSED`, `REJECTED`, `WITHDRAWN` | Candidate | Offer details / deadline notes optional. | Yes | `OFFER_RECEIVED` |
| `REJECTED` | `CLOSED`, `IN_PROGRESS` (Re-open) | Candidate | Optional rejection reason. | No | `REJECTION_RECORDED` |
| `WITHDRAWN` | `CLOSED`, `IN_PROGRESS` (Re-open) | Candidate | Optional withdrawal reason. | Yes | `APPLICATION_WITHDRAWN` |
| `CLOSED` | `IN_PROGRESS` (Re-open) | Candidate | Admin/candidate re-opening confirmation. | Yes | `APPLICATION_REOPENED` |

---

## 8. Manual Submission Workflow

The manual submission workflow is designed to be frictionless, safe, and transparent:

```
                            MANUAL SUBMISSION WORKFLOW
                            
Candidate Dashboard (Application in 'APPROVED' state)
       |
       v
[ 1. Review Packet Summary ]
       |-- Shows Tailored Resume, Cover Letter, Screening Answers, Attachment Manifest
       |-- Displays External Application URL (SSRF-validated)
       v
[ 2. Action: 'Open Employer Portal' ]
       |-- Opens external URL in a new browser tab with rel="noopener noreferrer"
       |-- Emits audit event: EXTERNAL_APPLICATION_URL_OPENED (does NOT change status!)
       |-- Displays guidance: "Complete your application on the employer's portal, then return here to confirm."
       v
(Candidate Manually Submits on Employer Site)
       v
[ 3. Action: 'Confirm Manual Submission' ]
       |-- Opens confirmation modal / form:
       |     * Submission Date/Time (default: now, past-date allowed)
       |     * Submission Channel (Company Portal, LinkedIn, Email, Referral, Other)
       |     * Confirmation Number / Reference ID (optional)
       |     * Submission Notes (optional)
       |     * Upload Confirmation Document/Screenshot (optional, max 5MB, PDF/PNG/JPG)
       |     * Mandatory Checkbox: "I confirm that I have manually submitted this application."
       v
[ 4. Cryptographic Record & State Transition ]
       |-- Creates immutable record in submission_confirmations table
       |-- Emits audit event: SUBMISSION_CONFIRMED to application_events table
       |-- Updates applications table: status = 'SUBMITTED', date_submitted = timestamp
       v
[ 5. Automated Follow-Up Prompt ]
       |-- "Submission recorded! Would you like to schedule a reminder to follow up in 7 days?"
       |-- One-click creation of follow-up task
```

---

## 9. Proposed Database Schema

To support the full application lifecycle, audit timeline, and follow-up management while preserving existing Phase 1–6 data, Phase 7 introduces three new tables and augments the existing `applications` table:

### 9.1 Augmented `applications` Table
Existing applications table is preserved and extended to support manual creation, rich metadata, and archival:

```sql
-- Upgraded applications table with full Phase 7 lifecycle support
CREATE TABLE IF NOT EXISTS applications_v7 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    job_description_id INTEGER,
    job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    active_resume_id INTEGER,
    company_name TEXT NOT NULL,
    job_title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN (
        'DRAFT', 'PREPARING', 'READY_FOR_REVIEW', 'APPROVED',
        'SUBMITTED', 'IN_PROGRESS', 'ASSESSMENT', 'INTERVIEW',
        'OFFER', 'REJECTED', 'WITHDRAWN', 'CLOSED',
        -- Legacy status compatibility
        'Discovered', 'Under Review', 'Shortlisted', 'Application Prepared', 'Awaiting Approval', 'Applied'
    )),
    application_source TEXT NOT NULL DEFAULT 'JOB_DESCRIPTION' CHECK (application_source IN ('JOB_DESCRIPTION', 'MATCH_RESULT', 'PREPARED_PACKET', 'MANUAL')),
    external_application_url TEXT,
    target_role TEXT,
    employment_type TEXT,
    location TEXT,
    salary_range TEXT,
    application_deadline DATETIME,
    date_prepared DATETIME,
    date_submitted DATETIME,
    resume_used TEXT,
    cover_letter_reference TEXT,
    notes TEXT,
    is_archived INTEGER DEFAULT 0 CHECK(is_archived IN (0, 1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(id, user_id),
    FOREIGN KEY (job_description_id, user_id) REFERENCES job_descriptions(id, user_id) ON DELETE SET NULL,
    FOREIGN KEY (active_resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE SET NULL
);
```

### 9.2 New `application_events` Table (Append-Only Audit Timeline)
Tracks all lifecycle milestones, state transitions, and user actions:

```sql
CREATE TABLE IF NOT EXISTS application_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT,
    actor_type TEXT NOT NULL DEFAULT 'CANDIDATE' CHECK(actor_type IN ('CANDIDATE', 'SYSTEM')),
    actor_name TEXT NOT NULL,
    session_id TEXT,
    event_payload_json TEXT,
    event_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_events_app_user ON application_events(application_id, user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_app_events_user_type ON application_events(user_id, event_type);
```

### 9.3 New `submission_confirmations` Table
Captures authoritative proof and metadata for candidate-submitted applications:

```sql
CREATE TABLE IF NOT EXISTS submission_confirmations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    packet_id INTEGER,
    packet_version_hash TEXT,
    submission_timestamp DATETIME NOT NULL,
    submission_channel TEXT NOT NULL CHECK(submission_channel IN ('COMPANY_PORTAL', 'LINKEDIN', 'INDEEP', 'EMAIL', 'RECRUITER', 'REFERRAL', 'OTHER')),
    confirmation_reference TEXT,
    confirmation_doc_path TEXT,
    confirmation_doc_hash TEXT,
    candidate_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (packet_id, user_id) REFERENCES prepared_packets(id, user_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_sub_conf_app ON submission_confirmations(application_id, user_id);
```

### 9.4 New `application_follow_ups` Table
Enables candidate-controlled reminder and follow-up scheduling:

```sql
CREATE TABLE IF NOT EXISTS application_follow_ups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    follow_up_date DATE NOT NULL,
    follow_up_type TEXT NOT NULL CHECK(follow_up_type IN ('STATUS_INQUIRY', 'THANK_YOU_NOTE', 'PORTFOLIO_UPDATE', 'RECRUITER_CHECKIN', 'PHONE_CALL', 'OTHER')),
    description TEXT NOT NULL,
    is_completed INTEGER DEFAULT 0 CHECK(is_completed IN (0, 1)),
    completed_at DATETIME,
    outcome_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_follow_ups_user_due ON application_follow_ups(user_id, is_completed, follow_up_date);
CREATE INDEX IF NOT EXISTS idx_follow_ups_app ON application_follow_ups(application_id, user_id);
```

---

## 10. Proposed Migration Strategy

A 10-step zero-downtime, idempotent SQLite migration `_migrate_phase7_lifecycle_tables()` in `src/database/db_manager.py`:

1. **Verify Database Integrity:** Execute `PRAGMA foreign_key_check` and `PRAGMA integrity_check` before starting.
2. **Begin Atomic Transaction:** All migration steps wrapped inside `with self.transaction()`.
3. **Inspect Existing `applications` Columns:** Check `PRAGMA table_info(applications)` to see if Phase 7 columns (`external_application_url`, `application_source`, `is_archived`) already exist.
4. **Table Rebuild (if needed for CHECK constraints):**
   - Create `applications_v7` with expanded status CHECK constraint and composite foreign keys (`ON DELETE SET NULL` on `job_descriptions` and `resumes`).
   - Copy existing records: `INSERT INTO applications_v7 SELECT ... FROM applications`.
   - Drop old `applications` table and rename `applications_v7` to `applications`.
5. **Create Child Tables:**
   - Execute `CREATE TABLE IF NOT EXISTS application_events`.
   - Execute `CREATE TABLE IF NOT EXISTS submission_confirmations`.
   - Execute `CREATE TABLE IF NOT EXISTS application_follow_ups`.
6. **Create Performance & Security Indexes:**
   - Index on `(application_id, user_id, created_at)` for fast timeline rendering.
   - Index on `(user_id, is_completed, follow_up_date)` for fast follow-up notifications.
7. **Backfill Initial Events for Historical Applications:**
   - For applications with `date_prepared IS NOT NULL`, insert `APPLICATION_PREPARED` event.
   - For applications with `status = 'Applied'` or `date_submitted IS NOT NULL`, insert `SUBMISSION_CONFIRMED` event.
8. **Re-enable Foreign Keys & Validate:**
   - Execute `PRAGMA foreign_key_check` to guarantee zero dangling references.
9. **Log Migration Success:**
   - Record migration record in `auth_audit_logs` or application log.
10. **Idempotence Check:**
    - Subsequent runs detect existing tables and columns, exiting cleanly with zero side-effects.

---

## 11. Proposed Service & API Architecture

All operations will be housed in `DashboardService` and backed by `DatabaseManager`, enforcing session-derived user authentication:

```
                                  SERVICE ARCHITECTURE
                                  
   Streamlit Views (Tracker / Preparer)
             |
             v (passes authenticated user_id & session_id)
   +-------------------------------------------------------------------+
   | DashboardService (Security & Lifecycle Orchestration)            |
   |                                                                   |
   |   create_candidate_application(...)                               |
   |   get_candidate_application(application_id, user_id)             |
   |   list_candidate_applications(user_id, filters, sorting)          |
   |   transition_application_status(application_id, user_id, ...)     |
   |   record_manual_submission(application_id, user_id, ...)          |
   |   get_application_timeline(application_id, user_id)               |
   |   create_application_follow_up(application_id, user_id, ...)      |
   |   complete_application_follow_up(follow_up_id, user_id, ...)     |
   +-------------------------------------------------------------------+
             |
             +---------------------------+
             |                           |
             v                           v
   +---------------------------+   +---------------------------+
   | ApplicationStateMachine   |   | DatabaseManager           |
   | (Validation, Preconditions|   | (ACID Transactions,       |
   |  and Event Emitting)      |   |  Composite Key Queries,   |
   +---------------------------+   |  Audit Record Storage)    |
                                   +---------------------------+
```

### Detailed Method Specifications:

1. **`create_candidate_application(user_id: int, company_name: str, job_title: str, ...)`**
   - *Input:* `user_id`, `company_name`, `job_title`, optional `job_description_id`, `resume_id`, `url`, `employment_type`.
   - *Validation:* Verifies ownership of JD and resume. Prevents duplicate active application for same company + title.
   - *Output:* Newly created `Application` model.
   - *Audit:* Emits `APPLICATION_CREATED`.

2. **`transition_application_status(application_id: int, user_id: int, new_status: str, session_id: str, notes: Optional[str] = None)`**
   - *Input:* `application_id`, `user_id`, `new_status`, `session_id`, `notes`.
   - *Validation:* Validates active session via `get_authenticated_candidate_session`. Checks transition matrix via `ApplicationStateMachine`.
   - *Output:* `Tuple[bool, str, Application]`.
   - *Audit:* Emits `APPLICATION_STATUS_UPDATED` with `previous_status` and `new_status`.

3. **`record_candidate_manual_submission(application_id: int, user_id: int, session_id: str, submission_channel: str, ...)`**
   - *Input:* `application_id`, `user_id`, `session_id`, `submission_channel`, `submission_timestamp`, `confirmation_reference`, optional confirmation file bytes, notes.
   - *Validation:* Verifies application is in `APPROVED` state. Verifies active session ownership. If file provided, validates magic bytes via `FileSecurityValidator` and writes to isolated user folder.
   - *Output:* `Tuple[bool, str, SubmissionConfirmation]`.
   - *Audit:* Emits `SUBMISSION_CONFIRMED`. Sets `applications.status = 'SUBMITTED'`.

4. **`get_application_timeline(application_id: int, user_id: int) -> List[ApplicationEvent]`**
   - *Input:* `application_id`, `user_id`.
   - *Validation:* Verifies application belongs to `user_id`.
   - *Output:* Chronological list of `ApplicationEvent` objects.

5. **`create_application_follow_up(application_id: int, user_id: int, follow_up_date: date, follow_up_type: str, description: str)`**
   - *Input:* `application_id`, `user_id`, `follow_up_date`, `follow_up_type`, `description`.
   - *Output:* Newly created `ApplicationFollowUp`.
   - *Audit:* Emits `FOLLOW_UP_SCHEDULED`.

---

## 12. Proposed Dashboard Architecture

The existing `dashboard/views/application_tracker.py` page will be overhauled to present an executive candidate application control center:

### Component Layout:
1. **Header & KPI Metric Cards:**
   - Total Tracked Applications.
   - Ready for Review / Approved.
   - Submitted / In Progress.
   - Active Interviews & Assessments.
   - Offers Received.
   - Upcoming / Overdue Follow-ups (highlighted badge).
2. **Search, Filter & View Controls:**
   - Full-text search across company, job title, and notes.
   - Multi-select status filter (e.g. "Only Active", "Submitted", "Interviews").
   - View Toggle:
     - **Board View (Kanban):** Drag-and-drop or column layout categorized by lifecycle stages:
       `[Preparing & Ready]` -> `[Approved (Awaiting Submission)]` -> `[Submitted & In Progress]` -> `[Interviews & Offers]` -> `[Closed & Archived]`.
     - **Table View:** Dense tabular layout with sortable columns, status badges, match scores, and quick action buttons.
3. **Application Detail Hub (Slide-out / Expander):**
   - **Overview Tab:** Company, role, location, employment type, salary, match score badge, external job link.
   - **Document Manifest Tab:** One-click download buttons for the exact tailored resume (PDF/DOCX) and cover letter used, and link to view canonical approved packet.
   - **Timeline Tab:** Visual vertical stepper of all chronological events with actor, timestamp, and details.
   - **Status Transition Bar:** Clear buttons for allowable next transitions based on current state.
   - **Manual Submission Action:** If `APPROVED`, displays prominent "Submit on Employer Site" card with link and "Confirm Submission" trigger.
   - **Follow-Up Manager:** List of scheduled follow-ups, checkbox to mark complete with outcome notes, and "Add Follow-up" form.

---

## 13. Application Timeline & Audit Design

Every state change, document action, and candidate confirmation writes an immutable record to `application_events`:

### Event Structure:
- `event_id`: Auto-incrementing integer.
- `application_id`: Scoped application ID.
- `user_id`: Authenticated user ID.
- `event_type`: Standardized enum string (e.g. `APPLICATION_CREATED`, `RESUME_TAILORED`, `PACKET_APPROVED`, `EXTERNAL_URL_OPENED`, `SUBMISSION_CONFIRMED`, `STATUS_CHANGED`, `FOLLOW_UP_SCHEDULED`, `INTERVIEW_LOGGED`).
- `previous_status` & `new_status`: Captures state delta if applicable.
- `actor_type` (`CANDIDATE` or `SYSTEM`) & `actor_name`.
- `session_id`: Active session identifier.
- `event_payload_json`: RFC 8785 canonical JSON string of event metadata.
- `event_hash`: SHA-256 hash of `f"{application_id}:{event_type}:{previous_status}:{new_status}:{timestamp}:{payload_json}"`.
- `created_at`: UTC timestamp.

### Immutability Assurance:
- No `UPDATE` or `DELETE` queries are ever exposed or executed against `application_events`.
- SQLite trigger or application-level enforcement prevents modifying existing event records.

---

## 14. Follow-Up Management Design

Candidate follow-up tracking provides proactive organization without intrusive or automated communications:

1. **Follow-Up Types:**
   - `STATUS_INQUIRY`: Follow-up on submitted application (e.g. 10–14 days post-submission).
   - `THANK_YOU_NOTE`: Post-interview thank you email (within 24 hours of interview).
   - `PORTFOLIO_UPDATE`: Sending updated work samples or project links.
   - `RECRUITER_CHECKIN`: Periodic touchpoint with hiring manager or recruiter.
   - `PHONE_CALL`: Scheduled call or outreach.
   - `OTHER`: Custom candidate reminder.
2. **Strict Privacy & Anti-Spam Principle:**
   - The platform **never sends emails or messages** automatically to recruiters or external employers.
   - Reminders are surfaced exclusively within the candidate dashboard UI (e.g. warning chip: "2 Follow-ups Due Today").
3. **Completion & Outcome Tracking:**
   - Candidate clicks "Mark Complete", enters optional outcome notes (e.g. "Recruiter replied, scheduled screen for Thursday"), and records `completed_at`.

---

## 15. Multi-User Isolation Strategy

Multi-user safety is enforced across four distinct architectural layers:

```
                            FOUR-LAYER ISOLATION MODEL
                            
Layer 1: Session Resolution
   `DashboardService.get_authenticated_candidate_session(user_id, session_id)`
   Rejects missing, expired, unbound, or cross-user sessions.
   
Layer 2: Service-Layer Parameter Derivation
   user_id is NEVER read from user input or UI text fields.
   It is derived strictly from st.session_state["authenticated_user_id"].
   
Layer 3: Relational Composite Key Queries
   Every SQL SELECT / UPDATE / DELETE query mandates:
   `WHERE id = :resource_id AND user_id = :authenticated_user_id`
   Attempting to access another user's ID returns None or raises CrossUserAccessError.
   
Layer 4: Database Foreign Key Constraints
   Composite constraints enforce integrity at SQLite level:
   `FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE`
```

---

## 16. Testing Strategy

Phase 7 introduces 5 targeted test suites designed to achieve 100% test pass rate across the full repository:

1. **`tests/test_application_lifecycle_schema.py` (Database & Migrations):**
   - Verifies table creation, columns, composite foreign keys, and indexes.
   - Tests migration from legacy schema with historical data backfilling.
   - Verifies `PRAGMA foreign_key_check` and `PRAGMA integrity_check`.
2. **`tests/test_application_state_machine.py` (State Transitions):**
   - Tests all valid transitions in transition matrix.
   - Asserts rejection of illegal transitions (e.g. `DRAFT` directly to `SUBMITTED`).
   - Asserts rejection of transition to `APPROVED` without valid human approval gate.
   - Asserts rejection of transition to `SUBMITTED` without approved packet.
3. **`tests/test_submission_and_timeline.py` (Manual Submission & Audit):**
   - Tests recording manual submission with channels, dates, and confirmation notes.
   - Tests confirmation file upload validation (rejects invalid MIME/magic bytes, accepts valid PDF/PNG).
   - Verifies append-only event timeline ordering and event hashing.
   - Asserts that opening external URL emits an event but does NOT mark application as submitted.
4. **`tests/test_application_follow_ups.py` (Follow-Up Management):**
   - Tests creating, listing, filtering, and completing follow-ups.
   - Verifies overdue calculation and status filtering.
5. **`tests/test_application_lifecycle_security.py` (Multi-User Isolation & IDOR):**
   - User A cannot view, transition, submit, or schedule follow-ups for User B's application.
   - Forged `user_id` or cross-user session IDs fail closed with `SecurityAuthorizationError`.
   - Archiving job description or resume does not orphan application (`ON DELETE SET NULL`).
   - Full regression suite execution (verifying all 470 existing tests continue to pass).

---

## 17. File-by-File Implementation Plan

| Action | File Path | Scope of Implementation |
| :--- | :--- | :--- |
| **Modify** | `src/database/schema.sql` | Add DDL for `application_events`, `submission_confirmations`, `application_follow_ups`, and upgrade `applications` table. |
| **Modify** | `src/database/models.py` | Add dataclasses `ApplicationEvent`, `SubmissionConfirmation`, `ApplicationFollowUp`, and update `ApplicationStatus` enum. |
| **Modify** | `src/database/db_manager.py` | Add migration `_migrate_phase7_lifecycle_tables()` and CRUD operations for applications, events, submissions, and follow-ups. |
| **Create** | `src/lifecycle/__init__.py` | Package initialization for lifecycle management. |
| **Create** | `src/lifecycle/state_machine.py` | `ApplicationStateMachine` enforcing valid transitions, preconditions, and event emission. |
| **Modify** | `dashboard/services/dashboard_service.py` | Add high-level lifecycle orchestrator methods (`transition_application_status`, `record_manual_submission`, etc.). |
| **Modify** | `dashboard/views/application_tracker.py` | Overhaul page to render multi-user Kanban board, metrics, detail view, timeline stepper, and follow-up manager. |
| **Modify** | `dashboard/views/application_preparer.py` | Seamless handoff in Tab 7/8 linking approved applications to Tracker submission workflow. |
| **Create** | `tests/test_application_lifecycle_schema.py` | Migration and relational constraint tests. |
| **Create** | `tests/test_application_state_machine.py` | State machine transition tests. |
| **Create** | `tests/test_submission_and_timeline.py` | Submission confirmation and timeline tests. |
| **Create** | `tests/test_application_follow_ups.py` | Follow-up management tests. |
| **Create** | `tests/test_application_lifecycle_security.py` | Multi-user isolation, IDOR, and session security tests. |
| **Modify** | `docs/PHASE_7_APPLICATION_LIFECYCLE.md` | Comprehensive user and developer documentation. |
| **Modify** | `AGENTS.md` | Roadmap checklist updates upon verified completion. |

---

## 18. Implementation Sequence Divided into Incremental Sub-Phases

To prevent regressions and ensure surgical precision, Phase 7 implementation is partitioned into six discrete sub-phases:

```
                               PHASE 7 IMPLEMENTATION WAVES
                               
   +--------------------------------------------------------------------------+
   | Phase 7.1: Database Models, Schema Migration & Relational Constraints    |
   |   - Schema migration for applications, events, confirmations, follow-ups |
   |   - Dataclass models & enums in models.py                                |
   |   - Automated regression test suite: test_application_lifecycle_schema.py|
   +--------------------------------------------------------------------------+
                                        |
                                        v
   +--------------------------------------------------------------------------+
   | Phase 7.2: Application State Machine & Core Service Layer                |
   |   - ApplicationStateMachine validation engine in src/lifecycle/          |
   |   - Status transition methods with strict preconditions in db_manager    |
   |   - Automated regression test suite: test_application_state_machine.py   |
   +--------------------------------------------------------------------------+
                                        |
                                        v
   +--------------------------------------------------------------------------+
   | Phase 7.3: Manual Submission Confirmation & Append-Only Timeline         |
   |   - Candidate submission confirmation workflow & document storage        |
   |   - Immutable event recording with SHA-256 event hashing                 |
   |   - Automated regression test suite: test_submission_and_timeline.py     |
   +--------------------------------------------------------------------------+
                                        |
                                        v
   +--------------------------------------------------------------------------+
   | Phase 7.4: Candidate-Controlled Follow-Up Engine                         |
   |   - Follow-up scheduling, categorization, and completion logging         |
   |   - Due-date calculation and filtering without automated outbound spam   |
   |   - Automated regression test suite: test_application_follow_ups.py      |
   +--------------------------------------------------------------------------+
                                        |
                                        v
   +--------------------------------------------------------------------------+
   | Phase 7.5: Streamlit Application Tracker & Lifecycle UI Overhaul         |
   |   - Complete redesign of dashboard/views/application_tracker.py          |
   |   - Kanban board, timeline stepper, submission modal, and follow-up chips|
   |   - Application preparer Tab 7/8 integration                             |
   +--------------------------------------------------------------------------+
                                        |
                                        v
   +--------------------------------------------------------------------------+
   | Phase 7.6: Multi-User Security Hardening, Full Regression & Verification |
   |   - Cross-user IDOR penetration tests (test_application_lifecycle_sec)   |
   |   - Full test suite verification (100% pass rate across all tests)       |
   |   - Static analysis: Ruff, Pyflakes, Mypy, git diff --check              |
   |   - Documentation in PHASE_7_APPLICATION_LIFECYCLE.md & AGENTS.md        |
   +--------------------------------------------------------------------------+
```

---

## 19. Risks & Mitigations

| Risk Identified | Severity | Architectural Mitigation |
| :--- | :--- | :--- |
| **R1. Breaking Phase 2 / Phase 6 Tests** | High | Backward compatibility aliases maintained: `ApplicationStatus` supports both new uppercase and legacy title-case strings (`Discovered`, `Under Review`, `Applied`). Legacy `job_id`-based methods delegate safely without breaking catalog workflows. |
| **R2. Accidental Automated Submission** | Critical | Strict architectural barrier: zero browser execution libraries (`playwright.sync_api`, `selenium`) imported into lifecycle modules. Only outbound link formatting. |
| **R3. Database Lock Contention on Events** | Medium | Event timeline records are inserted in the same atomic transaction as the status update, minimizing open lock windows. SQLite WAL mode already enabled. |
| **R4. Orphaned Records upon Resume Deletion**| Medium | `ON DELETE SET NULL` applied to `job_descriptions` and `resumes` foreign keys in `applications`; application history remains intact even if original resume is archived. |

---

## 20. Acceptance Criteria

Phase 7 will be considered complete and verified only when:

1. **State Machine Verification:** All 12 lifecycle states and valid transitions operate deterministically with invalid transitions rejected by `ApplicationStateMachine`.
2. **Manual Submission Separation:** `APPROVED` and `SUBMITTED` operate as strictly distinct states; an application cannot become `SUBMITTED` without candidate confirmation of external submission details.
3. **Audit Trail Completeness:** Opening the external URL, updating statuses, confirming submission, and logging follow-ups each append an immutable record to `application_events`.
4. **Follow-Up Management:** Candidates can create, view, complete, and track follow-ups with zero automated outbound spam.
5. **Dashboard Usability:** `Application Tracker` displays the candidate's actual multi-user applications with interactive Kanban, detail drawer, timeline stepper, and document download links.
6. **Multi-User Isolation:** All operations enforce `user_id` derived from active session; cross-user access attempts raise `CrossUserAccessError` or fail closed.
7. **Regression Integrity:** 100% pass rate on all 470 existing unit tests plus all new Phase 7 test suites.
8. **Static Analysis Clean:** 0 Ruff syntax/fatal errors, 0 Pyflakes errors on modified files, and clean `git diff --check`.

---

## 21. Explicit Out-of-Scope Features

The following capabilities are strictly forbidden from implementation in Phase 7:

- ❌ **Automatic Application Submission:** No automated bot form submission, headless browser button clicking on employer portals, or ATS script execution.
- ❌ **Employer Portal Authentication:** No storing, prompting for, or decrypting candidate passwords or session cookies for third-party employer portals (Workday, Greenhouse, Lever, Taleo, etc.).
- ❌ **CAPTCHA or Anti-Bot Bypassing:** No integration with 2Captcha, AntiCaptcha, Cloudflare turnstile bypassers, or fingerprint spoofers.
- ❌ **Automated Outbound Messaging:** No automatic emailing, SMS, or direct messaging to recruiters or employers.
- ❌ **Inferred Submission:** Never marking an application as submitted merely because an external link was clicked or a timer elapsed.

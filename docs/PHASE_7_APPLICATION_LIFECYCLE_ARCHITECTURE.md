# PHASE 7 — APPLICATION LIFECYCLE & TRACKING
## Architecture Audit, Security Review & Implementation Blueprint

**Architecture Version:** v2.1.1  
**Project:** Universal AI Job Application Assistant  
**Document:** `docs/PHASE_7_APPLICATION_LIFECYCLE_ARCHITECTURE.md`  
**Current Commit:** `5e9587891d636403594047652bf3da2e5943ec15` (Verified Base Commit for Phase 7.1)
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

## 9. Implemented Database Schema (Phase 7.1 Verified Foundation)

To support the full application lifecycle, audit timeline, and follow-up management while preserving existing Phase 1–6 data, Phase 7 introduces three new tables and augments the existing `applications` table with strict composite ownership:

### 9.1 Augmented `applications` Table
Existing applications table is preserved and extended to support manual creation, rich metadata, and archival:

```sql
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    job_description_id INTEGER,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resume_id INTEGER,
    company_name TEXT NOT NULL,
    job_title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'DRAFT' CHECK(status IN (
        'DRAFT', 'PREPARING', 'READY_FOR_REVIEW', 'APPROVED',
        'SUBMITTED', 'IN_PROGRESS', 'ASSESSMENT', 'INTERVIEW',
        'OFFER', 'REJECTED', 'WITHDRAWN', 'CLOSED',
        -- Legacy status compatibility
        'Discovered', 'Under Review', 'Shortlisted', 'Application Prepared',
        'Awaiting Approval', 'Applied', 'Interview', 'Rejected', 'Withdrawn'
    )),
    application_source TEXT NOT NULL DEFAULT 'JOB_DESCRIPTION' CHECK(application_source IN ('JOB_DESCRIPTION', 'MATCH_RESULT', 'PREPARED_PACKET', 'MANUAL')),
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
    FOREIGN KEY (job_description_id, user_id) REFERENCES job_descriptions(id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE RESTRICT
);
```

#### Composite Foreign Key Deletion Behavior:
- **`job_descriptions` and `resumes`:** Enforced as `ON DELETE RESTRICT`. A composite foreign key referencing `(id, user_id)` cannot use `ON DELETE SET NULL` because `user_id` is a required primary owner field that cannot be NULL. Physical deletion of active source resumes or job descriptions linked to applications is blocked (`ResumeInUseError` or soft-archival `is_active = 0`), preserving historical relationship integrity.
- **`job_id`:** Single-column reference to global scraped catalog jobs using `ON DELETE SET NULL` (catalog cleanups do not delete candidate applications).
- **`user_id`:** Enforced as `NOT NULL REFERENCES users(id) ON DELETE CASCADE`.

### 9.2 `application_events` Table (Append-Only Audit Timeline)
Tracks all lifecycle milestones, state transitions, and user actions with cryptographic hash linkage:

```sql
CREATE TABLE IF NOT EXISTS application_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sequence_no INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT,
    actor_type TEXT NOT NULL DEFAULT 'CANDIDATE' CHECK(actor_type IN ('CANDIDATE', 'SYSTEM')),
    actor_identifier TEXT NOT NULL,
    session_reference TEXT,
    event_payload_json TEXT NOT NULL DEFAULT '{}',
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(application_id, sequence_no),
    FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE RESTRICT
);

CREATE TRIGGER IF NOT EXISTS trg_prevent_application_events_update
BEFORE UPDATE ON application_events
BEGIN
    SELECT RAISE(FAIL, 'application_events records are append-only and cannot be updated.');
END;

CREATE TABLE IF NOT EXISTS _privacy_erasure_tokens (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token_nonce TEXT NOT NULL,
    authorized_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS trg_prevent_application_events_delete
BEFORE DELETE ON application_events
BEGIN
    SELECT RAISE(FAIL, 'application_events records are immutable and cannot be deleted except via authorized privacy erasure.')
    WHERE NOT EXISTS (
        SELECT 1 FROM _privacy_erasure_tokens WHERE user_id = OLD.user_id
    );
END;
```

#### Event Immutability & Retention Guarantees:
- **Append-Only Trigger:** `trg_prevent_application_events_update` aborts any direct `UPDATE` statement on `application_events`.
- **Deletion Prevention Trigger:** `trg_prevent_application_events_delete` blocks any direct `DELETE` statement on `application_events` during normal database operations.
- **Application Deletion Invariant:** `FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE RESTRICT` ensures normal application deletions are prevented when event history exists; applications must be archived (`is_archived = 1`) rather than physically deleted.
- **Cryptographic Hash Chain (v2 with Timestamp Binding):** Each event computes `event_hash = SHA256(RFC8785_canonical_json(hash_payload))` where `hash_payload` covers `sequence_no`, `application_id`, `user_id`, `event_type`, `previous_status`, `new_status`, `actor_type`, `actor_identifier`, `session_reference`, `event_payload_json`, `created_at` (UTC timestamp string), and `previous_event_hash` (`'GENESIS'` for sequence 1). Binding `created_at` prevents retroactive timestamp forgery. Backward compatibility maintains verification of legacy v1 hashes.
- **Honest Security Scope & Tail-Deletion Limitation:** The SHA-256 chain provides deterministic tamper evidence against tampering, payload altering, timestamp forging, and out-of-order mutations when verified via `verify_application_event_chain`. However, a database administrator who truncates or drops the final event (tail deletion) cannot be detected by internal chain hashing alone without an external trusted checkpoint (such as a signed external ledger or immutable application status checkpoint).
- **Authorized Privacy Erasure (GDPR):** When a user explicitly exercises their right to be forgotten via `delete_user_account_data`, an ephemeral authorization token is inserted into `_privacy_erasure_tokens` within the atomic transaction, permitting `application_events` deletion before deleting the user and cleaning up the token.

### 9.3 `submission_confirmations` Table
Captures authoritative proof and metadata for candidate-submitted applications:

```sql
CREATE TABLE IF NOT EXISTS submission_confirmations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    packet_id INTEGER,
    packet_version_hash TEXT,
    submission_timestamp DATETIME NOT NULL,
    submission_channel TEXT NOT NULL CHECK(submission_channel IN ('COMPANY_PORTAL', 'LINKEDIN', 'INDEED', 'EMAIL', 'RECRUITER', 'REFERRAL', 'OTHER')),
    confirmation_reference TEXT,
    confirmation_doc_path TEXT,
    confirmation_doc_hash TEXT,
    candidate_notes TEXT,
    is_active_confirmation INTEGER DEFAULT 1 CHECK(is_active_confirmation IN (0, 1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (packet_id, user_id) REFERENCES prepared_packets(id, user_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_conf_active_app ON submission_confirmations(application_id) WHERE is_active_confirmation = 1;
```

#### Submission Safeguard Invariants:
- `submission_channel` is controlled (`COMPANY_PORTAL`, `LINKEDIN`, `INDEED`, `EMAIL`, `RECRUITER`, `REFERRAL`, `OTHER`).
- Partial unique index `idx_sub_conf_active_app` allows complete historical submission re-attempts while guaranteeing at most one active confirmation per application (`is_active_confirmation = 1`).
- `FOREIGN KEY (packet_id, user_id) REFERENCES prepared_packets(id, user_id) ON DELETE RESTRICT`: Hardened in Phase 7.1.1 from `ON DELETE SET NULL` to `ON DELETE RESTRICT` to guarantee that prepared packet audit records cannot be deleted while referenced by active or historical submission records.
- **Storage-Only vs. Status Transition Boundary:**
  - `transition_status=False` (default): Purely stores external confirmation metadata without mutating application status.
  - `transition_status=True`: Strictly validates that `packet_id` is supplied, that the application is in an approved state (`APPROVED`), that an active revision packet exists with an unconsumed human approval record in `application_approvals`, consumes the approval ticket atomically (`is_consumed = 1`, `consumed_at = CURRENT_TIMESTAMP`), advances status to `SUBMITTED`, sets `date_submitted`, and emits `SUBMISSION_CONFIRMED`.
- Candidate-provided evidence is recorded truthfully without presenting unverified candidate entries as employer-verified receipts.

### 9.4 `application_follow_ups` Table
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
```

---

## 10. Implemented Migration Strategy (`_migrate_phase7_lifecycle_tables`)

A 12-step zero-downtime, idempotent, fully transactional SQLite migration `_migrate_phase7_lifecycle_tables()` in `src/database/db_manager.py`:

1. **Verify Database Integrity:** Inspect `applications` table existence, column nullability, and foreign key definitions. If already migrated with NOT NULL `user_id` and RESTRICT constraints, returns immediately.
2. **Preflight Ownership & Integrity Safeguards:** Abort with `MigrationPreflightError` if:
   - Any application has `user_id IS NULL`. Historical applications are never arbitrarily assigned.
   - Any application has invalid non-existent `user_id`.
   - Cross-user reference detected on `job_descriptions` (`applications.user_id != job_descriptions.user_id`).
   - Cross-user reference detected on `resumes` (`applications.user_id != resumes.user_id`).
   - Cross-user reference detected on `prepared_packets` or `application_approvals`.
3. **Deterministic Legacy Status Mapping (Real Schema Query):**
   - Queries `application_approvals` joined with `prepared_packets` using actual Phase 6.1.3 schema:
     `a.is_consumed = 0 AND p.is_active_revision = 1 AND a.packet_version_hash = p.packet_version_hash AND a.application_id = p.application_id AND a.user_id = p.user_id`.
   - `Discovered` -> `DRAFT`
   - `Under Review` / `Shortlisted` -> `PREPARING`
   - `Application Prepared` -> `READY_FOR_REVIEW`
   - `Awaiting Approval` -> `APPROVED` if and only if an active unconsumed human approval matches the active packet; otherwise maps conservatively to `READY_FOR_REVIEW`.
   - `Applied` -> `SUBMITTED` (without fabricating false submission confirmations).
   - `Interview` -> `INTERVIEW`, `Rejected` -> `REJECTED`, `Withdrawn` -> `WITHDRAWN`.
4. **Explicit Transactional Boundary & Atomic Rollback:**
   - Uses manual isolation mode (`conn.isolation_level = None`).
   - Disables foreign keys (`PRAGMA foreign_keys = OFF;`) and starts an immediate transaction (`BEGIN IMMEDIATE TRANSACTION;`).
   - All steps (table rebuild, row copy, table swap, index creation, child table creation, trigger installation, event backfill) execute within this atomic transaction.
   - If any exception occurs at any point, `ROLLBACK;` is cleanly executed and `conn.isolation_level` and foreign keys are restored in `finally`, leaving the legacy database 100% intact.
5. **Table Rebuild Execution:**
   - Create replacement table `applications_v7` with strict composite constraints and status CHECK constraints.
   - Copy existing rows using explicit column lists, preserving application IDs, company names, job titles, and timestamps.
   - Drop old `applications` table and rename `applications_v7` to `applications`.
6. **Recreate Dependent Indexes:**
   - `idx_applications_user`, `idx_applications_user_status`, `idx_applications_job_id`, `idx_applications_archived`, `idx_applications_status`, `uq_applications_id_user`, `uq_applications_user_jd`.
7. **Ensure Child Tables Exist:**
   - `application_events`, `submission_confirmations`, `application_follow_ups`, `_privacy_erasure_tokens`, and triggers `trg_prevent_application_events_update` & `trg_prevent_application_events_delete`.
8. **Backfill Initial Events for Historical Applications:**
   - For every migrated application without an event, insert `MIGRATION_INITIALIZED` event with `sequence_no = 1`, `previous_event_hash = "GENESIS"`, `hash_version = "v2"`, UTC timestamp binding, and canonical JSON payload preserving the legacy status.
9. **Post-Migration Verification & Commit:**
   - Validate integrity before commit: `PRAGMA foreign_key_check;` and `PRAGMA integrity_check;`.
   - On discrepancy, executes `ROLLBACK;` and raises `DatabaseMigrationError`.
   - On clean check, executes `COMMIT;`.
10. **Idempotence Guarantee:**
    - Subsequent executions detect existing tables, constraints, and events, returning immediately with zero side-effects.

### 10.1 Discovered Catalogue Job Insertion vs. User Application Tracking

In Phase 1–5, the platform operated as a single-candidate tool, meaning discovered scraper jobs in the catalog were automatically treated as applications for that single candidate (`ApplicationStatus.DISCOVERED`).

In the multi-user architecture (Phase 6–7), public catalog discovery and candidate-owned applications are cleanly separated:
- **`insert_job()`:** Inserts public job listings into the `jobs` catalog. It **never** assigns jobs to arbitrary users (no `SELECT id FROM users LIMIT 1`) and **never** creates placeholder system users (`system@localhost`).
- **`insert_job(job, user_id=...)` (Backwards Compatibility):** When an explicit, validated `user_id` is passed, it validates that the user exists and creates an application record and `APPLICATION_CREATED` event specifically for that candidate.
- **Candidate Application Creation:** Candidates track catalog or manual opportunities via `create_user_application(user_id=..., job_id=...)`, preserving strict ownership boundaries.

### 10.2 Phase 7.1.1 Corrective Hardening Summary

| Area | Issue Identified | Corrective Solution Implemented |
| :--- | :--- | :--- |
| **Approval Migration Query** | Queried non-existent `is_revoked = 0` column. | Queried real Phase 6.1.3 schema: `a.is_consumed = 0` joined on `(application_id, user_id, packet_version_hash)` where `is_active_revision = 1`. |
| **Submission Confirmation FK** | Used `ON DELETE SET NULL` on composite `(packet_id, user_id)`. | Hardened to `ON DELETE RESTRICT` preventing deletion of prepared packets referenced in active or historical submission records. |
| **Approval-to-Submission Boundary** | `create_submission_confirmation` lacked clear operational distinction. | Strict separation: `transition_status=False` is storage-only; `transition_status=True` validates preconditions, approved status, active unconsumed approval, atomically consumes ticket, updates status to `SUBMITTED`, and emits `SUBMISSION_CONFIRMED`. |
| **Catalogue Job Insertion** | `insert_job` auto-assigned jobs to `SELECT id FROM users LIMIT 1` or `system@localhost`. | Removed arbitrary user guessing and placeholder candidate creation. Added explicit, validated `user_id` parameter for backwards-compatible test workflows. |
| **Event Hashing & Deletion Protection** | Timestamps were omitted from hash; normal users could delete events. | Upgraded hash to `v2` (binding UTC `created_at` timestamp); installed `trg_prevent_application_events_delete` trigger; restricted event deletion to authorized privacy erasure (`_privacy_erasure_tokens`); documented tail deletion limitation. |
| **Migration Atomicity & Rollback** | Migration lacked explicit transaction wrapping and rollback handling. | Wrapped in `conn.isolation_level = None`, `BEGIN IMMEDIATE TRANSACTION;`, explicit `ROLLBACK;` on error, and verified foreign keys/integrity before `COMMIT;`. |

### 10.3 Phase 7.1.2 Final Database Safety & Migration Hardening Summary

| Area | Issue Identified | Corrective Solution Implemented |
| :--- | :--- | :--- |
| **Generic Event Status Immutability** | `create_application_event()` accepted `new_status` and automatically ran `UPDATE applications SET status = ...`, bypassing state transitions. | Removed status update from `create_application_event()`. Event timeline is strictly append-only audit tracking. Status mutations must occur via explicit, validated lifecycle methods. |
| **Submission Status Allowlist** | Status validation used a blacklist, failing to block invalid non-approved statuses such as `REJECTED`, `WITHDRAWN`, `CLOSED`, `IN_PROGRESS`, etc. | Replaced blacklist with strict allowlist (`APPROVED` and legacy `'Awaiting Approval'`). Any other status raises `SecurityAuthorizationError`. |
| **Consumed Approval Rejection** | Consumed approvals could previously be bypassed if the application was already `SUBMITTED`. | Unconditionally reject consumed approvals (`is_consumed = 1`) on transition attempts. Added `correct_submission_confirmation()` to update artifacts without re-submitting. |
| **Existing Phase 7.1 DB Migration** | Existing Phase 7.1 databases with `SET NULL` on `submission_confirmations` were bypassed because `applications` was already migrated. | Added inspection of `submission_confirmations` foreign keys, automatically rebuilding the table with `ON DELETE RESTRICT` while preserving all rows, IDs, and timestamps. |
| **Migration Lock Ordering** | Preflight checks and application row snapshots occurred before `BEGIN IMMEDIATE TRANSACTION;`, creating race hazards with concurrent writers. | Reordered migration: Set manual isolation -> Disable FKs -> `BEGIN IMMEDIATE TRANSACTION;` acquiring RESERVED write lock -> Preflight checks -> Table rebuilds -> Integrity check -> `COMMIT;`. |
| **Connection-Scoped Privacy Erasure** | Relying on `_privacy_erasure_tokens` table was vulnerable to token insertion, session leakage, and foreign key hazards. | Dropped `_privacy_erasure_tokens` table. Trigger uses connection-scoped SQLite UDF `verify_privacy_erasure_authorization(OLD.user_id) != 1`. Authorization is granted ephemerally via `_authorized_privacy_erasure_scope(conn, user_id)` strictly for the calling connection. |

### 10.4 Phase 7.1.3 Submission Confirmation Audit Consistency & Timestamp Integrity Summary

| Area | Issue Identified | Corrective Solution Implemented |
| :--- | :--- | :--- |
| **Atomic Confirmation Correction** | `correct_submission_confirmation()` committed confirmation updates in one transaction and emitted audit events in a separate, swallowed `try...except` block, risking un-audited state mutation. | Made confirmation metadata updates and `SUBMISSION_CONFIRMATION_UPDATED` timeline event insertion atomic within the same SQLite transaction. Failure at any point triggers complete rollback of both. |
| **Timestamp Separation** | `create_submission_confirmation()` substituted the candidate's reported `submission_timestamp` for `application_events.created_at`, compromising audit trail chronometry. | Separated candidate-reported submission time (`submission_confirmations.submission_timestamp`, `applications.date_submitted`) from server event creation time (`application_events.created_at`). Server UTC time is bound into the v2 hash and verified independently. |
| **Audit Event Semantics** | Inconsistent event type naming obscured whether an application transition occurred. | Enforced clear audit event semantics: `SUBMISSION_CONFIRMATION_RECORDED` for storage-only confirmations without status transitions, `SUBMISSION_CONFIRMED` for transitions to `SUBMITTED`, and `SUBMISSION_CONFIRMATION_UPDATED` for metadata corrections. |
| **Centralized Event Helper** | Duplicated event sequence, hashing, and insertion logic across multiple methods. | Implemented `_insert_application_event_internal(cursor, ...)` to encapsulate sequence calculation, hash computation, timestamp binding, and insertion on an existing connection/cursor without status mutation. |

### 10.5 Phase 7.1.3.1 Transaction Failure-Injection Verification & Audit Review Summary

| Failure Point Tested | Injection Mechanism | Rollback & Invariant Guarantees Verified |
| :--- | :--- | :--- |
| **Point A: Canonicalization Failure** | Simulated exception during payload canonicalization (`canonical_json_bytes`). | Confirmation updates rolled back; no `SUBMISSION_CONFIRMATION_UPDATED` event persisted; audit chain valid; exception propagated. |
| **Point B: Sequence Lookup Failure** | Intercepted max sequence number query via connection proxy on active cursor. | Confirmation updates rolled back; contiguous event sequence preserved; no orphan sequence gap; hash chain valid. |
| **Point C: Event Hash Failure** | Injected exception into `DatabaseManager.compute_event_hash()`. | Exception propagates; confirmation updates rolled back; original approval records unaltered; zero partial events. |
| **Point D: Event Insertion Failure** | SQLite `BEFORE INSERT` trigger on `application_events` raising `FAIL`. | Native SQLite constraint rolls back multi-table update; confirmation fields retain initial values; zero timeline mutation. |
| **Point E: Transaction Commit Failure** | Proxy connection intercepting `conn.commit()` post-update/insert. | `DatabaseManager.transaction()` catches exception, executes `conn.rollback()`, connection closed cleanly; neither update nor event persists. |
| **Audit Event Field Provenance** | `SUBMISSION_CONFIRMATION_UPDATED` event payload inspection. | Records both `updated_fields` (new values) and `previous_fields` (prior values) alongside `confirmation_id`, providing complete before/after audit traceability. |

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
```

### 11.1 Phase 7.2 Service-Layer Security Contract

When Phase 7.2 exposes application lifecycle management and submission workflows, the service layer must strictly enforce the following ten security requirements:

1. **Session-Derived User Resolution:** The authenticated candidate `user_id` must be resolved exclusively from the verified active login session.
2. **Rejection of Client-Supplied User IDs:** The service layer must never accept, trust, or act upon a `user_id` passed directly from client requests, URL query parameters, or form payloads.
3. **Strict Session Verification:** Use `DashboardService.get_authenticated_candidate_session(user_id, session_id)`, which fails closed immediately on missing, invalid, expired, or cross-user sessions.
4. **Session-to-User Binding Enforcement:** Reject any request where `session.user_id != user_id`.
5. **Mandatory Candidate Intent for Submissions:** Transitioning an application to `SUBMITTED` requires an explicit, deliberate candidate confirmation action in the UI (e.g. interactive confirmation modal with required channel selection).
6. **Single-Use Action Tickets:** Submission confirmation should consume a single-use action ticket (e.g. `MANUAL_SUBMISSION`) bound to `(application_id, packet_id, user_id)` to prevent replay attacks and race conditions.
7. **Packet Integrity & Ownership Verification:** Ensure the target prepared packet is the active revision, belongs to the candidate and application, and has a cryptographic `packet_version_hash` matching the unconsumed human approval record.
8. **Protected Database Submission Invocation:** Call `DatabaseManager.create_submission_confirmation(transition_status=True, ...)`, relying on its strict allowlist (`APPROVED` / `'Awaiting Approval'`) and unconditional consumed-approval rejection.
9. **Outbound Navigation Non-Equivalence:** Clicking, previewing, or opening an external job portal URL must NEVER be treated as a submission action or automatically advance an application to `SUBMITTED`.
10. **Zero Automated Final Submission:** The platform must strictly maintain its zero-automation boundary. Final submission is performed manually by the candidate on the employer's portal; the assistant only provides preparation assistance and records candidate confirmation.
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

---

## 22. Phase 7.2 Implementation Details: Application State Machine & Core Service Layer

Phase 7.2 implements the application state machine, transactional status transition engine, and core service layer bridging candidate authenticated sessions with application lifecycle actions.

### 22.1 UI-Independent State Machine (`src/lifecycle/state_machine.py`)
- **12 Lifecycle States**: `DRAFT`, `PREPARING`, `READY_FOR_REVIEW`, `APPROVED`, `SUBMITTED`, `IN_PROGRESS`, `ASSESSMENT`, `INTERVIEW`, `OFFER`, `REJECTED`, `WITHDRAWN`, `CLOSED`.
- **Bidirectional Legacy Status Mapping**: Automatically normalizes legacy title-case states (`Discovered` -> `DRAFT`, `Under Review` -> `PREPARING`, `Shortlisted` -> `READY_FOR_REVIEW`, `Application Prepared` -> `READY_FOR_REVIEW`, `Awaiting Approval` -> `APPROVED`, `Applied` -> `SUBMITTED`).
- **Strict Transition Matrix (`ALLOWED_TRANSITIONS`)**:
  - `DRAFT` -> `PREPARING`, `WITHDRAWN`, `CLOSED`
  - `PREPARING` -> `DRAFT`, `READY_FOR_REVIEW`, `WITHDRAWN`, `CLOSED`
  - `READY_FOR_REVIEW` -> `PREPARING`, `APPROVED`, `WITHDRAWN`, `CLOSED`
  - `APPROVED` -> `READY_FOR_REVIEW`, `SUBMITTED`, `WITHDRAWN`, `CLOSED`
  - `SUBMITTED` -> `IN_PROGRESS`, `ASSESSMENT`, `INTERVIEW`, `REJECTED`, `WITHDRAWN`, `CLOSED`
  - `IN_PROGRESS` -> `ASSESSMENT`, `INTERVIEW`, `OFFER`, `REJECTED`, `WITHDRAWN`, `CLOSED`
  - `ASSESSMENT` -> `IN_PROGRESS`, `INTERVIEW`, `OFFER`, `REJECTED`, `WITHDRAWN`, `CLOSED`
  - `INTERVIEW` -> `IN_PROGRESS`, `ASSESSMENT`, `OFFER`, `REJECTED`, `WITHDRAWN`, `CLOSED`
  - `OFFER` -> `CLOSED`, `WITHDRAWN`, `REJECTED`
  - `REJECTED` -> `IN_PROGRESS` (Re-open only)
  - `WITHDRAWN` -> `IN_PROGRESS` (Re-open only)
  - `CLOSED` -> `IN_PROGRESS` (Re-open only)
- **Gate-Protected Transitions**:
  - Transition to `APPROVED` requires an active approved packet.
  - Transition to `SUBMITTED` requires submission confirmation with an active unconsumed human approval.
- **Terminal Status Re-opening**: Terminal statuses (`REJECTED`, `WITHDRAWN`, `CLOSED`) can only transition to `IN_PROGRESS`, requiring an explicit re-opening rationale and emitting `APPLICATION_REOPENED`.

### 22.2 Atomic Status Transition Engine (`DatabaseManager.transition_application_status`)
- Executes within an atomic write lock transaction (`with self.transaction() as conn:`).
- Checks user ownership and authorization, raising `CrossUserAccessError` on foreign application access attempts.
- Performs optimistic concurrency validation via `expected_current_status`, raising `StaleDataError` if concurrent edits occurred.
- Validates status transition using `ApplicationStateMachine.validate_transition()`.
- Executes conditional atomic `UPDATE applications SET status = ?, updated_at = ... WHERE id = ? AND user_id = ? AND status = ?`.
- Appends immutable audit event (`STATUS_CHANGED` or `APPLICATION_REOPENED`) via `_insert_application_event_internal()`, ensuring state mutation and timeline history commit atomically.

### 22.3 Core Service Layer (`DashboardService`)
- **Session Identity Enforcement**: `resolve_authenticated_candidate(session_id, client_user_id)` strictly validates the active candidate session, enforces non-null `session.user_id`, and matches `client_user_id == session.user_id`.
- **Application CRUD**: `create_candidate_application()`, `get_candidate_application()`, `list_candidate_applications()` supporting filtering by status, search terms, and sort orders.
- **16-Step Protected Manual Submission Sequence**:
  1. Resolves candidate session and verifies identity.
  2. Retrieves application and verifies candidate ownership.
  3. Verifies application status is `APPROVED`.
  4. Validates state transition via `ApplicationStateMachine`.
  5. Resolves active revision prepared packet.
  6. Independently verifies packet integrity via canonical JSON snapshot hash.
  7. Retrieves human approval record and verifies it is unconsumed (`is_consumed == 0`).
  8. Verifies approval packet hash matches current active packet hash.
  9. Validates candidate submission channel against allowed channel list.
  10. Verifies and consumes single-use HMAC action ticket via `SessionManager`.
  11. Enforces action ticket cryptographic scope (`application_id`, `packet_hash`, `action_type="confirm_submission"`).
  12. Records manual submission confirmation receipt in `submission_confirmations`.
  13. Atomically consumes human approval (`is_consumed = 1`).
  14. Advances application status to `SUBMITTED`.
  15. Emits `SUBMISSION_CONFIRMED` audit timeline event.
  16. Returns updated application model and confirmation record.
- **External Portal Audit**: `log_external_application_url_opened()` validates external URLs via `URLSafetyValidator` and records `EXTERNAL_PORTAL_OPENED` timeline events without mutating application status.
- **Strict Zero-Automation Safeguard**: No browser automation tools or automated form fillers are invoked. Candidate manually completes external submission and provides submission details.

---

## 23. Phase 7.2.1 Security Hardening & State Transition Authorization

Phase 7.2.1 addresses key security and integrity findings identified during independent source review of Phase 7.2:

### 23.1 Removal of Boolean-Based Gate Authorization Bypass
- **Eliminated Caller-Supplied Flags**: Caller-supplied booleans (e.g. `is_gate_authorized=True`) are completely rejected as proof of authorization.
- **Dedicated Workflow Enforcement**:
  - `APPROVED` status can **only** be achieved through `HumanApprovalGate.authorize_universal_packet()`, which requires an active session, user identity binding, active packet integrity verification, candidate confirmation, and valid single-use HMAC `HUMAN_APPROVAL` action ticket consumption.
  - `SUBMITTED` status can **only** be achieved through `DatabaseManager.create_submission_confirmation()` / `DashboardService.record_candidate_manual_submission()`, which requires an active unconsumed human approval record, active packet integrity, candidate confirmation, and valid single-use HMAC `MANUAL_SUBMISSION` action ticket consumption.
- **Generic Transition Prohibition**: Both `DatabaseManager.transition_application_status()` and `DashboardService.transition_application_status()` unconditionally reject transitions to `APPROVED` or `SUBMITTED`, raising `SecurityAuthorizationError`.

### 23.2 Mandatory Reopening Rationale Enforcement & Terminal State Rules
- **Non-Empty Rationale Mandatory**: Reopening an application from terminal statuses (`REJECTED`, `WITHDRAWN`, `CLOSED`) to `IN_PROGRESS` strictly requires a non-empty, non-whitespace rationale string passed via `reopen_rationale`. Attempts to pass `None`, empty string `""`, whitespace, or bypass via unrelated metadata keys are rejected with `ValidationError`.
- **Immutable Reopening Audit Event**: Emits `APPLICATION_REOPENED` with `previous_status`, `new_status: IN_PROGRESS`, `reopen_rationale`, `actor_type`, and `session_reference` recorded in the append-only event log.
- **Terminal Progression vs. Reopening**:
  - `REJECTED -> CLOSED` and `WITHDRAWN -> CLOSED` are valid terminal progressions (administrative archiving/closure of a finalized cycle) and do not require reopening rationale.
  - Arbitrary transitions out of terminal states (e.g. `CLOSED -> REJECTED`, `CLOSED -> WITHDRAWN`, `REJECTED -> ASSESSMENT`) are strictly prohibited by the transition matrix.

### 23.3 External URL Safety Validation & Query Parameter Redaction
- **SSRF Defense via `URLSafetyValidator`**: Validates URLs upon application creation (`job_url`) and external URL opening (`log_external_application_url_opened()`), strictly rejecting unsafe schemes (`javascript:`, `file:`, `ftp:`), loopback/private addresses (`localhost`, `127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`), embedded credentials (`user:pass@host`), and malformed URLs.
- **Audit Privacy & Sensitive Query Redaction**: `DashboardService._redact_sensitive_url()` redacts tokens, secrets, passwords, api keys, auth codes, and session identifiers (`REDACTED`) before persisting URLs into `EXTERNAL_APPLICATION_URL_OPENED` event payloads.
- **Status Invariance**: External link access and logging strictly preserves current application status without mutating it to `SUBMITTED`.

### 23.4 SQLite Immediate Write-Lock & Concurrency Hardening
- **`immediate_transaction()`**: Acquires SQLite's RESERVED write lock via `BEGIN IMMEDIATE` at the start of the transaction, prior to any SELECT or state inspection, eliminating concurrent read-before-write race conditions.
- **Atomic Rollback & Optimistic Concurrency**: Stale expected status checks (`expected_current_status`) and conditional `UPDATE` rowcount verification prevent race conditions, rolling back status mutation and event logging atomically on failure.

### 23.5 Protection of Reserved Audit Payload Fields
- **Reserved Field Allowlist**: Protects reserved audit fields (`previous_status`, `new_status`, `application_id`, `user_id`, `actor_type`, `session_reference`, `reopen_rationale`, `created_at`, `sequence_no`, `event_hash`, `prev_event_hash`, `event_type`) against caller tampering.
- **Validation**: Any attempt to pass reserved keys in `transition_metadata` raises `ValidationError`, guaranteeing that event payloads never contradict canonical database columns.

### 23.6 Action Ticket In-Memory Lifetime Limitation
- **Architectural Scope**: Action ticket nonces and rotation keys are maintained in-memory by `SessionManager`. Replay protection operates across the active process lifetime. Process restarts or distributed worker deployments require ticket re-issuance.

---

## 24. Phase 7.2.2 Human Approval Atomicity, Ticket Provenance & URL Security

Phase 7.2.2 resolves approval workflow consistency, action ticket metadata, URL validation, and transaction error-handling issues identified during independent review of Phase 7.2.1:

### 24.1 Human Approval Workflow Atomicity & Immediate Write Lock
- **Elimination of Multi-Transaction Gap**: Refactored `HumanApprovalGate.authorize_universal_packet()` and `DatabaseManager.record_packet_approval()` to eliminate the two-phase transaction vulnerability where approval records could commit while application status update or event logging failed.
- **`authorize_application_packet_atomic()`**: Executes all four operations within a single SQLite `immediate_transaction()` under an immediate RESERVED write lock:
  1. Validates that current application status is `READY_FOR_REVIEW` (or legacy `APPLICATION_PREPARED`). Rejects any other status (`DRAFT`, `PREPARING`, `APPROVED`, `SUBMITTED`, `REJECTED`, `WITHDRAWN`, `CLOSED`) with `InvalidStatusTransitionError`.
  2. Records approval in `application_approvals` with user ownership, packet revision check, and hash matching via `_record_packet_approval_internal()`.
  3. Appends `HUMAN_APPROVAL_GRANTED` record to `application_logs`.
  4. Updates `applications.status` to `APPROVED` (or `Awaiting Approval`).
  5. Inserts `PACKET_HUMAN_APPROVED` event into `application_events` and advances the cryptographic event chain hash.
- **Zero Partial State Guarantee**: If any step fails, the entire transaction rolls back completely, ensuring no orphan approval records or inconsistent application states are persisted.

### 24.2 Action Ticket Constituent Parsing & Accurate Metadata Persistence
- **`SessionManager.parse_action_ticket()`**: Centralized classmethod parser extracting `(key_id, nonce, timestamp, signature)` from `TKT-{key_id}-{nonce}.{timestamp}.{signature}` (and legacy `TKT-{nonce}.{timestamp}.{signature}`). Validates dot-delimited structure, non-empty segments, integer timestamp, and non-empty key/nonce.
- **Accurate Metadata Binding**: Corrected `HumanApprovalGate` parsing to ensure `application_approvals.key_id` records the actual key ID (e.g. `'v1'`), not the timestamp integer, and `application_approvals.ticket_nonce` records the exact 32-character hex nonce rather than composite header prefixes.
- **Pre-Consumption Integrity**: Ticket parsing errors reject the request before ticket consumption, while valid tickets consumed in memory cannot be replayed even if downstream database operations fail.

### 24.3 DNS Resolution & SSRF Boundary Hardening
- **Elimination of `skip_dns=True` Bypass**: Both `create_candidate_application()` and `log_external_application_url_opened()` perform full DNS validation through `URLSafetyValidator.validate_url()`, resolving hostnames and asserting that all resolved IP addresses are public, globally routable addresses.
- **Injectable DNS Resolver**: `DashboardService` accepts an optional `url_resolver: Optional[Callable[[str, int], List[str]]]` in `__init__`, enabling deterministic, network-isolated unit and integration testing without external DNS dependencies while enforcing strict SSRF boundaries.

### 24.4 Complete URL Audit Redaction & Fragment Elimination
- **Fragment Stripping**: `DashboardService._redact_sensitive_url()` completely removes URL fragments (setting fragment to empty string `""`), preventing sensitive OAuth access tokens (`#access_token=...`), ID tokens (`#id_token=...`), or private client state from leaking into `application_events` audit payloads.
- **Case-Insensitive Unquoted Parameter Redaction**: Query parameter keys are unquoted and evaluated case-insensitively against sensitive substrings (`token`, `secret`, `auth`, `key`, `password`, `session`, `jwt`, `code`, `sig`, `bearer`, `credential`), replacing sensitive values with `REDACTED` while preserving non-sensitive operational parameters (`job_id`, `source`, `utm_campaign`, `category`, `page`).

### 24.5 Hardened `immediate_transaction()` Error Handling
- **Active Transaction State Tracking**: `immediate_transaction()` tracks whether `BEGIN IMMEDIATE` succeeded (`txn_started = True`).
- **Lock Contention Preservation**: If `BEGIN IMMEDIATE` fails due to lock contention (`sqlite3.OperationalError: database is locked`), `ROLLBACK` is not attempted in autocommit mode, preventing SQLite from raising secondary `cannot rollback - no transaction is active` errors and cleanly preserving the original lock contention exception.

---

## 25. Phase 7.2.2.1 Trusted Approval Boundary & Complete Atomicity Verification

Phase 7.2.2.1 closes the remaining human-approval authorization boundary, completes approval transaction failure-injection coverage across all seven failure modes, and hardens ticket parsing and SQLite lock contention verification:

### 25.1 Trusted Approval Authorization Boundary Closure
- **Internal Database Operation (`_authorize_application_packet_atomic`)**: The atomic human approval persistence routine was converted to an internal method on `DatabaseManager` (`_authorize_application_packet_atomic`), preventing external modules or callers from bypassing the human approval gate.
- **Elimination of Caller-Selectable Target Status**: Removed the `target_status` argument entirely. The target status is derived deterministically and immutably from current application status (`READY_FOR_REVIEW -> APPROVED`; legacy `Application Prepared -> Awaiting Approval`). Calling code cannot supply arbitrary statuses (`SUBMITTED`, `IN_PROGRESS`, `REJECTED`, `WITHDRAWN`, `CLOSED`, etc.).
- **`VerifiedApprovalContext` Trusted Capability**: Introduced `VerifiedApprovalContext` in `src.database.models`, an immutable dataclass representing verified approval state (application ID, user ID, packet ID, packet version hash, ticket nonce, key ID, approver name, session ID). The database operation asserts that a verified context is provided and validates candidate ownership before proceeding.
- **Exclusive Public Entry Point**: The sole public candidate-facing approval workflow remains `HumanApprovalGate.authorize_universal_packet()`. Generic transitions via `DatabaseManager.transition_application_status()` and `DashboardService.transition_application_status()` continue to raise `SecurityAuthorizationError` on direct attempts to transition to `APPROVED` or `SUBMITTED`.

### 25.2 Comprehensive 7-Point Failure-Injection Verification
Verified that any failure during the atomic approval transaction results in a clean, complete transaction rollback across seven failure modes:
1. **Test A (Approval Insert Failure)**: SQLite trigger on `application_approvals` simulates insert failure.
2. **Test B (Application Log Insert Failure)**: SQLite trigger on `application_logs` simulates insert failure.
3. **Test C (Status Update Failure)**: SQLite trigger on `applications` simulates status update failure.
4. **Test D (Event Canonicalization Failure)**: Simulated failure in `canonical_json_bytes` during event payload construction.
5. **Test E (Event Hash Computation Failure)**: Simulated failure in `DatabaseManager.compute_event_hash` during event hash generation.
6. **Test F (Event Insertion Failure)**: SQLite trigger on `application_events` simulates timeline insertion failure.
7. **Test G (Transaction Commit Failure)**: SQLite connection wrapper simulates disk I/O error during `conn.execute("COMMIT")`.

**Common Rollback Invariants (Enforced on All 7 Scenarios)**:
- Zero approvals added to `application_approvals`.
- Zero log entries added to `application_logs` for `HUMAN_APPROVAL_GRANTED`.
- Application status strictly preserved at exact pre-attempt value (`READY_FOR_REVIEW`).
- Zero events added to `application_events` for `PACKET_HUMAN_APPROVED`.
- Pre-existing timeline events remain untouched.
- Sequence numbers in `application_events` remain contiguous (`1..N`).
- Event hash chain remains intact and cryptographically verifiable.
- No false success is reported (returns `False` or raises).
- Used action ticket is marked consumed in memory and cannot be replayed.
- Retrying with a freshly issued ticket after removing the failure condition succeeds completely.

### 25.3 Hyphenated Key ID Support & Replay Protection
- **`rsplit("-", 1)` Nonce Separation**: Updated `SessionManager.parse_action_ticket()` to use `header_nonce.rsplit("-", 1)` instead of `split("-", 1)`. Because nonces generated by `secrets.token_hex(16)` never contain hyphens, splitting on the rightmost hyphen cleanly isolates arbitrarily hyphenated key IDs (e.g. `production-2026`, `auth-v2-prod-key`, `multi-part-cluster-key`).
- **Whitespace & Structure Validation**: Rejects empty, whitespace-only, or corrupt key IDs and nonces.
- **Persistence Verification**: Verified that `application_approvals.key_id` records the complete hyphenated key identifier and `application_approvals.ticket_nonce` records the exact clean 32-character hex nonce without hyphens.
- **Key Rotation Synchronization**: Updated `SessionManager.configure_keys()` to keep `SessionManager._rotation_keys` and the internal `KeyRotationManager` synchronized.

### 25.4 Real SQLite Multi-Connection Lock Contention
- **Unmocked Concurrency Verification**: Added `test_real_sqlite_write_lock_contention_between_connections` using two independent connections against a temporary file-backed SQLite database.
- **Non-Masking Behavior**: Connection A holds `BEGIN IMMEDIATE` while Connection B invokes `immediate_transaction(timeout=0.05)`. Demonstrates that SQLite raises `sqlite3.OperationalError: database is locked`, that Connection B skips `ROLLBACK` in autocommit mode, that the original error is preserved without being masked, that Connection B closes cleanly, and that Connection B successfully acquires the immediate write transaction once Connection A releases the lock.

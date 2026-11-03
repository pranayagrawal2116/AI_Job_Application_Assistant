# Phase 6 — Universal Application Preparation & Document Generation

**Architecture Version:** v2.1.1  
**Phase:** 6 of 11  
**Status:** Completed & Verified  
**Tests:** 367 / 367 Passing (100%)  

---

## 1. Executive Summary

Phase 6 transforms the **Universal AI Job Application Assistant** into an enterprise-grade application preparation and document generation suite. Every registered candidate, regardless of profession (Tech, Healthcare, Law, Finance, Engineering, Education, Trades, Sales, etc.), can prepare role-specific, ATS-optimized application materials using their own verified credentials, selected resume, and target job description.

The system guarantees:
- **Strict Multi-User Profile Isolation:** Eliminates legacy single-candidate profile fallbacks (`config.candidate_profile`, `get_latest_candidate_profile()`). Newly registered users start with an empty profile or a profile populated exclusively from their own parsed resume documents.
- **Zero-Hallucination Policy:** The engine never fabricates degrees, institutions, GPA cutoffs, employers, job titles, start/end dates, metrics, percentages, dollar figures, or unverified skills.
- **Claim-Level Provenance Tracking:** Every generated section, paragraph, and bullet point carries an immutable `ClaimProvenance` record (`claim_id`, `source_type`, `source_field`, `evidence_status`, `confidence`).
- **Universal Multi-Format Document Generation:** Native export to ATS-optimized PDF and Microsoft Word DOCX formats across 7 professional templates (Modern, Minimal, Traditional, Executive, Technical, Healthcare, Academic).
- **Consolidated Application Packet Versioning:** Reuses Phase 2 `prepared_packets` and `application_approvals` tables with RFC 8785 canonical JSON hashing and single-use HMAC authorization tickets.
- **Strict Human-in-the-Loop Audit Gate:** Automated agents and background processes are forbidden from authorizing applications or submitting them to external portals.

---

## 2. Core Architectural Components

### 2.1 Multi-User Profile Isolation (Milestone 6.0)
- **Files Modified:** `dashboard/views/candidate_profile.py`, `dashboard/services/dashboard_service.py`, `src/database/db_manager.py`.
- **Preflight Fixes:**
  - Removed all fallback paths to `config.candidate_profile` and `get_latest_candidate_profile()` in user workflows.
  - New user accounts start with an empty profile dictionary (`{}`).
  - User-scoped profile saves execute atomically via `self.db.save_user_candidate_profile(user_id, profile_data)` without suppressing exceptions.
  - Validated by `tests/test_profile_isolation.py` proving that distinct accounts (User A and User B) maintain independent profiles and version histories.

### 2.2 Application Preparation Workspace (Milestone 6.1)
- **Method:** `DatabaseManager.get_or_create_application_workspace(user_id, job_description_id, resume_id)`
- **Behavior:** Enforces that `job_description_id` belongs to `user_id`. Queries existing applications for the composite key `(user_id, job_description_id)` to avoid creating duplicate application records when reopening preparation. Automatically updates the linked `resume_id` and tracks lifecycle status.

### 2.3 Universal Tailored Resume Generator (Milestone 6.2)
- **Module:** `src/preparer/tailored_resume_generator.py`
- **Class:** `UniversalTailoredResumeGenerator`
- **Capabilities:**
  - Evaluates candidate's verified skills against target JD requirements, promoting matching skills to core focus areas.
  - Scores and reorders work experience bullets so that experiences demonstrating required responsibilities are prioritized.
  - Attaches `ClaimProvenance` to every bullet point.
  - Provides in-place editing via `TailoredResume.update_bullet()`, automatically updating provenance to `source_type="user_edit"` and `evidence_status="USER_CONFIRMED"`.
  - Produces unified diffs against original resume bullets via `diff_with_original()`.
  - Exports to clean Markdown and ATS plain text.

### 2.4 Universal Cover Letter Generator (Milestone 6.3)
- **Module:** `src/preparer/cover_letter_generator.py`
- **Class:** `CoverLetterGenerator`
- **Capabilities:**
  - Supports 4 distinct professional tones: `PROFESSIONAL_DIRECT`, `ENTHUSIASTIC_MODERN`, `EXECUTIVE_FORMAL`, `ACADEMIC_RESEARCH`.
  - Adapts structure and emphasis according to career level: `STUDENT_FRESHER`, `MID_CAREER`, `SENIOR_EXECUTIVE`, `CAREER_CHANGER`, `FREELANCER_CONSULTANT`.
  - Strict zero-fabrication: never invents referral names, company awards, or artificial anecdotes.
  - Attaches provenance claims to each paragraph (`opening`, `qualifications`, `alignment`, `closing`).
  - Preserves full backward compatibility with legacy single-job methods.

### 2.5 Screening Question Answer Assistant (Milestone 6.4)
- **Module:** `src/preparer/question_answerer.py`
- **Class:** `QuestionAnswerer`
- **Capabilities:**
  - Classifies incoming questions into 19 standardized categories (Experience Years, Technical Skills, Education, Licensing, Work Authorization, Salary Expectations, Availability, Remote/Location, Languages, Management, Behavioral STAR, Portfolio, Domain, Travel, Background Check, Shifts, Home Office, Motivation, General).
  - Enforces 5 review states: `GENERATED_DRAFT`, `NEEDS_CANDIDATE_INPUT`, `USER_EDITED`, `USER_APPROVED`, `REJECTED`.
  - Missing or subjective information (salary, availability, relocation, STAR narratives) strictly returns `NEEDS_CANDIDATE_INPUT`.
  - Character limit enforcement with truncation/over-limit flags.
  - Batch question answering from plain text lists.

### 2.6 Document Generation & Export Engine (Milestone 6.5)
- **Module:** `src/preparer/document_generator.py`
- **Class:** `UniversalDocumentGenerator`
- **Capabilities:**
  - Generates PDF (via ReportLab Flowables) and DOCX (via python-docx) for:
    1. Tailored Resume
    2. Cover Letter
    3. Screening Questions & Answers
    4. Consolidated Application Packet (combining Resume, Letter, QA, and Audit Summary)
  - 7 Layout Templates: `Modern`, `Minimal`, `Traditional`, `Executive`, `Technical`, `Healthcare`, `Academic`.
  - Secure storage in isolated user application directory: `data/users/<user_id>/applications/<application_id>/`.
  - Structural validation: verifies `%PDF-` header and text extractability via `pypdf`, and verifies DOCX ZIP package integrity with `word/document.xml`.

### 2.7 Application Packet Versioning & Approval Gate (Milestone 6.6)
- **Module:** `src/preparer/approval_gate.py`
- **Class:** `HumanApprovalGate`
- **Capabilities:**
  - Calculates RFC 8785 canonical JSON hash (`canonical_json_hash`) across all application materials.
  - Increments packet `version_num` on new drafts; deactivates older revisions (`is_active_revision = 0`).
  - Single-use HMAC action ticket issuance and verification (`verify_and_consume_action_ticket`).
  - Enforces strict human audit approval: rejects empty names, automated/bot keywords (`bot`, `agent`, `auto`, `system`), and unconfirmed checkboxes.
  - Transitions application status to `Awaiting Approval`.

### 2.8 Interactive Streamlit Dashboard (Milestone 6.7)
- **View:** `dashboard/views/application_preparer.py`
- **Unified 8-Tab Layout:**
  1. `🎯 Overview & Selection`: JD and resume pickers, workspace status, match score, preparation checklist.
  2. `📄 Tailored Resume`: Tailoring controls, structured resume viewer, inline bullet editor, provenance inspector, unified diff.
  3. `✍️ Tailored Cover Letter`: Tone and career level selectors, live Markdown editor, claim inspector.
  4. `💬 Screening Questions`: Question ingestor, 19-category classification, evidence-grounded answers, character counters, status transitions.
  5. `📋 Application Details`: Confirmed logistics, compensation, availability, relocation, and notes.
  6. `📎 Attachments Manifest`: Cryptographic manifest of all application files.
  7. `🛡️ Review & Approval`: Export PDF/DOCX button, assemble packet button, human audit authorization gate with single-use ticket.
  8. `📜 Packet History & Downloads`: Historical packet revisions, SHA-256 hashes, approval audit trail, one-click download buttons for PDF and DOCX files.

---

## 3. Test Coverage & Verification

Phase 6 introduces 6 new automated test suites (31 new tests), bringing the total test suite to **367 passing tests (100% pass rate)**:

| Test Suite | Tests | Purpose |
| :--- | :--- | :--- |
| `tests/test_profile_isolation.py` | 5 | Multi-user profile independence and zero cross-account leakage |
| `tests/test_tailored_resume.py` | 6 | Zero-hallucination tailoring, bullet scoring, editing, and diffs |
| `tests/test_cover_letter.py` | 4 | Multi-tone, multi-career-level cover letter generation & provenance |
| `tests/test_screening_questions.py` | 5 | 19-category classification, 5 states, missing data enforcement |
| `tests/test_document_generation.py` | 6 | PDF and DOCX generation, 7 templates, and structural validation |
| `tests/test_application_packet_integrity.py` | 5 | Packet versioning, RFC 8785 canonical hashing, ticket replay protection |
| `tests/test_phase6_1_hardening.py` | 37 | Multi-user security, session ownership, truthful evidence, packet provenance |
| **Existing Phase 1–5.1.1 Suites** | 336 | Regression tests for all previous deliverables |
| **Total Test Suite** | **424** | **100% Passing** |

---

## 4. Stopping Protocol Compliance

Phase 6, 6.1, and 6.1.1 implement complete application preparation, document generation, and provenance hardening. In strict accordance with `AGENTS.md` and Phase 6 specifications:
- No automatic submission actions are executed.
- No Playwright browser automation or external employer portal interactions are invoked.
- Application status stops cleanly at `Awaiting Approval` under strict human governance.

---

## 5. Phase 6.1 Security, Provenance & Packet Integrity Hardening

Phase 6.1 performed a comprehensive security, provenance, and data-integrity audit of the Phase 6 application preparation engine, ensuring complete cross-user isolation and cryptographic auditability:

1. **Authentication Fail-Closed & Session Ownership**:
   - `get_current_user_id()` fails closed without unauthenticated fallbacks to User #1.
   - `HumanApprovalGate.authorize_universal_packet` validates session ownership against `user_id` and verifies active packet revision.
   - Cross-user session injection and packet authorization across different user accounts are strictly blocked.
   - `DatabaseManager.get_or_create_application_workspace` enforces resume ownership (`CrossUserAccessError`) and blocks archived/inactive resumes.

2. **Database Approval Integrity & Replay Protection**:
   - `DatabaseManager.record_packet_approval` strictly verifies application ownership, packet ownership, application ID binding, hash matching, and active revision status.
   - Single-use HMAC action tickets are consumed upon approval, preventing replay attacks.
   - Content guardrails in `HumanApprovalGate` prevent packet approval if any screening answer remains in `NEEDS_CANDIDATE_INPUT` or exceeds character limits.

3. **Truthful Evidence & Elimination of Hardcoded Fallbacks**:
   - `UniversalTailoredResumeGenerator` preserves verification states and ensures unconfirmed certifications, statutory licenses, experience, education, and projects remain `EXTRACTED_UNVERIFIED`.
   - `CoverLetterGenerator` removed opening over-claims ("closely followed", "established professional") and verifies statutory licensure before claiming it.
   - Eliminated all legacy hardcoded defaults ("Pranay Anup Agrawal", "MIT World Peace University", "Medical Chatbot", "Sarita Infotech Pvt. Ltd.") across all generators and matchers.
   - Removed implicit disk loading of `candidate_profile.json` in constructors; generators require explicit profile injection.

4. **Immutable Packet Provenance & RFC 8785 Snapshot Persistence**:
   - Added schema columns to `prepared_packets`: `canonical_snapshot_json`, `candidate_profile_version`, `candidate_profile_hash`, `matching_result_id`, `template_id`, `template_version`.
   - RFC 8785 canonical JSON bytes stored directly in SQLite, guaranteeing `sha256(canonical_snapshot_json) == packet_version_hash`.
   - Real disk-inspected `attachments_manifest` with file format verification, on-disk size calculation, and SHA-256 hashes.
   - PDF validation requires non-empty extractable text.
   - Streamlit UI context keys isolate session state per application workspace, resume hash, JD snapshot hash, and candidate profile hash.

---

## 6. Phase 6.1.1 Authenticated Session Binding & Complete Packet Hash Integrity

Phase 6.1.1 completed final hardening for authenticated approval sessions and canonical packet integrity:

1. **Actual Login Session Requirement for Packet Approval**:
   - Streamlit Application Preparer workflow (Tab 7) strictly resolves the active authenticated session from the actual Phase 2 login state (`st.session_state["authenticated_session_id"]` or `st.session_state["session_id"]`).
   - Replaced ambiguous `get_or_create_candidate_session()` fallback with `DashboardService.get_authenticated_candidate_session(user_id, session_id)`.
   - Strictly fails if the session ID is missing, unissued, expired, deactivated, or belongs to another user (`InvalidSessionError`, `SessionExpiredError`, `SecurityAuthorizationError`).
   - Strictly NEVER automatically fabricates or creates sessions during approval attempts.

2. **Server-Side Session & User Identity Verification**:
   - `HumanApprovalGate.authorize_universal_packet` independently validates the session existence, activity, and expiration directly via `SessionManager.validate_session`.
   - Strictly verifies that `session.user_id == user_id` and the candidate identity matches.
   - All approval tickets are cryptographically bound to the authenticated session ID, user ID, application ID, packet version hash, and single-use HMAC nonce.

3. **Complete Canonical Packet Payload**:
   - Enriched RFC 8785 canonical JSON dictionary to cover all persisted provenance and artifact hashes:
     - **Identity & Source Versions**: `user_id`, `application_id`, `packet_version`, `original_resume_id`, `original_resume_version_num`, `original_resume_file_hash`, `candidate_profile_version`, `candidate_profile_snapshot_hash`, `job_description_id`, `job_description_snapshot_hash`, `matching_result_id`, `matching_engine_version`, `scoring_configuration_version`.
     - **Generated Materials**: Complete tailored resume content & provenance map, tailored resume document content hash, cover letter text & provenance claims, cover letter document content hash, screening QA list with review states, provenance, character limits, candidate edits, and confirmation state.
     - **Attachment Manifest**: Actual artifacts with type, stored filename, file format, byte size, SHA-256 content hash, source version, and creation timestamp.
     - **Rendering Metadata**: `template_id`, `template_version`, `rendering_engine`, `generation_timestamp`.
   - Stored file paths serve as reference locators only; integrity is cryptographically guaranteed by SHA-256 content hashes.

4. **Independent Packet Hash Verification**:
   - `HumanApprovalGate.verify_packet_integrity(packet)` independently re-computes `hashlib.sha256(packet.canonical_snapshot_json.encode('utf-8')).hexdigest()` and verifies exact match with `packet.packet_version_hash`.
   - `authorize_universal_packet` validates packet integrity prior to approval; tampered snapshot JSON or mismatched hashes fail closed.

5. **Legacy Packet Migration & Handling**:
   - Migration `_migrate_prepared_packets_foreign_keys` preserves historical packet records and approval audit records without fabricating missing metadata.
   - `PreparedPacket.is_legacy` property cleanly identifies historical packets missing canonical snapshots (`canonical_snapshot_json is None`), preventing invalid hash recalculations.

6. **Resume Archival & Packet Retention**:
   - `prepared_packets` foreign key migrated to `FOREIGN KEY (original_resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE RESTRICT`.
   - `delete_user_resume`: If a resume is referenced by historical prepared packets or match results, it is safely archived (`is_active = 0, is_primary = 0`), preserving historical packet versions, original file hashes, and disk files intact.
   - Explicit user account privacy erasure (`delete_user_account_data`) deletes prepared packets prior to users table cascade, cleanly distinguishing normal resume archival from user account deletion.

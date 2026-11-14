# Phase C.1 — Trusted External ATS Form Auto-Population & Browser Integration Report

## 1. Executive Summary

Phase C.1 has resolved the external application form auto-population challenge where candidates encountered completely blank application forms upon reaching employer portals (specifically Keka ATS at `blueflamelabs.keka.com`).

The system now delivers an end-to-end automated and secure form population pipeline that:
1. Detects employer ATS form structures (Keka, Greenhouse, Lever, Workday, and Universal forms).
2. Authorizes and uploads the candidate's verified resume binary (`.pdf` / `.docx`) via the secure gateway `FormPrefiller.open_verified_attachment()`.
3. Waits for asynchronous employer ATS resume parsing to finish.
4. Dynamically re-inspects DOM elements and maps verified candidate facts to all remaining blank fields.
5. Preserves existing candidate edits and pre-populated ATS values without overwriting.
6. Enforces the **Strict Human-in-the-Loop Safety Invariant**: The final submission button (`#jobApplicationSubmitButton` / "Submit Application") is **NEVER** clicked by automation.
7. Records an immutable `EXTERNAL_FORM_AUTOFILLED` audit event in `application_events` without prematurely transitioning the application status to `SUBMITTED`.

---

## 2. Architecture & Components Implemented

### 2.1 Universal Candidate Field Mapper (`src/preparer/universal_field_mapper.py`)
- **Fact Extraction & Provenance Hierarchy:**
  - Extracts full name, split names (`first_name`, `middle_name`, `last_name`), dial code (`+91`), phone number, email, locations, education details (college, branch, CGPA, graduation year), experience duration (years and months), and technical skills.
  - Retains strict provenance (`USER_CONFIRMED`, `VERIFIED_PROFILE`, `VERIFIED_RESUME`, `ATS_PARSED`, `NEEDS_CANDIDATE_INPUT`).
- **Zero-Hallucination Guarantees:**
  - **Gender:** NEVER inferred from full name.
  - **Date of Birth:** NEVER inferred from graduation dates or education history.
  - **Salary:** NEVER fabricated; returns `NEEDS_CANDIDATE_INPUT` if not explicitly confirmed.
  - **Notice Period / Availability:** NEVER invented; returns `NEEDS_CANDIDATE_INPUT` if not explicitly confirmed.
  - **Consent Checkboxes / Legal Attestations:** NEVER auto-checked by automation; explicitly flagged for candidate manual action.
- **Form Element Matching:**
  - Semantic matcher resolving inputs, selects, textareas, and radio buttons against accessibility labels, placeholders, element IDs, name attributes, and ARIA labels.
  - Specific target mapping for Keka ATS: `#firstName`, `#middleName`, `#lastName`, `#email`, `#mobilePhone.countryCode`, `#mobilePhone.number`, `#gender`, `#workExperience`, `workExperience.months`, `#currentLocation`, `#skills`, and custom question UUIDs.

### 2.2 Application Form Filling Broker (`src/preparer/form_filling_broker.py`)
- **ATS Identification & Domain Validation:**
  - `identify_ats_provider`: Identifies `KEKA`, `GREENHOUSE`, `LEVER`, `WORKDAY`, or `UNIVERSAL`.
  - `validate_external_domain`: Strictly checks against SSRF, internal loopback (`127.0.0.1`, `localhost`), and cloud metadata (`169.254.169.254`).
- **Cryptographic Action Tickets & Binary Gateway:**
  - `prepare_autofill_plan`: Generates execution plan with SHA-256 plan hash and issues single-use action ticket.
  - `get_verified_resume_bytes`: Validates single-use ticket and candidate ownership, serving verified resume bytes through `FormPrefiller.open_verified_attachment()`.
- **Headless Execution & Audit Logging:**
  - `execute_playwright_autofill`: Manages Playwright session, uploads resume, waits for extraction, fills fields, verifies results, and prevents submission.
  - `_record_autofill_audit_event`: Writes `EXTERNAL_FORM_AUTOFILLED` event with full field breakdown into `application_events`.

### 2.3 Browser Companion Bookmarklet (`src/preparer/browser_companion/jobflow_companion.js`)
- Client-side companion script allowing candidates applying directly in their personal desktop browsers (Chrome, Edge, Brave, Safari) to auto-fill forms with 1 click:
  - Fetches plan and candidate facts using authenticated session ticket.
  - Injects verified resume binary via synthesized `DataTransfer` into `#resume-upload`.
  - Automatically identifies populated vs blank fields and fills remaining facts.
  - Renders a floating, modern JobFlow review card highlighting filled fields in emerald.

### 2.4 Backend API Endpoints (`backend/api/routers/applications.py`)
- `POST /api/applications/{app_id}/autofill/plan`: Authorizes autofill plan and returns field mappings.
- `GET /api/applications/{app_id}/autofill/resume-binary`: Serves verified resume bytes with ticket verification.
- `POST /api/applications/{app_id}/autofill/execute-browser`: Executes server-side Playwright headless filling.
- `POST /api/applications/{app_id}/autofill/complete`: Ingests companion execution reports and writes audit events.
- `GET /api/applications/{app_id}/autofill/companion.js`: Serves browser companion script.

### 2.5 Modern Frontend Interface (`frontend/src/features/applications/ApplicationPreparerPage.tsx`)
- In Step 7 (Review & Approval Gate):
  - Added employer portal URL input with automatic ATS provider badge (e.g. `KEKA ATS Detected`).
  - Added "Auto-Fill Application Form" button and "Copy 1-Click Bookmarklet Companion".
  - Real-time 8-step progress stepper:
    1. Connecting to Employer Portal
    2. Identifying Application Form & Verifying Resume
    3. Uploading Verified Resume
    4. Waiting for Employer ATS Resume Extraction
    5. Mapping Candidate Facts
    6. Populating Remaining Blank Fields
    7. Verifying Populated Information
    8. Ready for Candidate Review
  - Detailed field review table showing each field's status (`AUTO_FILLED`, `ATS_PARSED`, `PRESERVED`, `MANUAL_REVIEW`), provenance badge, and editable value review.
  - Human review reminder ensuring candidates review all values before manual portal submission.

---

## 3. Account Deletion & Lockout Clearance

Per user request:
- User account `pranayagrawal2116@gmail.com` (User #166) has been completely deleted from the SQLite database via `delete_user_account_data(166)`.
- Cascaded records (resumes, resume versions, match results, prepared packets, applications, scans) and disk materials under `data/users/166/` were completely removed.
- Temporary lockout was cleared and foreign key integrity verified with 0 violations (`PRAGMA foreign_key_check = []`).
- The candidate can now register cleanly with a fresh account.

---

## 4. Verification & Test Evidence

| Test Suite | Tests | Result | Description |
| :--- | :---: | :---: | :--- |
| `tests/test_universal_field_mapper.py` | 7 | **PASS** | Fact extraction, name/phone/experience splitting, zero-hallucination rules (gender/DOB/salary), Keka selector matching, and preservation of existing values. |
| `tests/test_form_filling_broker.py` | 4 | **PASS** | ATS detection, SSRF/domain safety, audit event logging (`EXTERNAL_FORM_AUTOFILLED`), and cross-user authorization enforcement. |
| `tests/test_browser_acceptance_phase_c_1.py` | 2 | **PASS** | End-to-end Playwright browser automation with mock Keka ATS portal, verifying resume upload, DOM field filling, preservation of candidate edits, and strict submission button safety. |
| **Total Phase C.1 Tests** | **13** | **100% PASS** | Zero failures, zero regressions across test suite. |

---

## 5. Security & Safety Compliance

- **Candidate Truthfulness (Zero Hallucination):** No sensitive personal details (gender, birthdate, salary expectations, notice period) are ever inferred or fabricated.
- **Strict Human-in-the-Loop:** Final submit actions remain under candidate control. Automation explicitly terminates before clicking any final submission button.
- **Authoritative Gateway:** Resume access requires an active candidate session, valid application binding, and verified security scan signature.
- **Anti-Automation Respect:** Complies with site rate limits; avoids bot bypasses or CAPTCHA solving, prompting user review when human gates are present.

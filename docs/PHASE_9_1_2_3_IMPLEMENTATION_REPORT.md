# Phase 9.1.2.3 Implementation Report
# Legacy Provenance, Manifest-Version & Attachment Lifecycle Closure

**Architecture:** Universal AI Job Application Assistant v2.1.1  
**Milestone:** Phase 9.1.2.3  
**Verified Baseline Commit:** `9636b536265691923cadecc539f0b55e36f1da8e`  
**Execution Date:** 2026-11-06  

---

## 1. Executive Summary

Phase 9.1.2.3 closes the critical provenance and lifecycle defects identified during post-implementation security inspection of Phase 9.1.2.2. Specifically, it eliminates brittle string timestamp comparisons, introduces an authoritative `binary_integrity_state` database column with append-only migration audit evidence, enforces strict supported manifest versions (`{"v1", "v2"}`) while requiring `v2` binary provenance for active security acceptance, unifies signing-key registration under strict immutability and entropy invariants, and establishes a tamper-evident `VerifiedAttachmentRef` lifecycle with use-time Time-of-Check to Time-of-Use (TOCTOU) verification.

All 16 targeted test specifications in `tests/test_phase_9_1_2_3_provenance_and_identity_closure.py` and all 1,484 test suite cases across the repository pass cleanly (100% pass rate). Static analysis (`ruff check` and `pyflakes`) is 100% clean with zero warnings or errors.

---

## 2. Baseline & Preflight Verification

Before implementing code modifications, the repository was verified:
- **Local Branch:** `main`
- **Starting HEAD Commit:** `9636b536265691923cadecc539f0b55e36f1da8e`
- **Working Tree:** Clean, tracking `origin/main` without diverged commits.
- **Previous Milestones Verified:** Phase 9.1.1, 9.1.1.1, 9.1.1.2, 9.1.1.3, 9.1.2, 9.1.2.1, and 9.1.2.2.

---

## 3. Remediation Details & Implementation Architecture

### Part A: Explicit Legacy Binary-Integrity State & Durable Migration Audit
1. **Elimination of Fragile String Heuristics:**
   - Removed `str(jd.created_at) < "2026-11-06T00:00:00"` and `is_legacy_record` dictionary flag checks in `SecurityPreflightManager.check_job_description_security()`. This eliminates date-string formatting collisions (such as space vs. ISO `T`) and prevents arbitrary timestamp backdating.
2. **Authoritative `binary_integrity_state` Schema Column:**
   - Added `binary_integrity_state TEXT DEFAULT 'REQUIRED' CHECK(binary_integrity_state IN ('REQUIRED', 'LEGACY_TEXT_ONLY', 'VERIFIED', 'NOT_APPLICABLE'))` to `job_descriptions` in `src/database/schema.sql` and `src/database/models.py`.
   - Backward-compatible SQLite column addition is guaranteed in `DatabaseManager._ensure_backward_compatible_columns()`.
3. **Append-Only Migration Audit Table:**
   - Created `legacy_integrity_exceptions` table in SQLite schema with triggers `trg_prevent_legacy_integrity_exceptions_update` and `trg_prevent_legacy_integrity_exceptions_delete` preventing any in-place mutation or deletion of audit records.
   - Added `LegacyIntegrityException` dataclass model and database methods `record_legacy_integrity_exception()` and `get_legacy_integrity_exception()`.
4. **Migration & Preflight Enforcement:**
   - Implemented `_migrate_historical_job_description_integrity(cursor)`:
     - Sets non-uploaded sources to `'NOT_APPLICABLE'`.
     - Sets complete uploaded sources with all 4 binary fields to `'VERIFIED'`.
     - Sets pre-Phase-9.1.1 uploaded sources with all 4 NULL binary fields to `'LEGACY_TEXT_ONLY'` and records an immutable audit entry in `legacy_integrity_exceptions` (provided no prior scan exists with `source_binary_hash IS NOT NULL`).
   - `save_job_description_snapshot()` strictly disallows assigning `'LEGACY_TEXT_ONLY'` via public API (raising `SecurityAuthorizationError`), reserving it exclusively for historical migrations.
   - `check_job_description_security()` validates that any record claiming `'LEGACY_TEXT_ONLY'` has all 4 binary fields NULL, has an authoritative `legacy_integrity_exceptions` record, matches `source_snapshot_hash`, and has no prior scan with physical binary provenance.

### Part B: Manifest-Version Validation & v2 Enforcement
1. **Supported Versions Set:**
   - Defined `SUPPORTED_MANIFEST_VERSIONS = {"v1", "v2"}` in `src/security/scan_signer.py`.
   - `SecurityScanSigner.build_canonical_manifest()` strictly validates that any caller-specified `manifest_version` belongs to `SUPPORTED_MANIFEST_VERSIONS`, raising `SecurityAuthorizationError` on unknown or malformed versions (`"v3"`, `"v0"`, `""`, etc.).
2. **Rejection of v1 Manifests When Binary Provenance Is Required:**
   - `SecurityScanSigner.verify_scan_record()` validates `manifest_version` against `SUPPORTED_MANIFEST_VERSIONS`.
   - If `expected_source_binary_hash` is provided and the scan record is `v1`, verification fails closed with `SecurityAuthorizationError("Scan record has manifest version 'v1' lacking binary provenance... A 'v2' rescan is required.")`.
3. **Rescan & Upgrade Protocol:**
   - `SecurityPreflightManager.check_resume_security()` detects historical `v1` resume scans and forces an append-only rescan yielding a signed `v2` record with physical binary provenance before accepting it in security-sensitive workflows (while permanently preserving quarantine status for quarantined scans).

### Part C: Unified Key Registration & Identity Immutability
1. **Unified Registration Routine:**
   - Added `ScanKeyManager._register_key(key_id, secret, is_active=False)` unifying active key loading in constructor, configured rotation keys, and runtime `rotate_key()`.
2. **Key ID Immutability:**
   - Attempting to register an existing key ID with differing secret material raises `SecurityAuthorizationError`.
   - Registering an existing key ID with identical secret bytes succeeds idempotently.
3. **Entropy & Cryptographic Separation:**
   - All keys across all registration paths require at least 32 bytes (256 bits) of entropy.
   - Non-reuse of action ticket keys (`ACTION_TICKET_SECRET_KEY` and rotation keys) is strictly enforced.
   - Production mode (`APP_ENV="production"`) fails closed on malformed rotation key JSON or non-dictionary configurations.

### Part D: Authoritative Verified Attachment Reference & TOCTOU Defense
1. **Typed Attachment Reference Dataclass:**
   - Introduced `VerifiedAttachmentRef` in `src/preparer/form_prefiller.py` binding `user_id`, `resume_id`, `version_num`, `storage_filename`, `file_path`, `file_hash`, `file_size_bytes`, `file_format`, `scan_id`, `scan_signature`, and `verified_at`.
2. **FormFillPlan Integration:**
   - Extended `FormFillPlan` with `attachment_ref: Optional[VerifiedAttachmentRef] = None`.
   - `FormPrefiller.build_form_payload()` populates `attachment_ref` from verified resume records and authoritative security scans.
3. **Use-Time TOCTOU Verification Routine:**
   - Implemented `FormPrefiller.open_verified_attachment(plan_or_ref, user_id) -> bytes`:
     - Enforces candidate ownership (`user_id == ref.user_id`).
     - Enforces directory containment and prevents symlink directory traversal.
     - Reads physical disk file and verifies exact SHA-256 hash and byte size against `attachment_ref`.
     - Validates format magic byte headers (`%PDF-` for PDF, `PK\x03\x04` for DOCX).
     - Reverifies security scan in database, ensuring scan ID matches, key is unrevoked, HMAC is valid, and classification is not `QUARANTINED`.
     - Returns verified raw file bytes.

---

## 4. Empirical Verification & Test Results

### Dedicated Test Suite: `tests/test_phase_9_1_2_3_provenance_and_identity_closure.py`
All 16 test cases passed on Python 3.13:
```
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_01_new_same_day_uploaded_records_with_all_null_fail_closed PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_02_older_timestamp_manipulation_cannot_make_record_legacy PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_03_explicitly_migrated_historical_records_remain_compatible PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_04_historical_exceptions_have_durable_audit_evidence PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_05_scan_hmac_binary_provenance_cannot_be_bypassed_by_clearing_source_metadata PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_06_unknown_manifest_versions_fail_closed PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_07_v1_cannot_satisfy_v2_binary_provenance_requirements PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_08_old_resume_scans_are_upgraded_to_v2_before_current_acceptance PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_09_active_rotation_key_collisions_rejected_during_init PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_10_duplicate_normalized_key_ids_cannot_overwrite PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_11_historical_key_ids_always_resolve_to_original_secret_bytes PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_12_form_fill_plan_contains_exact_verified_attachment_identity PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_13_files_replaced_after_plan_creation_rejected_at_use_time PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_14_all_legitimate_pasted_url_and_uploaded_workflows_functional PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_15_legacy_text_only_rejected_via_public_api PASSED
tests/test_phase_9_1_2_3_provenance_and_identity_closure.py::TestPhase9123ProvenanceAndIdentityClosure::test_16_open_verified_attachment_validates_magic_bytes_quarantine_and_user PASSED
```

### Full Repository Regression Suite
```
pytest tests/ -q
1484 passed in 79.82s (0:01:19)
```

### Static Analysis
```
ruff check src/ database/ security/ preparer/ tests/
All checks passed!

pyflakes src/ database/ security/ preparer/ tests/
0 errors.
```

---

## 5. Security & Invariant Analysis

| Invariant | Pre-Phase 9.1.2.3 Status | Post-Phase 9.1.2.3 Status |
|:---|:---|:---|
| **Legacy Text Record Proof** | Timestamp string comparison (`created_at < "2026-11-06T00:00:00"`) permitted same-day uploaded records with NULL metadata due to whitespace vs 'T' lexicographical comparison | Strictly requires `binary_integrity_state == 'LEGACY_TEXT_ONLY'` with durable, append-only row in `legacy_integrity_exceptions` and verified snapshot hash |
| **Prior Scan Provenance** | Attacker could clear binary columns on uploaded record to bypass physical binary check | If a prior scan exists with `source_binary_hash IS NOT NULL`, record cannot be accepted as legacy text-only |
| **Manifest Version Support** | Unknown versions coerced or unchecked | Strict validation against `{"v1", "v2"}`; fails closed on `"v3"`, `"v0"`, or empty strings |
| **Binary Provenance Enforcement** | `v1` scan records could be used for uploaded sources | `v1` scan records cannot satisfy requirements when binary provenance is expected; `check_resume_security` upgrades `v1` to `v2` append-only |
| **Key Identity Immutability** | Constructor assigned rotation keys without collision check | Unified `_register_key` rejects any key ID reuse with different secrets across all constructor and rotation paths |
| **Attachment TOCTOU Defense** | `FormFillPlan` held file path string without use-time re-verification | `VerifiedAttachmentRef` binds file hash, size, format, scan ID and HMAC; `open_verified_attachment()` verifies disk file and scan before consumption |

---

## 6. Stop Condition & Next Milestone

Phase 9.1.2.3 is complete, fully tested, and verified.
As mandated by project guidelines and safety protocols:
**STOP.** No Phase 9.1.3 features or code changes have been started. Awaiting user review and authorization.

# Phase 9.1.2.5 — Implementation Report: Legacy Eligibility Proof & Migration Evidence Closure

**Project:** Universal AI Job Application Assistant  
**Repository:** `https://github.com/pranayagrawal2116/AI_Job_Application_Assistant.git`  
**Target Branch:** `main`  
**Architecture:** v2.1.1  
**Verified Baseline Commit:** `76cc3677c71242056aa2c3d0fe289e54896fddd8`  
**Verified Final Commit:** `24deca1f4e40ab156bd5928b998c00891ad2feae`  
**Date:** November 06, 2026  
**Status:** Completed & Fully Verified  

---

## 1. Executive Summary

Phase 9.1.2.5 establishes strict, evidence-based legacy binary-integrity eligibility and closes the historical provenance loophole in architecture v2.1.1. The milestone resolves the core vulnerability wherein uploaded job descriptions could be grandfathered into `LEGACY_TEXT_ONLY` status without independent, trustworthy historical proof.

### Key Deliverables Completed:
1. **Authoritative Evidence-Based Legacy Eligibility Contract (Section 4.1 & 4.2):**
   - Established the explicit rule: **Unknown historical origin = NOT VERIFIED (fails closed, remains in `REQUIRED`)**.
   - Missing binary metadata is strictly prohibited from being interpreted as proof that a record is historical.
   - Disallowed grandfathering records into `LEGACY_TEXT_ONLY` based solely on mutable `created_at` timestamps or 9-key snapshot hashes.
   - An uploaded record may enter `LEGACY_TEXT_ONLY` only when supported by an independently verifiable external attestation record in `legacy_evidence_attestations` matching its exact user ID, job description ID, and canonical snapshot hash.
2. **Durable Evidence Attestation & Exception Audit Model (Part C):**
   - Extended `legacy_integrity_exceptions` with explicit provenance columns: `evidence_type TEXT` and `evidence_reference_id TEXT`.
   - Created the immutable `legacy_evidence_attestations` table with database-level `BEFORE UPDATE` and `BEFORE DELETE` trigger protection preventing tampering or deletion.
   - Enforced in `SecurityPreflightManager` that any record claiming `LEGACY_TEXT_ONLY` must have an audit row with non-empty `evidence_type` and `evidence_reference_id`.
3. **Controlled Recovery Procedure (Section 5.1):**
   - Implemented `DatabaseManager.recover_unverified_job_description(user_id, job_description_id, file_bytes, original_filename)`.
   - Preserves the historical snapshot completely immutable while marking it inactive (`is_active = 0`).
   - Validates physical file bytes (PDF/DOCX magic bytes, 10MB size cap), recomputes SHA-256 and size, stores the physical binary securely, creates an authoritative new child revision linked via `supersedes_job_description_id` with `binary_integrity_state = 'VERIFIED'`, generates a fresh signed v2 authenticated security scan, and audits the recovery outcome.
4. **Corrective Reconciliation Migration (`phase_9_1_2_5_legacy_evidence_closure`) (Section 4.3):**
   - Implemented `_migrate_phase_9_1_2_5_legacy_evidence_reconciliation()`.
   - Preserved `phase_9_1_2_3_legacy_binary_integrity` finality.
   - Reconciled any existing `LEGACY_TEXT_ONLY` records lacking independent evidence back to `REQUIRED` (fail closed) with audit log entries recording `outcome = 'REVERTED'`.
   - Recorded `phase_9_1_2_5_legacy_evidence_closure` in `schema_migrations`.
5. **Schema Migration Ledger Immutability (Section 7):**
   - Refactored `record_schema_migration()` to eliminate `INSERT OR REPLACE` semantics.
   - Identical re-applications no-op cleanly, preserving original `applied_at` timestamps. Inconsistent versions raise `ConcurrencyConflictError`.
6. **Exhaustive Testing & Verification:**
   - Corrected Phase 9.1.2.4 audit documentation in `docs/PHASE_9_1_2_4_IMPLEMENTATION_REPORT.md` (baseline `af23612`, final commit `76cc3677c71242056aa2c3d0fe289e54896fddd8`, added Section 2.6).
   - Authored 25 dedicated tests in `tests/test_phase_9_1_2_5_legacy_evidence_closure.py` covering all 20 required migration scenarios, the critical regression test proving modern uploads remain `REQUIRED`, controlled recovery, reconciliation, and ledger immutability (100% pass rate).
   - Executed full repository regression test suite: **1,571 tests passing across 108 test suites (100% pass rate in 80.74s)**.
   - Zero ruff warnings, zero pyflakes errors.

---

## 2. Historical Evidence Sources Inspected & The Provenance Fallacy

### 2.1 Evidence Sources Inspected
A thorough audit of the repository history and database schema was conducted across:
- `src/database/schema.sql` (all 26 tables, triggers, and indexes).
- `src/database/db_manager.py` (database initialization, migrations, and snapshot creation routines).
- Git commit lineage from Phase 9.0 through Phase 9.1.2.4.

### 2.2 Findings on Historical Provenance Mechanisms
1. **Pre-Phase 9.1.1 Artifacts:** Prior to Phase 9.1.1, `job_descriptions` stored text extraction fields (`raw_content`, `content_hash`, `parsed_data`, `parser_version`, `snapshot_hash`). Binary metadata columns (`storage_filename`, `file_hash`, `file_size_bytes`, `file_format`, `binary_integrity_state`) did not exist.
2. **Absence of Pre-Phase 9.1.1 Cryptographic Ledgers:** The project contained no pre-existing signed import manifests, deployment markers, or digital signatures prior to Phase 9.1.2.
3. **Mutable Timestamps in SQLite:** The `created_at` column in SQLite is an unverified string column populated by caller input or `CURRENT_TIMESTAMP`. It has no cryptographic attestation and can be modified or backdated.

### 2.3 The Snapshot Hash Equivalence Fallacy
The previous migration routine (`_migrate_historical_job_description_integrity`) attempted to identify historical uploads by verifying that their `snapshot_hash` matched an RFC 8785 canonical JSON hash of a 9-field manifest (`user_id`, `company_name`, `job_title`, `raw_content_hash`, `parsed_data`, `parser_version`, `source_type`, `source_url`, `original_filename`).

**Why this was flawed:**
In architecture v2.1.1, the public `save_job_description_snapshot()` method generates that **exact same 9-field manifest hash** for modern uploads today. Binary metadata fields are stored in dedicated table columns but are intentionally omitted from `snapshot_hash` to ensure text parser stability. Therefore:
$$\text{Data Integrity} \neq \text{Historical Provenance}$$
A valid snapshot hash proves mathematical consistency with the database row fields from which it was computed; it provides **zero independent proof** of when that row was created or whether it existed before Phase 9.1.1.

---

## 3. Legacy Eligibility Contract & No-Trustworthy-History Default

### 3.1 Strict Evidence-Based Contract
Under Phase 9.1.2.5, a candidate record in `job_descriptions` may receive `LEGACY_TEXT_ONLY` status if and only if all of the following conditions are satisfied:
1. `lower(source_type) IN ('uploaded_document', 'upload')`.
2. All four binary metadata fields are strictly `NULL` (`storage_filename`, `file_hash`, `file_size_bytes`, `file_format`).
3. `binary_integrity_state != 'VERIFIED'` (never downgrade verified records).
4. No signed security scan with binary provenance (`source_binary_hash IS NOT NULL`) exists for this record.
5. The record's `snapshot_hash` matches the canonical RFC 8785 hash of its 9-key manifest.
6. **Authoritative External Evidence Attestation:** An authoritative record exists in `legacy_evidence_attestations` for `(job_description_id, user_id)` with non-empty `evidence_type`, non-empty `evidence_reference_id`, and matching `source_snapshot_hash`.
7. An immutable audit row is persisted in `legacy_integrity_exceptions` recording `evidence_type` and `evidence_reference_id`.

### 3.2 No-Trustworthy-History Default
If condition 6 is not met (i.e., no external attestation exists in `legacy_evidence_attestations`), the engine enforces:
$$\text{Unknown historical origin} = \text{NOT VERIFIED (remains } \texttt{REQUIRED}\text{)}$$
The record remains in `REQUIRED` state and fails closed on all security-sensitive actions (e.g., preflight for document generation or application preparation) with:
`SecurityAuthorizationError: JobDescription #... is an uploaded record missing required binary metadata.`

---

## 4. Controlled Recovery Procedure

Where historical provenance cannot be established, candidates or administrators must execute the controlled recovery path rather than manufacturing unproven legacy exceptions.

```
+-----------------------------------------------------------------------------------------+
|                               CONTROLLED RECOVERY PIPELINE                              |
|                                                                                         |
|  [Unverified JobDescription (REQUIRED)] + [Candidate Physical PDF/DOCX Bytes]           |
|                                        │                                                |
|                                        ▼                                                |
|                   1. Ownership & State Validation                                       |
|                      - Verify user_id == jd.user_id                                     |
|                      - Verify jd.is_active == 1                                         |
|                      - Verify source_type in ('upload', 'uploaded_document')            |
|                      - Verify binary_integrity_state == 'REQUIRED'                     |
|                                        │                                                |
|                                        ▼                                                |
|                   2. Physical Binary Validation (FileSecurityValidator)                  |
|                      - Magic bytes inspection (%PDF- / PK zip DOCX)                     |
|                      - 10 MB strict size cap & filename sanitization                    |
|                      - Recompute physical SHA-256 and exact size                        |
|                                        │                                                |
|                                        ▼                                                |
|                   3. Secure Physical Persistence & Text Extraction                      |
|                      - Persist file to user's private job_descriptions directory         |
|                      - Extract text using JobParser (pdfplumber / docx)                 |
|                                        │                                                |
|                                        ▼                                                |
|                   4. Authoritative Child Revision Creation                              |
|                      - supersedes_job_description_id = old_jd_id                        |
|                      - Deactivate parent (old_jd.is_active = 0, immutable)              |
|                      - Set binary_integrity_state = 'VERIFIED'                          |
|                      - Store physical file_hash, file_size_bytes, file_format           |
|                                        │                                                |
|                                        ▼                                                |
|                   5. Fresh Security Scanning & Signed Scan Persistence                  |
|                      - Multi-engine prompt injection scan on extracted text             |
|                      - Sign v2 manifest with HMAC-SHA256 and source_binary_hash         |
|                      - Persist signed record in security_scans                          |
|                                        │                                                |
|                                        ▼                                                |
|                   6. Durable Audit Logging                                              |
|                      - Record JOB_DESCRIPTION_RECOVERED event in application_logs       |
+-----------------------------------------------------------------------------------------+
```

---

## 5. Corrective Reconciliation Migration Architecture

### 5.1 Preservation of Prior Migration Finality
`phase_9_1_2_3_legacy_binary_integrity` is preserved as a completed ledger entry in `schema_migrations`. It is never reset or deleted during application startup.

### 5.2 Corrective Migration: `phase_9_1_2_5_legacy_evidence_closure`
To reconcile existing databases where records may have received `LEGACY_TEXT_ONLY` status without independent evidence, a new migration `_migrate_phase_9_1_2_5_legacy_evidence_reconciliation` runs automatically during database initialization:
1. Checks `schema_migrations` for `phase_9_1_2_5_legacy_evidence_closure`. If found, exits immediately.
2. Queries all records with `binary_integrity_state = 'LEGACY_TEXT_ONLY'`.
3. For each record, inspects `legacy_evidence_attestations`:
   - If valid attestation exists matching snapshot hash: inserts audit row into `legacy_integrity_exceptions` with `outcome = 'SUCCESS'` and `migration_version = '9.1.2.5'`.
   - If NO valid attestation exists: reverts `job_descriptions.binary_integrity_state` to `'REQUIRED'` and inserts an audit row into `legacy_integrity_exceptions` with `outcome = 'REVERTED'`, `evidence_type = 'NONE'`, `evidence_reference_id = 'NONE'`, and `migration_reason = 'Reconciled: lacked independent historical evidence proof; reverted to REQUIRED'`.
4. Records `phase_9_1_2_5_legacy_evidence_closure` in `schema_migrations`.

---

## 6. Schema & Model Updates

### 6.1 `legacy_integrity_exceptions` (Audit Table)
```sql
CREATE TABLE IF NOT EXISTS legacy_integrity_exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    job_description_id INTEGER NOT NULL REFERENCES job_descriptions(id) ON DELETE RESTRICT,
    original_source_type TEXT NOT NULL,
    previous_binary_state TEXT,
    assigned_legacy_state TEXT NOT NULL,
    source_snapshot_hash TEXT,
    migration_version TEXT NOT NULL,
    evidence_type TEXT,
    evidence_reference_id TEXT,
    migration_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    migration_reason TEXT NOT NULL,
    outcome TEXT NOT NULL
);
```

### 6.2 `legacy_evidence_attestations` (Evidence Table)
```sql
CREATE TABLE IF NOT EXISTS legacy_evidence_attestations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    job_description_id INTEGER NOT NULL REFERENCES job_descriptions(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    evidence_reference_id TEXT NOT NULL,
    source_snapshot_hash TEXT NOT NULL,
    attested_by TEXT NOT NULL,
    attested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);

CREATE TRIGGER IF NOT EXISTS trg_prevent_legacy_evidence_attestations_update
BEFORE UPDATE ON legacy_evidence_attestations
BEGIN
    SELECT RAISE(FAIL, 'legacy_evidence_attestations records are append-only and cannot be updated.');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_legacy_evidence_attestations_delete
BEFORE DELETE ON legacy_evidence_attestations
BEGIN
    SELECT RAISE(FAIL, 'legacy_evidence_attestations records are immutable and cannot be deleted.');
END;
```

---

## 7. Test Results Matrix

### 7.1 Dedicated Test Suite: `tests/test_phase_9_1_2_5_legacy_evidence_closure.py`
| Test ID | Test Method | Scenario Description | Status |
|:---|:---|:---|:---:|
| 1 | `test_01_genuinely_supported_historical_record_with_independent_evidence` | Historical upload with external attestation enters `LEGACY_TEXT_ONLY` | PASSED |
| 2 | `test_02_current_uploaded_record_with_valid_nine_field_snapshot_hash` | Valid 9-field snapshot hash without evidence remains `REQUIRED` | PASSED |
| 3 | `test_03_current_uploaded_record_with_old_created_at` | Backdated `created_at` timestamp without evidence remains `REQUIRED` | PASSED |
| 4 | `test_04_newly_inserted_record_with_all_four_metadata_fields_null` | Newly inserted record with NULL binary fields remains `REQUIRED` | PASSED |
| 5 | `test_05_current_record_with_timestamp_manually_backdated_before_first_migration` | Current upload backdated before first migration remains `REQUIRED` | PASSED |
| 6 | `test_06_record_with_manually_reconstructed_nine_field_snapshot_hash` | Reconstructed 9-field snapshot hash remains `REQUIRED` | PASSED |
| 7 | `test_07_record_with_no_preexisting_migration_evidence` | Fresh database with no attestations grants 0 legacy exceptions | PASSED |
| 8 | `test_08_record_with_already_completed_migration_marker` | Migration marker in `schema_migrations` prevents re-evaluations | PASSED |
| 9 | `test_09_conflicting_signed_v2_binary_provenance_scan` | Record with attestation but signed v2 binary scan remains `REQUIRED` | PASSED |
| 10 | `test_10_previously_verified_record_with_binary_metadata_removed` | Previously `VERIFIED` record cannot be downgraded to legacy | PASSED |
| 11 | `test_11_verified_record_manually_changed_to_required` | `VERIFIED` record changed to `REQUIRED` with signed scan blocked | PASSED |
| 12 | `test_12_partially_populated_binary_metadata_record` | Upload with partial binary metadata (2 of 4 set) fails closed | PASSED |
| 13 | `test_13_historical_exception_with_missing_audit_evidence` | Preflight rejects legacy exception missing evidence provenance | PASSED |
| 14 | `test_14_historical_exception_with_mismatched_snapshot_hash` | Preflight rejects legacy exception with tampered snapshot hash | PASSED |
| 15 | `test_15_repeated_migration_invocation` | Repeated migration execution is strictly idempotent | PASSED |
| 16 | `test_16_restarted_database_manager_after_completed_migration` | Reopened database recognizes ledger and skips re-execution | PASSED |
| 17 | `test_17_failed_audit_insertion_and_full_rollback` | Simulated audit insertion failure triggers complete rollback | PASSED |
| 18 | `test_18_failed_migration_marker_persistence_and_full_rollback` | Simulated marker insertion failure triggers complete rollback | PASSED |
| 19 | `test_19_unknown_historical_origin_remains_required` | Section 4.2 invariant: unknown origin = NOT VERIFIED | PASSED |
| 20 | `test_20_pasted_and_url_sources_remain_not_applicable` | Non-uploaded sources transition to `NOT_APPLICABLE` | PASSED |
| CR | `test_critical_regression_modern_upload_with_null_metadata_and_backdated_timestamp_remains_required` | Section 6.2 critical regression test | PASSED |
| R1 | `test_controlled_recovery_procedure_supersedes_and_verifies` | Section 5.1 controlled recovery validates bytes and supersedes | PASSED |
| R2 | `test_controlled_recovery_rejects_cross_user_or_already_verified` | Controlled recovery rejects unauthorized or already verified JDs | PASSED |
| M1 | `test_reconciliation_migration_reverts_unattested_legacy_records` | Corrective migration reverts unattested records to `REQUIRED` | PASSED |
| M2 | `test_schema_migration_ledger_immutable_and_rejects_inconsistent_version` | Migration ledger rejects version conflicts and prevents replacement | PASSED |

**Dedicated Test Results:** 25 passed in 1.58s (100% pass rate).

---

## 8. Full Repository Regression Results

```bash
pytest tests/ -q
....................................................................................
....................................................................................
....................................................................................
1571 passed in 80.74s (0:01:20)
```

- **Total Test Suites Executed:** 108
- **Total Tests Passed:** 1,571
- **Failures:** 0
- **Errors:** 0
- **Skips:** 0
- **Pass Rate:** 100.0%
- **Code Quality:** `ruff check src/ tests/` (All checks passed!), `pyflakes` (Zero errors).

---

## 9. Known Limitations

1. **Physical File Re-Upload Requirement:** In deployed installations where historical job descriptions were uploaded prior to Phase 9.1.1 without independent archival evidence, those records cannot be used for security-sensitive workflows until the user re-uploads the source file via `recover_unverified_job_description()`. This is by design: backward compatibility must never compromise binary-integrity guarantees.
2. **Text-Only Pasted/URL Disclaimers:** Pasted and URL job descriptions retain `NOT_APPLICABLE` status and are subject to Unicode and prompt injection scanning, but cannot offer binary file provenance.

---

## 10. Explicit Sign-Off & Recommendation for Phase 9.1.3

- **Phase 9.1.2.5 Objective:** Fully Achieved.
- **Fail-Closed Default:** Enforced.
- **Critical Regression Test:** Verified.
- **Historical Evidence Closure:** Complete.
- **Roadmap Recommendation:** **GO FOR PHASE 9.1.3** (Security Dashboard UI, Candidate Quarantine Overrides, and User Consent Protocols).

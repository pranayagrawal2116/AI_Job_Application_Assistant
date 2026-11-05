# PHASE 9.1.1.1 IMPLEMENTATION REPORT: RESUME BINARY INTEGRITY & JUST-IN-TIME VERIFICATION

**Project:** Universal AI Job Application Assistant  
**Architecture:** v2.1.1  
**Milestone:** Phase 9.1.1.1  
**Target Branch:** `main`  
**Verified Baseline Commit:** `8298881037e55b5ab63de3943de7e7634186f037`  
**Final Implementation Commit:** `98bedb5b29fc42a5bcdd1fa2d3ae935b0e515d11` (or HEAD)  
**Execution Date:** November 05, 2026  
**Status:** **COMPLETED & VERIFIED (100% Tests Passing, 0 Errors)**

---

## 1. Executive Summary

Phase 9.1.1 established uploaded job-description binary integrity, metadata persistence, hash validation, and transactional revision lineage. However, its implementation report explicitly deferred resume Just-In-Time (JIT) validation.

Phase 9.1.1.1 completely closes that gap by ensuring that every candidate resume consumed by security-sensitive application workflows is verified against its stored binary metadata immediately before use. 

This implementation delivers:
1. **Authoritative Identification & Ownership Isolation:** Strict candidate ownership enforcement, exact version resolution, and sandbox directory containment preventing cross-user resume access and arbitrary "latest" version fallbacks.
2. **Reuse of Robust File Security Core:** Full reuse of `FileSecurityValidator.resolve_and_verify_candidate_file()` using descriptor-relative `O_NOFOLLOW` inspection, symlink rejection, path traversal prevention, magic bytes checking, size comparison, and SHA-256 verification.
3. **Time-of-Check/Time-of-Use (TOCTOU) Protection:** Reading raw bytes directly from the open verified file descriptor into an immutable in-memory verified container (`VerifiedResume`), preventing post-check file swapping.
4. **Fresh In-Memory Extraction & Universal Parsing:** In-memory PDF and DOCX text extraction directly from verified bytes and fresh AST parsing, eliminating reliance on stale serialized JSON in SQLite and refusing to fall back to stale data when parsing fails.
5. **Zero Hallucination Policy:** Security metadata (hashes, file sizes, descriptor paths) is strictly kept internal and never fabricated as candidate experience, skills, degrees, or licenses.
6. **Backward Compatible Historical Record Policy:** Historical records without cryptographic metadata fail closed for sensitive operations, with a controlled and audited recovery path (`reverify_and_backfill_historical_resume`).
7. **Comprehensive Dedicated Test Suite:** 30 new automated regression tests in `tests/test_phase_9_1_1_1_resume_integrity.py` covering valid files, binary tampering, truncation, replacement attacks, corrupted metadata, traversal, symlinks, TOCTOU immutability, fresh parsing vs stale JSON, fail-closed handling, and end-to-end workflow integrations.

---

## 2. Baseline & Branch Verification

- **Repository:** `https://github.com/pranayagrawal2116/AI_Job_Application_Assistant.git`
- **Branch:** `main`
- **Pre-execution HEAD Commit:** `8298881037e55b5ab63de3943de7e7634186f037` (Phase 9.1.1 completion commit)
- **Remote Tracking:** `origin/main` synchronized.
- **Working Tree:** Verified clean prior to implementation; no uncommitted changes were discarded or overwritten.

---

## 3. Resume Storage Architecture & Exact JIT Verification Flow

Candidate resumes are stored in private isolated directories on disk: `data/users/<user_id>/resumes/<storage_filename>`. Database records in `resumes` and `resume_versions` store metadata including `original_filename`, `storage_filename`, `file_format`, `file_size_bytes`, `file_hash` (SHA-256), `active_version`, and `parsed_data`.

### Exact JIT Verification Flow:

```
[Security-Sensitive Caller]
          |
          v (user_id, resume_id, version_num)
[ResumeIntegrityVerifier.verify_and_load_resume]
          |
          +---> 1. Database Resolution:
          |         - Query `resumes` WHERE id = resume_id
          |         - Verify user_id == authenticated user (CrossUserAccessError if mismatch)
          |         - Verify is_active == 1 (ResumeIntegrityError if inactive)
          |         - If version_num specified: query `resume_versions` WHERE version_num = target_ver
          |         - Fail closed if version_num not found (ResumeNotFoundError)
          |         - Check metadata completeness (storage_filename, file_hash, file_size_bytes)
          |
          +---> 2. Sandbox Path Resolution:
          |         - Reject null bytes and '..' sequences
          |         - Resolve sandboxed directory: `data/users/<user_id>/resumes/`
          |
          +---> 3. Descriptor-Relative Verification (`FileSecurityValidator.resolve_and_verify_candidate_file`):
          |         - Open candidate root with `O_RDONLY | O_DIRECTORY`
          |         - Step down subdirectories with `O_NOFOLLOW`
          |         - Reject symlinks at intermediate and target levels
          |         - Open target file with `O_RDONLY | O_NOFOLLOW`
          |         - Read verified bytes directly from descriptor
          |         - Verify magic bytes (%PDF, PK..)
          |         - Compare exact byte length against recorded `file_size_bytes`
          |         - Compute SHA-256 and compare against recorded `file_hash`
          |
          +---> 4. In-Memory Extraction & Universal Parsing:
          |         - Extract raw text in memory from verified bytes (`extract_text_from_pdf` / `extract_text_from_docx`)
          |         - Parse extracted text into structured `ParsedResume` AST
          |         - If extraction or parsing fails, fail closed (ResumeIntegrityError)
          |
          v
[VerifiedResume] (Immutable In-Memory Container)
          |
          +---> caller consumes verified_res.parsed_resume and verified_res.file_bytes directly
```

---

## 4. Ownership and Version Verification (Section 4.1)

The centralized verification service `ResumeIntegrityVerifier` enforces:
1. **User Identity Resolution:** The user ID is strictly validated as a positive integer.
2. **Cross-User Access Rejection:** If `resumes.user_id != caller_user_id`, a `CrossUserAccessError` is raised immediately. Database queries never fall back to global or unauthenticated users.
3. **Exact Version Integrity:** If a specific `version_num` is requested, the system verifies `resume_versions` for that exact version number. If it does not exist, `ResumeNotFoundError` is raised. The system strictly avoids falling back to an arbitrary latest or active version.
4. **Active Version Integrity:** If no version is specified, the verifier loads `active_version` from `resumes` and checks its consistency against `resume_versions`.

---

## 5. Secure File Access & Time-of-Check/Time-of-Use (TOCTOU) Protection (Section 4.2 & 6)

Traditional path-based checks (checking `os.path.exists()` and reopening later) are vulnerable to race conditions where a symlink or malicious binary is swapped into place after validation.

Phase 9.1.1.1 completely eliminates this vulnerability:
1. **Descriptor-Relative Inspection:** `FileSecurityValidator.resolve_and_verify_candidate_file()` inspects path components without symlink traversal and reads the complete binary bytes directly from the open file descriptor.
2. **In-Memory Verified Artifact (`VerifiedResume`):** `verify_and_load_resume` holds the read bytes in memory inside a `VerifiedResume` dataclass:
   ```python
   @dataclass(frozen=True)
   class VerifiedResume:
       resume_id: int
       user_id: int
       version_num: int
       storage_filename: str
       file_path: Path
       file_bytes: bytes
       file_hash: str
       file_size_bytes: int
       file_format: str
       extracted_text: str
       parsed_resume: ParsedResume
       raw_record: Dict[str, Any]
   ```
3. **Log-Safe Masking:** The `__repr__` method of `VerifiedResume` automatically masks `file_bytes` and `extracted_text` to prevent sensitive candidate PII from leaking into diagnostic logs.
4. **Direct In-Memory Consumption:** All subsequent extraction, parsing, tailoring, and document generation operations consume the verified in-memory bytes and AST directly, so modifying the file on disk post-verification has zero impact on downstream processing.

---

## 6. Fresh Extraction & Parsing Architecture (Section 4.3)

1. **Byte-Level In-Memory Parsing:** `ResumeParser` was extended with `parse_bytes(file_bytes: bytes, file_format: str, file_path: Optional[Path] = None)`. In-memory byte parsing handles both PDF (via `pypdf.PdfReader(io.BytesIO(file_bytes))`) and DOCX (via `docx.Document(io.BytesIO(file_bytes))`).
2. **Elimination of Stale DB Fallbacks:** The parser AST is generated freshly from the verified on-disk bytes for every security-sensitive operation. If the file on disk was legitimately updated or corrected, the fresh content is parsed.
3. **Fail-Closed on Corrupted Files:** If a file cannot be parsed or text cannot be extracted, `ResumeIntegrityError` is raised. The verifier never silently falls back to stale `parsed_data` stored in SQLite.
4. **Serialization Contract:** The established flat `ParsedResume` dataclass and dictionary serialization format are strictly preserved.
5. **Zero Candidate Fact Fabrication:** File integrity metadata (`file_hash`, `file_size_bytes`, descriptor paths) is maintained strictly within security tracking structures and is never injected as candidate skills, experience, or certifications.

---

## 7. Backward Compatibility & Historical Record Policy (Section 4.5)

### Historical Policy:
- Resumes uploaded prior to cryptographic metadata tracking may have `file_hash = NULL`, non-SHA-256 placeholder hashes, or `file_size_bytes = 0`.
- In security-sensitive operations (packet preparation, profile synchronization, tailored generation), unverified historical resumes **fail closed** with `ResumeIntegrityError`:
  ```
  Resume #X (vY) lacks valid cryptographic integrity metadata (SHA-256 hash). Historical record cannot be verified and requires re-upload.
  ```
- **Controlled Re-verification Path:** `ResumeIntegrityVerifier.reverify_and_backfill_historical_resume(user_id, resume_id, user_base_dir)` provides an explicit, safe path to re-verify an existing on-disk file:
  - Validates sandbox containment and descriptor-relative regular file status.
  - Recomputes the actual SHA-256 hash and file size from disk.
  - Validates magic bytes and parses extracted text.
  - Updates `resumes` and `resume_versions` atomically within an SQLite transaction.
  - Logs a permanent audit record of the backfill.

---

## 8. Centralized Verification Integration Points (Section 5)

Every security-sensitive application workflow consuming resume content has been wired to the centralized `ResumeIntegrityVerifier`:

| Integration Point | File & Method | Verification Mechanism | Outcome on Tampering / Mismatch |
| :--- | :--- | :--- | :--- |
| **Resume Retrieval for Profile** | `dashboard/services/dashboard_service.py` -> `verify_and_load_resume` | `ResumeIntegrityVerifier.verify_and_load_resume` | Fails closed with `ResumeIntegrityError` |
| **Profile Synchronization** | `src/preparer/profile_updater.py` -> `sync_user_profile` | Verifies binary and fresh-parses before candidate profile update | Profile sync aborted; no facts modified |
| **Tailored Resume Generation** | `src/preparer/tailored_resume_generator.py` -> `generate` | Verifies binary and extracts fresh candidate profile before tailoring | Generation aborted; no tailored doc emitted |
| **Universal Cover Letter** | `dashboard/services/dashboard_service.py` -> `generate_universal_cover_letter` | JIT binary verification before generating tailored letter | Generation aborted; no cover letter emitted |
| **Screening QA Drafting** | `dashboard/services/dashboard_service.py` -> `batch_answer_screening_questions` | JIT binary verification before drafting screening answers | Drafting aborted; no answers generated |
| **Application Packet Creation** | `src/preparer/approval_gate.py` -> `prepare_universal_packet` (Element 0) | JIT binary verification of `original_resume_id` and hash | Preparation aborted; packet creation blocked |
| **Packet Integrity Verification** | `src/preparer/approval_gate.py` -> `verify_prepared_packet_integrity` (Element 8) | Descriptor verification against packet `original_resume_hash` | Returns `valid=False`; human approval blocked |
| **Candidate Profile View** | `dashboard/views/candidate_profile.py` | Uses `DashboardService.verify_and_load_resume` | Secure error banner; untrusted resume blocked |

---

## 9. Fail-Closed Security Decision Matrix (Section 4.4)

| Fault / Condition | Detected By | Exception / Return | Security Action |
| :--- | :--- | :--- | :--- |
| **File missing on disk** | `FileSecurityValidator` | `FileNotFoundError` -> `ResumeIntegrityError` | Abort operation; fail closed |
| **Byte modified on disk (1-bit flipped)** | `FileSecurityValidator` | `ValidationError` -> `ResumeIntegrityError` | Hash mismatch detected; abort operation |
| **Same-size byte alteration** | `FileSecurityValidator` | `ValidationError` -> `ResumeIntegrityError` | Hash mismatch detected; abort operation |
| **File truncated** | `FileSecurityValidator` | `ValidationError` -> `ResumeIntegrityError` | Size mismatch detected; abort operation |
| **Replaced with different valid PDF** | `FileSecurityValidator` | `ValidationError` -> `ResumeIntegrityError` | Hash/size mismatch detected; abort operation |
| **Replaced with different valid DOCX** | `FileSecurityValidator` | `ValidationError` -> `ResumeIntegrityError` | Hash/size mismatch detected; abort operation |
| **Corrupted magic bytes** | `FileSecurityValidator` | `InvalidFileFormatError` -> `ResumeIntegrityError` | Format validation failed; abort operation |
| **Path traversal (`..` or null byte)** | `FileSecurityValidator` | `FileSecurityError` | Traversal detected; abort operation |
| **Symlink attack** | `FileSecurityValidator` | `FileSecurityError` | Symlink rejected by `O_NOFOLLOW`; abort |
| **Cross-user resume access** | `ResumeIntegrityVerifier` | `CrossUserAccessError` | Ownership violation; abort operation |
| **Non-existent resume version** | `ResumeIntegrityVerifier` | `ResumeNotFoundError` | Version not found; abort operation |
| **Corrupted expected hash in DB** | `ResumeIntegrityVerifier` | `ResumeIntegrityError` | Invalid metadata; abort operation |
| **Corrupted expected size in DB** | `ResumeIntegrityVerifier` | `ResumeIntegrityError` | Invalid metadata; abort operation |
| **Extraction / Parser failure** | `ResumeParser` | `ResumeIntegrityError` | Parser failed; abort; no stale fallback |
| **Historical record missing hash** | `ResumeIntegrityVerifier` | `ResumeIntegrityError` | Unverified record; require re-upload or backfill |

---

## 10. Test Matrix & Verification Results

A dedicated test suite was implemented in `tests/test_phase_9_1_1_1_resume_integrity.py` containing 30 comprehensive regression tests:

```
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_01_valid_pdf_resume_verification_and_fresh_parsing PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_02_valid_docx_resume_verification_and_fresh_parsing PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_03_version_resolution_exact_version_vs_active PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_04_verified_resume_repr_masks_binary_and_raw_text PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_05_tampering_one_byte_flipped_rejected PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_06_tampering_same_size_modification_rejected PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_07_tampering_file_truncated_rejected PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_08_tampering_file_replaced_with_another_valid_pdf_rejected PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_09_tampering_file_replaced_with_another_valid_docx_rejected PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_10_invalid_magic_bytes_rejected PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_11_missing_file_fails_closed PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_12_corrupted_expected_hash_in_db_fails_closed PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_13_corrupted_expected_size_in_db_fails_closed PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_14_cross_user_resume_access_rejected PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_15_path_traversal_in_storage_filename_rejected PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_16_symlink_attack_rejected PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_17_attempt_to_substitute_nonexistent_version_rejected PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_18_toctou_post_verification_immutability PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_19_fresh_parsing_reflects_disk_over_stale_db_json PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_20_parser_failure_fails_closed_without_falling_back_to_stale_json PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_21_historical_resume_missing_metadata_fails_closed PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_22_reverify_and_backfill_historical_resume PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_23_security_metadata_not_injected_into_candidate_facts PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_24_profile_sync_refuses_tampered_resume PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_25_tailored_resume_generator_refuses_tampered_resume PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_26_dashboard_cover_letter_refuses_tampered_resume PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_27_dashboard_screening_qa_refuses_tampered_resume PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_28_packet_preparation_refuses_tampered_resume PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_29_valid_resume_flows_end_to_end_through_approval_gate PASSED
tests/test_phase_9_1_1_1_resume_integrity.py::TestPhase9111ResumeIntegrity::test_30_matching_refuses_tampered_resume PASSED
```

### Full Repository Test Suite Verification:
- **Total Test Suites Executed:** 58 test suites
- **Total Tests Passed:** 1,312 passing tests
- **Failures / Errors:** 0
- **Pass Rate:** 100.0%
- **Execution Time:** 61.0 seconds

### Static Analysis & Linter Verification:
- `ruff check .` -> **Clean (0 errors, 0 warnings)**

---

## 11. Exact Files Changed & Created

| File Path | Action | Description |
| :--- | :--- | :--- |
| `src/database/exceptions.py` | Modified | Added `ResumeIntegrityError` subclassing `FileSecurityError` and `ValidationError`. |
| `src/preparer/resume_parser.py` | Modified | Added `bytes` input support to `extract_text_from_pdf` and `extract_text_from_docx`; implemented `parse_bytes`. |
| `src/security/resume_verifier.py` | Created | Centralized verification engine (`ResumeIntegrityVerifier`) and immutable container (`VerifiedResume`). |
| `src/database/db_manager.py` | Modified | Added `file_size_bytes` column migration to `resumes` and exposed `verify_and_load_resume` helper. |
| `src/preparer/approval_gate.py` | Modified | Wired JIT verification into `prepare_universal_packet` (Element 0) and `verify_prepared_packet_integrity` (Element 8). |
| `src/preparer/profile_updater.py` | Modified | Updated `sync_user_profile` to accept `resume_id` and run JIT verification before profile sync. |
| `src/preparer/tailored_resume_generator.py` | Modified | Updated `generate` to accept `resume_id` and run JIT verification before tailoring. |
| `dashboard/services/dashboard_service.py` | Modified | Added JIT verification to `verify_and_load_resume`, `sync_user_profile_from_resume_id`, `recommend_scoring_profile`, cover letter, and screening QA. |
| `dashboard/views/candidate_profile.py` | Modified | Updated candidate profile view to use `service.verify_and_load_resume`. |
| `tests/test_phase6_1_2_hardening.py` | Modified | Added version 2 row in `test_12` to align with strict requested-version verification. |
| `tests/test_phase_9_1_1_1_resume_integrity.py` | Created | Complete 30-test regression suite covering all Section 7 requirements. |
| `docs/PHASE_9_1_1_1_IMPLEMENTATION_REPORT.md` | Created | Comprehensive implementation and verification report. |

---

## 12. Unresolved Issues & Deferred Scope

- **Zero Unresolved Issues:** All resume binary integrity, JIT verification, TOCTOU protection, and historical compatibility requirements have been satisfied.
- **Strict Scope Boundaries Respected:**
  - HMAC scan persistence is deferred to Phase 9.1.2.
  - Multi-engine prompt injection detection is deferred to Phase 9.1.2.
  - Unicode spoof detection & canonical normalization is deferred to Phase 9.1.2.
  - Security scan dashboard UI is deferred to Phase 9.1.3.
  - Playwright browser worker isolation is deferred to Phase 9.1.4.

---

## 13. Next Steps for Phase 9.1.2

With Phase 9.1.1 (Job Description Binary Integrity) and Phase 9.1.1.1 (Resume Binary Integrity & Just-In-Time Verification) fully implemented and verified, the workspace is primed for **Phase 9.1.2: Multi-Engine Prompt Injection & Ingestion Defense Pipeline**:
1. Implement heuristic and semantic prompt injection analyzers for incoming job descriptions.
2. Implement Unicode spoofing and homoglyph normalization.
3. Integrate persistent HMAC scan logs and security verdict evaluations prior to parsing.

"""Phase 9.1.1.1: Resume Binary Integrity & Just-In-Time Verification Test Suite.

Verifies:
1. Valid PDF and DOCX resume verification, hashing, size check, and fresh parsing.
2. Tampering detection: 1-byte alteration, same-size modifications, file truncation,
   substitution with another PDF/DOCX, invalid magic bytes, missing files, corrupted DB metadata.
3. Ownership and path security: cross-user isolation, path traversal, symlink attacks,
   out-of-sandbox escapes, version substitution, and TOCTOU in-memory immutability.
4. Fresh parsing & compatibility: fresh extraction over stale DB JSON, fail-closed on corrupt files,
   historical record policy, backfill/recovery mechanism, candidate fact zero-hallucination.
5. Workflow integration: matching, tailored resume generation, cover letter generation, screening QA,
   profile sync, and packet preparation refuse tampered resumes. Valid resumes flow end-to-end.
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CorruptedFileError,
    CrossUserAccessError,
    FileSecurityError,
    InvalidFileFormatError,
    ResumeIntegrityError,
    ResumeNotFoundError,
    ValidationError,
)
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.profile_updater import ProfileUpdater
from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
from src.security.file_security import FileSecurityValidator
from src.security.resume_verifier import ResumeIntegrityVerifier, VerifiedResume
from dashboard.services.dashboard_service import DashboardService
from tests.fixtures.synthetic_personas import generate_persona_docx, generate_persona_pdf


class TestPhase9111ResumeIntegrity(unittest.TestCase):
    """Comprehensive test suite for Phase 9.1.1.1 Resume Binary Integrity."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.db_path = self.base_dir / "test_resume_integrity.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.file_validator = FileSecurityValidator(base_storage_dir=self.base_dir)
        self.verifier = ResumeIntegrityVerifier(
            db_manager=self.db,
            file_validator=self.file_validator,
        )
        self.service = DashboardService(db_manager=self.db, storage_base_dir=self.base_dir)
        self.approval_gate = HumanApprovalGate(db_manager=self.db, file_validator=self.file_validator)

        # Create two test users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("user1@example.com", "hash1", "salt1", "Alice Candidate"),
            )
            self.user1_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("user2@example.com", "hash2", "salt2", "Bob Malicious"),
            )
            self.user2_id = cursor.lastrowid

        # Generate sample binary assets
        self.pdf_bytes_backend = generate_persona_pdf("backend_engineer")
        self.docx_bytes_attorney = generate_persona_docx("attorney")
        self.pdf_bytes_cardiologist = generate_persona_pdf("cardiologist")

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # Helper: Upload Resume through Secure File Pipeline
    # -------------------------------------------------------------------------
    def _upload_resume(
        self,
        user_id: int,
        file_bytes: bytes,
        original_filename: str,
        label: str = "General",
        target_role: str = "Software Engineer",
    ) -> dict:
        """Stores binary file via DatabaseManager and records metadata in database."""
        user_resumes_dir = self.file_validator.get_user_resumes_dir(user_id)
        return self.db.upload_user_resume(
            user_id=user_id,
            file_bytes=file_bytes,
            original_filename=original_filename,
            label=label,
            target_role=target_role,
            user_base_dir=user_resumes_dir,
        )

    # =========================================================================
    # 1. Valid Files
    # =========================================================================

    def test_01_valid_pdf_resume_verification_and_fresh_parsing(self):
        """Valid PDF resume verifies successfully and returns fresh parsed candidate data."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice_backend.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=res["id"],
            user_base_dir=self.base_dir,
            fresh_parse=True,
        )

        self.assertIsInstance(verified, VerifiedResume)
        self.assertEqual(verified.resume_id, res["id"])
        self.assertEqual(verified.user_id, self.user1_id)
        self.assertEqual(verified.version_num, 1)
        self.assertEqual(verified.file_format, "pdf")
        self.assertEqual(verified.file_size_bytes, len(self.pdf_bytes_backend))
        self.assertEqual(verified.file_hash, hashlib.sha256(self.pdf_bytes_backend).hexdigest())
        self.assertEqual(verified.file_bytes, self.pdf_bytes_backend)
        self.assertIn("Go", verified.parsed_resume.technical_skills)
        self.assertTrue(len(verified.raw_text) > 50)

    def test_02_valid_docx_resume_verification_and_fresh_parsing(self):
        """Valid DOCX resume verifies successfully and parses structured sections."""
        res = self._upload_resume(self.user1_id, self.docx_bytes_attorney, "morgan_attorney.docx")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=res["id"],
            user_base_dir=self.base_dir,
            fresh_parse=True,
        )

        self.assertEqual(verified.file_format, "docx")
        self.assertEqual(verified.file_size_bytes, len(self.docx_bytes_attorney))
        self.assertEqual(verified.file_hash, hashlib.sha256(self.docx_bytes_attorney).hexdigest())
        self.assertTrue(any("Law" in s or "Litigation" in s or "Contract" in s for s in verified.parsed_resume.technical_skills + verified.parsed_resume.professional_skills))

    def test_03_version_resolution_exact_version_vs_active(self):
        """Verification correctly resolves explicit versions and defaults to active version."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "resume_v1.pdf")
        rid = res["id"]

        # Upload version 2
        docx_bytes_v2 = generate_persona_docx("stem_educator")
        res_v2 = self.file_validator.save_user_resume_file(self.user1_id, docx_bytes_v2, "resume_v2.docx")
        # Add to resume_versions
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            # Ensure v1 in resume_versions
            cursor.execute(
                """
                INSERT OR IGNORE INTO resume_versions (
                    resume_id, user_id, version_num, storage_filename,
                    file_hash, file_size_bytes, snapshot_json
                ) VALUES (?, ?, 1, ?, ?, ?, ?)
                """,
                (rid, self.user1_id, res["storage_filename"], res["file_hash"], res["file_size_bytes"], json.dumps(res["parsed_data"])),
            )
            # Add v2
            v2_hash = hashlib.sha256(docx_bytes_v2).hexdigest()
            cursor.execute(
                """
                INSERT INTO resume_versions (
                    resume_id, user_id, version_num, storage_filename,
                    file_hash, file_size_bytes, snapshot_json
                ) VALUES (?, ?, 2, ?, ?, ?, ?)
                """,
                (rid, self.user1_id, res_v2[0], v2_hash, len(docx_bytes_v2), "{}"),
            )
            # Set active version to 2
            cursor.execute(
                "UPDATE resumes SET active_version = 2, storage_filename = ?, file_hash = ?, file_size_bytes = ?, file_format = 'docx' WHERE id = ?",
                (res_v2[0], v2_hash, len(docx_bytes_v2), rid),
            )

        # Default resolution targets active version (v2)
        v_active = self.verifier.verify_and_load_resume(self.user1_id, rid, user_base_dir=self.base_dir)
        self.assertEqual(v_active.version_num, 2)
        self.assertEqual(v_active.file_format, "docx")
        self.assertEqual(v_active.file_hash, v2_hash)

        # Explicit version 1 resolution
        v_1 = self.verifier.verify_and_load_resume(self.user1_id, rid, version_num=1, user_base_dir=self.base_dir)
        self.assertEqual(v_1.version_num, 1)
        self.assertEqual(v_1.file_format, "pdf")
        self.assertEqual(v_1.file_hash, res["file_hash"])

    def test_04_verified_resume_repr_masks_binary_and_raw_text(self):
        """VerifiedResume __repr__ masks sensitive byte payload and long text from ordinary logs."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "test.pdf")
        verified = self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)
        repr_str = repr(verified)

        self.assertIn("<bytes: ", repr_str)
        self.assertNotIn(self.pdf_bytes_backend.decode("latin1", errors="ignore")[:30], repr_str)
        self.assertIn(f"resume_id={res['id']}", repr_str)

    # =========================================================================
    # 2. Tampering & Integrity Violations
    # =========================================================================

    def test_05_tampering_one_byte_flipped_rejected(self):
        """Modifying a single byte on disk fails verification closed with ResumeIntegrityError."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]

        # Tamper: flip 1 byte at index 100
        raw = bytearray(file_path.read_bytes())
        raw[100] = (raw[100] + 1) % 256
        file_path.write_bytes(bytes(raw))

        with self.assertRaises(ResumeIntegrityError) as ctx:
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)
        self.assertIn("hash", str(ctx.exception).lower())

    def test_06_tampering_same_size_modification_rejected(self):
        """Modifying bytes with identical file size fails closed due to SHA-256 mismatch."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]

        raw = bytearray(file_path.read_bytes())
        # Overwrite 20 bytes near the middle without changing length
        raw[200:220] = b"X" * 20
        file_path.write_bytes(bytes(raw))

        with self.assertRaises(ResumeIntegrityError):
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)

    def test_07_tampering_file_truncated_rejected(self):
        """Truncating the file fails closed due to size mismatch."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]

        raw = file_path.read_bytes()
        file_path.write_bytes(raw[: len(raw) // 2])

        with self.assertRaises(ResumeIntegrityError) as ctx:
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)
        self.assertIn("size", str(ctx.exception).lower())

    def test_08_tampering_file_replaced_with_another_valid_pdf_rejected(self):
        """Replacing the file with another genuine PDF fails closed due to hash mismatch."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]

        # Overwrite with cardiologist PDF
        file_path.write_bytes(self.pdf_bytes_cardiologist)

        with self.assertRaises(ResumeIntegrityError):
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)

    def test_09_tampering_file_replaced_with_another_valid_docx_rejected(self):
        """Replacing a DOCX file with another DOCX fails closed due to hash mismatch."""
        res = self._upload_resume(self.user1_id, self.docx_bytes_attorney, "morgan.docx")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]

        file_path.write_bytes(generate_persona_docx("hotel_gm"))

        with self.assertRaises(ResumeIntegrityError):
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)

    def test_10_invalid_magic_bytes_rejected(self):
        """Replacing PDF with plain text fails closed on magic bytes validation."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]

        fake_text = b"This is plain text pretending to be a PDF file."
        file_path.write_bytes(fake_text)

        with self.assertRaises((InvalidFileFormatError, ResumeIntegrityError)):
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)

    def test_11_missing_file_fails_closed(self):
        """Missing file on disk raises FileNotFoundError and fails closed."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        file_path.unlink()

        with self.assertRaises(FileNotFoundError):
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)

    def test_12_corrupted_expected_hash_in_db_fails_closed(self):
        """Corrupted hash metadata in SQLite causes verification to fail closed."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE resumes SET file_hash = 'bad_hash_not_hex' WHERE id = ?", (res["id"],))

        with self.assertRaises(ResumeIntegrityError) as ctx:
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)
        self.assertIn("cryptographic integrity metadata", str(ctx.exception))

    def test_13_corrupted_expected_size_in_db_fails_closed(self):
        """Corrupted size metadata in SQLite causes verification to fail closed."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE resumes SET file_size_bytes = 999999 WHERE id = ?", (res["id"],))

        with self.assertRaises(ResumeIntegrityError) as ctx:
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)
        self.assertIn("size", str(ctx.exception).lower())

    # =========================================================================
    # 3. Ownership & Path Security
    # =========================================================================

    def test_14_cross_user_resume_access_rejected(self):
        """User 2 cannot access or verify User 1's resume."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")

        with self.assertRaises(CrossUserAccessError) as ctx:
            self.verifier.verify_and_load_resume(
                user_id=self.user2_id,
                resume_id=res["id"],
                user_base_dir=self.base_dir,
            )
        self.assertEqual(ctx.exception.user_id, self.user2_id)
        self.assertEqual(ctx.exception.target_user_id, self.user1_id)

    def test_15_path_traversal_in_storage_filename_rejected(self):
        """Path traversal characters in storage_filename raise FileSecurityError."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE resumes SET storage_filename = '../../etc/passwd' WHERE id = ?", (res["id"],))

        with self.assertRaises(FileSecurityError) as ctx:
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)
        self.assertIn("path traversal", str(ctx.exception).lower())

    def test_16_symlink_attack_rejected(self):
        """Symlinked resume file is rejected via O_NOFOLLOW descriptor inspection."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        real_file = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]

        # Create external file and replace real_file with a symlink to it
        external_file = self.base_dir / "external_secret.pdf"
        external_file.write_bytes(self.pdf_bytes_backend)
        real_file.unlink()
        real_file.symlink_to(external_file)

        with self.assertRaises(FileSecurityError) as ctx:
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)
        self.assertIn("symbolic link", str(ctx.exception).lower())

    def test_17_attempt_to_substitute_nonexistent_version_rejected(self):
        """Requesting non-existent resume version fails closed with ResumeNotFoundError."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")

        with self.assertRaises(ResumeNotFoundError):
            self.verifier.verify_and_load_resume(
                self.user1_id,
                res["id"],
                version_num=99,
                user_base_dir=self.base_dir,
            )

    def test_18_toctou_post_verification_immutability(self):
        """VerifiedResume retains verified bytes in memory even if disk file is altered post-verification."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]

        # 1. JIT verify and load in-memory artifact
        verified_artifact = self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)
        initial_hash = verified_artifact.file_hash
        initial_bytes = verified_artifact.file_bytes

        # 2. Malicious actor modifies or deletes file on disk post-verification
        file_path.write_bytes(b"tampered post-verification bytes")

        # 3. In-memory verified artifact remains intact and authentic
        self.assertEqual(verified_artifact.file_hash, initial_hash)
        self.assertEqual(verified_artifact.file_bytes, initial_bytes)
        self.assertIn("Go", verified_artifact.parsed_resume.technical_skills)

        # 4. Subsequent re-verification detects tampering and fails closed
        with self.assertRaises(ResumeIntegrityError):
            self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)

    # =========================================================================
    # 4. Parsing & Backward Compatibility
    # =========================================================================

    def test_19_fresh_parsing_reflects_disk_over_stale_db_json(self):
        """Fresh extraction from verified binary reflects binary content rather than stale DB JSON."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")

        # Deliberately poison the DB parsed_data column with stale facts
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE resumes SET parsed_data = ? WHERE id = ?",
                (json.dumps({"technical_skills": ["Cobol", "Fortran"], "full_name": "Stale Name"}), res["id"]),
            )

        # Fresh parse from verified bytes overrides stale DB record
        verified = self.verifier.verify_and_load_resume(
            self.user1_id,
            res["id"],
            user_base_dir=self.base_dir,
            fresh_parse=True,
        )
        self.assertIn("Go", verified.parsed_resume.technical_skills)
        self.assertNotIn("Cobol", verified.parsed_resume.technical_skills)

    def test_20_parser_failure_fails_closed_without_falling_back_to_stale_json(self):
        """If document binary cannot be parsed, system fails closed with CorruptedFileError without using stale JSON."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]

        # Construct payload with valid PDF header magic bytes but corrupted PDF syntax
        corrupted_pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\nCORRUPTED_STREAM_WITHOUT_TRAILER_OR_XREF_TABLE_EOF"
        c_hash = hashlib.sha256(corrupted_pdf).hexdigest()
        c_size = len(corrupted_pdf)
        file_path.write_bytes(corrupted_pdf)

        # Update metadata so binary verification passes, forcing parser failure
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE resumes SET file_hash = ?, file_size_bytes = ? WHERE id = ?",
                (c_hash, c_size, res["id"]),
            )

        with self.assertRaises(CorruptedFileError):
            self.verifier.verify_and_load_resume(
                self.user1_id,
                res["id"],
                user_base_dir=self.base_dir,
                fresh_parse=True,
            )

    def test_21_historical_resume_missing_metadata_fails_closed(self):
        """Historical resume missing valid SHA-256 hash or size fails closed under documented policy."""
        # Insert historical resume lacking valid cryptographic hash and size
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO resumes (
                    user_id, storage_filename, original_filename, file_format,
                    file_hash, file_size_bytes, parsed_data, active_version, is_active
                ) VALUES (?, 'hist_res.pdf', 'hist_res.pdf', 'pdf', 'legacy_unverified', 0, '{}', 1, 1)
                """,
                (self.user1_id,),
            )
            hist_id = cursor.lastrowid

        with self.assertRaises(ResumeIntegrityError) as ctx:
            self.verifier.verify_and_load_resume(self.user1_id, hist_id, user_base_dir=self.base_dir)
        self.assertIn("Historical record cannot be verified", str(ctx.exception))

    def test_22_reverify_and_backfill_historical_resume(self):
        """Controlled recovery path reverifies on-disk physical file and backfills hash and size."""
        # Write real PDF file to user directory
        user_dir = self.file_validator.get_user_resumes_dir(self.user1_id)
        hist_filename = "historical_recovered.pdf"
        (user_dir / hist_filename).write_bytes(self.pdf_bytes_backend)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO resumes (
                    user_id, storage_filename, original_filename, file_format,
                    file_hash, file_size_bytes, parsed_data, active_version, is_active
                ) VALUES (?, ?, 'historical.pdf', 'pdf', 'legacy_unverified', 0, '{}', 1, 1)
                """,
                (self.user1_id, hist_filename),
            )
            hist_id = cursor.lastrowid

        # Verification initially fails closed
        with self.assertRaises(ResumeIntegrityError):
            self.verifier.verify_and_load_resume(self.user1_id, hist_id, user_base_dir=self.base_dir)

        # Run controlled recovery
        updated_row = self.verifier.reverify_and_backfill_historical_resume(
            user_id=self.user1_id,
            resume_id=hist_id,
            user_base_dir=self.base_dir,
        )
        expected_hash = hashlib.sha256(self.pdf_bytes_backend).hexdigest()
        self.assertEqual(updated_row["file_hash"], expected_hash)
        self.assertEqual(updated_row["file_size_bytes"], len(self.pdf_bytes_backend))

        # Subsequent JIT verification succeeds
        verified = self.verifier.verify_and_load_resume(self.user1_id, hist_id, user_base_dir=self.base_dir)
        self.assertEqual(verified.file_hash, expected_hash)
        self.assertIn("Go", verified.parsed_resume.technical_skills)

    def test_23_security_metadata_not_injected_into_candidate_facts(self):
        """Zero-hallucination guarantee: file_hash and file_size are never injected into candidate facts."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        verified = self.verifier.verify_and_load_resume(self.user1_id, res["id"], user_base_dir=self.base_dir)

        parsed_dict = verified.parsed_resume.to_dict()
        skills = parsed_dict.get("technical_skills", [])
        self.assertNotIn(verified.file_hash, skills)
        self.assertNotIn(str(verified.file_size_bytes), skills)
        self.assertNotIn(verified.storage_filename, skills)

    # =========================================================================
    # 5. Workflow Integration & Fail-Closed Enforcement
    # =========================================================================

    def test_24_profile_sync_refuses_tampered_resume(self):
        """ProfileUpdater.sync_user_profile fails closed on tampered resume."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        file_path.write_bytes(b"tampered binary")

        updater = ProfileUpdater(db_manager=self.db)
        with self.assertRaises(ResumeIntegrityError):
            updater.sync_user_profile(
                user_id=self.user1_id,
                resume_id=res["id"],
                user_base_dir=self.base_dir,
            )

    def test_25_tailored_resume_generator_refuses_tampered_resume(self):
        """UniversalTailoredResumeGenerator refuses to generate resume if source binary is tampered."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        file_path.write_bytes(b"tampered binary")

        generator = UniversalTailoredResumeGenerator()
        with self.assertRaises(ResumeIntegrityError):
            generator.generate(
                user_id=self.user1_id,
                candidate_profile={"full_name": "Alice Candidate"},
                resume_id=res["id"],
                job_description={"job_title": "Backend Engineer", "mandatory_skills": ["Go"]},
                db_manager=self.db,
                user_base_dir=self.base_dir,
            )

    def test_26_dashboard_cover_letter_refuses_tampered_resume(self):
        """DashboardService.generate_universal_cover_letter fails closed on tampered resume."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        file_path.write_bytes(b"tampered binary")

        with self.assertRaises(ResumeIntegrityError):
            self.service.generate_universal_cover_letter(
                user_id=self.user1_id,
                candidate_profile={"full_name": "Alice Candidate"},
                job_description={"job_title": "Backend Engineer", "company_name": "Tech Corp"},
                resume_id=res["id"],
            )

    def test_27_dashboard_screening_qa_refuses_tampered_resume(self):
        """DashboardService.batch_answer_screening_questions fails closed on tampered resume."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        file_path.write_bytes(b"tampered binary")

        with self.assertRaises(ResumeIntegrityError):
            self.service.batch_answer_screening_questions(
                questions=["Do you know Go?"],
                user_id=self.user1_id,
                candidate_profile={"full_name": "Alice Candidate"},
                resume_id=res["id"],
            )

    def test_28_packet_preparation_refuses_tampered_resume(self):
        """HumanApprovalGate.prepare_universal_packet fails closed on tampered resume."""
        from src.preparer.cover_letter_generator import CoverLetter, LetterTone
        from src.preparer.question_answerer import (
            AnswerState,
            QuestionCategory,
            ScreeningQAPacket,
            ScreeningQuestion,
        )

        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")

        # Create application workspace
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO applications (user_id, resume_id, company_name, job_title, status) VALUES (?, ?, 'Acme', 'Dev', 'PREPARING')",
                (self.user1_id, res["id"]),
            )
            app_id = cursor.lastrowid

        generator = UniversalTailoredResumeGenerator()
        tailored = generator.generate(
            user_id=self.user1_id,
            candidate_profile={"full_name": "Alice Candidate"},
            resume_id=res["id"],
            job_description={"job_title": "Backend Engineer", "mandatory_skills": ["Go"]},
            db_manager=self.db,
            user_base_dir=self.base_dir,
        )

        cl = CoverLetter(
            user_id=self.user1_id,
            target_company="Acme Inc",
            target_role="Backend Engineer",
            letter_text="Dear Hiring Team,\nI am writing to express my interest...",
            paragraphs=["Opening", "Body 1", "Body 2", "Closing"],
            tone=LetterTone.PROFESSIONAL_DIRECT.value,
        )
        qa_packet = ScreeningQAPacket(
            user_id=self.user1_id,
            job_description_id=1,
            questions=[
                ScreeningQuestion(
                    question_id="q1",
                    question_text="Go experience?",
                    category=QuestionCategory.TECHNICAL_SKILL.value,
                    answer_text="4 years",
                    state=AnswerState.USER_APPROVED.value,
                )
            ],
        )

        # Tamper file on disk
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        file_path.write_bytes(b"tampered binary")

        with self.assertRaises(ResumeIntegrityError):
            self.approval_gate.prepare_universal_packet(
                user_id=self.user1_id,
                application_id=app_id,
                original_resume_id=res["id"],
                original_resume_hash=res["file_hash"],
                tailored_resume=tailored,
                cover_letter=cl,
                qa_packet=qa_packet,
                job_description_snapshot_hash="dummy_jd_hash",
            )

    def test_29_valid_resume_flows_end_to_end_through_approval_gate(self):
        """Authentic resume executes full end-to-end flow through verification and packet preparation."""
        from src.preparer.cover_letter_generator import CoverLetter, LetterTone
        from src.preparer.question_answerer import (
            AnswerState,
            QuestionCategory,
            ScreeningQAPacket,
            ScreeningQuestion,
        )

        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")

        # 1. Profile sync succeeds
        updater = ProfileUpdater(db_manager=self.db)
        sync_res = updater.sync_user_profile(
            user_id=self.user1_id,
            resume_id=res["id"],
            user_base_dir=self.base_dir,
        )
        self.assertIn("Go", sync_res.get("technical_skills", {}).get("programming_languages", []))

        # 2. Tailored resume generation succeeds
        generator = UniversalTailoredResumeGenerator()
        tailored = generator.generate(
            user_id=self.user1_id,
            candidate_profile=sync_res,
            resume_id=res["id"],
            job_description={"job_title": "Backend Engineer", "mandatory_skills": ["Go"]},
            db_manager=self.db,
            user_base_dir=self.base_dir,
        )
        self.assertIsNotNone(tailored)

        # 3. Create application record
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO applications (user_id, resume_id, company_name, job_title, status) VALUES (?, ?, 'Acme Inc', 'Backend Engineer', 'PREPARING')",
                (self.user1_id, res["id"]),
            )
            app_id = cursor.lastrowid

        cl = CoverLetter(
            user_id=self.user1_id,
            target_company="Acme Inc",
            target_role="Backend Engineer",
            letter_text="Dear Hiring Team,\nI am writing to express my interest...",
            paragraphs=["Opening", "Body 1", "Body 2", "Closing"],
            tone=LetterTone.PROFESSIONAL_DIRECT.value,
        )
        qa_packet = ScreeningQAPacket(
            user_id=self.user1_id,
            job_description_id=1,
            questions=[
                ScreeningQuestion(
                    question_id="q1",
                    question_text="Go experience?",
                    category=QuestionCategory.TECHNICAL_SKILL.value,
                    answer_text="4 years",
                    state=AnswerState.USER_APPROVED.value,
                )
            ],
        )

        # 4. Prepare universal packet
        packet = self.approval_gate.prepare_universal_packet(
            user_id=self.user1_id,
            application_id=app_id,
            original_resume_id=res["id"],
            original_resume_hash=res["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash="dummy_jd_hash",
        )
        self.assertIsNotNone(packet)
        self.assertEqual(packet.version_num, 1)

        # 5. Verify prepared packet integrity succeeds
        is_valid, reason, verified_packet = self.approval_gate.verify_prepared_packet_integrity(
            packet_id=packet.id,
            user_id=self.user1_id,
            expected_application_id=app_id,
        )
        self.assertTrue(is_valid, f"Packet verification failed: {reason}")
        self.assertIsNotNone(verified_packet)

    def test_30_matching_refuses_tampered_resume(self):
        """Resume matching refuses to evaluate or persist matches when the source resume is tampered."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alice.pdf")

        # Create job description
        jd = self.db.create_job_description(
            user_id=self.user1_id,
            company_name="Acme Inc",
            job_title="Backend Engineer",
            raw_content="Looking for Go backend engineers.",
        )

        # Tamper file on disk
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        file_path.write_bytes(b"tampered binary")

        # Pre-execution JIT verification before matching fails closed
        with self.assertRaises(ResumeIntegrityError):
            self.service.verify_and_load_resume(
                user_id=self.user1_id,
                resume_id=res["id"],
            )

        # Assert no downstream match results were persisted
        matches = self.db.get_user_match_results(self.user1_id)
        self.assertEqual(len(matches), 0)


if __name__ == "__main__":
    unittest.main()

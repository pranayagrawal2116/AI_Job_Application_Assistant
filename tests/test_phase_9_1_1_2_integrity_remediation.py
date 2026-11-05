"""Phase 9.1.1.2 Comprehensive Security Remediation Test Suite.

Exhaustively verifies all 6 findings and remediation contracts:
- Finding A: Matching pipeline bypass closure via JIT verification.
- Finding B: Removal of unverified fallback in scoring-profile recommendation.
- Finding C: Correct historical resume recovery with exact-version targeting,
  tamper detection (rejects re-signing valid cryptographic hashes), and durable audit logging.
- Finding D: Genuine immutability of VerifiedResume (frozen dataclass, defensive copying,
  server path sanitization, and PII masking).
- Finding E: Alternate resume-data bypass closure across document generators and profile sync.
- Finding F: Exact-version identity consistency in VerifiedResume.
"""

from dataclasses import FrozenInstanceError
import hashlib
from pathlib import Path
import tempfile
from typing import Any, Dict, Optional
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    FileSecurityError,
    ResumeIntegrityError,
    ResumeNotFoundError,
)
from src.preparer.profile_updater import ProfileUpdater
from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
from src.security.file_security import FileSecurityValidator
from src.security.resume_verifier import ResumeIntegrityVerifier, VerifiedResume
from tests.fixtures.synthetic_personas import (
    generate_persona_docx,
    generate_persona_pdf,
)


class TestPhase9112IntegrityRemediation(unittest.TestCase):
    """Full remediation test suite for Phase 9.1.1.2."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.db_path = self.base_dir / "test_remediation.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.file_validator = FileSecurityValidator(base_storage_dir=self.base_dir)
        self.verifier = ResumeIntegrityVerifier(
            db_manager=self.db,
            file_validator=self.file_validator,
        )
        self.service = DashboardService(
            db_manager=self.db,
            storage_base_dir=self.base_dir,
        )

        # Create two isolated test users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("user1@example.com", "hash1", "salt1", "Alice Candidate"),
            )
            self.user1_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("user2@example.com", "hash2", "salt2", "Bob Adversary"),
            )
            self.user2_id = cursor.lastrowid

        # Synthetic binary assets
        self.pdf_bytes_student = generate_persona_pdf("freshman_cs_student")
        self.pdf_bytes_backend = generate_persona_pdf("backend_engineer")
        self.docx_bytes_attorney = generate_persona_docx("attorney")

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # Helper: Upload Resume
    # -------------------------------------------------------------------------
    def _upload_resume(
        self,
        user_id: int,
        file_bytes: bytes,
        original_filename: str,
        label: str = "General",
        target_role: str = "Software Engineer",
    ) -> Dict[str, Any]:
        """Uploads resume through DatabaseManager into isolated user storage."""
        user_resumes_dir = self.file_validator.get_user_resumes_dir(user_id)
        return self.db.upload_user_resume(
            user_id=user_id,
            file_bytes=file_bytes,
            original_filename=original_filename,
            label=label,
            target_role=target_role,
            user_base_dir=user_resumes_dir,
        )

    # -------------------------------------------------------------------------
    # Helper: Create Job Description
    # -------------------------------------------------------------------------
    def _create_job_description(
        self,
        user_id: int,
        title: str = "Software Engineer Intern",
        mandatory_skills: Optional[list] = None,
    ) -> int:
        """Creates a job description for the given user."""
        skills = mandatory_skills or ["Python"]
        jd = self.db.create_job_description(
            user_id=user_id,
            company_name="TechCorp Labs",
            job_title=title,
            raw_content=f"{title} position requiring {', '.join(skills)}",
            source_type="pasted",
            parsed_data={"mandatory_skills": skills, "internship_duration": "3 months"},
        )
        return jd.id

    # =========================================================================
    # FINDING A: Close the Actual Matching Pipeline Bypass
    # =========================================================================

    def test_finding_a_01_valid_pdf_matching_succeeds(self):
        """DashboardService.run_match_evaluation JIT-verifies and evaluates valid PDF resume."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin_student.pdf")
        jd_id = self._create_job_description(self.user1_id, mandatory_skills=["Python"])

        result = self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res["id"],
            job_description_id=jd_id,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.user_id, self.user1_id)
        self.assertEqual(result.resume_file_hash, hashlib.sha256(self.pdf_bytes_student).hexdigest())
        self.assertGreaterEqual(result.match_score, 50.0)

        # Verify exactly one match_results record is persisted in SQLite
        history = self.service.get_user_match_history(self.user1_id)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].resume_id, res["id"])

    def test_finding_a_02_valid_docx_matching_succeeds(self):
        """DashboardService.run_match_evaluation JIT-verifies and evaluates valid DOCX resume."""
        res = self._upload_resume(self.user1_id, self.docx_bytes_attorney, "morgan_attorney.docx")
        jd_id = self._create_job_description(self.user1_id, title="Associate Attorney", mandatory_skills=["Contract Drafting"])

        result = self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res["id"],
            job_description_id=jd_id,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.resume_file_hash, hashlib.sha256(self.docx_bytes_attorney).hexdigest())
        history = self.service.get_user_match_history(self.user1_id)
        self.assertEqual(len(history), 1)

    def test_finding_a_03_tampered_resume_fails_before_scoring(self):
        """Matching fails immediately on tampered resume and persists zero match_results."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        jd_id = self._create_job_description(self.user1_id)

        # Tamper 1 byte on disk
        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        raw = bytearray(disk_path.read_bytes())
        raw[20] ^= 0xFF
        disk_path.write_bytes(bytes(raw))

        with self.assertRaises(ResumeIntegrityError) as ctx:
            self.service.run_match_evaluation(
                user_id=self.user1_id,
                resume_id=res["id"],
                job_description_id=jd_id,
            )
        self.assertIn("does not match expected hash", str(ctx.exception).lower())

        # Crucial security guarantee: NO match_results record is persisted
        history = self.service.get_user_match_history(self.user1_id)
        self.assertEqual(len(history), 0)

    def test_finding_a_04_same_size_binary_replacement_fails(self):
        """Replacing resume with an altered binary of identical size fails and prevents match persistence."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        jd_id = self._create_job_description(self.user1_id)

        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        raw = bytearray(disk_path.read_bytes())
        # Flip a byte without changing length
        raw[len(raw) - 10] ^= 0x01
        disk_path.write_bytes(bytes(raw))

        with self.assertRaises(ResumeIntegrityError):
            self.service.run_match_evaluation(
                user_id=self.user1_id,
                resume_id=res["id"],
                job_description_id=jd_id,
            )

        history = self.service.get_user_match_history(self.user1_id)
        self.assertEqual(len(history), 0)

    def test_finding_a_05_missing_resume_file_fails(self):
        """Missing physical resume file fails closed and records zero match results."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        jd_id = self._create_job_description(self.user1_id)

        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        disk_path.unlink()

        with self.assertRaises((FileNotFoundError, ResumeIntegrityError)):
            self.service.run_match_evaluation(
                user_id=self.user1_id,
                resume_id=res["id"],
                job_description_id=jd_id,
            )

        history = self.service.get_user_match_history(self.user1_id)
        self.assertEqual(len(history), 0)

    def test_finding_a_06_historical_unverified_resume_fails(self):
        """Historical resume record missing cryptographic hash fails JIT validation before matching."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        jd_id = self._create_job_description(self.user1_id)

        # Set file_hash to unverified placeholder in DB to simulate unverified legacy record
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE resumes SET file_hash = 'legacy_unverified' WHERE id = ?", (res["id"],))
            cursor.execute("UPDATE resume_versions SET file_hash = 'legacy_unverified' WHERE resume_id = ?", (res["id"],))

        with self.assertRaises(ResumeIntegrityError) as ctx:
            self.service.run_match_evaluation(
                user_id=self.user1_id,
                resume_id=res["id"],
                job_description_id=jd_id,
            )
        self.assertIn("lacks valid cryptographic integrity metadata", str(ctx.exception))

        history = self.service.get_user_match_history(self.user1_id)
        self.assertEqual(len(history), 0)

    def test_finding_a_07_fresh_binary_differs_from_stale_db_json(self):
        """Match evaluation reflects freshly parsed binary content rather than stale database JSON."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_backend, "alex.pdf")
        jd_id = self._create_job_description(self.user1_id, mandatory_skills=["Go", "Kubernetes"])

        # Inject stale, completely different JSON into database resumes.parsed_data
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE resumes SET parsed_data = '{\"technical_skills\": [\"Brainfuck\", \"COBOL\"]}' WHERE id = ?",
                (res["id"],),
            )

        # Match evaluation should fresh-parse the binary (which has Go & Kubernetes)
        result = self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res["id"],
            job_description_id=jd_id,
        )

        # The evaluated skills must reflect the actual binary skills (Go, Rust), not Brainfuck/COBOL
        matched_skills = [
            sa.job_skill
            for sa in result.skills_assessment
            if sa.classification in ("EXACT_MATCH", "RELATED_MATCH", "PARTIAL_MATCH")
        ]
        self.assertIn("Go", matched_skills)
        self.assertNotIn("Brainfuck", str(result.skills_assessment))

    def test_finding_a_08_cross_user_resume_rejected(self):
        """Cross-user resume evaluation attempt is rejected and persists no match results."""
        user1_res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        user2_jd = self._create_job_description(self.user2_id)

        with self.assertRaises((CrossUserAccessError, ResumeNotFoundError)):
            self.service.run_match_evaluation(
                user_id=self.user2_id,
                resume_id=user1_res["id"],
                job_description_id=user2_jd,
            )

        history = self.service.get_user_match_history(self.user2_id)
        self.assertEqual(len(history), 0)

    # =========================================================================
    # FINDING B: Remove Unverified Fallback in Scoring Profile Recommendation
    # =========================================================================

    def test_finding_b_01_valid_resume_recommends_scoring_profile(self):
        """Valid resume successfully informs scoring profile recommendation."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        jd_id = self._create_job_description(self.user1_id, title="Software Engineering Intern")

        rec_id, reason = self.service.recommend_scoring_profile(
            user_id=self.user1_id,
            resume_id=res["id"],
            job_description_id=jd_id,
        )
        self.assertEqual(rec_id, "student_intern")
        self.assertTrue(len(reason) > 0)

    def test_finding_b_02_tampered_resume_fails_closed_in_recommendation(self):
        """Tampered resume raises ResumeIntegrityError and does NOT fall back to stale DB data."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        jd_id = self._create_job_description(self.user1_id)

        # Tamper disk file
        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        raw = bytearray(disk_path.read_bytes())
        raw[15] ^= 0xAA
        disk_path.write_bytes(bytes(raw))

        with self.assertRaises(ResumeIntegrityError):
            self.service.recommend_scoring_profile(
                user_id=self.user1_id,
                resume_id=res["id"],
                job_description_id=jd_id,
            )

    def test_finding_b_03_missing_resume_file_fails_closed_in_recommendation(self):
        """Missing resume file fails closed rather than returning a silent default profile."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        jd_id = self._create_job_description(self.user1_id)

        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        disk_path.unlink()

        with self.assertRaises((FileNotFoundError, ResumeIntegrityError)):
            self.service.recommend_scoring_profile(
                user_id=self.user1_id,
                resume_id=res["id"],
                job_description_id=jd_id,
            )

    def test_finding_b_04_stale_db_data_never_used_when_file_invalid(self):
        """Stale DB career level is never consulted when the underlying file is tampered."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        jd_id = self._create_job_description(self.user1_id)

        # Ensure DB has student career level
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE resumes SET parsed_data = '{\"career_level\": \"student\"}' WHERE id = ?",
                (res["id"],),
            )

        # Break the file
        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        disk_path.write_bytes(b"CORRUPTED_NOT_PDF")

        with self.assertRaises(ResumeIntegrityError):
            self.service.recommend_scoring_profile(
                user_id=self.user1_id,
                resume_id=res["id"],
                job_description_id=jd_id,
            )

    def test_finding_b_05_none_resume_id_allows_generic_fallback(self):
        """Explicitly passing resume_id=None succeeds with generic baseline profile."""
        jd_id = self._create_job_description(self.user1_id)

        rec_id, reason = self.service.recommend_scoring_profile(
            user_id=self.user1_id,
            resume_id=None,
            job_description_id=jd_id,
        )
        self.assertIsNotNone(rec_id)
        self.assertTrue(len(reason) > 0)

    # =========================================================================
    # FINDING C: Correct Historical Resume Recovery & Audit Trail
    # =========================================================================

    def _setup_multi_version_resume(self) -> tuple[int, str, str, str, str]:
        """Creates a resume with distinct Version 1 and Version 2 binaries."""
        res1 = self._upload_resume(self.user1_id, self.pdf_bytes_student, "v1_student.pdf")
        res_id = res1["id"]
        v1_fn = res1["storage_filename"]
        v1_hash = hashlib.sha256(self.pdf_bytes_student).hexdigest()

        # Add Version 2 with backend engineer PDF
        user_resumes = self.file_validator.get_user_resumes_dir(self.user1_id)
        v2_fn = f"resume_{res_id}_v2.pdf"
        (user_resumes / v2_fn).write_bytes(self.pdf_bytes_backend)
        v2_hash = hashlib.sha256(self.pdf_bytes_backend).hexdigest()
        v2_size = len(self.pdf_bytes_backend)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO resume_versions (
                    resume_id, user_id, version_num, storage_filename, file_hash, file_size_bytes, change_notes, snapshot_json
                ) VALUES (?, ?, 2, ?, ?, ?, 'Promoted to backend', '{}')
                """,
                (res_id, self.user1_id, v2_fn, v2_hash, v2_size),
            )
            # Update parent to active_version = 2
            cursor.execute(
                """
                UPDATE resumes
                SET active_version = 2, storage_filename = ?, file_hash = ?, file_size_bytes = ?
                WHERE id = ?
                """,
                (v2_fn, v2_hash, v2_size, res_id),
            )

        return res_id, v1_fn, v1_hash, v2_fn, v2_hash

    def test_finding_c_01_multi_version_fixtures_v1_and_v2_distinct(self):
        """Multi-version setup accurately creates distinct files and hashes for v1 and v2."""
        res_id, v1_fn, v1_hash, v2_fn, v2_hash = self._setup_multi_version_resume()
        self.assertNotEqual(v1_fn, v2_fn)
        self.assertNotEqual(v1_hash, v2_hash)

        # Check DB records
        res_row = self.db.get_user_resume(res_id, self.user1_id)
        self.assertEqual(res_row["active_version"], 2)
        self.assertEqual(res_row["storage_filename"], v2_fn)

    def test_finding_c_02_recover_active_version_with_missing_metadata(self):
        """Active version recovery populates both resume_versions and parent resumes row."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "v1.pdf")
        res_id = res["id"]
        expected_hash = hashlib.sha256(self.pdf_bytes_student).hexdigest()

        # Set metadata to legacy placeholder to simulate missing historical metadata
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE resumes SET file_hash = 'legacy_unverified', file_size_bytes = 0 WHERE id = ?", (res_id,))
            cursor.execute("UPDATE resume_versions SET file_hash = 'legacy_unverified', file_size_bytes = 0 WHERE resume_id = ?", (res_id,))

        recovered = self.verifier.reverify_and_backfill_historical_resume(
            user_id=self.user1_id,
            resume_id=res_id,
            version_num=1,
            user_base_dir=self.base_dir,
        )

        self.assertEqual(recovered["file_hash"], expected_hash)
        self.assertEqual(recovered["version_num"], 1)

        # Verify DB updated
        res_row = self.db.get_user_resume(res_id, self.user1_id)
        self.assertEqual(res_row["file_hash"], expected_hash)

        # Verify audit record persisted
        audits = self.db.get_resume_recovery_audit(self.user1_id, res_id)
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0]["recovery_outcome"], "SUCCESS")
        self.assertEqual(audits[0]["recovered_file_hash"], expected_hash)

    def test_finding_c_03_recover_historical_non_active_version(self):
        """Recovering non-active Version 1 updates resume_versions row without altering parent resumes row."""
        res_id, v1_fn, v1_hash, v2_fn, v2_hash = self._setup_multi_version_resume()

        # Wipe version 1 metadata in resume_versions
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE resume_versions SET file_hash = 'legacy_unverified', file_size_bytes = 0 WHERE resume_id = ? AND version_num = 1",
                (res_id,),
            )

        recovered = self.verifier.reverify_and_backfill_historical_resume(
            user_id=self.user1_id,
            resume_id=res_id,
            version_num=1,
            user_base_dir=self.base_dir,
        )

        self.assertEqual(recovered["version_num"], 1)
        self.assertEqual(recovered["file_hash"], v1_hash)

        # Crucial check: parent resumes table must STILL have Version 2 metadata!
        parent_row = self.db.get_user_resume(res_id, self.user1_id)
        self.assertEqual(parent_row["active_version"], 2)
        self.assertEqual(parent_row["storage_filename"], v2_fn)
        self.assertEqual(parent_row["file_hash"], v2_hash)

    def test_finding_c_04_recovering_v1_does_not_modify_v2(self):
        """Recovering version 1 leaves version 2 row in resume_versions untouched."""
        res_id, v1_fn, v1_hash, v2_fn, v2_hash = self._setup_multi_version_resume()

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE resume_versions SET file_hash = 'legacy_unverified', file_size_bytes = 0 WHERE resume_id = ? AND version_num = 1",
                (res_id,),
            )

        self.verifier.reverify_and_backfill_historical_resume(
            user_id=self.user1_id,
            resume_id=res_id,
            version_num=1,
            user_base_dir=self.base_dir,
        )

        # Check version 2 row in resume_versions
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM resume_versions WHERE resume_id = ? AND version_num = 2",
                (res_id,),
            )
            v2_row = dict(cursor.fetchone())
            self.assertEqual(v2_row["file_hash"], v2_hash)
            self.assertEqual(v2_row["storage_filename"], v2_fn)

    def test_finding_c_05_tamper_rejection_valid_existing_hash_mismatch_cannot_be_re_signed(self):
        """Attempt to recover a resume with valid existing hash that differs from disk is rejected as tampering."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "v1.pdf")
        res_id = res["id"]
        original_hash = res["file_hash"]

        # Alter the disk file without clearing DB hash
        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        raw = bytearray(disk_path.read_bytes())
        raw[25] ^= 0xEE
        disk_path.write_bytes(bytes(raw))

        with self.assertRaises(ResumeIntegrityError) as ctx:
            self.verifier.reverify_and_backfill_historical_resume(
                user_id=self.user1_id,
                resume_id=res_id,
                version_num=1,
                user_base_dir=self.base_dir,
            )
        self.assertIn("tampering", str(ctx.exception).lower())

        # Check DB hash was NOT re-signed or overwritten
        res_row = self.db.get_user_resume(res_id, self.user1_id)
        self.assertEqual(res_row["file_hash"], original_hash)

        # Audit table must record REJECTED_TAMPERING_SUSPECTED
        audits = self.db.get_resume_recovery_audit(self.user1_id, res_id)
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0]["recovery_outcome"], "REJECTED_TAMPERING_SUSPECTED")

    def test_finding_c_06_corrupted_file_cannot_be_re_signed(self):
        """Corrupted file with invalid magic bytes fails recovery and records validation failure in audit."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "v1.pdf")
        res_id = res["id"]

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE resumes SET file_hash = 'legacy_unverified', file_size_bytes = 0 WHERE id = ?", (res_id,))
            cursor.execute("UPDATE resume_versions SET file_hash = 'legacy_unverified', file_size_bytes = 0 WHERE resume_id = ?", (res_id,))

        # Overwrite disk file with corrupt bytes
        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        disk_path.write_bytes(b"CORRUPTED_HEADER_DATA")

        with self.assertRaises((ResumeIntegrityError, FileSecurityError)):
            self.verifier.reverify_and_backfill_historical_resume(
                user_id=self.user1_id,
                resume_id=res_id,
                version_num=1,
                user_base_dir=self.base_dir,
            )

        audits = self.db.get_resume_recovery_audit(self.user1_id, res_id)
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0]["recovery_outcome"], "REJECTED_FILE_VALIDATION_FAILED")

    def test_finding_c_07_cross_user_recovery_rejected(self):
        """Cross-user recovery attempt is rejected with CrossUserAccessError."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "v1.pdf")

        with self.assertRaises((CrossUserAccessError, ResumeNotFoundError)):
            self.verifier.reverify_and_backfill_historical_resume(
                user_id=self.user2_id,
                resume_id=res["id"],
                version_num=1,
                user_base_dir=self.base_dir,
            )

    def test_finding_c_08_missing_version_file_rejected(self):
        """Recovery fails cleanly when target version file is missing from disk."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "v1.pdf")
        res_id = res["id"]

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE resumes SET file_hash = 'legacy_unverified', file_size_bytes = 0 WHERE id = ?", (res_id,))
            cursor.execute("UPDATE resume_versions SET file_hash = 'legacy_unverified', file_size_bytes = 0 WHERE resume_id = ?", (res_id,))

        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        disk_path.unlink()

        with self.assertRaises((FileNotFoundError, ResumeIntegrityError, FileSecurityError)):
            self.verifier.reverify_and_backfill_historical_resume(
                user_id=self.user1_id,
                resume_id=res_id,
                version_num=1,
                user_base_dir=self.base_dir,
            )

        audits = self.db.get_resume_recovery_audit(self.user1_id, res_id)
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0]["recovery_outcome"], "REJECTED_FILE_VALIDATION_FAILED")

    def test_finding_c_09_nonexistent_version_rejected(self):
        """Attempting to recover a non-existent version number fails with ResumeNotFoundError."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "v1.pdf")

        with self.assertRaises(ResumeNotFoundError):
            self.verifier.reverify_and_backfill_historical_resume(
                user_id=self.user1_id,
                resume_id=res["id"],
                version_num=99,
                user_base_dir=self.base_dir,
            )

    def test_finding_c_10_audit_trail_persistence_and_queries(self):
        """DatabaseManager query helpers accurately record and retrieve recovery audit entries."""
        self.db.record_resume_recovery_audit(
            user_id=self.user1_id,
            resume_id=42,
            version_num=2,
            previous_state={"file_hash": "legacy_unverified", "file_size_bytes": 0},
            recovery_outcome="SUCCESS",
            recovered_file_hash="a" * 64,
            recovered_file_size_bytes=1024,
            details="Test migration entry",
        )

        entries = self.db.get_resume_recovery_audit(self.user1_id, 42)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["version_num"], 2)
        self.assertEqual(entries[0]["recovery_outcome"], "SUCCESS")
        self.assertEqual(entries[0]["recovered_file_hash"], "a" * 64)

    # =========================================================================
    # FINDING D: VerifiedResume Genuine Immutability
    # =========================================================================

    def test_finding_d_01_verified_resume_frozen_instance(self):
        """VerifiedResume is a frozen dataclass; attribute mutation raises FrozenInstanceError."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=res["id"],
            user_base_dir=self.base_dir,
        )
        self.assertIsInstance(verified, VerifiedResume)

        with self.assertRaises((FrozenInstanceError, AttributeError)):
            verified.resume_id = 999  # type: ignore

        with self.assertRaises((FrozenInstanceError, AttributeError)):
            verified.file_hash = "hacked_hash"  # type: ignore

    def test_finding_d_02_parsed_resume_defensive_copy(self):
        """Mutating the parsed_resume property does not alter internal state of VerifiedResume."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=res["id"],
            user_base_dir=self.base_dir,
        )
        self.assertIsInstance(verified, VerifiedResume)

        original_skills_count = len(verified.parsed_resume.technical_skills)

        # Mutate the copy returned by the property
        verified.parsed_resume.technical_skills.append("FABRICATED_SKILL_999")

        # Access property again: internal state must remain pristine
        fresh_access = verified.parsed_resume.technical_skills
        self.assertEqual(len(fresh_access), original_skills_count)
        self.assertNotIn("FABRICATED_SKILL_999", fresh_access)

    def test_finding_d_03_to_dict_sanitizes_paths_and_omits_binary(self):
        """VerifiedResume.to_dict() sanitizes resolved_path and omits raw file_bytes and raw_text."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=res["id"],
            user_base_dir=self.base_dir,
        )
        self.assertIsInstance(verified, VerifiedResume)

        d = verified.to_dict()
        self.assertNotIn("file_bytes", d)
        self.assertNotIn("raw_text", d)
        # resolved_path must be sanitized to basename only
        self.assertNotIn(str(self.base_dir), d["resolved_path"])
        self.assertEqual(d["resolved_path"], res["storage_filename"])

    def test_finding_d_04_repr_masks_pii_and_content(self):
        """VerifiedResume.__repr__ masks file_bytes and raw_text lengths."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=res["id"],
            user_base_dir=self.base_dir,
        )
        self.assertIsInstance(verified, VerifiedResume)

        r = repr(verified)
        self.assertIn("bytes=<bytes: ", r)
        self.assertIn("text_len=", r)

    # =========================================================================
    # FINDING E: Close Alternate Resume-Data Bypasses
    # =========================================================================

    def test_finding_e_01_tailored_resume_with_resume_id_no_file_hash_verifies_jit(self):
        """DashboardService.generate_tailored_resume verifies JIT when caller supplies id without file_hash."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")

        # Break file on disk
        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        raw = bytearray(disk_path.read_bytes())
        raw[10] ^= 0x11
        disk_path.write_bytes(bytes(raw))

        # Caller provides resume_data dictionary with 'id' but no 'file_hash'
        with self.assertRaises(ResumeIntegrityError):
            self.service.generate_tailored_resume(
                user_id=self.user1_id,
                candidate_profile={"full_name": "Alice Candidate", "skills": ["Python"]},
                resume_data={"id": res["id"], "career_level": "student"},
                job_description={"job_title": "Software Engineer Intern", "mandatory_skills": ["Python"]},
            )

    def test_finding_e_02_cover_letter_with_null_file_hash_verifies_jit(self):
        """DashboardService.generate_universal_cover_letter verifies JIT when caller supplies null file_hash."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")

        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        raw = bytearray(disk_path.read_bytes())
        raw[12] ^= 0x22
        disk_path.write_bytes(bytes(raw))

        with self.assertRaises(ResumeIntegrityError):
            self.service.generate_universal_cover_letter(
                user_id=self.user1_id,
                candidate_profile={"full_name": "Alice Candidate", "skills": ["Python"]},
                job_description={"job_title": "Software Engineer Intern", "mandatory_skills": ["Python"]},
                resume_data={"resume_id": res["id"], "file_hash": None},
            )

    def test_finding_e_03_screening_qa_with_forged_file_hash_verifies_jit(self):
        """DashboardService.batch_answer_screening_questions verifies JIT and rejects forged file_hash."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")

        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        raw = bytearray(disk_path.read_bytes())
        raw[14] ^= 0x33
        disk_path.write_bytes(bytes(raw))

        with self.assertRaises(ResumeIntegrityError):
            self.service.batch_answer_screening_questions(
                questions=["Tell us about yourself"],
                user_id=self.user1_id,
                candidate_profile={"full_name": "Alice Candidate", "skills": ["Python"]},
                resume_data={"id": res["id"], "file_hash": "a" * 64},
                job_description={"job_title": "Software Engineer Intern"},
            )

    def test_finding_e_04_universal_tailored_resume_generator_direct_generate_verifies_jit(self):
        """UniversalTailoredResumeGenerator.generate verifies JIT when resume_data has id."""
        res = self._upload_resume(self.user1_id, self.pdf_bytes_student, "kevin.pdf")

        disk_path = self.file_validator.get_user_resumes_dir(self.user1_id) / res["storage_filename"]
        raw = bytearray(disk_path.read_bytes())
        raw[16] ^= 0x44
        disk_path.write_bytes(bytes(raw))

        gen = UniversalTailoredResumeGenerator()

        with self.assertRaises(ResumeIntegrityError):
            gen.generate(
                user_id=self.user1_id,
                candidate_profile={"full_name": "Alice Candidate", "skills": ["Python"]},
                resume_data={"id": res["id"]},
                job_description={"job_title": "Software Engineer Intern"},
                db_manager=self.db,
                user_base_dir=self.base_dir,
            )

    def test_finding_e_05_profile_updater_rejects_path_traversal(self):
        """ProfileUpdater.sync_user_profile rejects path traversal sequences and null bytes."""
        updater = ProfileUpdater(db_manager=self.db)

        with self.assertRaises((FileSecurityError, ResumeIntegrityError)):
            updater.sync_user_profile(user_id=self.user1_id, resume_path="../../etc/passwd")

        with self.assertRaises((FileSecurityError, ResumeIntegrityError)):
            updater.sync_user_profile(user_id=self.user1_id, resume_path="resume\x00malicious.pdf")

    # =========================================================================
    # FINDING F: Exact-Version Identity Consistency
    # =========================================================================

    def test_finding_f_01_multi_version_identity_consistency(self):
        """VerifiedResume consistently identifies target version storage_filename and hash."""
        res_id, v1_fn, v1_hash, v2_fn, v2_hash = self._setup_multi_version_resume()

        # Load Version 1
        ver1 = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=res_id,
            version_num=1,
            user_base_dir=self.base_dir,
        )
        self.assertEqual(ver1.version_num, 1)
        self.assertEqual(ver1.storage_filename, v1_fn)
        self.assertEqual(ver1.file_hash, v1_hash)

        # Load Version 2
        ver2 = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=res_id,
            version_num=2,
            user_base_dir=self.base_dir,
        )
        self.assertEqual(ver2.version_num, 2)
        self.assertEqual(ver2.storage_filename, v2_fn)
        self.assertEqual(ver2.file_hash, v2_hash)

        # Neither should borrow the other's filename
        self.assertNotEqual(ver1.storage_filename, ver2.storage_filename)


if __name__ == "__main__":
    unittest.main()

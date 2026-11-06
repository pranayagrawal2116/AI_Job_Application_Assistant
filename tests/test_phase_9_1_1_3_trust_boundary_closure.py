"""Comprehensive Test Suite for Phase 9.1.1.3: Final Resume Trust-Boundary & Recovery Audit Closure.

Architecture v2.1.1 (Phase 9.1.1.3)

Verifies:
- Finding A: Strict input trust contract in resume generators (reject unverified dicts without ID,
             accept VerifiedResume, require JIT verification for IDs, allow genuine profile-only).
- Finding B: Persistent matching requires verified resume input in UniversalMatcher.evaluate()
             (reject unverified caller-supplied dicts, enforce JIT verification, preserve persist=False).
- Finding C: VerifiedResume.to_dict() safe serialization excluding raw_text, file_bytes, and absolute paths recursively.
- Finding D: Genuine immutability and defensive copying of VerifiedResume.
- Finding E: Multi-version format selection in historical recovery (derived from target version, not parent format).
- Finding F: Concurrency-safe CAS semantics in historical recovery with rowcount validation.
- Finding G: Append-only durability and SQLite triggers for resume_recovery_audit with atomic commit.
- Finding H: Sandbox containment and descriptor verification in ProfileUpdater.sync_user_profile().
"""

from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ConcurrencyConflictError,
    CrossUserAccessError,
    FileSecurityError,
    ResumeIntegrityError,
)
from src.matcher.universal_matcher import UniversalMatcher
from src.preparer.profile_updater import ProfileUpdater
from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
from src.security.file_security import FileSecurityValidator
from src.security.resume_verifier import ResumeIntegrityVerifier
from tests.fixtures.synthetic_personas import (
    generate_persona_docx,
    generate_persona_pdf,
)


class TestPhase9113TrustBoundaryClosure(unittest.TestCase):
    """Rigorous verification suite for Phase 9.1.1.3 security remediations."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.db_path = self.base_dir / "test_trust_boundary.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.file_validator = FileSecurityValidator(base_storage_dir=self.base_dir)
        self.verifier = ResumeIntegrityVerifier(
            db_manager=self.db,
            file_validator=self.file_validator,
        )

        # Create two isolated users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("candidate1@example.com", "h1", "s1", "Candidate One"),
            )
            self.user1_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("candidate2@example.com", "h2", "s2", "Candidate Two"),
            )
            self.user2_id = cursor.lastrowid

        # Candidate profile for user 1
        self.profile1_data = {
            "personal": {"full_name": "Candidate One", "email": "candidate1@example.com", "headline": "Software Engineer"},
            "technical_skills": ["Python", "Machine Learning", "SQL", "Docker"],
            "work_experience": [
                {
                    "job_title": "Software Engineer",
                    "employer": "Tech Corp",
                    "responsibilities": ["Developed Python backend APIs", "Implemented ML models in production"],
                }
            ],
            "education": [{"degree": "B.Tech Computer Science", "institution": "Tech University", "graduation_year": 2024}],
        }
        self.db.save_user_candidate_profile(self.user1_id, self.profile1_data)

        # Job Description for user 1
        jd = self.db.create_job_description(
            user_id=self.user1_id,
            source_type="pasted",
            company_name="AI Global Innovations",
            job_title="ML Engineer",
            raw_content="Looking for an ML Engineer with Python and Docker experience.",
            parsed_data={"mandatory_skills": ["Python", "Docker"], "job_title": "ML Engineer", "company_name": "AI Global Innovations"},
        )
        self.jd1_id = jd.id

        # Valid persona files
        self.pdf_bytes_student = generate_persona_pdf("freshman_cs_student")
        self.pdf_bytes_backend = generate_persona_pdf("backend_engineer")
        self.docx_bytes_attorney = generate_persona_docx("attorney")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _upload_resume(self, user_id: int, file_bytes: bytes, original_filename: str) -> dict:
        """Helper to upload resume into user's isolated directory with full metadata."""
        user_resumes_dir = self.file_validator.get_user_resumes_dir(user_id)
        user_resumes_dir.mkdir(parents=True, exist_ok=True)
        return self.db.upload_user_resume(
            user_id=user_id,
            file_bytes=file_bytes,
            original_filename=original_filename,
            label="Engineering",
            target_role="ML Engineer",
            user_base_dir=self.base_dir,
        )

    # =========================================================================
    # FINDING A: Reject Unverified Resume Dictionaries Without Authoritative Identity
    # =========================================================================

    def test_finding_a_01_tailored_resume_rejects_unverified_dictionary_without_id(self):
        """UniversalTailoredResumeGenerator.generate() rejects unverified dict without id/resume_id."""
        gen = UniversalTailoredResumeGenerator()
        unverified_resume_dict = {
            "full_name": "Fabricated Candidate",
            "technical_skills": ["Python", "Rust", "Golang", "Kubernetes"],
            "work_experience": [{"job_title": "Senior Architect", "employer": "Shadow Corp"}],
        }

        with self.assertRaises(ResumeIntegrityError) as ctx:
            gen.generate(
                user_id=self.user1_id,
                candidate_profile=self.profile1_data,
                resume_data=unverified_resume_dict,
                job_description={"job_title": "Architect", "company_name": "Target"},
                db_manager=self.db,
                user_base_dir=self.base_dir,
            )
        self.assertIn("authoritative identity", str(ctx.exception))

    def test_finding_a_02_tailored_resume_verifies_dict_with_id_against_disk(self):
        """UniversalTailoredResumeGenerator.generate() verifies dict containing 'id' via JIT verifier."""
        uploaded = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        gen = UniversalTailoredResumeGenerator()

        # Supply dictionary containing valid id
        input_dict = {"id": uploaded["id"], "file_hash": "untrusted_user_hash"}
        tailored = gen.generate(
            user_id=self.user1_id,
            candidate_profile=self.profile1_data,
            resume_data=input_dict,
            job_description={"job_title": "ML Engineer", "company_name": "AI Global"},
            db_manager=self.db,
            user_base_dir=self.base_dir,
        )
        self.assertIsNotNone(tailored)
        self.assertEqual(tailored.target_company, "AI Global")

    def test_finding_a_03_tailored_resume_fails_closed_if_file_tampered(self):
        """UniversalTailoredResumeGenerator.generate() fails closed if resume binary is tampered."""
        uploaded = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        # Tamper the file on disk
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / uploaded["storage_filename"]
        with open(file_path, "wb") as f:
            f.write(b"%PDF-tampered-content")

        gen = UniversalTailoredResumeGenerator()
        with self.assertRaises(ResumeIntegrityError):
            gen.generate(
                user_id=self.user1_id,
                candidate_profile=self.profile1_data,
                resume_data={"resume_id": uploaded["id"]},
                job_description={"job_title": "ML Engineer", "company_name": "AI Global"},
                db_manager=self.db,
                user_base_dir=self.base_dir,
            )

    def test_finding_a_04_tailored_resume_accepts_verified_resume_artifact(self):
        """UniversalTailoredResumeGenerator.generate() accepts an authoritative VerifiedResume artifact."""
        uploaded = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=uploaded["id"],
            user_base_dir=self.base_dir,
        )

        gen = UniversalTailoredResumeGenerator()
        tailored = gen.generate(
            user_id=self.user1_id,
            candidate_profile=self.profile1_data,
            resume_data=verified,
            job_description={"job_title": "ML Engineer", "company_name": "AI Global"},
            db_manager=self.db,
            user_base_dir=self.base_dir,
        )
        self.assertIsNotNone(tailored)

    def test_finding_a_05_tailored_resume_blocks_cross_user_verified_resume(self):
        """UniversalTailoredResumeGenerator.generate() rejects VerifiedResume from another user."""
        uploaded = self._upload_resume(self.user2_id, self.pdf_bytes_student, "user2.pdf")
        verified_u2 = self.verifier.verify_and_load_resume(
            user_id=self.user2_id,
            resume_id=uploaded["id"],
            user_base_dir=self.base_dir,
        )

        gen = UniversalTailoredResumeGenerator()
        with self.assertRaises(CrossUserAccessError):
            gen.generate(
                user_id=self.user1_id,
                candidate_profile=self.profile1_data,
                resume_data=verified_u2,
                job_description={"job_title": "ML Engineer", "company_name": "AI Global"},
                db_manager=self.db,
                user_base_dir=self.base_dir,
            )

    def test_finding_a_06_profile_only_workflow_allowed_when_no_resume_supplied(self):
        """Profile-only workflows (resume_data=None, resume_id=None) generate without resume requirement."""
        gen = UniversalTailoredResumeGenerator()
        tailored = gen.generate(
            user_id=self.user1_id,
            candidate_profile=self.profile1_data,
            resume_data=None,
            resume_id=None,
            job_description={"job_title": "ML Engineer", "company_name": "AI Global"},
            db_manager=self.db,
            user_base_dir=self.base_dir,
        )
        self.assertIsNotNone(tailored)
        self.assertEqual(tailored.personal_info["full_name"], "Candidate One")

    def test_finding_a_07_dashboard_service_cover_letter_and_qa_reject_unverified_dict(self):
        """DashboardService cover letter and screening QA generators reject unverified dict without ID."""
        service = DashboardService(db_manager=self.db, storage_base_dir=self.base_dir)
        unverified_dict = {"skills": ["Python", "Java"], "experience": "5 years"}

        # Cover letter rejects unverified dict
        with self.assertRaises(ResumeIntegrityError):
            service.generate_universal_cover_letter(
                user_id=self.user1_id,
                candidate_profile=self.profile1_data,
                job_description={"company_name": "Target", "job_title": "Engineer"},
                resume_data=unverified_dict,
            )

        # Screening questions reject unverified dict
        with self.assertRaises(ResumeIntegrityError):
            service.batch_answer_screening_questions(
                questions=["What are your skills?"],
                user_id=self.user1_id,
                candidate_profile=self.profile1_data,
                job_description={"company_name": "Target", "job_title": "Engineer"},
                resume_data=unverified_dict,
            )

    # =========================================================================
    # FINDING B: Persistent Matching Requires Verified Resume Input
    # =========================================================================

    def test_finding_b_01_persistent_matching_requires_verified_resume(self):
        """UniversalMatcher.evaluate(persist=True) rejects unverified resume dictionary."""
        matcher = UniversalMatcher(db_manager=self.db)
        unverified_dict = {"technical_skills": ["Python"], "raw_text": "Sample"}

        with self.assertRaises(ResumeIntegrityError) as ctx:
            matcher.evaluate(
                user_id=self.user1_id,
                resume_data=unverified_dict,
                job_data={"job_title": "Dev", "mandatory_skills": ["Python"]},
                persist=True,
            )
        self.assertIn("Persistent matching requires a verified resume", str(ctx.exception))

    def test_finding_b_02_persistent_matching_with_resume_id_verifies_disk_binary(self):
        """UniversalMatcher.evaluate(persist=True) with resume_id executes JIT verification."""
        uploaded = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        matcher = UniversalMatcher(db_manager=self.db, file_validator=self.file_validator)

        # With valid file, evaluation succeeds and persists
        result = matcher.evaluate(
            user_id=self.user1_id,
            resume_id=uploaded["id"],
            job_description_id=self.jd1_id,
            persist=True,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.resume_file_hash, uploaded["file_hash"])
        self.assertEqual(result.resume_version_num, uploaded["active_version"])

        # History has 1 persisted record
        history = self.db.get_user_match_results(self.user1_id, resume_id=uploaded["id"])
        self.assertEqual(len(history), 1)

    def test_finding_b_03_persistent_matching_fails_closed_if_binary_tampered(self):
        """UniversalMatcher.evaluate(persist=True) fails closed before persisting if file is tampered."""
        uploaded = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        file_path = self.file_validator.get_user_resumes_dir(self.user1_id) / uploaded["storage_filename"]
        with open(file_path, "wb") as f:
            f.write(b"%PDF-tampered-data")

        matcher = UniversalMatcher(db_manager=self.db, file_validator=self.file_validator)
        with self.assertRaises(ResumeIntegrityError):
            matcher.evaluate(
                user_id=self.user1_id,
                resume_id=uploaded["id"],
                job_description_id=self.jd1_id,
                persist=True,
            )

        # Verified zero match results persisted
        history = self.db.get_user_match_results(self.user1_id, resume_id=uploaded["id"])
        self.assertEqual(len(history), 0)

    def test_finding_b_04_persistent_matching_accepts_verified_resume_artifact(self):
        """UniversalMatcher.evaluate(persist=True) accepts VerifiedResume artifact and persists exact hashes."""
        uploaded = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=uploaded["id"],
            user_base_dir=self.base_dir,
        )

        matcher = UniversalMatcher(db_manager=self.db, file_validator=self.file_validator)
        result = matcher.evaluate(
            user_id=self.user1_id,
            verified_resume=verified,
            job_description_id=self.jd1_id,
            persist=True,
        )
        self.assertEqual(result.resume_file_hash, verified.file_hash)
        self.assertEqual(result.resume_version_num, verified.version_num)

    def test_finding_b_05_non_persistent_matching_preserves_synthetic_testing(self):
        """UniversalMatcher.evaluate(persist=False) continues to accept synthetic inputs for testing."""
        matcher = UniversalMatcher(db_manager=self.db, file_validator=self.file_validator)
        synthetic_resume = {"technical_skills": ["Python", "Docker"]}
        synthetic_job = {"mandatory_skills": ["Python"]}

        # Non-persistent synthetic evaluation must succeed without needing database binary
        result = matcher.evaluate(
            user_id=self.user1_id,
            resume_data=synthetic_resume,
            job_data=synthetic_job,
            persist=False,
        )
        self.assertIsNotNone(result)
        self.assertGreater(result.match_score, 0)

    def test_finding_b_06_profile_only_persistent_matching_allowed(self):
        """UniversalMatcher.evaluate(persist=True) allows profile-only matching when no resume referenced."""
        matcher = UniversalMatcher(db_manager=self.db, file_validator=self.file_validator)
        result = matcher.evaluate(
            user_id=self.user1_id,
            resume_data=None,
            resume_id=None,
            profile_data=self.profile1_data,
            job_description_id=self.jd1_id,
            persist=True,
        )
        self.assertIsNotNone(result)
        self.assertIsNone(result.resume_id)

    # =========================================================================
    # FINDING C: Fix VerifiedResume Serialization Leakage in to_dict()
    # =========================================================================

    def test_finding_c_01_to_dict_omits_raw_text_and_raw_bytes_recursively(self):
        """VerifiedResume.to_dict() strictly omits raw_text, file_bytes, and raw bytes across all levels."""
        uploaded = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=uploaded["id"],
            user_base_dir=self.base_dir,
        )

        d = verified.to_dict()
        # Top-level checks
        self.assertNotIn("file_bytes", d)
        self.assertNotIn("raw_text", d)

        # Nested parsed_data checks
        parsed_data = d.get("parsed_data", {})
        self.assertNotIn("raw_text", parsed_data)
        self.assertNotIn("file_bytes", parsed_data)
        self.assertNotIn("bytes", parsed_data)

        # Check JSON serializability without circular refs or bytes
        serialized = json.dumps(d)
        self.assertNotIn(str(self.base_dir), serialized)

    def test_finding_c_02_to_dict_sanitizes_paths_to_basenames(self):
        """VerifiedResume.to_dict() sanitizes file_path and resolved_path to basename only."""
        uploaded = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=uploaded["id"],
            user_base_dir=self.base_dir,
        )

        d = verified.to_dict()
        self.assertEqual(d["resolved_path"], uploaded["storage_filename"])
        self.assertNotIn(str(self.base_dir), d["resolved_path"])

        parsed_data = d.get("parsed_data", {})
        if "file_path" in parsed_data:
            self.assertEqual(parsed_data["file_path"], uploaded["storage_filename"])
            self.assertNotIn(str(self.base_dir), parsed_data["file_path"])

    # =========================================================================
    # FINDING D: Genuine Immutability & Defensive Copying
    # =========================================================================

    def test_finding_d_01_verified_resume_is_frozen_dataclass(self):
        """VerifiedResume attributes cannot be modified post-initialization."""
        uploaded = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=uploaded["id"],
            user_base_dir=self.base_dir,
        )

        with self.assertRaises(FrozenInstanceError):
            verified.file_hash = "malicious_hash"

        with self.assertRaises(FrozenInstanceError):
            verified.file_size_bytes = 0

    def test_finding_d_02_parsed_resume_property_returns_deep_copy(self):
        """Mutating the parsed_resume property does not mutate the internal VerifiedResume state."""
        uploaded = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        verified = self.verifier.verify_and_load_resume(
            user_id=self.user1_id,
            resume_id=uploaded["id"],
            user_base_dir=self.base_dir,
        )

        p1 = verified.parsed_resume
        p1.technical_skills.append("FABRICATED_SKILL")

        # Second access must not contain the mutated skill
        p2 = verified.parsed_resume
        self.assertNotIn("FABRICATED_SKILL", p2.technical_skills)

    # =========================================================================
    # FINDING E: Multi-Version Format Selection in Historical Recovery
    # =========================================================================

    def test_finding_e_01_recovery_format_derived_from_target_version_not_parent(self):
        """Recovery format is derived from target version extension, not parent resumes.file_format."""
        # 1. Upload v1 as PDF
        u1 = self._upload_resume(self.user1_id, self.pdf_bytes_student, "resume_v1.pdf")
        res_id = u1["id"]

        # 2. Upload v2 as DOCX (parent resumes.file_format becomes 'docx')
        user_resumes = self.file_validator.get_user_resumes_dir(self.user1_id)
        v2_fn = f"resume_{res_id}_v2.docx"
        (user_resumes / v2_fn).write_bytes(self.docx_bytes_attorney)
        v2_hash = hashlib.sha256(self.docx_bytes_attorney).hexdigest()
        v2_size = len(self.docx_bytes_attorney)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO resume_versions (
                    resume_id, user_id, version_num, storage_filename, file_hash, file_size_bytes, change_notes, snapshot_json
                ) VALUES (?, ?, 2, ?, ?, ?, 'Switched to attorney', '{}')
                """,
                (res_id, self.user1_id, v2_fn, v2_hash, v2_size),
            )
            cursor.execute(
                """
                UPDATE resumes
                SET active_version = 2, file_format = 'docx', storage_filename = ?, file_hash = ?, file_size_bytes = ?
                WHERE id = ?
                """,
                (v2_fn, v2_hash, v2_size, res_id),
            )

        # Verify parent format is DOCX
        parent = self.db.get_user_resume(res_id, user_id=self.user1_id)
        self.assertEqual(parent["file_format"], "docx")
        self.assertEqual(parent["active_version"], 2)

        # Clear cryptographic metadata for v1 in resume_versions to simulate historical record
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE resume_versions SET file_hash = NULL, file_size_bytes = NULL WHERE resume_id = ? AND version_num = 1",
                (res_id,),
            )

        # Recover v1 (PDF) - MUST evaluate as PDF, not DOCX!
        recovered = self.verifier.reverify_and_backfill_historical_resume(
            user_id=self.user1_id,
            resume_id=res_id,
            version_num=1,
            user_base_dir=self.base_dir,
        )
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered["version_num"], 1)

        # Expected SHA-256 is the PDF hash
        expected_pdf_hash = hashlib.sha256(self.pdf_bytes_student).hexdigest()
        self.assertEqual(recovered["file_hash"], expected_pdf_hash)

    # =========================================================================
    # FINDING F: Concurrency-Safe CAS Semantics in Historical Recovery
    # =========================================================================

    def test_finding_f_01_concurrent_parent_modification_causes_conflict(self):
        """Concurrent modification to parent resume during recovery triggers ConcurrencyConflictError."""
        u1 = self._upload_resume(self.user1_id, self.pdf_bytes_student, "resume_v1.pdf")
        res_id = u1["id"]

        # Clear metadata for recovery
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE resumes SET file_hash = 'legacy', file_size_bytes = 0 WHERE id = ?",
                (res_id,),
            )

        # Hook into parser to simulate a concurrent write while reverify_and_backfill is running
        original_parse_bytes = self.verifier.parser.parse_bytes

        def concurrent_writer(*args, **kwargs):
            with self.db.transaction() as conn:
                conn.cursor().execute(
                    "UPDATE resumes SET active_version = 99 WHERE id = ?",
                    (res_id,),
                )
            return original_parse_bytes(*args, **kwargs)

        self.verifier.parser.parse_bytes = concurrent_writer

        with self.assertRaises(ConcurrencyConflictError):
            self.verifier.reverify_and_backfill_historical_resume(
                user_id=self.user1_id,
                resume_id=res_id,
                version_num=1,
                user_base_dir=self.base_dir,
            )

        # Audit table records REJECTED_CONCURRENCY_CONFLICT
        audit_records = self.db.get_resume_recovery_audit(self.user1_id)
        self.assertTrue(any(a["recovery_outcome"] == "REJECTED_CONCURRENCY_CONFLICT" for a in audit_records))

    def test_finding_f_02_concurrent_version_modification_causes_conflict(self):
        """Concurrent modification to resume_versions during recovery triggers ConcurrencyConflictError."""
        u1 = self._upload_resume(self.user1_id, self.pdf_bytes_student, "resume_v1.pdf")
        res_id = u1["id"]

        # Clear metadata
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE resume_versions SET file_hash = NULL, file_size_bytes = NULL WHERE resume_id = ? AND version_num = 1",
                (res_id,),
            )

        original_parse_bytes = self.verifier.parser.parse_bytes

        def concurrent_writer(*args, **kwargs):
            with self.db.transaction() as conn:
                conn.cursor().execute(
                    "UPDATE resume_versions SET file_hash = 'changed_concurrently' WHERE resume_id = ? AND version_num = 1",
                    (res_id,),
                )
            return original_parse_bytes(*args, **kwargs)

        self.verifier.parser.parse_bytes = concurrent_writer

        with self.assertRaises(ConcurrencyConflictError):
            self.verifier.reverify_and_backfill_historical_resume(
                user_id=self.user1_id,
                resume_id=res_id,
                version_num=1,
                user_base_dir=self.base_dir,
            )

    # =========================================================================
    # FINDING G: Append-Only Durability & Atomic Commit of Audit Table
    # =========================================================================

    def test_finding_g_01_audit_table_triggers_prevent_update_and_delete(self):
        """SQLite triggers prevent UPDATE and DELETE on resume_recovery_audit."""
        # Insert a sample audit record directly
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO resume_recovery_audit (
                    user_id, resume_id, version_num, previous_state_json,
                    recovered_file_hash, recovered_file_size_bytes, recovery_outcome, details
                ) VALUES (?, 1, 1, '{}', 'hash', 100, 'SUCCESS', 'test')
                """,
                (self.user1_id,),
            )
            audit_id = cursor.lastrowid

        # UPDATE must fail
        with self.assertRaises(sqlite3.IntegrityError) as ctx_up:
            with self.db.transaction() as conn:
                conn.cursor().execute(
                    "UPDATE resume_recovery_audit SET details = 'tampered' WHERE id = ?",
                    (audit_id,),
                )
        self.assertIn("append-only", str(ctx_up.exception))

        # DELETE must fail
        with self.assertRaises(sqlite3.IntegrityError) as ctx_del:
            with self.db.transaction() as conn:
                conn.cursor().execute(
                    "DELETE FROM resume_recovery_audit WHERE id = ?",
                    (audit_id,),
                )
        self.assertIn("immutable", str(ctx_del.exception))

    def test_finding_g_02_authorized_privacy_erasure_allows_audit_deletion(self):
        """Authorized privacy erasure allows deletion of resume_recovery_audit records."""
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO resume_recovery_audit (
                    user_id, resume_id, version_num, previous_state_json,
                    recovered_file_hash, recovered_file_size_bytes, recovery_outcome, details
                ) VALUES (?, 1, 1, '{}', 'hash', 100, 'SUCCESS', 'test')
                """,
                (self.user1_id,),
            )
            audit_id = cursor.lastrowid

        # Deletion within authorized scope succeeds
        with self.db.connection() as conn:
            with self.db._authorized_privacy_erasure_scope(conn, self.user1_id):
                conn.execute("DELETE FROM resume_recovery_audit WHERE id = ?", (audit_id,))
                conn.commit()

        # Confirm deletion
        with self.db.connection() as conn:
            row = conn.execute("SELECT id FROM resume_recovery_audit WHERE id = ?", (audit_id,)).fetchone()
            self.assertIsNone(row)

    def test_finding_g_03_recovery_and_success_audit_commit_atomically(self):
        """Successful historical recovery and audit entry commit atomically."""
        u1 = self._upload_resume(self.user1_id, self.pdf_bytes_student, "student.pdf")
        res_id = u1["id"]

        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE resume_versions SET file_hash = NULL, file_size_bytes = NULL WHERE resume_id = ? AND version_num = 1",
                (res_id,),
            )

        recovered = self.verifier.reverify_and_backfill_historical_resume(
            user_id=self.user1_id,
            resume_id=res_id,
            version_num=1,
            user_base_dir=self.base_dir,
        )
        self.assertIsNotNone(recovered)

        # Audit entry exists with SUCCESS outcome
        audit_records = self.db.get_resume_recovery_audit(self.user1_id)
        success_record = next((a for a in audit_records if a["recovery_outcome"] == "SUCCESS" and a["resume_id"] == res_id), None)
        self.assertIsNotNone(success_record)
        self.assertEqual(success_record["recovered_file_hash"], recovered["file_hash"])

    # =========================================================================
    # FINDING H: ProfileUpdater Sandbox Containment & Verification
    # =========================================================================

    def test_finding_h_01_profile_updater_rejects_path_traversal_and_null_bytes(self):
        """ProfileUpdater.sync_user_profile rejects traversal and null bytes immediately."""
        updater = ProfileUpdater(db_manager=self.db)

        with self.assertRaises(FileSecurityError):
            updater.sync_user_profile(user_id=self.user1_id, resume_path="../../etc/passwd", user_base_dir=self.base_dir)

        with self.assertRaises(FileSecurityError):
            updater.sync_user_profile(user_id=self.user1_id, resume_path="resume\x00evil.pdf", user_base_dir=self.base_dir)

    def test_finding_h_02_profile_updater_rejects_path_outside_sandbox(self):
        """ProfileUpdater.sync_user_profile rejects paths outside user's private storage root."""
        updater = ProfileUpdater(db_manager=self.db)
        outside_file = self.base_dir / "outside_leak.pdf"
        with open(outside_file, "wb") as f:
            f.write(self.pdf_bytes_student)

        with self.assertRaises(FileSecurityError):
            updater.sync_user_profile(
                user_id=self.user1_id,
                resume_path=outside_file,
                user_base_dir=self.base_dir,
            )

    def test_finding_h_03_profile_updater_rejects_symlink_path(self):
        """ProfileUpdater.sync_user_profile rejects symlinked resume files."""
        user_resumes_dir = self.file_validator.get_user_resumes_dir(self.user1_id)
        user_resumes_dir.mkdir(parents=True, exist_ok=True)
        real_target = user_resumes_dir / "real.pdf"
        with open(real_target, "wb") as f:
            f.write(self.pdf_bytes_student)

        symlink_path = user_resumes_dir / "symlink.pdf"
        try:
            os.symlink(real_target, symlink_path)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not supported on this platform/filesystem.")

        updater = ProfileUpdater(db_manager=self.db)
        with self.assertRaises(FileSecurityError):
            updater.sync_user_profile(
                user_id=self.user1_id,
                resume_path=symlink_path,
                user_base_dir=self.base_dir,
            )

    def test_finding_h_04_profile_updater_succeeds_for_contained_valid_file(self):
        """ProfileUpdater.sync_user_profile parses through verified bytes for contained file."""
        user_resumes_dir = self.file_validator.get_user_resumes_dir(self.user1_id)
        user_resumes_dir.mkdir(parents=True, exist_ok=True)
        valid_file = user_resumes_dir / "contained_student.pdf"
        with open(valid_file, "wb") as f:
            f.write(self.pdf_bytes_student)

        updater = ProfileUpdater(db_manager=self.db)
        profile_data = updater.sync_user_profile(
            user_id=self.user1_id,
            resume_path=valid_file,
            user_base_dir=self.base_dir,
        )
        self.assertIsNotNone(profile_data)
        self.assertIn("technical_skills", profile_data)


if __name__ == "__main__":
    unittest.main()

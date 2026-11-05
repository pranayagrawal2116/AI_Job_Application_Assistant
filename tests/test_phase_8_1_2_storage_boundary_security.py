"""Comprehensive regression test suite for Phase 8.1.2:
Storage Boundary Enforcement & Fail-Closed Security Completion.

Tests cover:
- Finding A: Candidate private-storage containment & integrity verification
- Finding B: Job description content integrity & canonical snapshot verification
- Finding C: Malformed screening QA fail-closed verification
- Finding D: Candidate profile update approval invalidation & lifecycle transition
- Finding E: Failure-safe emergency signing key rotation
- Finding F: Unambiguous and fail-closed approval lookup
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CorruptedFileError,
    CrossUserAccessError,
    FileSecurityError,
    FileTooLargeError,
    InvalidFileFormatError,
    KeyRevokedError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetter
from src.preparer.document_generator import GeneratedDocument
from src.preparer.question_answerer import ScreeningQAPacket, ScreeningQuestion
from src.preparer.tailored_resume_generator import TailoredResume
from src.security.file_security import FileSecurityValidator
from src.security.session_manager import KeyRotationManager, SessionManager
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash


# Minimal valid magic-byte headers
PDF_HEADER = b"%PDF-1.4\n%test content inside user storage\n"
DOCX_HEADER = b"PK\x03\x04\x14\x00\x00\x00\x08\x00test docx body for verification\n"
PNG_HEADER = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
JPEG_HEADER = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"


class TestPhase812StorageBoundarySecurity(unittest.TestCase):
    """Test suite verifying all security invariants required by Phase 8.1.2."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.db_path = str(self.base_dir / "test_phase_8_1_2.db")
        self.storage_dir = self.base_dir / "users"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=self.db_path)
        self.session_mgr = SessionManager(server_secret=b"test_secret_32_bytes_long_phase812__", db_manager=self.db)
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)
        self.gate = HumanApprovalGate(
            db_manager=self.db,
            session_manager=self.session_mgr,
            file_validator=self.file_validator,
        )

        # Create two test users
        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'candidate1@example.com', 'h1', 's1', 'Candidate One')"
            )
            cur.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'candidate2@example.com', 'h2', 's2', 'Candidate Two')"
            )
        self.user_1 = 1
        self.user_2 = 2

        self.session_1 = self.session_mgr.authenticate_candidate(
            candidate_id="cand_1",
            candidate_name="Candidate One",
            user_id=self.user_1,
        )
        self.session_2 = self.session_mgr.authenticate_candidate(
            candidate_id="cand_2",
            candidate_name="Candidate Two",
            user_id=self.user_2,
        )

        # Setup candidate 1 storage directory
        self.user1_dir = self.storage_dir / "1"
        self.user1_dir.mkdir(parents=True, exist_ok=True)
        (self.user1_dir / "resumes").mkdir(parents=True, exist_ok=True)
        (self.user1_dir / "applications").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    # =========================================================================
    # FINDING A: Candidate Private-Storage Boundaries & Integrity Verification
    # =========================================================================

    def test_file_validator_candidate_storage_root(self):
        """Authoritative candidate storage root resolves strictly to users/<user_id>."""
        root1 = self.file_validator.get_candidate_storage_root(self.user_1)
        expected1 = (self.storage_dir / "1").resolve()
        self.assertEqual(root1, expected1)

        root2 = self.file_validator.get_candidate_storage_root(self.user_2)
        expected2 = (self.storage_dir / "2").resolve()
        self.assertEqual(root2, expected2)

        # Rejects non-positive or invalid user IDs
        with self.assertRaises((FileSecurityError, ValidationError)):
            self.file_validator.get_candidate_storage_root(0)
        with self.assertRaises((FileSecurityError, ValidationError)):
            self.file_validator.get_candidate_storage_root(-5)

    def test_file_validator_rejects_path_traversal(self):
        """Rejects absolute paths outside user sandbox and relative ../ traversals."""
        # Absolute path outside sandbox (e.g. system file)
        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path="/etc/passwd",
                expected_hash=hashlib.sha256(b"dummy").hexdigest(),
                expected_size=10,
            )
        self.assertIn("Path containment violation", str(ctx.exception))

        # Relative ../ traversal
        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path="../../users/2/resumes/secret.pdf",
                expected_hash=hashlib.sha256(b"dummy").hexdigest(),
                expected_size=10,
            )
        self.assertIn("Path traversal", str(ctx.exception))

        # NUL byte injection
        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path="resumes/test\x00.pdf",
                expected_hash=hashlib.sha256(b"dummy").hexdigest(),
                expected_size=10,
            )
        self.assertIn("Null byte", str(ctx.exception))

    def test_file_validator_rejects_symlinks(self):
        """Rejects file path if it is a symlink or any directory segment is a symlink."""
        target_file = self.base_dir / "external_target.pdf"
        target_file.write_bytes(PDF_HEADER)

        # 1. Symlink on target file itself
        symlink_file = self.user1_dir / "resumes" / "symlink_resume.pdf"
        os.symlink(target_file, symlink_file)

        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(symlink_file),
                expected_hash=hashlib.sha256(PDF_HEADER).hexdigest(),
                expected_size=len(PDF_HEADER),
            )
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

        # 2. Symlink on parent directory
        external_dir = self.base_dir / "external_dir"
        external_dir.mkdir()
        ext_child = external_dir / "resume.pdf"
        ext_child.write_bytes(PDF_HEADER)

        symlink_dir = self.user1_dir / "symlink_dir"
        os.symlink(external_dir, symlink_dir)

        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(symlink_dir / "resume.pdf"),
                expected_hash=hashlib.sha256(PDF_HEADER).hexdigest(),
                expected_size=len(PDF_HEADER),
            )
        self.assertTrue("cannot be a symbolic link" in str(ctx.exception) or "Path containment violation" in str(ctx.exception))

    def test_file_validator_checks_size_hash_and_format(self):
        """Verifies existence, regular file, size match, SHA-256 match, and magic bytes."""
        valid_pdf = self.user1_dir / "resumes" / "valid.pdf"
        valid_pdf.write_bytes(PDF_HEADER)
        correct_hash = hashlib.sha256(PDF_HEADER).hexdigest()
        correct_size = len(PDF_HEADER)

        # 1. Success case
        resolved_path, data, h, sz = self.file_validator.resolve_and_verify_candidate_file(
            user_id=self.user_1,
            file_path=str(valid_pdf),
            expected_hash=correct_hash,
            expected_size=correct_size,
            expected_format="pdf",
        )
        self.assertEqual(resolved_path, valid_pdf.resolve())
        self.assertEqual(h, correct_hash)
        self.assertEqual(sz, correct_size)

        # 2. Missing file
        with self.assertRaises(FileNotFoundError):
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(self.user1_dir / "resumes" / "nonexistent.pdf"),
                expected_hash=correct_hash,
                expected_size=correct_size,
            )

        # 3. Directory instead of regular file
        with self.assertRaises(ValidationError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(self.user1_dir / "resumes"),
                expected_hash=correct_hash,
                expected_size=correct_size,
            )
        self.assertIn("is not a regular file", str(ctx.exception))

        # 4. Byte size mismatch
        with self.assertRaises(ValidationError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(valid_pdf),
                expected_hash=correct_hash,
                expected_size=correct_size + 10,
            )
        self.assertIn("does not match manifest", str(ctx.exception))

        # 5. SHA-256 hash mismatch
        with self.assertRaises(ValidationError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(valid_pdf),
                expected_hash="0" * 64,
                expected_size=correct_size,
            )
        self.assertIn("does not match expected hash", str(ctx.exception))

        # 6. Format magic-byte mismatch (plain text with .pdf extension)
        fake_pdf = self.user1_dir / "resumes" / "fake.pdf"
        fake_content = b"This is not a PDF file format content!"
        fake_pdf.write_bytes(fake_content)
        with self.assertRaises(InvalidFileFormatError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(fake_pdf),
                expected_hash=hashlib.sha256(fake_content).hexdigest(),
                expected_size=len(fake_content),
                expected_format="pdf",
            )
        self.assertIn("missing valid PDF header magic bytes", str(ctx.exception))

    def test_end_to_end_packet_with_tampered_document_fails_integrity(self):
        """Packet verification fails closed when tailored doc or cover letter doc is tampered on disk."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        # Tamper tailored resume file on disk
        tailored_file = Path(packet.tailored_resume_path)
        tailored_file.write_bytes(PDF_HEADER + b"\nTAMPERED!")

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("does not match expected hash", msg)

    # =========================================================================
    # FINDING B: Job Description Content Integrity & Snapshot Verification
    # =========================================================================

    def test_job_description_raw_content_tampered_fails_closed(self):
        """Direct database tampering with job_descriptions.raw_content causes integrity failure."""
        app, packet, snap_hash, jd = self._create_complete_verified_application(self.user_1)

        # Tamper raw_content in database
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE job_descriptions SET raw_content = 'Tampered content secretly injected' WHERE id = ?",
                (jd.id,),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("Job description raw content has been altered", msg)

    def test_job_description_content_hash_altered_fails_closed(self):
        """Altering job_descriptions.content_hash causes integrity failure."""
        app, packet, snap_hash, jd = self._create_complete_verified_application(self.user_1)

        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE job_descriptions SET content_hash = ? WHERE id = ?",
                ("a" * 64, jd.id),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("Job description raw content has been altered", msg)

    def test_job_description_snapshot_hash_altered_fails_closed(self):
        """Altering job_descriptions.snapshot_hash causes integrity failure."""
        app, packet, snap_hash, jd = self._create_complete_verified_application(self.user_1)

        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE job_descriptions SET snapshot_hash = ? WHERE id = ?",
                ("b" * 64, jd.id),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("Job description snapshot hash does not match recomputed manifest hash", msg)

    def test_job_description_inactive_fails_closed(self):
        """Inactive or archived job description causes packet integrity verification to fail."""
        app, packet, snap_hash, jd = self._create_complete_verified_application(self.user_1)

        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE job_descriptions SET is_active = 0 WHERE id = ?",
                (jd.id,),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("inactive or archived", msg)

    def test_cross_user_job_description_fails_closed(self):
        """Packet pointing to another candidate's job description fails closed."""
        # Create JD for user 2
        jd2 = self.db.save_job_description_snapshot(
            user_id=self.user_2,
            company_name="User2 Company",
            job_title="User2 Role",
            raw_content="Role for candidate 2 only.",
        )
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        # Mutate packet to point to user 2's JD with matching hash
        snap = json.loads(packet.canonical_snapshot_json)
        snap["job_description_id"] = jd2.id
        tampered_hash = canonical_json_hash(snap)
        tampered_bytes = canonical_json_bytes(snap)
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET job_description_id = ?, packet_version_hash = ?, canonical_snapshot_json = ? WHERE id = ?",
                (jd2.id, tampered_hash, tampered_bytes.decode("utf-8"), packet.id),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertTrue("access denied" in msg or "CrossUserAccessError" in msg or "not found" in msg or "denied" in msg or "unauthorized" in msg or "Cross-user" in msg)

    # =========================================================================
    # FINDING C: Malformed Screening QA Must Fail Closed
    # =========================================================================

    def test_screening_qa_corrupt_json_fails_closed(self):
        """Unparseable or corrupt JSON string in screening_answers_json fails closed."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET screening_answers_json = '{corrupt_json...' WHERE id = ?",
                (packet.id,),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("screening_answers_json is corrupt or unparseable", msg)

    def test_screening_qa_non_list_type_fails_closed(self):
        """Top-level non-list screening answers (e.g. dict or integer) fail closed."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        # Dict instead of list
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET screening_answers_json = ? WHERE id = ?",
                (json.dumps({"question": "invalid"}), packet.id),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("screening_questions must be a list", msg)

    def test_screening_qa_non_dict_question_items_fail_closed(self):
        """Null or non-dict question items within the list fail closed."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        # Null item
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET screening_answers_json = ? WHERE id = ?",
                (json.dumps([None]), packet.id),
            )
        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("not a valid dictionary object", msg)

        # String item
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET screening_answers_json = ? WHERE id = ?",
                (json.dumps(["string_question_item"]), packet.id),
            )
        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("not a valid dictionary object", msg)

    def test_screening_qa_missing_mandatory_fields_fail_closed(self):
        """Question item missing question_id, question_text, or answer_text fails closed."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        # Missing answer_text
        bad_item = {
            "question_id": "q1",
            "question_text": "Do you have Python experience?",
            # answer_text missing
            "state": "USER_APPROVED",
        }
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET screening_answers_json = ? WHERE id = ?",
                (json.dumps([bad_item]), packet.id),
            )
        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("missing mandatory 'answer_text'", msg)

    def test_screening_qa_unresolved_input_or_overflow_fails_closed(self):
        """Question in NEEDS_CANDIDATE_INPUT state or exceeding limit fails closed."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        # NEEDS_CANDIDATE_INPUT
        unanswered_item = {
            "question_id": "q_salary",
            "question_text": "Expected salary?",
            "answer_text": "NEEDS CANDIDATE INPUT",
            "state": "NEEDS_CANDIDATE_INPUT",
        }
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET screening_answers_json = ? WHERE id = ?",
                (json.dumps([unanswered_item]), packet.id),
            )
        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertIn("requires candidate input before authorization", msg)

        # Exceeds character limit
        overflow_item = {
            "question_id": "q_intro",
            "question_text": "Brief intro",
            "answer_text": "Too long" * 100,
            "state": "USER_APPROVED",
            "exceeds_limit": True,
        }
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET screening_answers_json = ? WHERE id = ?",
                (json.dumps([overflow_item]), packet.id),
            )
        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertFalse(valid)
        self.assertTrue("exceeds the allowable character limit" in msg or "exceeds" in msg)

    def test_screening_qa_valid_empty_or_approved_passes(self):
        """Empty list [] or fully approved items pass integrity verification."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        # Valid empty list
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET screening_answers_json = '[]' WHERE id = ?",
                (packet.id,),
            )
        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertTrue(valid, f"Failed on valid empty screening QA: {msg}")

        # Valid approved questions
        approved_item = {
            "question_id": "q1",
            "question_text": "How many years of Python experience?",
            "answer_text": "5 years building backend services and pipelines.",
            "state": "USER_APPROVED",
            "exceeds_limit": False,
        }
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET screening_answers_json = ? WHERE id = ?",
                (json.dumps([approved_item]), packet.id),
            )
        valid, msg, _ = self.gate.verify_prepared_packet_integrity(packet.id, self.user_1)
        self.assertTrue(valid, f"Failed on valid approved screening QA: {msg}")

    # =========================================================================
    # FINDING D: Approval Invalidation & Lifecycle Transition on Profile Update
    # =========================================================================

    def test_profile_update_invalidates_unconsumed_approval_and_transitions_lifecycle(self):
        """Saving candidate profile revokes unconsumed approvals, transitions APPROVED app to READY_FOR_REVIEW with timeline event."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        # Authorize packet
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        succ, msg, approval = self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Authorization failed: {msg}")

        # Verify application transitioned to Awaiting Approval
        app_after_auth = self.db.get_user_application(app.id, self.user_1)
        self.assertEqual(app_after_auth.status, "Awaiting Approval")
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # Save updated candidate profile
        new_profile_data = {
            "full_name": "Candidate One Updated",
            "headline": "Senior Software Architect",
            "technical_skills": ["Python", "Go", "Distributed Systems"],
        }
        self.db.save_user_candidate_profile(
            user_id=self.user_1,
            profile_data=new_profile_data,
        )

        # 1. Approval must now be invalid
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # 2. Application status must transition from APPROVED to READY_FOR_REVIEW
        app_after_prof_update = self.db.get_user_application(app.id, self.user_1)
        self.assertEqual(app_after_prof_update.status, "READY_FOR_REVIEW")

        # 3. Timeline event PACKET_APPROVAL_REVOKED must be appended with valid hash chain
        events = self.db.get_application_events(app.id, self.user_1)
        revocation_event = events[-1]
        self.assertEqual(revocation_event.event_type, "PACKET_APPROVAL_REVOKED")
        self.assertEqual(revocation_event.previous_status, "Awaiting Approval")
        self.assertEqual(revocation_event.new_status, "READY_FOR_REVIEW")

        payload = json.loads(revocation_event.event_payload_json)
        self.assertEqual(payload["revocation_reason"], "CANDIDATE_PROFILE_UPDATED")
        self.assertEqual(payload["packet_id"], packet.id)

        # Verify event hash chain validity
        valid_chain = self.db.verify_application_event_chain(app.id, self.user_1)
        self.assertTrue(valid_chain)

    def test_profile_update_transactional_rollback_on_failure(self):
        """If event insertion fails during profile update, transaction rolls back cleanly."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )

        # Simulate exception during _insert_application_event_internal
        with patch.object(self.db, "_insert_application_event_internal", side_effect=RuntimeError("Simulated Event DB Error")):
            with self.assertRaises(RuntimeError):
                self.db.save_user_candidate_profile(
                    user_id=self.user_1,
                    profile_data={"headline": "Broken Profile Update"},
                )

        # Invariant: application status remains Awaiting Approval and approval remains intact
        app_check = self.db.get_user_application(app.id, self.user_1)
        self.assertEqual(app_check.status, "Awaiting Approval")
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

    # =========================================================================
    # FINDING E: Failure-Safe Emergency Signing Key Rotation
    # =========================================================================

    def test_emergency_key_rotation_validates_replacement_key_preconditions(self):
        """Emergency key rotation fails closed before DB writes if replacement key is invalid."""
        km = self.session_mgr.key_rotation_mgr

        # Short key (< 32 bytes)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            km.rotate_keys(
                new_key_id="v2",
                new_secret=b"short_key_under_32",
                mode=KeyRotationManager.MODE_EMERGENCY,
            )
        self.assertIn("at least 32 bytes", str(ctx.exception))

        # Empty key ID
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            km.rotate_keys(
                new_key_id="",
                new_secret=b"a" * 32,
                mode=KeyRotationManager.MODE_EMERGENCY,
            )
        self.assertIn("cannot be empty", str(ctx.exception))

    def test_emergency_key_rotation_sqlite_failure_leaves_in_memory_state_unchanged(self):
        """If SQLite durable revocation fails, in-memory state is unchanged and failure reported."""
        km = self.session_mgr.key_rotation_mgr
        old_key_id = km.active_key_id
        old_key_bytes = km.get_signing_key()[1]

        # Simulate SQLite failure on revoke_signing_key_approvals
        with patch.object(self.db, "revoke_signing_key_approvals", side_effect=RuntimeError("Simulated SQLite write error")):
            with self.assertRaises((RuntimeError, SecurityAuthorizationError)):
                km.rotate_keys(
                    new_key_id="v2_emergency",
                    new_secret=b"replacement_secret_32_bytes_long!",
                    mode=KeyRotationManager.MODE_EMERGENCY,
                    db_manager=self.db,
                )

        # In-memory keys must remain unchanged
        self.assertEqual(km.active_key_id, old_key_id)
        self.assertEqual(km.get_signing_key()[1], old_key_bytes)

    def test_emergency_key_rotation_revokes_approvals_and_purges_grants(self):
        """Successful emergency key rotation invalidates active tickets, grants, and persisted approvals."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # Perform emergency rotation
        new_key = b"emergency_key_32_bytes_long_12345"
        self.session_mgr.rotate_keys(
            new_key_id="v2_emergency",
            new_secret=new_key,
            mode=KeyRotationManager.MODE_EMERGENCY,
        )

        # 1. Stored approval signed by old key is revoked
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # 2. Previously issued ticket cannot be consumed or verified
        with self.assertRaises((KeyRevokedError, SecurityAuthorizationError)):
            self.session_mgr.verify_action_ticket(
                ticket_str=ticket,
                expected_action="HUMAN_APPROVAL",
                expected_resource_id=app.id,
                expected_packet_hash=snap_hash,
            )

    # =========================================================================
    # FINDING F: Unambiguous and Fail-Closed Approval Lookup
    # =========================================================================

    def test_approval_lookup_rejects_malformed_user_id(self):
        """has_valid_human_approval fails closed when user_id is malformed or non-positive."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        # Valid lookup
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # Malformed user_ids
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=0))
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=-1))
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id="bad_user"))  # type: ignore

    def test_approval_lookup_enforces_cross_candidate_isolation(self):
        """User 2 cannot check or access User 1's human approval."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )

        # User 1 has valid approval
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # User 2 checking User 1's application must return False
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_2))

    def test_approval_lookup_rejects_consumed_or_revoked_approvals(self):
        """Approval lookup returns False once consumed or revoked."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        succ, msg, approval = self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # 1. Consumed approval
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE application_approvals SET consumed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (approval.id,),
            )
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # 2. Revoked approval
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE application_approvals SET consumed_at = NULL, revoked_at = CURRENT_TIMESTAMP WHERE id = ?",
                (approval.id,),
            )
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

    def test_legacy_log_fallback_blocked_when_prepared_packets_exist(self):
        """Legacy audit log approval fallback is blocked if application has prepared packets."""
        app, packet, snap_hash, _ = self._create_complete_verified_application(self.user_1)

        # Insert a mock legacy approval log in application_logs
        with self.db.transaction() as conn:
            conn.cursor().execute(
                """
                INSERT INTO application_logs (job_id, application_id, user_id, action, details)
                VALUES (NULL, ?, ?, 'Status changed to Applied (Manual Confirmation)', 'Approved by candidate')
                """,
                (app.id, self.user_1),
            )

        # Because packet exists, has_valid_human_approval must NOT fall back to legacy logs
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _create_complete_verified_application(self, user_id: int):
        """Creates a fully consistent candidate application with valid files and hashes."""
        # 1. Candidate Profile
        prof = self.db.save_user_candidate_profile(
            user_id=user_id,
            profile_data={
                "full_name": "Candidate One",
                "headline": "Lead Data Engineer",
                "technical_skills": ["Python", "Spark", "SQL"],
            },
        )

        # 2. Job Description
        jd = self.db.save_job_description_snapshot(
            user_id=user_id,
            company_name="Apex Global Technologies",
            job_title="Lead Data Engineer",
            raw_content="Build distributed pipelines with Spark and Python.",
        )

        # 3. Source Resume on disk
        user_res_dir = self.storage_dir / str(user_id) / "resumes"
        user_res_dir.mkdir(parents=True, exist_ok=True)
        res_file = user_res_dir / "original_source.pdf"
        res_file.write_bytes(PDF_HEADER)
        res_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        res_record = self.db.create_user_resume(
            user_id=user_id,
            original_filename="original_source.pdf",
            storage_filename=str(res_file),
            file_format="pdf",
            file_hash=res_hash,
            file_size_bytes=len(PDF_HEADER),
        )

        # 4. Application
        app = self.db.create_user_application(
            user_id=user_id,
            company_name="Apex Global Technologies",
            job_title="Lead Data Engineer",
            status="READY_FOR_REVIEW",
            job_description_id=jd.id,
            resume_id=res_record["id"],
        )

        # 5. Tailored Resume Doc & Cover Letter Doc on disk
        user_app_dir = self.storage_dir / str(user_id) / "applications" / str(app.id)
        user_app_dir.mkdir(parents=True, exist_ok=True)

        tailored_file = user_app_dir / "tailored_resume.pdf"
        tailored_file.write_bytes(PDF_HEADER)
        tailored_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        cover_file = user_app_dir / "cover_letter.pdf"
        cover_file.write_bytes(PDF_HEADER)
        cover_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        # Wrap in GeneratedDocument objects
        tailored_doc = GeneratedDocument(
            document_type="resume",
            file_format="pdf",
            file_path=str(tailored_file),
            filename="tailored_resume.pdf",
            file_hash=tailored_hash,
            file_size_bytes=len(PDF_HEADER),
            template="Modern",
        )
        cover_doc = GeneratedDocument(
            document_type="cover_letter",
            file_format="pdf",
            file_path=str(cover_file),
            filename="cover_letter.pdf",
            file_hash=cover_hash,
            file_size_bytes=len(PDF_HEADER),
            template="Modern",
        )

        tailored_model = TailoredResume(
            user_id=user_id,
            target_role="Lead Data Engineer",
            target_company="Apex Global Technologies",
            professional_summary="Experienced Data Engineer with Spark and Python",
        )
        cover_model = CoverLetter(
            user_id=user_id,
            target_company="Apex Global Technologies",
            target_role="Lead Data Engineer",
            letter_text="I am thrilled to apply for the Lead Data Engineer position.",
            paragraphs=["I am thrilled to apply for the Lead Data Engineer position."],
            file_path=str(cover_file),
        )

        packet = self.gate.prepare_universal_packet(
            user_id=user_id,
            application_id=app.id,
            original_resume_id=res_record["id"],
            original_resume_hash=res_hash,
            tailored_resume=tailored_model,
            tailored_resume_pdf_doc=tailored_doc,
            cover_letter=cover_model,
            cover_letter_pdf_doc=cover_doc,
            qa_packet=ScreeningQAPacket(user_id=user_id, job_description_id=jd.id, questions=[]),
            job_description_snapshot_hash=jd.snapshot_hash,
            candidate_profile_version=prof.get("version"),
            candidate_profile_hash=prof.get("profile_hash"),
        )
        snap_hash = packet.packet_version_hash

        return app, packet, snap_hash, jd


if __name__ == "__main__":
    unittest.main()

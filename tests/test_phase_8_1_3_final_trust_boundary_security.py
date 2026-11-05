"""Comprehensive regression and verification test suite for Phase 8.1.3:
Final Trust-Boundary & Approval Lookup Remediation.

Tests cover:
- Finding A: Trusted candidate storage root & strict symlink defenses
- Finding B: Failure-safe emergency signing key rotation with persistent revocation
- Finding C: Disambiguated approval lookups & exact audit scoping
- Finding D: State-machine validation during candidate profile invalidation
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from unittest.mock import MagicMock, patch

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    FileSecurityError,
    InvalidFileFormatError,
    InvalidStatusTransitionError,
    KeyRevokedError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.lifecycle.state_machine import ApplicationStateMachine, ApplicationStatus
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetter
from src.preparer.document_generator import GeneratedDocument
from src.preparer.question_answerer import ScreeningQAPacket
from src.preparer.tailored_resume_generator import TailoredResume
from src.security.file_security import FileSecurityValidator
from src.security.session_manager import KeyRotationManager, SessionManager
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash

PDF_HEADER = b"%PDF-1.4\n%phase813 test content inside user storage\n"


class BasePhase813TestCase(unittest.TestCase):
    """Shared fixture for Phase 8.1.3 tests."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.db_path = str(self.base_dir / "test_phase_8_1_3.db")
        self.storage_dir = self.base_dir / "users"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=self.db_path)
        self.session_mgr = SessionManager(
            server_secret=b"test_secret_32_bytes_long_phase813__",
            db_manager=self.db,
        )
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)
        self.gate = HumanApprovalGate(
            db_manager=self.db,
            session_manager=self.session_mgr,
            file_validator=self.file_validator,
        )

        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'cand1@example.com', 'h1', 's1', 'Candidate One')"
            )
            cur.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'cand2@example.com', 'h2', 's2', 'Candidate Two')"
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

        self.user1_dir = self.storage_dir / "1"
        self.user1_dir.mkdir(parents=True, exist_ok=True)
        (self.user1_dir / "resumes").mkdir(parents=True, exist_ok=True)
        (self.user1_dir / "applications").mkdir(parents=True, exist_ok=True)

        self.user2_dir = self.storage_dir / "2"
        self.user2_dir.mkdir(parents=True, exist_ok=True)
        (self.user2_dir / "resumes").mkdir(parents=True, exist_ok=True)
        (self.user2_dir / "applications").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_verified_application(self, user_id: int, job_id: Optional[int] = None):
        """Helper to create a complete verified application packet."""
        prof = self.db.save_user_candidate_profile(
            user_id=user_id,
            profile_data={
                "full_name": f"Candidate {user_id}",
                "headline": "Software Engineer",
                "technical_skills": ["Python", "SQL"],
            },
        )
        jd = self.db.save_job_description_snapshot(
            user_id=user_id,
            company_name="Acme Corp",
            job_title="Software Engineer",
            raw_content="Develop software in Python.",
        )
        user_res_dir = self.storage_dir / str(user_id) / "resumes"
        user_res_dir.mkdir(parents=True, exist_ok=True)
        res_file = user_res_dir / "source.pdf"
        res_file.write_bytes(PDF_HEADER)
        res_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        res_record = self.db.create_user_resume(
            user_id=user_id,
            original_filename="source.pdf",
            storage_filename=str(res_file),
            file_format="pdf",
            file_hash=res_hash,
            file_size_bytes=len(PDF_HEADER),
        )

        app = self.db.create_user_application(
            user_id=user_id,
            company_name="Acme Corp",
            job_title="Software Engineer",
            status="READY_FOR_REVIEW",
            job_description_id=jd.id,
            resume_id=res_record["id"],
            job_id=job_id,
        )

        user_app_dir = self.storage_dir / str(user_id) / "applications" / str(app.id)
        user_app_dir.mkdir(parents=True, exist_ok=True)

        tailored_file = user_app_dir / "tailored.pdf"
        tailored_file.write_bytes(PDF_HEADER)
        tailored_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        cover_file = user_app_dir / "cover.pdf"
        cover_file.write_bytes(PDF_HEADER)
        cover_hash = hashlib.sha256(PDF_HEADER).hexdigest()

        tailored_doc = GeneratedDocument(
            document_type="resume",
            file_format="pdf",
            file_path=str(tailored_file),
            filename="tailored.pdf",
            file_hash=tailored_hash,
            file_size_bytes=len(PDF_HEADER),
            template="Modern",
        )
        cover_doc = GeneratedDocument(
            document_type="cover_letter",
            file_format="pdf",
            file_path=str(cover_file),
            filename="cover.pdf",
            file_hash=cover_hash,
            file_size_bytes=len(PDF_HEADER),
            template="Modern",
        )

        tailored_model = TailoredResume(
            user_id=user_id,
            target_role="Software Engineer",
            target_company="Acme Corp",
            professional_summary="Engineer with Python skills",
        )
        cover_model = CoverLetter(
            user_id=user_id,
            target_company="Acme Corp",
            target_role="Software Engineer",
            letter_text="Application letter text",
            paragraphs=["Application letter text"],
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
        return app, packet, packet.packet_version_hash, jd


# =============================================================================
# FINDING A: TRUSTED CANDIDATE STORAGE ROOT & SYMLINK DEFENSES
# =============================================================================

class TestFindingASymlinkTrustBoundary(BasePhase813TestCase):
    """Verifies that candidate storage roots and path components reject symlinks."""

    def test_candidate_storage_root_symlink_to_another_candidate_rejected(self):
        """Candidate root directory that is a symlink to another candidate is rejected."""
        # Replace users/1 with symlink pointing to users/2
        shutil.rmtree(self.user1_dir)
        os.symlink(self.user2_dir, self.user1_dir)

        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.get_candidate_storage_root(self.user_1)
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

    def test_candidate_storage_root_symlink_pointing_outside_rejected(self):
        """Candidate root directory symlinked outside storage base is rejected."""
        shutil.rmtree(self.user1_dir)
        external_dir = self.base_dir / "external_private"
        external_dir.mkdir()
        os.symlink(external_dir, self.user1_dir)

        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.get_candidate_storage_root(self.user_1)
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

    def test_candidate_storage_root_valid_creation_and_strict_relparts(self):
        """Non-existent candidate directory is created cleanly and verified."""
        uid = 99
        root_99 = self.file_validator.get_candidate_storage_root(uid)
        self.assertTrue(root_99.is_dir())
        self.assertFalse(root_99.is_symlink())
        self.assertEqual(root_99.name, "99")

    def test_candidate_subdirectories_symlinks_rejected(self):
        """User subdirectories (resumes, job_descriptions, confirmations) reject symlinks."""
        # Resumes dir as symlink
        shutil.rmtree(self.user1_dir / "resumes")
        os.symlink(self.user2_dir / "resumes", self.user1_dir / "resumes")
        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.get_user_resumes_dir(self.user_1)
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

        # Job descriptions dir as symlink
        jd_dir = self.user1_dir / "job_descriptions"
        jd_dir.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(jd_dir)
        os.symlink(self.user2_dir / "job_descriptions", jd_dir)
        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.get_user_job_descriptions_dir(self.user_1)
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

        # Confirmations dir as symlink
        conf_dir = self.user1_dir / "confirmations"
        conf_dir.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(conf_dir)
        os.symlink(self.user2_dir / "confirmations", conf_dir)
        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.get_user_confirmations_dir(self.user_1)
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

    def test_resolve_and_verify_candidate_file_internal_symlink_within_root_rejected(self):
        """Intermediate directory symlink within candidate root is rejected before following."""
        # Create an internal directory in user 1 and symlink a subdir to it
        target_sub = self.user1_dir / "secret_sub"
        target_sub.mkdir()
        legit_file = target_sub / "legit.pdf"
        legit_file.write_bytes(PDF_HEADER)

        link_sub = self.user1_dir / "resumes" / "linked_sub"
        os.symlink(target_sub, link_sub)

        # Calling with link_sub/legit.pdf must be rejected
        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(link_sub / "legit.pdf"),
                expected_hash=hashlib.sha256(PDF_HEADER).hexdigest(),
                expected_size=len(PDF_HEADER),
            )
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

    def test_resolve_and_verify_candidate_file_parent_symlink_to_other_candidate_rejected(self):
        """Parent folder symlinked to another candidate's folder is rejected."""
        shutil.rmtree(self.user1_dir / "resumes")
        os.symlink(self.user2_dir / "resumes", self.user1_dir / "resumes")

        target_file = self.user2_dir / "resumes" / "cand2.pdf"
        target_file.write_bytes(PDF_HEADER)

        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(self.user1_dir / "resumes" / "cand2.pdf"),
                expected_hash=hashlib.sha256(PDF_HEADER).hexdigest(),
                expected_size=len(PDF_HEADER),
            )
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

    def test_resolve_and_verify_candidate_file_final_symlink_rejected(self):
        """A symlink pointing to a legitimate candidate file is rejected."""
        real_file = self.user1_dir / "resumes" / "real.pdf"
        real_file.write_bytes(PDF_HEADER)

        symlink_file = self.user1_dir / "resumes" / "alias.pdf"
        os.symlink(real_file, symlink_file)

        with self.assertRaises(FileSecurityError) as ctx:
            self.file_validator.resolve_and_verify_candidate_file(
                user_id=self.user_1,
                file_path=str(symlink_file),
                expected_hash=hashlib.sha256(PDF_HEADER).hexdigest(),
                expected_size=len(PDF_HEADER),
            )
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

    def test_resolve_and_verify_candidate_file_normal_file_succeeds(self):
        """A normal regular file inside candidate storage passes verification."""
        real_file = self.user1_dir / "resumes" / "normal.pdf"
        real_file.write_bytes(PDF_HEADER)
        h = hashlib.sha256(PDF_HEADER).hexdigest()

        resolved, data, res_h, res_sz = self.file_validator.resolve_and_verify_candidate_file(
            user_id=self.user_1,
            file_path=str(real_file),
            expected_hash=h,
            expected_size=len(PDF_HEADER),
            expected_format="pdf",
        )
        self.assertEqual(resolved, real_file.resolve())
        self.assertEqual(data, PDF_HEADER)
        self.assertEqual(res_h, h)
        self.assertEqual(res_sz, len(PDF_HEADER))


# =============================================================================
# FINDING B: EMERGENCY SIGNING KEY ROTATION FAILURE-INJECTION
# =============================================================================

class TestFindingBEmergencyKeyRotationFailureInjection(BasePhase813TestCase):
    """Verifies durable, failure-safe emergency key rotation."""

    def test_emergency_rotation_missing_database_fails_closed(self):
        """Emergency rotation without an active db_manager raises SecurityAuthorizationError."""
        km = KeyRotationManager(initial_secret=b"key_manager_secret_32_bytes_long_", db_manager=None)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            km.rotate_keys(
                new_key_id="v2",
                new_secret=b"replacement_secret_32_bytes_long_",
                mode=KeyRotationManager.MODE_EMERGENCY,
            )
        self.assertIn("revoke_signing_key_approvals support", str(ctx.exception))

    def test_emergency_rotation_database_lacking_operation_fails_closed(self):
        """Emergency rotation with a db object lacking revoke_signing_key_approvals fails closed."""
        fake_db = object()
        km = KeyRotationManager(initial_secret=b"key_manager_secret_32_bytes_long_", db_manager=fake_db)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            km.rotate_keys(
                new_key_id="v2",
                new_secret=b"replacement_secret_32_bytes_long_",
                mode=KeyRotationManager.MODE_EMERGENCY,
            )
        self.assertIn("revoke_signing_key_approvals support", str(ctx.exception))

    def test_emergency_rotation_database_exception_fails_closed(self):
        """Database exception during persistent revocation fails rotation cleanly."""
        km = self.session_mgr.key_rotation_mgr
        old_key_id = km.active_key_id
        old_secret = km._keys[old_key_id]

        with patch.object(self.db, "revoke_signing_key_approvals", side_effect=RuntimeError("Disk I/O error")):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.session_mgr.rotate_keys(
                    new_key_id="v2_emergency",
                    new_secret=b"new_secret_32_bytes_long_emergency_",
                    mode=KeyRotationManager.MODE_EMERGENCY,
                )
            self.assertIn("Durable emergency key revocation failed", str(ctx.exception))

        # Invariant: in-memory active key unchanged
        self.assertEqual(km.active_key_id, old_key_id)
        self.assertEqual(km._keys[old_key_id], old_secret)
        self.assertNotIn("v1", km._revoked_keys)
        self.assertNotIn("v2_emergency", km._retired_keys)

    def test_emergency_rotation_in_memory_state_persists_revocation_first(self):
        """Emergency rotation writes revocation to DB before updating active in-memory keys."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
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

        # Create a 6-part action ticket before rotation
        ticket_6part = self.session_mgr.create_action_ticket(
            action_type="HUMAN_APPROVAL",
            resource_id=app.id,
            packet_version_hash=snap_hash,
        )

        # Execute emergency rotation
        new_key = b"brand_new_secret_32_bytes_long_emg"
        self.session_mgr.rotate_keys(
            new_key_id="v2",
            new_secret=new_key,
            mode=KeyRotationManager.MODE_EMERGENCY,
        )

        # 1. Approval in DB is revoked
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # 2. In-memory grants purged
        self.assertEqual(len(self.session_mgr._active_grants), 0)

        # 3. Old ticket rejected with KeyRevokedError
        with self.assertRaises(KeyRevokedError):
            self.session_mgr.verify_action_ticket(
                ticket_str=ticket_6part,
                expected_action="HUMAN_APPROVAL",
                expected_resource_id=app.id,
                expected_packet_hash=snap_hash,
            )

    def test_fresh_session_manager_instance_rejects_revoked_key(self):
        """Fresh SessionManager instance connected to same DB recognizes revoked key."""
        # Issue 6-part ticket under v1 before rotation
        ticket_v1 = self.session_mgr.create_action_ticket(
            action_type="HUMAN_APPROVAL",
            resource_id=1,
            packet_version_hash="dummy",
        )

        # Perform emergency rotation
        self.session_mgr.rotate_keys(
            new_key_id="v2",
            new_secret=b"brand_new_secret_32_bytes_long_emg",
            mode=KeyRotationManager.MODE_EMERGENCY,
        )

        # Create a fresh SessionManager with same initial default key v1
        fresh_sm = SessionManager(
            server_secret=b"test_secret_32_bytes_long_phase813__",
            db_manager=self.db,
        )
        with self.assertRaises(KeyRevokedError):
            fresh_sm.verify_action_ticket(
                ticket_str=ticket_v1,
                expected_action="HUMAN_APPROVAL",
                expected_resource_id=1,
                expected_packet_hash="dummy",
            )

    def test_key_id_reuse_of_revoked_key_fails_closed(self):
        """Reusing a key ID that was previously revoked fails closed."""
        self.session_mgr.rotate_keys(
            new_key_id="v2",
            new_secret=b"brand_new_secret_32_bytes_long_emg",
            mode=KeyRotationManager.MODE_EMERGENCY,
        )
        # Attempt to rotate back to v1
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.session_mgr.rotate_keys(
                new_key_id="v1",
                new_secret=b"attempt_reuse_of_v1_secret_32_bytes",
                mode=KeyRotationManager.MODE_EMERGENCY,
            )
        self.assertIn("previously revoked key ID", str(ctx.exception))

    def test_replacement_key_works_normally(self):
        """New tickets and grants issued under replacement key operate successfully."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
        self.session_mgr.rotate_keys(
            new_key_id="v2",
            new_secret=b"brand_new_secret_32_bytes_long_emg",
            mode=KeyRotationManager.MODE_EMERGENCY,
        )

        ticket_v2 = self.session_mgr.issue_action_ticket(
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
            action_ticket=ticket_v2,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Authorization failed under v2 key: {msg}")
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))


# =============================================================================
# FINDING C: DISAMBIGUATED APPROVAL LOOKUPS & AUDIT SCOPING
# =============================================================================

class TestFindingCDisambiguatedApprovalLookups(BasePhase813TestCase):
    """Verifies that has_valid_human_approval fails closed against positional and cross-user calls."""

    def test_overlapping_numeric_application_and_job_id(self):
        """When an application ID equals an unrelated job ID, approval resolves against the correct entity."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
        # Create a catalog job with ID matching app.id
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "INSERT INTO jobs (id, company_name, job_title, job_url, platform) VALUES (?, 'Collision Co', 'Collision Job', ?, 'direct')",
                (app.id, f"https://job.url/{app.id}"),
            )

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

        # 1. Explicit application lookup for app.id succeeds
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # 2. Legacy job lookup for same numeric ID must NOT return True based on application app.id's approval
        self.assertFalse(self.db.has_valid_human_approval(job_id=app.id, user_id=self.user_1))

    def test_two_candidates_same_catalog_job_isolation(self):
        """Two candidates applying to the same catalog job have isolated approvals."""
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "INSERT INTO jobs (id, company_name, job_title, job_url, platform) VALUES (555, 'Acme Corp', 'Software Engineer', 'https://job.url/555', 'linkedin')"
            )
        # Candidate 1 application for job 555
        app1, packet1, snap_hash1, _ = self._create_verified_application(self.user_1, job_id=555)
        # Candidate 2 application for job 555
        app2, packet2, snap_hash2, _ = self._create_verified_application(self.user_2, job_id=555)

        ticket1 = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app1.id,
            packet_hash=snap_hash1,
        )
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app1.id,
            packet_id=packet1.id,
            approver_name="Candidate One",
            session_id=self.session_1.session_id,
            action_ticket=ticket1,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Auth failed: {msg}")

        # Candidate 1 has approval
        self.assertTrue(self.db.has_valid_human_approval(application_id=app1.id, user_id=self.user_1))
        # Candidate 2 MUST NOT have approval
        self.assertFalse(self.db.has_valid_human_approval(application_id=app2.id, user_id=self.user_2))
        # Candidate 2 cannot claim Candidate 1's approval
        self.assertFalse(self.db.has_valid_human_approval(application_id=app1.id, user_id=self.user_2))

    def test_positional_identifier_fails_closed(self):
        """Calling has_valid_human_approval positionally fails closed immediately."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
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

        # Positional calls fail closed
        self.assertFalse(self.db.has_valid_human_approval(app.id))
        self.assertFalse(self.db.has_valid_human_approval(12345))

    def test_missing_user_id_rejected_for_candidate_owned_applications(self):
        """Calling has_valid_human_approval without user_id on candidate-owned app returns False."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
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

        # Missing user_id fails closed
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id))

    def test_malformed_user_id_rejected(self):
        """Malformed user_id values fail closed."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=0))
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=-5))
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id="non_numeric"))  # type: ignore

    def test_wrong_packet_hash_or_historical_revision_rejected(self):
        """Wrong expected packet hash or historical inactive revision returns False."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
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

        # Wrong hash
        self.assertFalse(
            self.db.has_valid_human_approval(
                application_id=app.id,
                user_id=self.user_1,
                expected_packet_hash="f" * 64,
            )
        )

        # New revision marks old revision inactive
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET is_active_revision = 0 WHERE id = ?",
                (packet.id,),
            )
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

    def test_modern_application_cannot_fall_back_to_legacy_logs(self):
        """Modern application with prepared packet never falls back to application_logs."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
        # Insert catalog job 10 first to satisfy foreign key
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "INSERT INTO jobs (id, company_name, job_title, job_url, platform) VALUES (10, 'Leg Co', 'Leg Job', 'https://job.url/10', 'direct')"
            )
            conn.cursor().execute(
                "INSERT INTO application_logs (job_id, application_id, action, details) "
                "VALUES (10, ?, 'HUMAN_APPROVAL_RECORDED', '{}')",
                (app.id,),
            )
        # Approval in prepared_packets is not granted yet; legacy log must NOT satisfy check
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))


# =============================================================================
# FINDING D: STATE-MACHINE VALIDATION DURING CANDIDATE PROFILE INVALIDATION
# =============================================================================

class TestFindingDStateMachineProfileInvalidation(BasePhase813TestCase):
    """Verifies state-machine validation, grouping, and atomic rollback on profile update."""

    def test_approved_application_invalidates_to_ready_for_review(self):
        """Updating candidate profile invalidates approval and transitions status to READY_FOR_REVIEW."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
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

        app_before = self.db.get_user_application(app.id, self.user_1)
        self.assertEqual(app_before.status, "Awaiting Approval")
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # Update profile
        self.db.save_user_candidate_profile(
            user_id=self.user_1,
            profile_data={"full_name": "Updated Name", "technical_skills": ["Rust"]},
        )

        # Verify approval is revoked
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # Verify status transitioned to READY_FOR_REVIEW
        app_after = self.db.get_user_application(app.id, self.user_1)
        self.assertEqual(app_after.status, ApplicationStatus.READY_FOR_REVIEW.value)

        # Verify event logged
        events = self.db.get_application_events(app.id, self.user_1)
        last_event = events[-1]
        self.assertEqual(last_event.event_type, "PACKET_APPROVAL_REVOKED")
        self.assertEqual(last_event.previous_status, "Awaiting Approval")
        self.assertEqual(last_event.new_status, "READY_FOR_REVIEW")

        # Verify event hash chain validity
        self.assertTrue(self.db.verify_application_event_chain(app.id, self.user_1))

    def test_multiple_approvals_for_one_app_produce_exactly_one_revocation_event(self):
        """When an application has multiple approval records, exactly one timeline event is created."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
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

        # Insert a second unconsumed approval for the same application
        with self.db.transaction() as conn:
            conn.cursor().execute(
                """
                INSERT INTO application_approvals (
                    user_id, application_id, packet_id, packet_version_hash,
                    approver_name, ticket_nonce, key_id, session_id
                ) VALUES (?, ?, ?, ?, 'Candidate One', 'nonce2', 'v1', 'sess_test')
                """,
                (self.user_1, app.id, packet.id, snap_hash),
            )

        events_before_count = len(self.db.get_application_events(app.id, self.user_1))

        # Update profile
        self.db.save_user_candidate_profile(
            user_id=self.user_1,
            profile_data={"full_name": "Updated Name 2"},
        )

        events_after = self.db.get_application_events(app.id, self.user_1)
        # Exactly one new event added
        self.assertEqual(len(events_after), events_before_count + 1)
        self.assertEqual(events_after[-1].event_type, "PACKET_APPROVAL_REVOKED")

    def test_invalid_state_machine_transition_is_prevented(self):
        """Applications in post-submission status revoke approvals but do not illegally mutate to READY_FOR_REVIEW."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
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

        # Force application into APPLIED status
        with self.db.transaction() as conn:
            conn.cursor().execute("UPDATE applications SET status = 'Applied' WHERE id = ?", (app.id,))

        # Update candidate profile
        self.db.save_user_candidate_profile(
            user_id=self.user_1,
            profile_data={"full_name": "Updated After Applied"},
        )

        # Approvals are revoked
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # But status is NOT illegally mutated to READY_FOR_REVIEW; it remains Applied!
        app_check = self.db.get_user_application(app.id, self.user_1)
        self.assertEqual(app_check.status, "Applied")

        # Explicit state-machine check verifies Applied -> READY_FOR_REVIEW is illegal
        with self.assertRaises(InvalidStatusTransitionError):
            ApplicationStateMachine.validate_transition(
                ApplicationStatus.APPLIED,
                ApplicationStatus.READY_FOR_REVIEW,
            )

    def test_failure_during_event_insertion_rolls_back_entire_transaction(self):
        """Failure during timeline event insertion rolls back profile and approval changes."""
        app, packet, snap_hash, _ = self._create_verified_application(self.user_1)
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

        with patch.object(self.db, "_insert_application_event_internal", side_effect=RuntimeError("Simulated Event Insert Failure")):
            with self.assertRaises(RuntimeError):
                self.db.save_user_candidate_profile(
                    user_id=self.user_1,
                    profile_data={"full_name": "Broken Event Insert"},
                )

        # Status remains Awaiting Approval
        app_check = self.db.get_user_application(app.id, self.user_1)
        self.assertEqual(app_check.status, "Awaiting Approval")

        # Approval remains valid
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

    def test_reauthorization_after_profile_update_restores_valid_approval(self):
        """After invalidation, candidate creates new packet revision and re-authorizes."""
        app, packet, snap_hash, jd = self._create_verified_application(self.user_1)
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

        # Invalidate via profile update
        new_prof = self.db.save_user_candidate_profile(
            user_id=self.user_1,
            profile_data={"full_name": "Candidate One Prime", "technical_skills": ["Python", "Rust"]},
        )
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))

        # Create new packet revision v2 with new profile version & hash
        user_app_dir = self.storage_dir / str(self.user_1) / "applications" / str(app.id)
        tailored_file = user_app_dir / "tailored_v2.pdf"
        tailored_file.write_bytes(PDF_HEADER + b"\nv2")
        tailored_hash = hashlib.sha256(PDF_HEADER + b"\nv2").hexdigest()

        cover_file = user_app_dir / "cover_v2.pdf"
        cover_file.write_bytes(PDF_HEADER + b"\nv2")
        cover_hash = hashlib.sha256(PDF_HEADER + b"\nv2").hexdigest()

        tailored_doc2 = GeneratedDocument(
            document_type="resume",
            file_format="pdf",
            file_path=str(tailored_file),
            filename="tailored_v2.pdf",
            file_hash=tailored_hash,
            file_size_bytes=len(PDF_HEADER) + 3,
            template="Modern",
        )
        cover_doc2 = GeneratedDocument(
            document_type="cover_letter",
            file_format="pdf",
            file_path=str(cover_file),
            filename="cover_v2.pdf",
            file_hash=cover_hash,
            file_size_bytes=len(PDF_HEADER) + 3,
            template="Modern",
        )

        packet2 = self.gate.prepare_universal_packet(
            user_id=self.user_1,
            application_id=app.id,
            original_resume_id=packet.original_resume_id,
            original_resume_hash=packet.original_resume_hash,
            tailored_resume=TailoredResume(
                user_id=self.user_1,
                target_role="Software Engineer",
                target_company="Acme Corp",
                professional_summary="Engineer with Python and Rust",
            ),
            tailored_resume_pdf_doc=tailored_doc2,
            cover_letter=CoverLetter(
                user_id=self.user_1,
                target_company="Acme Corp",
                target_role="Software Engineer",
                letter_text="Updated letter",
                paragraphs=["Updated letter"],
                file_path=str(cover_file),
            ),
            qa_packet=ScreeningQAPacket(user_id=self.user_1, job_description_id=jd.id, questions=[]),
            job_description_snapshot_hash=jd.snapshot_hash,
            candidate_profile_version=new_prof.get("version"),
            candidate_profile_hash=new_prof.get("profile_hash"),
        )

        ticket2 = self.session_mgr.issue_action_ticket(
            session_id=self.session_1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=packet2.packet_version_hash,
        )
        succ, msg, approval2 = self.gate.authorize_universal_packet(
            user_id=self.user_1,
            application_id=app.id,
            packet_id=packet2.id,
            approver_name="Candidate One Prime",
            session_id=self.session_1.session_id,
            action_ticket=ticket2,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Re-authorization failed: {msg}")
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_1))


if __name__ == "__main__":
    unittest.main()

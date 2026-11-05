"""Tests for Phase 8.1.1 Security Remediation: Persisted Approval Revocation & Packet Integrity.

Covers:
- Finding A: Durable emergency key revocation, unconsumed approval invalidation in SQLite,
  and mandatory candidate re-authorization.
- Finding B: Candidate profile change invalidation in SQLite and fail-closed profile version/hash verification.
- Finding C: Fail-closed verification of source resume, job description, generated documents, attachments, and screening QA.
- Finding D: Disambiguated approval lookup, user isolation, active revision enforcement, and legacy log segregation.
"""

from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    SecurityAuthorizationError,
)
from src.database.models import ApplicationStatus
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetter, CoverLetterGenerator
from src.preparer.question_answerer import QuestionAnswerer, ScreeningQAPacket
from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
from src.security.auth import AuthManager
from src.security.session_manager import KeyRotationManager, SessionManager
from src.utils.canonical_json import canonical_json_bytes


class Phase811TestBase(unittest.TestCase):
    """Base test fixture for Phase 8.1.1 security tests."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "phase811_test.db"
        self.user_base_dir = Path(self.temp_dir.name) / "users"
        self.user_base_dir.mkdir(parents=True, exist_ok=True)

        SessionManager.reset_instance()
        self.session_mgr = SessionManager()
        self.db = DatabaseManager(db_path=self.db_path, session_manager=self.session_mgr)
        self.auth = AuthManager(db_manager=self.db)
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)
        self.service = DashboardService(db_manager=self.db)
        self.service.session_manager = self.session_mgr

        # Create two test candidates
        self.user_a = self.auth.register("candidate.a@example.com", "Password123!", "Candidate A")
        self.user_b = self.auth.register("candidate.b@example.com", "Password123!", "Candidate B")

        # Authenticate sessions
        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="cand_a", candidate_name="Candidate A", user_id=self.user_a.id
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="cand_b", candidate_name="Candidate B", user_id=self.user_b.id
        )

        # Generate a valid PDF resume for User A
        pdf_stream = io.BytesIO()
        doc = SimpleDocTemplate(pdf_stream, pagesize=letter)
        doc.build([Paragraph("Resume of Candidate A - Software Engineer", getSampleStyleSheet()["Normal"])])
        self.valid_resume_bytes = pdf_stream.getvalue()

        self.resume_a = self.db.upload_user_resume(
            user_id=self.user_a.id,
            file_bytes=self.valid_resume_bytes,
            original_filename="cand_a_resume.pdf",
            user_base_dir=self.user_base_dir,
        )

        # Create a Job Description for User A
        self.jd_a = self.db.create_job_description(
            user_id=self.user_a.id,
            company_name="Nexus Technologies",
            job_title="Backend Security Architect",
            raw_content="Looking for a Backend Security Architect with Python, Cryptography, and SQLite.",
            parsed_data={"required_skills": ["Python", "Cryptography", "SQLite"]},
        )

        # Candidate profile for User A
        self.profile_a = {
            "personal": {"full_name": "Candidate A", "email": "candidate.a@example.com"},
            "work_experience": [
                {
                    "employer": "SecureSoft",
                    "job_title": "Security Engineer",
                    "duration": "3 years",
                    "responsibilities": ["HMAC authorization", "Session hardening"],
                }
            ],
            "skills": ["Python", "Cryptography", "SQLite"],
            "education": [{"institution": "Tech Institute", "degree": "BS Computer Science"}],
        }
        self.saved_profile_a = self.db.save_user_candidate_profile(self.user_a.id, self.profile_a)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_and_approve_packet(self, user_id: int):
        """Creates an application workspace, prepares a packet, and authorizes it."""
        app = self.db.get_or_create_application_workspace(
            user_id=user_id,
            job_description_id=self.jd_a.id,
            resume_id=self.resume_a["id"],
        )
        res_gen = UniversalTailoredResumeGenerator()
        tailored_res = res_gen.generate(
            user_id=user_id,
            candidate_profile=self.profile_a,
            job_description={"company_name": "Nexus Technologies", "role_title": "Backend Security Architect"},
        )
        cl_gen = CoverLetterGenerator()
        cover_letter: CoverLetter = cl_gen.generate_universal_cover_letter(
            user_id=user_id,
            candidate_profile=self.profile_a,
            job_description={"company_name": "Nexus Technologies", "role_title": "Backend Security Architect"},
        )
        qa = QuestionAnswerer()
        qs = qa.batch_answer_questions(["Years of security experience?"], user_id=user_id, candidate_profile=self.profile_a)
        for q in qs:
            q.state = "USER_APPROVED"
        qa_packet = ScreeningQAPacket(user_id=user_id, job_description_id=self.jd_a.id, questions=qs)

        packet = self.gate.prepare_universal_packet(
            user_id=user_id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored_res,
            cover_letter=cover_letter,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.content_hash,
            template_id="modern",
        )

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )

        succ, msg, approval = self.gate.authorize_universal_packet(
            user_id=user_id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate A",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Authorization failed: {msg}")
        self.assertIsNotNone(approval)
        return app, packet, approval


class TestFindingAEmergencyKeyRevocation(Phase811TestBase):
    """Finding A: Durable emergency key rotation persists revocation in SQLite,
    revokes unconsumed approvals, rejects submissions even with fresh tickets under replacement keys,
    and requires re-authorization under active key.
    """

    def test_emergency_key_rotation_persists_in_sqlite(self):
        """Emergency key rotation records revoked key in revoked_signing_keys table and marks approvals revoked."""
        app, packet, approval = self._create_and_approve_packet(self.user_a.id)
        old_key_id = approval.key_id

        # Verify initial approval is active and unrevoked
        self.assertTrue(self.db.has_valid_human_approval(app.id))
        appr_db = self.db.get_packet_approval(packet.id, self.user_a.id)
        self.assertIsNotNone(appr_db)
        self.assertFalse(appr_db.is_revoked)

        # Trigger EMERGENCY key rotation
        new_secret = os.urandom(32)
        self.session_mgr.rotate_keys(
            new_key_id="v2_emergency",
            new_secret=new_secret,
            mode=KeyRotationManager.MODE_EMERGENCY,
        )

        # 1. Durable key revocation persisted in SQLite
        self.assertTrue(self.db.is_key_revoked(old_key_id))

        # 2. Unconsumed approval marked is_revoked = 1 with revocation_reason
        appr_after = self.db.get_packet_approval(packet.id, self.user_a.id, include_revoked=True)
        self.assertIsNotNone(appr_after)
        self.assertTrue(appr_after.is_revoked)
        self.assertEqual(appr_after.revocation_reason, "EMERGENCY_KEY_REVOCATION")
        self.assertIsNotNone(appr_after.revoked_at)

        # 3. Default get_packet_approval returns None for revoked approval
        self.assertIsNone(self.db.get_packet_approval(packet.id, self.user_a.id, include_revoked=False))

        # 4. has_valid_human_approval returns False
        self.assertFalse(self.db.has_valid_human_approval(app.id))

    def test_manual_submission_rejected_even_with_fresh_ticket_under_replacement_key(self):
        """Submission is rejected if the underlying approval was revoked, even with a fresh ticket under the new key."""
        app, packet, approval = self._create_and_approve_packet(self.user_a.id)

        # Emergency rotation
        self.session_mgr.rotate_keys(
            new_key_id="v2_emergency",
            new_secret=os.urandom(32),
            mode=KeyRotationManager.MODE_EMERGENCY,
        )

        # Issue fresh MANUAL_SUBMISSION ticket under replacement key v2_emergency
        fresh_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        self.assertIn("v2_emergency", fresh_ticket)

        # Attempt manual submission
        with self.assertRaises(SecurityAuthorizationError) as cm:
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=fresh_ticket,
                candidate_confirmed=True,
                submission_channel="COMPANY_CAREER_PORTAL",
                confirmation_reference="REF-CONFIRM-12345",
                candidate_notes="Submitted externally",
            )
        self.assertIn("revoked", str(cm.exception).lower())

        # Ticket must remain unconsumed because failure occurred before consumption
        _k_id, nonce, _ts, _sig = self.session_mgr.parse_action_ticket(fresh_ticket)
        self.assertFalse(self.db.is_nonce_consumed(nonce))

    def test_reauthorization_under_new_active_key_enables_successful_submission(self):
        """Candidate re-authorizes under replacement key; submission succeeds and consumes approval."""
        app, packet, _ = self._create_and_approve_packet(self.user_a.id)

        # Emergency rotation
        self.session_mgr.rotate_keys(
            new_key_id="v2_emergency",
            new_secret=os.urandom(32),
            mode=KeyRotationManager.MODE_EMERGENCY,
        )

        # Candidate explicitly re-authorizes the application packet under the new key
        reauth_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        self.assertIn("v2_emergency", reauth_ticket)

        succ_reauth, msg_reauth, new_approval = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate A",
            session_id=self.session_a.session_id,
            action_ticket=reauth_ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_reauth, f"Re-authorization failed: {msg_reauth}")
        self.assertEqual(new_approval.key_id, "v2_emergency")
        self.assertFalse(new_approval.is_revoked)

        # Verify has_valid_human_approval is restored
        self.assertTrue(self.db.has_valid_human_approval(app.id))

        # Issue submission ticket and confirm manual submission
        sub_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        conf = self.service.record_candidate_manual_submission(
            application_id=app.id,
            session_id=self.session_a.session_id,
            submission_ticket=sub_ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
            confirmation_reference="REF-CONFIRM-REAUTH",
            candidate_notes="Submitted after re-authorization",
        )
        self.assertIsNotNone(conf)
        updated_app = self.db.get_user_application(app.id, self.user_a.id)
        self.assertEqual(updated_app.status, ApplicationStatus.SUBMITTED.value)


class TestFindingBCandidateProfileChangeInvalidation(Phase811TestBase):
    """Finding B: Candidate profile modification invalidates unconsumed approvals in SQLite
    and causes verify_prepared_packet_integrity to reject stale packets.
    """

    def test_candidate_profile_save_invalidates_unconsumed_approvals(self):
        """Updating candidate profile marks existing unconsumed approvals as revoked in SQLite."""
        app, packet, approval = self._create_and_approve_packet(self.user_a.id)
        self.assertFalse(approval.is_revoked)

        # Modify and save candidate profile
        modified_profile = dict(self.profile_a)
        modified_profile["skills"] = ["Python", "Cryptography", "SQLite", "Rust", "Zero Trust"]
        new_prof = self.db.save_user_candidate_profile(self.user_a.id, modified_profile)
        self.assertEqual(new_prof["version"], 2)

        # Unconsumed approval in SQLite is revoked with CANDIDATE_PROFILE_UPDATED
        appr_after = self.db.get_packet_approval(packet.id, self.user_a.id, include_revoked=True)
        self.assertIsNotNone(appr_after)
        self.assertTrue(appr_after.is_revoked)
        self.assertEqual(appr_after.revocation_reason, "CANDIDATE_PROFILE_UPDATED")
        self.assertIsNotNone(appr_after.revoked_at)

        # has_valid_human_approval returns False
        self.assertFalse(self.db.has_valid_human_approval(app.id))

    def test_packet_integrity_detects_candidate_profile_hash_and_version_mismatch(self):
        """verify_prepared_packet_integrity compares active DB profile against packet metadata and rejects stale packets."""
        app, packet, _ = self._create_and_approve_packet(self.user_a.id)

        # Before profile edit: packet integrity succeeds
        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertTrue(valid)

        # Candidate updates profile
        modified_profile = dict(self.profile_a)
        modified_profile["work_experience"][0]["job_title"] = "Principal Security Architect"
        self.db.save_user_candidate_profile(self.user_a.id, modified_profile)

        # After profile edit: verify_prepared_packet_integrity fails closed
        valid_post, msg_post, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid_post)
        self.assertIn("Candidate profile has been modified", msg_post)
        self.assertIn("fresh packet revision is required", msg_post)

    def test_submission_rejected_when_candidate_profile_modified_post_approval(self):
        """record_candidate_manual_submission fails closed if candidate profile changed after approval."""
        app, packet, _ = self._create_and_approve_packet(self.user_a.id)

        # Update candidate profile
        self.db.save_user_candidate_profile(self.user_a.id, {"personal": {"full_name": "Updated Name"}})

        # Issue submission ticket
        sub_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )

        with self.assertRaises(SecurityAuthorizationError) as cm:
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=sub_ticket,
                candidate_confirmed=True,
                submission_channel="COMPANY_CAREER_PORTAL",
                confirmation_reference="REF-POST-PROFILE-CHANGE",
                candidate_notes="Submitting stale packet",
            )
        self.assertTrue(
            "candidate profile has been modified" in str(cm.exception).lower()
            or "revoked" in str(cm.exception).lower()
        )


class TestFindingCFailClosedVerification(Phase811TestBase):
    """Finding C: Fail-closed verification of source resume, job description,
    generated documents, attachments, and screening QA.
    """

    def test_source_resume_missing_file_on_disk_fails_closed(self):
        """If source resume file is removed from disk, integrity check fails closed."""
        app, packet, _ = self._create_and_approve_packet(self.user_a.id)

        # Find and delete source resume file on disk
        storage_fn = self.resume_a["storage_filename"]
        target_file = self.user_base_dir / storage_fn
        if not target_file.exists():
            target_file = self.user_base_dir / str(self.user_a.id) / "resumes" / storage_fn
        self.assertTrue(target_file.exists(), f"Source file must exist before test at {target_file}")
        target_file.unlink()

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("Source resume file for Resume", msg)
        self.assertIn("not found on disk", msg)

    def test_source_resume_symlink_fails_closed(self):
        """If source resume file is replaced with a symlink, integrity check fails closed."""
        app, packet, _ = self._create_and_approve_packet(self.user_a.id)

        storage_fn = self.resume_a["storage_filename"]
        target_file = self.user_base_dir / storage_fn
        if not target_file.exists():
            target_file = self.user_base_dir / str(self.user_a.id) / "resumes" / storage_fn

        # Replace file with a symlink to /etc/hosts
        target_file.unlink()
        os.symlink("/etc/hosts", target_file)

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("cannot be a symbolic link", msg)

    def test_source_resume_tampered_disk_bytes_fails_closed(self):
        """If source resume bytes on disk are altered without DB update, integrity check fails."""
        app, packet, _ = self._create_and_approve_packet(self.user_a.id)

        storage_fn = self.resume_a["storage_filename"]
        target_file = self.user_base_dir / storage_fn
        if not target_file.exists():
            target_file = self.user_base_dir / str(self.user_a.id) / "resumes" / storage_fn

        # Overwrite with altered PDF bytes
        target_file.write_bytes(b"%PDF-1.4 altered content maliciously injected into resume")

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("Original source resume file hash has changed", msg)

    def test_job_description_archived_or_inactive_fails_closed(self):
        """If job description is archived/deactivated, verification fails closed."""
        app, packet, _ = self._create_and_approve_packet(self.user_a.id)

        with self.db.transaction() as conn:
            conn.execute("UPDATE job_descriptions SET is_active = 0 WHERE id = ?", (self.jd_a.id,))

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("is inactive or archived", msg)

    def test_tailored_resume_disk_file_missing_fails_closed(self):
        """If tailored resume file on disk is missing, packet integrity fails closed."""
        app = self.db.get_or_create_application_workspace(
            user_id=self.user_a.id, job_description_id=self.jd_a.id, resume_id=self.resume_a["id"]
        )
        res_gen = UniversalTailoredResumeGenerator()
        tailored_res = res_gen.generate(self.user_a.id, self.profile_a, {"company_name": "Nexus", "role_title": "Arch"})
        cl_gen = CoverLetterGenerator()
        cl = cl_gen.generate_universal_cover_letter(self.user_a.id, self.profile_a, {"company_name": "Nexus", "role_title": "Arch"})
        qa = QuestionAnswerer()
        qs = qa.batch_answer_questions(["Experience?"], user_id=self.user_a.id, candidate_profile=self.profile_a)
        qa_packet = ScreeningQAPacket(self.user_a.id, self.jd_a.id, qs)

        # Create dummy PDF file for tailored resume
        fake_tr_path = self.user_base_dir / str(self.user_a.id) / "tailored_res.pdf"
        fake_tr_path.write_bytes(b"%PDF-1.4 dummy tailored resume")
        fake_hash = hashlib.sha256(b"%PDF-1.4 dummy tailored resume").hexdigest()

        snap_dict = {
            "user_id": self.user_a.id,
            "application_id": app.id,
            "packet_version": 1,
            "original_resume_id": self.resume_a["id"],
            "original_resume_file_hash": self.resume_a["file_hash"],
            "job_description_id": self.jd_a.id,
            "job_description_snapshot_hash": self.jd_a.content_hash,
            "tailored_resume_document_hash": fake_hash,
        }
        canon_bytes = canonical_json_bytes(snap_dict)
        canon_str = canon_bytes.decode("utf-8")
        pkt_hash = hashlib.sha256(canon_bytes).hexdigest()

        packet = self.db.create_prepared_packet(
            application_id=app.id,
            user_id=self.user_a.id,
            version_num=1,
            packet_version_hash=pkt_hash,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            screening_answers=[],
            tailored_resume_path=str(fake_tr_path),
            tailored_resume_hash=fake_hash,
            job_description_snapshot_hash=self.jd_a.content_hash,
            canonical_snapshot_json=canon_str,
        )

        # Remove the file
        fake_tr_path.unlink()

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("Tailored resume file not found on disk", msg)

    def test_attachments_manifest_size_mismatch_fails_closed(self):
        """Attachment in manifest with mismatched byte length fails integrity check."""
        app = self.db.get_or_create_application_workspace(
            user_id=self.user_a.id, job_description_id=self.jd_a.id, resume_id=self.resume_a["id"]
        )
        att_file = self.user_base_dir / str(self.user_a.id) / "cert.pdf"
        att_bytes = b"%PDF-1.4 certification bytes"
        att_file.write_bytes(att_bytes)
        att_hash = hashlib.sha256(att_bytes).hexdigest()

        manifest = [{
            "filename": "cert.pdf",
            "file_path": str(att_file),
            "file_hash": att_hash,
            "size_bytes": len(att_bytes) + 100,  # Intentional size mismatch
            "format": "pdf",
        }]

        snap_payload = {
            "user_id": self.user_a.id,
            "application_id": app.id,
            "packet_version": 1,
            "original_resume_id": self.resume_a["id"],
            "original_resume_file_hash": self.resume_a["file_hash"],
            "job_description_id": self.jd_a.id,
            "job_description_snapshot_hash": self.jd_a.content_hash,
            "attachments_manifest": manifest,
        }
        canon_att_bytes = canonical_json_bytes(snap_payload)
        canon_att_str = canon_att_bytes.decode("utf-8")
        pkt_hash = hashlib.sha256(canon_att_bytes).hexdigest()

        packet = self.db.create_prepared_packet(
            application_id=app.id,
            user_id=self.user_a.id,
            version_num=1,
            packet_version_hash=pkt_hash,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            screening_answers=[],
            job_description_snapshot_hash=self.jd_a.content_hash,
            attachments_manifest=manifest,
            canonical_snapshot_json=canon_att_str,
        )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("file size on disk", msg)

    def test_screening_qa_valid_empty_list_passes(self):
        """A packet with valid empty list of screening questions [] passes Element 10."""
        app, packet, _ = self._create_and_approve_packet(self.user_a.id)

        # Update snapshot to have screening_questions: []
        snapshot = json.loads(packet.canonical_snapshot_json)
        snapshot["screening_questions"] = []
        raw_bytes = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
        new_hash = hashlib.sha256(raw_bytes).hexdigest()

        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = ?, packet_version_hash = ? WHERE id = ?",
                (raw_bytes.decode("utf-8"), new_hash, packet.id),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertTrue(valid, f"Expected empty list screening QA to pass, got: {msg}")


class TestFindingDDisambiguatedApprovalLookup(Phase811TestBase):
    """Finding D: Disambiguated approval lookup, user isolation,
    active revision enforcement, and legacy log segregation.
    """

    def test_has_valid_human_approval_with_explicit_kwargs(self):
        """has_valid_human_approval correctly resolves application_id and job_id explicitly."""
        app, packet, approval = self._create_and_approve_packet(self.user_a.id)

        # 1. Positional lookup
        self.assertTrue(self.db.has_valid_human_approval(app.id))

        # 2. Explicit keyword application_id lookup
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id))

        # 3. Explicit expected_packet_hash match
        self.assertTrue(
            self.db.has_valid_human_approval(application_id=app.id, expected_packet_hash=packet.packet_version_hash)
        )

        # 4. Mismatched packet hash returns False
        self.assertFalse(
            self.db.has_valid_human_approval(application_id=app.id, expected_packet_hash="wrong_hash_12345")
        )

    def test_has_valid_human_approval_enforces_user_isolation(self):
        """Passing another user's user_id returns False regardless of valid approval."""
        app, packet, _ = self._create_and_approve_packet(self.user_a.id)

        # Valid for user_a
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_a.id))

        # Rebuffed for user_b
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_b.id))

    def test_has_valid_human_approval_rejects_outdated_revision(self):
        """When a new packet revision is created, approval for revision 1 returns False."""
        app, packet_v1, _ = self._create_and_approve_packet(self.user_a.id)
        self.assertTrue(self.db.has_valid_human_approval(app.id))

        # Create revision 2
        res_gen = UniversalTailoredResumeGenerator()
        tailored_res = res_gen.generate(self.user_a.id, self.profile_a, {"company_name": "Nexus", "role_title": "Arch v2"})
        cl_gen = CoverLetterGenerator()
        cl = cl_gen.generate_universal_cover_letter(self.user_a.id, self.profile_a, {"company_name": "Nexus", "role_title": "Arch v2"})
        qa = QuestionAnswerer()
        qs = qa.batch_answer_questions(["Years?"], user_id=self.user_a.id, candidate_profile=self.profile_a)
        for q in qs:
            q.state = "USER_APPROVED"
        qa_packet = ScreeningQAPacket(self.user_a.id, self.jd_a.id, qs)

        packet_v2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored_res,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.content_hash,
            template_id="modern",
        )
        self.assertEqual(packet_v2.version_num, 2)

        # has_valid_human_approval must now return False because active revision has changed
        self.assertFalse(self.db.has_valid_human_approval(app.id))
        self.assertFalse(
            self.db.has_valid_human_approval(app.id, expected_packet_hash=packet_v1.packet_version_hash)
        )

    def test_modern_application_does_not_fall_back_to_legacy_logs(self):
        """If an application uses prepared packets, it must never fall back to legacy logs."""
        app, packet, _ = self._create_and_approve_packet(self.user_a.id)

        # Delete from application_approvals
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM application_approvals WHERE application_id = ?", (app.id,))

        # Inject legacy approval into application_logs
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO application_logs (application_id, user_id, action, details) VALUES (?, ?, 'HUMAN_APPROVAL_GRANTED', ?)",
                (app.id, self.user_a.id, json.dumps({"packet_version_hash": packet.packet_version_hash})),
            )

        # Must return False because modern application has prepared_packets and requires table approval
        self.assertFalse(self.db.has_valid_human_approval(app.id))


if __name__ == "__main__":
    unittest.main()

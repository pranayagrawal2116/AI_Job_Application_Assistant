"""Comprehensive Security Regression Test Suite for Phase 8.

Phase 8 — Human Approval Gate & Persistent Nonces:
1. Deliverable A: Comprehensive 11-Element Packet Verification
2. Deliverable B: Single-Use HMAC Action Tickets
3. Deliverable C: HMAC Key Rotation (Graceful Mode A & Emergency Mode B)
4. Deliverable D: Persistent SQLite Nonce Consumption & Concurrency
5. Deliverable E: Post-Approval Invalidation on Content / Material Changes
6. Deliverable F: Strict Protection Against Autonomous / Unapproved Submission
7. Failure Injection & Transaction Atomicity
"""

import concurrent.futures
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    SecurityAuthorizationError,
    TicketAlreadyConsumedError,
    UnconfirmedSubmissionError,
    ValidationError,
)
from src.database.models import ApplicationStatus, SubmissionChannel
from src.lifecycle.state_machine import ApplicationStateMachine
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetter, CoverLetterGenerator
from src.preparer.question_answerer import QuestionAnswerer, ScreeningQAPacket
from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
from src.security.auth import AuthManager
from src.security.session_manager import KeyRotationManager, SessionManager
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash


class Phase8TestBase(unittest.TestCase):
    """Base setup for Phase 8 security tests."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "phase8_security.db"
        self.user_base_dir = Path(self.temp_dir.name) / "users"
        self.user_base_dir.mkdir(parents=True, exist_ok=True)

        SessionManager.reset_instance()
        self.session_mgr = SessionManager()
        self.db = DatabaseManager(db_path=self.db_path, session_manager=self.session_mgr)
        self.auth = AuthManager(db_manager=self.db)
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)
        self.service = DashboardService(db_manager=self.db)
        self.service.session_manager = self.session_mgr

        # Create two isolated test users
        self.user_a = self.auth.register("alice@example.com", "Password123!", "Alice Candidate")
        self.user_b = self.auth.register("bob@example.com", "Password123!", "Bob Candidate")

        # Authenticate sessions
        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="alice_cand", candidate_name="Alice Candidate", user_id=self.user_a.id
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="bob_cand", candidate_name="Bob Candidate", user_id=self.user_b.id
        )

        # Upload a valid resume for Alice
        pdf_stream = io.BytesIO()
        p_doc = SimpleDocTemplate(pdf_stream, pagesize=letter)
        p_doc.build([Paragraph("Alice Candidate Resume - ML Engineer with Python", getSampleStyleSheet()["Normal"])])
        self.valid_resume_bytes = pdf_stream.getvalue()

        self.resume_a = self.db.upload_user_resume(
            user_id=self.user_a.id,
            file_bytes=self.valid_resume_bytes,
            original_filename="alice_resume.pdf",
            user_base_dir=self.user_base_dir,
        )

        # Create a Job Description for Alice
        self.jd_a = self.db.create_job_description(
            user_id=self.user_a.id,
            company_name="Apex AI Labs",
            job_title="Lead AI Engineer",
            raw_content="Looking for a Lead AI Engineer with Python, PyTorch, and NLP experience.",
            parsed_data={"required_skills": ["Python", "PyTorch", "NLP"]},
        )

        # Candidate profile for Alice
        self.profile_a = {
            "personal": {"full_name": "Alice Candidate", "email": "alice@example.com"},
            "work_experience": [
                {
                    "employer": "TechCorp",
                    "job_title": "Senior ML Engineer",
                    "duration": "3 years",
                    "responsibilities": ["Built transformer models"],
                }
            ],
            "skills": ["Python", "PyTorch", "NLP"],
            "education": [{"institution": "MIT", "degree": "BS Computer Science"}],
        }
        self.db.save_user_candidate_profile(self.user_a.id, self.profile_a)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _generate_test_materials(self, user_id: int):
        """Generates real universal packet materials."""
        res_gen = UniversalTailoredResumeGenerator()
        tailored_res = res_gen.generate(
            user_id=user_id,
            candidate_profile=self.profile_a,
            job_description={"company_name": "Apex AI Labs", "role_title": "Lead AI Engineer"},
        )
        cl_gen = CoverLetterGenerator()
        cover_letter = cl_gen.generate_universal_cover_letter(
            user_id=user_id,
            candidate_profile=self.profile_a,
            job_description={"company_name": "Apex AI Labs", "role_title": "Lead AI Engineer"},
        )
        qa = QuestionAnswerer()
        qs = qa.batch_answer_questions(
            ["What is your experience with PyTorch?"], user_id=user_id, candidate_profile=self.profile_a
        )
        for q in qs:
            q.state = "USER_APPROVED"
        qa_packet = ScreeningQAPacket(user_id=user_id, job_description_id=self.jd_a.id, questions=qs)
        return tailored_res, cover_letter, qa_packet

    def _create_full_universal_packet(self, user_id: int):
        """Creates an application workspace and a genuine prepared packet revision 1."""
        app = self.db.get_or_create_application_workspace(
            user_id=user_id,
            job_description_id=self.jd_a.id,
            resume_id=self.resume_a["id"],
        )
        tailored_res, cover_letter, qa_packet = self._generate_test_materials(user_id)
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
        return app, packet


class TestPhase8PacketIntegrity(Phase8TestBase):
    """Tests comprehensive 11-element packet verification."""

    def test_valid_packet_passes_all_11_elements(self):
        """Genuine universal packet satisfies all 11 integrity elements and authorizes successfully."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        # 1. Independent packet integrity check
        valid, msg, loaded_pkt = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id,
            user_id=self.user_a.id,
            expected_application_id=app.id,
        )
        self.assertTrue(valid, f"Packet integrity verification failed: {msg}")
        self.assertIsNotNone(loaded_pkt)

        # 2. Issue ticket and authorize
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )

        success, auth_msg, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(success, f"Approval authorization failed: {auth_msg}")
        self.assertIsNotNone(approval)
        self.assertEqual(approval.packet_version_hash, packet.packet_version_hash)

    def test_missing_canonical_snapshot_fails(self):
        """Packet with missing or NULL canonical snapshot fails Element 6."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        with self.db.transaction() as conn:
            conn.execute("UPDATE prepared_packets SET canonical_snapshot_json = NULL WHERE id = ?", (packet.id,))

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("Legacy packet record", msg)

    def test_unparseable_corrupt_json_snapshot_fails(self):
        """Packet with corrupted / non-JSON string snapshot fails Element 6."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = '{corrupt_json: invalid' WHERE id = ?",
                (packet.id,),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("corrupt or unparseable", msg)

    def test_non_dict_json_snapshot_fails(self):
        """Packet with JSON array or scalar fails Element 6."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        with self.db.transaction() as conn:
            conn.execute("UPDATE prepared_packets SET canonical_snapshot_json = '[1, 2, 3]' WHERE id = ?", (packet.id,))

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("must be a dictionary object", msg)

    def test_snapshot_identity_mismatch_fails(self):
        """Snapshot where user_id or application_id does not match packet fails Element 6."""
        app, packet = self._create_full_universal_packet(self.user_a.id)
        raw_snap = json.loads(packet.canonical_snapshot_json)
        raw_snap["user_id"] = 9999
        new_bytes = canonical_json_bytes(raw_snap)
        new_hash = canonical_json_hash(raw_snap)

        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = ?, packet_version_hash = ? WHERE id = ?",
                (new_bytes.decode("utf-8"), new_hash, packet.id),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("Snapshot internal identifiers do not match", msg)

    def test_tampered_packet_content_fails_sha256_equality(self):
        """Packet with tampered canonical snapshot fails Element 7 SHA-256 equality."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        # Alter a single character in canonical snapshot without updating stored hash
        tampered_json = packet.canonical_snapshot_json.replace("Apex AI Labs", "Apex Tampered Labs")
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = ? WHERE id = ?",
                (tampered_json, packet.id),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("Possible tampering detected", msg)

    def test_rfc8785_canonical_formatting_deviation_fails(self):
        """Canonical snapshot with non-RFC 8785 whitespace / formatting fails Element 7."""
        app, packet = self._create_full_universal_packet(self.user_a.id)
        raw_snap = json.loads(packet.canonical_snapshot_json)
        # Formatted with 4 spaces instead of RFC 8785 compact delimiters
        spaced_json = json.dumps(raw_snap, indent=4)
        spaced_hash = hashlib.sha256(spaced_json.encode("utf-8")).hexdigest()

        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = ?, packet_version_hash = ? WHERE id = ?",
                (spaced_json, spaced_hash, packet.id),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("deviates from RFC 8785 canonical formatting", msg)

    def test_inactive_historical_revision_fails(self):
        """Outdated historical revision (is_active_revision == 0) fails Element 5."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        with self.db.transaction() as conn:
            conn.execute("UPDATE prepared_packets SET is_active_revision = 0 WHERE id = ?", (packet.id,))

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("outdated historical revision", msg)

    def test_cross_user_packet_fails(self):
        """User B cannot verify or authorize User A's packet (Elements 1, 2, 3)."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_b.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertTrue("not found" in msg.lower() or "cross-user" in msg.lower() or "belongs to user" in msg.lower())

    def test_source_resume_hash_tampered_fails(self):
        """If source resume file hash in DB changes after packet creation, Element 8 fails."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE resumes SET file_hash = 'altered_hash_xyz' WHERE id = ?",
                (self.resume_a["id"],),
            )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("Original source resume file hash has changed", msg)

    def test_source_resume_inactive_fails(self):
        """If source resume is archived/deleted (is_active = 0), Element 8 fails."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        with self.db.transaction() as conn:
            conn.execute("UPDATE resumes SET is_active = 0 WHERE id = ?", (self.resume_a["id"],))

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("is inactive or deleted", msg)

    def test_job_description_inactive_fails(self):
        """If job description is archived/inactive, Element 9 fails."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        with self.db.transaction() as conn:
            conn.execute("UPDATE job_descriptions SET is_active = 0 WHERE id = ?", (self.jd_a.id,))

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("is inactive or archived", msg)

    def test_screening_qa_unanswered_question_fails(self):
        """Screening question with NEEDS_CANDIDATE_INPUT fails Element 10."""
        app = self.db.get_or_create_application_workspace(
            user_id=self.user_a.id, job_description_id=self.jd_a.id, resume_id=self.resume_a["id"]
        )
        tailored_res, cover_letter, qa_packet = self._generate_test_materials(self.user_a.id)
        # Mark question as needing input
        qa_packet.questions[0].state = "NEEDS_CANDIDATE_INPUT"

        packet = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored_res,
            cover_letter=cover_letter,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.content_hash,
        )

        valid, msg, _ = self.gate.verify_prepared_packet_integrity(
            packet_id=packet.id, user_id=self.user_a.id, expected_application_id=app.id
        )
        self.assertFalse(valid)
        self.assertIn("requires candidate input before authorization", msg)


class TestPhase8ActionTickets(Phase8TestBase):
    """Tests single-use HMAC action tickets and scope validation."""

    def test_valid_ticket_authorization_succeeds(self):
        """Cryptographically signed HMAC ticket authorizes approval."""
        app, packet = self._create_full_universal_packet(self.user_a.id)
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        success, msg, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(success, f"Authorization failed: {msg}")
        self.assertIsNotNone(approval)

    def test_malformed_ticket_structure_fails(self):
        """Ticket with missing segments fails parsing."""
        app, packet = self._create_full_universal_packet(self.user_a.id)
        malformed = "bad_ticket_without_enough_delimiters"
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=malformed,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertTrue("malformed" in msg.lower() or "invalid" in msg.lower())

    def test_tampered_signature_fails(self):
        """Ticket with forged / tampered HMAC signature is rejected."""
        app, packet = self._create_full_universal_packet(self.user_a.id)
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        parts = ticket.split(".")
        forged_sig = "a" * 64
        forged_ticket = f"{parts[0]}.{parts[1]}.{forged_sig}"

        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=forged_ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertTrue("signature mismatch" in msg.lower() or "forgery" in msg.lower())

    def test_expired_ticket_fails(self):
        """Ticket past TTL fails validation."""
        app, packet = self._create_full_universal_packet(self.user_a.id)
        # Issue ticket with negative TTL (expired)
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
            ttl_seconds=-10,
        )
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("expired", msg.lower())

    def test_wrong_action_type_ticket_fails(self):
        """Ticket issued for MANUAL_SUBMISSION cannot authorize HUMAN_APPROVAL."""
        app, packet = self._create_full_universal_packet(self.user_a.id)
        sub_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=sub_ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertTrue("scope mismatch" in msg.lower() or "action type" in msg.lower())

    def test_wrong_application_id_ticket_fails(self):
        """Ticket issued for App #1 cannot authorize App #2."""
        app1, packet1 = self._create_full_universal_packet(self.user_a.id)
        ticket_app1 = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app1.id,
            packet_id=packet1.id,
            packet_hash=packet1.packet_version_hash,
        )
        # Attempt to authorize different application ID
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=9999,
            packet_id=packet1.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket_app1,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)

    def test_wrong_packet_hash_ticket_fails(self):
        """Ticket issued for hash A cannot authorize hash B."""
        app, packet = self._create_full_universal_packet(self.user_a.id)
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash="b" * 64,
        )
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertTrue("version mismatch" in msg.lower() or "packet hash" in msg.lower())

    def test_ticket_replay_fails(self):
        """A consumed ticket cannot be reused for a second authorization."""
        app, packet = self._create_full_universal_packet(self.user_a.id)
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        # First use succeeds
        succ1, _, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ1)

        # Second use with same ticket fails
        succ2, msg2, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ2)
        self.assertIn("already been used", msg2)


class TestPhase8KeyRotation(Phase8TestBase):
    """Tests Mode A (Graceful) and Mode B (Emergency) HMAC key rotation."""

    def test_graceful_key_rotation_overlap_window(self):
        """Mode A (Graceful): Retired key remains valid during overlap window, fails after expiry."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        # Issue ticket with active key v1
        ticket_v1 = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        self.assertTrue(ticket_v1.startswith("TKT-v1-"))

        # Rotate to v2 gracefully with 5-second overlap window
        new_secret = "b" * 64
        self.session_mgr.rotate_keys(
            new_key_id="v2",
            new_secret=new_secret,
            mode=KeyRotationManager.MODE_GRACEFUL,
            overlap_window_seconds=5,
        )

        # New ticket must use v2
        ticket_v2 = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        self.assertTrue(ticket_v2.startswith("TKT-v2-"))

        # Ticket signed with v1 is still valid within overlap window
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket_v1,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Ticket v1 failed during overlap window: {msg}")

        # Now simulate expiration of overlap window
        self.session_mgr.key_rotation_mgr._retired_keys["v1"] = (
            self.session_mgr.key_rotation_mgr._retired_keys["v1"][0],
            time.time() - 1,  # Expired
        )
        # Re-issuing another v1 ticket to test after expiry
        ticket_v1_stale = f"TKT-v1-nonce1234.{int(time.time())}.{'a'*64}"
        succ_exp, msg_exp, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket_v1_stale,
            candidate_confirmed=True,
        )
        self.assertFalse(succ_exp)
        self.assertTrue("revoked" in msg_exp.lower() or "retired" in msg_exp.lower() or "expired" in msg_exp.lower())

    def test_emergency_key_rotation_immediate_revocation(self):
        """Mode B (Emergency): Compromised key is revoked immediately, grants and tickets purged."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        # Issue ticket with active key v1
        ticket_v1 = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )

        # Emergency rotation immediately revoking v1
        new_secret = "c" * 64
        self.session_mgr.rotate_keys(
            new_key_id="v2",
            new_secret=new_secret,
            mode=KeyRotationManager.MODE_EMERGENCY,
        )

        # Attempt to authorize using ticket v1 immediately fails
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket_v1,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertTrue("revoked" in msg.lower())

        # Fresh ticket under active key v2 succeeds
        ticket_v2 = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        succ2, msg2, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket_v2,
            candidate_confirmed=True,
        )
        self.assertTrue(succ2, f"Ticket v2 authorization failed: {msg2}")
        self.assertIsNotNone(approval)


class TestPhase8PersistentNonces(Phase8TestBase):
    """Tests SQLite-backed persistent nonces and concurrent single-use consumption."""

    def test_normal_single_use_consumption(self):
        """Normal first consumption records nonce in SQLite consumed_action_nonces."""
        nonce = "test_nonce_abcdef123456"
        self.db.consume_action_nonce_persistently(
            ticket_nonce=nonce,
            key_id="v1",
            user_id=self.user_a.id,
            action_type="HUMAN_APPROVAL",
        )
        # Duplicate consumption must raise TicketAlreadyConsumedError
        with self.assertRaises(TicketAlreadyConsumedError):
            self.db.consume_action_nonce_persistently(
                ticket_nonce=nonce,
                key_id="v1",
                user_id=self.user_a.id,
                action_type="HUMAN_APPROVAL",
            )

    def test_invalid_nonce_format_rejected(self):
        """Nonces with invalid lengths or non-hex characters fail validation."""
        # Nonce too short (< 8 chars)
        with self.assertRaises(ValidationError):
            self.db.consume_action_nonce_persistently(
                ticket_nonce="short",
                key_id="v1",
                user_id=self.user_a.id,
                action_type="HUMAN_APPROVAL",
            )
        # Nonce with invalid characters (non-hex, non-alphanumeric)
        with self.assertRaises(ValidationError):
            self.db.consume_action_nonce_persistently(
                ticket_nonce="invalid_nonce!@#$%^&*",
                key_id="v1",
                user_id=self.user_a.id,
                action_type="HUMAN_APPROVAL",
            )

    def test_concurrent_duplicate_consumption_multithreaded(self):
        """For N concurrent attempts to consume the same nonce across separate DB connections, exactly 1 succeeds."""
        target_nonce = "concurrent_nonce_0123456789abcdef"
        success_count = 0
        failure_count = 0

        def attempt_consumption(conn_index: int):
            local_db = DatabaseManager(db_path=self.db_path)
            try:
                local_db.consume_action_nonce_persistently(
                    ticket_nonce=target_nonce,
                    key_id="v1",
                    user_id=self.user_a.id,
                    action_type="HUMAN_APPROVAL",
                )
                return True
            except TicketAlreadyConsumedError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(attempt_consumption, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        success_count = sum(1 for r in results if r is True)
        failure_count = sum(1 for r in results if r is False)

        self.assertEqual(success_count, 1, "Exactly one concurrent attempt must succeed.")
        self.assertEqual(failure_count, 9, "All 9 duplicate concurrent attempts must fail.")

    def test_replay_prevention_across_fresh_session_manager_instances(self):
        """Simulated process restart / fresh SessionManager instance respects SQLite persistent nonces."""
        nonce = "persistent_cross_instance_nonce_1234"
        self.db.consume_action_nonce_persistently(
            ticket_nonce=nonce,
            key_id="v1",
            user_id=self.user_a.id,
            action_type="HUMAN_APPROVAL",
        )

        # Fresh SessionManager instance with empty in-memory state
        fresh_sm = SessionManager()
        self.assertEqual(len(fresh_sm._sessions), 0)

        # Attempt to consume the same nonce against fresh manager
        with self.assertRaises(TicketAlreadyConsumedError):
            self.db.consume_action_nonce_persistently(
                ticket_nonce=nonce,
                key_id="v1",
                user_id=self.user_a.id,
                action_type="HUMAN_APPROVAL",
            )


class TestPhase8PostApprovalInvalidation(Phase8TestBase):
    """Tests that modifying any constituent material invalidates prior approvals."""

    def test_resume_edit_creates_new_revision_and_invalidates_approval(self):
        """Editing resume creates revision 2, deactivating revision 1 and invalidating old approval."""
        app, packet1 = self._create_full_universal_packet(self.user_a.id)

        # 1. Authorize revision 1
        ticket1 = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet1.id,
            packet_hash=packet1.packet_version_hash,
        )
        succ, _, approval1 = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet1.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket1,
            candidate_confirmed=True,
        )
        self.assertTrue(succ)
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_a.id))

        # 2. Modify tailored resume content -> creates revision 2
        tailored_res2, cover_letter, qa_packet = self._generate_test_materials(self.user_a.id)
        tailored_res2.summary = "Updated AI Leadership Summary with Generative AI"
        packet2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored_res2,
            cover_letter=cover_letter,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.content_hash,
            template_id="modern",
        )
        self.assertEqual(packet2.version_num, 2)
        self.assertTrue(packet2.is_active_revision)

        # 3. Old revision is deactivated
        reloaded_pkt1 = self.db.get_prepared_packet(packet1.id, self.user_a.id)
        self.assertFalse(reloaded_pkt1.is_active_revision)

        # 4. Old approval record CANNOT authorize the active application / revision
        self.assertFalse(
            self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_a.id),
            "Application has an edited packet revision; old approval must not be valid for active revision.",
        )

        # 5. Old ticket cannot be used to submit revision 2
        with self.assertRaises(SecurityAuthorizationError):
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket1,  # old consumed approval ticket
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )

        # 6. Candidate must review and authorize revision 2 explicitly
        ticket2 = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet2.id,
            packet_hash=packet2.packet_version_hash,
        )
        succ2, msg2, approval2 = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet2.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket2,
            candidate_confirmed=True,
        )
        self.assertTrue(succ2, f"Failed authorizing revision 2: {msg2}")
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_a.id))

    def test_cover_letter_edit_invalidates_approval(self):
        """Editing cover letter creates revision 2 and invalidates old approval."""
        app, packet1 = self._create_full_universal_packet(self.user_a.id)
        ticket1 = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet1.id,
            packet_hash=packet1.packet_version_hash,
        )
        self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet1.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket1,
            candidate_confirmed=True,
        )
        self.assertTrue(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_a.id))

        # Edit cover letter text
        tailored_res, cover_letter2, qa_packet = self._generate_test_materials(self.user_a.id)
        cover_letter2.letter_text = "Completely updated cover letter body."
        packet2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored_res,
            cover_letter=cover_letter2,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.content_hash,
        )
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_a.id))


class TestPhase8AutonomousSubmissionPrevention(Phase8TestBase):
    """Tests strict human-in-the-loop protection against autonomous submissions."""

    def test_generic_state_transition_to_submitted_blocked(self):
        """Directly attempting to transition application status to SUBMITTED / Applied is blocked."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        # Attempting generic state machine transition to SUBMITTED raises SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError):
            self.db.transition_application_status(
                application_id=app.id,
                user_id=self.user_a.id,
                new_status="SUBMITTED",
            )

        with self.assertRaises(SecurityAuthorizationError):
            self.db.transition_application_status(
                application_id=app.id,
                user_id=self.user_a.id,
                new_status="Applied",
            )

    def test_unconfirmed_submission_rejected(self):
        """Candidate manual submission fails if candidate_confirmed=False."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        # Authorize packet
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )

        sub_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )

        with self.assertRaises(UnconfirmedSubmissionError):
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=sub_ticket,
                candidate_confirmed=False,  # Unconfirmed checkbox
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )

    def test_submission_without_human_approval_rejected(self):
        """Attempting manual submission on unapproved application fails."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        sub_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )

        with self.assertRaises(SecurityAuthorizationError):
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=sub_ticket,
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )

    def test_valid_manual_submission_workflow_succeeds_and_consumes_approval(self):
        """Candidate confirmation workflow atomically transitions to SUBMITTED and consumes approval."""
        app, packet = self._create_full_universal_packet(self.user_a.id)

        # 1. Human approval
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )
        self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )

        # 2. Manual submission
        sub_ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=app.id,
            packet_hash=packet.packet_version_hash,
        )

        conf = self.service.record_candidate_manual_submission(
            application_id=app.id,
            session_id=self.session_a.session_id,
            submission_ticket=sub_ticket,
            candidate_confirmed=True,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            confirmation_reference="REF-CONF-12345",
        )
        self.assertIsNotNone(conf)
        self.assertEqual(conf.application_id, app.id)

        # Check application status updated to SUBMITTED
        updated_app = self.db.get_user_application(app.id, self.user_a.id)
        self.assertEqual(updated_app.status, "SUBMITTED")

        # Approval is consumed, cannot be reused for second submission
        self.assertFalse(self.db.has_valid_human_approval(application_id=app.id, user_id=self.user_a.id))


class TestPhase8TransactionAtomicityAndFailureInjection(Phase8TestBase):
    """Tests atomic rollback under injected database failures."""

    def test_failure_injection_approval_record_insert(self):
        """Failure during approval record insert causes complete rollback, leaving ticket burned."""
        app, packet = self._create_full_universal_packet(self.user_a.id)
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=packet.packet_version_hash,
        )

        # Inject failure using SQLite trigger on application_approvals
        with self.db.transaction() as conn:
            conn.execute(
                "CREATE TRIGGER fail_app_approval BEFORE INSERT ON application_approvals "
                "BEGIN SELECT RAISE(ABORT, 'Simulated DB failure on approvals INSERT'); END;"
            )

        try:
            succ, msg, _ = self.gate.authorize_universal_packet(
                user_id=self.user_a.id,
                application_id=app.id,
                packet_id=packet.id,
                approver_name="Alice Candidate",
                session_id=self.session_a.session_id,
                action_ticket=ticket,
                candidate_confirmed=True,
            )
            self.assertFalse(succ)
            self.assertIn("Simulated DB failure", msg)
        finally:
            with self.db.transaction() as conn:
                conn.execute("DROP TRIGGER IF EXISTS fail_app_approval")

        # Check no partial record was inserted
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            count = cursor.fetchone()[0]
            self.assertEqual(count, 0)

        # Check ticket was consumed in memory and cannot be replayed
        succ_replay, msg_replay, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ_replay)
        self.assertIn("already been used", msg_replay)


if __name__ == "__main__":
    unittest.main()

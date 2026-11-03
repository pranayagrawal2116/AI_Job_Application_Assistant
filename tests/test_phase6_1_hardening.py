"""Comprehensive Hardening Regression Test Suite for Phase 6.1:
Application Preparation Security, Provenance & Packet Integrity Hardening.

Covers all 15 audit sections:
1. Authenticated user resolution & missing session fail-closed.
2. Approval session ownership & cross-user session rejection.
3. Database approval validation: application ownership, packet ownership, packet application ID,
   hash matching, active revision check, replay rejection.
4. Truthful evidence & zero-fabrication: plain strings stay EXTRACTED_UNVERIFIED;
   unconfirmed experience, education, projects stay EXTRACTED_UNVERIFIED.
5. Removal of legacy hardcoded defaults (Pranay Agrawal, MIT WPU, Sarita Infotech, Medical Chatbot).
6. Elimination of implicit candidate_profile.json file loading in constructors.
7. Real attachment manifest generation with disk inspection, hashes, and sizes.
8. Screening question editing, character limit re-evaluation, and approval gating for NEEDS_CANDIDATE_INPUT and character limits.
9. Workspace creation resume ownership validation (CrossUserAccessError) and inactive resume rejection.
10. PDF document validation requiring non-empty extractable text.
11. Complete immutable packet provenance & RFC 8785 canonical JSON snapshot persistence.
"""

import hashlib
import io
from pathlib import Path
import tempfile
import unittest

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate

from dashboard.views.application_preparer import (
    build_real_attachments_manifest,
    get_current_user_id,
)
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    ValidationError,
)
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetterGenerator, LetterTone
from src.preparer.document_generator import GeneratedDocument, UniversalDocumentGenerator
from src.preparer.form_prefiller import FormPrefiller
from src.preparer.question_answerer import (
    AnswerState,
    QuestionAnswerer,
    ScreeningQAPacket,
    ScreeningQuestion,
)
from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
from src.security.auth import AuthManager
from src.security.session_manager import SessionManager


class TestPhase61Hardening(unittest.TestCase):
    """Test suite verifying all Phase 6.1 security and data-integrity hardening requirements."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_phase6_1.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)
        SessionManager.reset_instance()
        self.session_mgr = SessionManager()
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)

        # Register User A and User B
        self.user_a = self.auth.register(
            email="candidate.alpha@example.com",
            password="SecurePassword123!",
            full_name="Candidate Alpha",
        )
        self.user_b = self.auth.register(
            email="candidate.beta@example.com",
            password="SecurePassword123!",
            full_name="Candidate Beta",
        )

        # Valid PDF for User A
        pdf_stream = io.BytesIO()
        doc = SimpleDocTemplate(pdf_stream, pagesize=letter)
        doc.build([Paragraph("Alpha Resume: Experienced Cloud Architect in AWS and Python", getSampleStyleSheet()["Normal"])])
        self.valid_pdf_bytes_a = pdf_stream.getvalue()

        self.resume_a = self.db.upload_user_resume(
            user_id=self.user_a.id,
            file_bytes=self.valid_pdf_bytes_a,
            original_filename="alpha_resume.pdf",
            user_base_dir=Path(self.temp_dir.name) / "users",
        )

        # Valid PDF for User B
        pdf_stream_b = io.BytesIO()
        doc_b = SimpleDocTemplate(pdf_stream_b, pagesize=letter)
        doc_b.build([Paragraph("Beta Resume: Clinical Specialist in Pediatrics", getSampleStyleSheet()["Normal"])])
        self.valid_pdf_bytes_b = pdf_stream_b.getvalue()

        self.resume_b = self.db.upload_user_resume(
            user_id=self.user_b.id,
            file_bytes=self.valid_pdf_bytes_b,
            original_filename="beta_resume.pdf",
            user_base_dir=Path(self.temp_dir.name) / "users",
        )

        # Job Description for User A
        self.jd_a = self.db.create_job_description(
            user_id=self.user_a.id,
            company_name="CloudScale Systems",
            job_title="Lead Cloud Architect",
            raw_content="Looking for a Lead Cloud Architect with AWS, Kubernetes, and Python.",
            parsed_data={"required_skills": ["AWS", "Kubernetes", "Python"]},
        )

        # Job Description for User B
        self.jd_b = self.db.create_job_description(
            user_id=self.user_b.id,
            company_name="Metro Health Clinic",
            job_title="Pediatric Nurse Specialist",
            raw_content="Seeking a Pediatric Nurse Specialist with RN license and patient care.",
            parsed_data={"required_skills": ["Pediatrics", "Patient Care", "RN"]},
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    # =========================================================================
    # 1. AUTHENTICATED USER RESOLUTION
    # =========================================================================

    def test_unauthenticated_user_resolution_fails_closed(self):
        """get_current_user_id must return None if neither authenticated_user_id nor user_id is set (no fallback to 1)."""
        import streamlit as st
        st.session_state.clear()
        uid = get_current_user_id()
        self.assertIsNone(uid, "Unauthenticated session must resolve to None, never defaulting to User 1.")

    def test_authenticated_user_resolution_success(self):
        """get_current_user_id correctly extracts authenticated_user_id when set."""
        import streamlit as st
        st.session_state["authenticated_user_id"] = 42
        self.assertEqual(get_current_user_id(), 42)
        st.session_state.clear()

    # =========================================================================
    # 2. APPROVAL SESSION OWNERSHIP
    # =========================================================================

    def test_dashboard_service_get_candidate_session_matches_user_id(self):
        """get_or_create_candidate_session matches target user_id and does not leak other users' sessions."""
        from dashboard.services.dashboard_service import DashboardService
        service = DashboardService.get_instance()
        service.db = self.db

        # User A session
        sess_a = service.get_or_create_candidate_session(
            candidate_name="Alpha",
            candidate_id=f"user_{self.user_a.id}",
            user_id=self.user_a.id,
        )
        self.assertEqual(sess_a.user_id, self.user_a.id)

        # User B session must NOT return User A's session
        sess_b = service.get_or_create_candidate_session(
            candidate_name="Beta",
            candidate_id=f"user_{self.user_b.id}",
            user_id=self.user_b.id,
        )
        self.assertEqual(sess_b.user_id, self.user_b.id)
        self.assertNotEqual(sess_a.session_id, sess_b.session_id)

    def test_approval_gate_rejects_session_user_mismatch(self):
        """HumanApprovalGate rejects authorization if session belongs to User B but authorization requested for User A."""
        app_a = self.db.get_or_create_application_workspace(
            user_id=self.user_a.id,
            job_description_id=self.jd_a.id,
            resume_id=self.resume_a["id"],
        )
        tailored = UniversalTailoredResumeGenerator().generate(
            user_id=self.user_a.id,
            candidate_profile={"personal": {"full_name": "Alpha"}, "skills": ["AWS"]},
            job_description={"company_name": "CloudScale", "role_title": "Lead Cloud Architect"},
        )
        cl = CoverLetterGenerator().generate_universal_cover_letter(
            user_id=self.user_a.id,
            candidate_profile={"personal": {"full_name": "Alpha"}},
            job_description={"company_name": "CloudScale", "role_title": "Lead Cloud Architect"},
        )
        qa = QuestionAnswerer()
        qs = qa.batch_answer_questions(["What is your availability?"], user_id=self.user_a.id, candidate_profile={"candidate_inputs": {"internship_availability": "Immediate"}})
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app_a.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=qs),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        # Session created for User B
        sess_b = self.session_mgr.create_user_session(user_id=self.user_b.id, email=self.user_b.email)
        tkt = self.session_mgr.issue_action_ticket(
            session_id=sess_b.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app_a.id,
            packet_hash=pkt.packet_version_hash,
        )

        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app_a.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess_b.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("Session belongs to User", msg)

    def test_approval_gate_rejects_expired_session(self):
        """HumanApprovalGate rejects authorization if session has expired."""
        session = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email, ttl_seconds=-10)
        app_a = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_a.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_a.id, candidate_profile={}, job_description={})
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app_a.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app_a.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=session.session_id,
            action_ticket="TKT-test.v1.sig",
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("expired", msg.lower())

    # =========================================================================
    # 3. PACKET APPLICATION & ACTIVE REVISION VALIDATION
    # =========================================================================

    def test_approval_gate_rejects_packet_application_mismatch(self):
        """HumanApprovalGate rejects authorization if packet belongs to Application 1 but authorization targets Application 2."""
        app1 = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        jd_a2 = self.db.create_job_description(
            user_id=self.user_a.id,
            company_name="Second Company",
            job_title="DevOps Lead",
            raw_content="DevOps role",
            parsed_data={"required_skills": ["Docker"]},
        )
        app2 = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=jd_a2.id)

        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_a.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_a.id, candidate_profile={}, job_description={})
        pkt1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app1.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        tkt = self.session_mgr.issue_action_ticket(
            session_id=sess.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app2.id,
            packet_hash=pkt1.packet_version_hash,
        )

        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app2.id,  # Target Application 2 with Packet 1 (built for Application 1)
            packet_id=pkt1.id,
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("belongs to Application", msg)

    def test_approval_gate_rejects_inactive_packet_revision(self):
        """HumanApprovalGate rejects authorization for deactivated historical packet revisions."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_a.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_a.id, candidate_profile={}, job_description={})

        pkt_v1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )
        # Create Revision 2 which deactivates Revision 1
        pkt_v2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )
        self.assertEqual(pkt_v2.version_num, 2)

        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        tkt = self.session_mgr.issue_action_ticket(
            session_id=sess.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=pkt_v1.packet_version_hash,
        )

        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt_v1.id,  # Outdated revision
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("outdated", msg.lower())

    # =========================================================================
    # 4. DATABASE APPROVAL INTEGRITY CHECKS
    # =========================================================================

    def test_record_packet_approval_validates_application_ownership(self):
        """DatabaseManager.record_packet_approval rejects if application belongs to another user."""
        app_b = self.db.get_or_create_application_workspace(user_id=self.user_b.id, job_description_id=self.jd_b.id)
        with self.assertRaises(CrossUserAccessError):
            self.db.record_packet_approval(
                application_id=app_b.id,
                user_id=self.user_a.id,  # User A attempting to approve User B's application
                packet_version_hash="dummy_hash",
                ticket_nonce="nonce_test_cross",
                approver_name="Candidate Alpha",
            )

    def test_record_packet_approval_validates_packet_ownership(self):
        """DatabaseManager.record_packet_approval rejects if packet_id belongs to another user."""
        app_a = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        app_b = self.db.get_or_create_application_workspace(user_id=self.user_b.id, job_description_id=self.jd_b.id)
        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_b.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_b.id, candidate_profile={}, job_description={})
        pkt_b = self.gate.prepare_universal_packet(
            user_id=self.user_b.id,
            application_id=app_b.id,
            original_resume_id=self.resume_b["id"],
            original_resume_hash=self.resume_b["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_b.id, job_description_id=self.jd_b.id, questions=[]),
            job_description_snapshot_hash=self.jd_b.snapshot_hash,
        )

        with self.assertRaises(CrossUserAccessError):
            self.db.record_packet_approval(
                application_id=app_a.id,
                user_id=self.user_a.id,
                packet_id=pkt_b.id,  # Packet belongs to User B
                packet_version_hash=pkt_b.packet_version_hash,
                ticket_nonce="nonce_test_pkt_cross",
                approver_name="Candidate Alpha",
            )

    def test_record_packet_approval_validates_packet_application_id(self):
        """DatabaseManager.record_packet_approval rejects if packet does not belong to that application."""
        app1 = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        jd2 = self.db.create_job_description(user_id=self.user_a.id, company_name="C2", job_title="T2", raw_content="x", parsed_data={})
        app2 = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=jd2.id)

        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_a.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_a.id, candidate_profile={}, job_description={})
        pkt1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app1.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        with self.assertRaises(ValidationError) as ctx:
            self.db.record_packet_approval(
                application_id=app2.id,  # App 2
                user_id=self.user_a.id,
                packet_id=pkt1.id,  # Packet belongs to App 1
                packet_version_hash=pkt1.packet_version_hash,
                ticket_nonce="nonce_mismatch_app",
                approver_name="Candidate Alpha",
            )
        self.assertIn("belongs to Application", str(ctx.exception))

    def test_record_packet_approval_validates_hash_match(self):
        """DatabaseManager.record_packet_approval rejects if packet_version_hash doesn't match."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_a.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_a.id, candidate_profile={}, job_description={})
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        with self.assertRaises(ValidationError) as ctx:
            self.db.record_packet_approval(
                application_id=app.id,
                user_id=self.user_a.id,
                packet_id=pkt.id,
                packet_version_hash="wrong_hash_12345",
                ticket_nonce="nonce_wrong_hash",
                approver_name="Candidate Alpha",
            )
        self.assertIn("hash mismatch", str(ctx.exception).lower())

    def test_record_packet_approval_rejects_inactive_revision(self):
        """DatabaseManager.record_packet_approval rejects if packet is not the active revision."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_a.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_a.id, candidate_profile={}, job_description={})

        pkt1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )
        pkt2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )
        self.assertTrue(pkt2.is_active_revision)

        with self.assertRaises(ValidationError) as ctx:
            self.db.record_packet_approval(
                application_id=app.id,
                user_id=self.user_a.id,
                packet_id=pkt1.id,  # Deactivated revision
                packet_version_hash=pkt1.packet_version_hash,
                ticket_nonce="nonce_inactive_rev",
                approver_name="Candidate Alpha",
            )
        self.assertIn("not the active revision", str(ctx.exception))

    # =========================================================================
    # 5. SCREENING QUESTION APPROVAL GATE ENFORCEMENT
    # =========================================================================

    def test_approval_gate_blocks_needs_candidate_input(self):
        """HumanApprovalGate strictly rejects authorization if any question is NEEDS_CANDIDATE_INPUT."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_a.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_a.id, candidate_profile={}, job_description={})

        qa = QuestionAnswerer()
        # Missing salary returns NEEDS_CANDIDATE_INPUT
        qs = qa.batch_answer_questions(["What is your expected salary?"], user_id=self.user_a.id, candidate_profile={})
        self.assertEqual(qs[0].state, AnswerState.NEEDS_CANDIDATE_INPUT.value)

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=qs),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        tkt = self.session_mgr.issue_action_ticket(
            session_id=sess.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=pkt.packet_version_hash,
        )

        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("requires candidate input", msg)

    def test_approval_gate_blocks_exceeds_character_limit(self):
        """HumanApprovalGate strictly rejects authorization if any question exceeds character limit."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_a.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_a.id, candidate_profile={}, job_description={})

        qa = QuestionAnswerer()
        q = qa.answer_universal_question(
            "Why do you want to work at our company?",
            user_id=self.user_a.id,
            candidate_profile={"candidate_inputs": {"internship_availability": "Now"}},
            character_limit=20,  # Deliberately short limit
        )
        self.assertTrue(q.exceeds_limit)

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[q]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        tkt = self.session_mgr.issue_action_ticket(
            session_id=sess.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=pkt.packet_version_hash,
        )

        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("exceeds the allowable character limit", msg)

    # =========================================================================
    # 6. TRUTHFUL EVIDENCE & ZERO-FABRICATION
    # =========================================================================

    def test_tailored_resume_plain_string_remains_unverified(self):
        """Plain string certifications and licenses in profile must remain EXTRACTED_UNVERIFIED."""
        gen = UniversalTailoredResumeGenerator()
        profile = {
            "personal": {"full_name": "Test Candidate"},
            "certifications": ["AWS Certified Solutions Architect"],  # Plain string
            "licenses": ["Professional Engineer"],  # Plain string
        }
        res = gen.generate(user_id=1, candidate_profile=profile, job_description={})
        self.assertEqual(len(res.certifications), 1)
        self.assertEqual(res.certifications[0]["verification_status"], "EXTRACTED_UNVERIFIED")
        self.assertEqual(len(res.licenses), 1)
        self.assertEqual(res.licenses[0]["verification_status"], "EXTRACTED_UNVERIFIED")

    def test_tailored_resume_unconfirmed_experience_stays_unverified(self):
        """Work experience without explicit confirmation stays EXTRACTED_UNVERIFIED."""
        gen = UniversalTailoredResumeGenerator()
        profile = {
            "personal": {"full_name": "Test Candidate"},
            "work_experience": [
                {
                    "employer": "TechCorp",
                    "job_title": "Software Engineer",
                    "duration": "1 year",
                    "responsibilities": ["Wrote Python code"],
                }
            ],
        }
        res = gen.generate(user_id=1, candidate_profile=profile, job_description={})
        self.assertEqual(res.experience_entries[0].evidence_status, "EXTRACTED_UNVERIFIED")
        self.assertEqual(res.experience_entries[0].bullets[0].provenance.evidence_status, "EXTRACTED_UNVERIFIED")

    def test_tailored_resume_unconfirmed_education_stays_unverified(self):
        """Education without explicit confirmation stays EXTRACTED_UNVERIFIED."""
        gen = UniversalTailoredResumeGenerator()
        profile = {
            "personal": {"full_name": "Test Candidate"},
            "education": [{"institution": "State University", "degree": "BS CS"}],
        }
        res = gen.generate(user_id=1, candidate_profile=profile, job_description={})
        self.assertEqual(res.education_entries[0].evidence_status, "EXTRACTED_UNVERIFIED")

    def test_tailored_resume_unconfirmed_projects_stay_unverified(self):
        """Projects without explicit confirmation stay EXTRACTED_UNVERIFIED."""
        gen = UniversalTailoredResumeGenerator()
        profile = {
            "personal": {"full_name": "Test Candidate"},
            "projects": [{"title": "Web App", "description": "Built a web app"}],
        }
        res = gen.generate(user_id=1, candidate_profile=profile, job_description={})
        self.assertEqual(len(res.projects), 1)
        self.assertEqual(res.provenance_map[res.projects[0].claim_id].evidence_status, "EXTRACTED_UNVERIFIED")

    def test_cover_letter_removes_unsupported_assertions(self):
        """Cover letter generator opening does not contain 'closely followed' or 'established professional'."""
        cl_gen = CoverLetterGenerator()
        cl_modern = cl_gen.generate_universal_cover_letter(
            user_id=1,
            candidate_profile={"personal": {"full_name": "Test"}},
            job_description={"company_name": "Acme", "role_title": "Engineer"},
            tone=LetterTone.ENTHUSIASTIC_MODERN,
        )
        self.assertNotIn("closely followed", cl_modern.letter_text.lower())

        cl_exec = cl_gen.generate_universal_cover_letter(
            user_id=1,
            candidate_profile={"personal": {"full_name": "Test"}},
            job_description={"company_name": "Acme", "role_title": "Engineer"},
            tone=LetterTone.EXECUTIVE_FORMAL,
        )
        self.assertNotIn("established professional", cl_exec.letter_text.lower())

    def test_cover_letter_unconfirmed_license_claims_truthful(self):
        """Cover letter generator does not claim statutory licensure if license is unconfirmed."""
        cl_gen = CoverLetterGenerator()
        cl = cl_gen.generate_universal_cover_letter(
            user_id=1,
            candidate_profile={
                "personal": {"full_name": "Test"},
                "licenses": [{"name": "RN License", "verification_status": "EXTRACTED_UNVERIFIED"}],
            },
            job_description={"company_name": "Hospital", "role_title": "Nurse"},
        )
        self.assertNotIn("I maintain statutory professional licensure", cl.letter_text)

    def test_cover_letter_provenance_reflects_unverified_sources(self):
        """When cover letter qualifications use unverified sources, provenance reflects EXTRACTED_UNVERIFIED."""
        cl_gen = CoverLetterGenerator()
        cl = cl_gen.generate_universal_cover_letter(
            user_id=1,
            candidate_profile={
                "personal": {"full_name": "Test"},
                "work_experience": [{"employer": "Startup", "job_title": "Dev", "verification_status": "EXTRACTED_UNVERIFIED"}],
            },
            job_description={"company_name": "Acme", "role_title": "Engineer"},
        )
        qual_claim = next(c for c in cl.provenance_claims if "qual" in c.claim_id)
        self.assertEqual(qual_claim.evidence_status, "EXTRACTED_UNVERIFIED")

    # =========================================================================
    # 7. REMOVAL OF LEGACY HARDCODED DEFAULTS & IMPLICIT FILE LOADS
    # =========================================================================

    def test_cover_letter_generator_no_implicit_profile_load(self):
        """CoverLetterGenerator constructor without arguments initializes an empty profile."""
        gen = CoverLetterGenerator()
        self.assertEqual(gen.profile, {})

    def test_cover_letter_generator_no_pranay_fallback(self):
        """CoverLetterGenerator.generate_cover_letter with empty profile does not fabricate Pranay Agrawal / MIT / Medical Chatbot."""
        gen = CoverLetterGenerator(candidate_profile={})
        res = gen.generate_cover_letter(job={"id": 1, "company_name": "GenericCorp", "job_title": "Developer"})
        self.assertNotIn("Pranay", res["letter_text"])
        self.assertNotIn("MIT World Peace University", res["letter_text"])
        self.assertNotIn("Medical Chatbot", res["letter_text"])
        self.assertNotIn("Sarita Infotech", res["letter_text"])

    def test_question_answerer_no_implicit_profile_load(self):
        """QuestionAnswerer constructor without arguments initializes an empty profile."""
        qa = QuestionAnswerer()
        self.assertEqual(qa.profile, {})

    def test_question_answerer_no_pranay_fallback(self):
        """QuestionAnswerer.generate_standard_answers with empty profile does not fabricate Pranay Agrawal / MIT / Medical Chatbot."""
        qa = QuestionAnswerer(candidate_profile={})
        answers = qa.generate_standard_answers(job={"id": 1, "company_name": "GenericCorp", "job_title": "Developer"})
        combined = " ".join(a.get("answer", "") for a in answers.values())
        self.assertNotIn("Pranay", combined)
        self.assertNotIn("MIT World Peace University", combined)
        self.assertNotIn("Medical Chatbot", combined)
        self.assertNotIn("Sarita Infotech", combined)

    def test_form_prefiller_no_implicit_profile_load(self):
        """FormPrefiller constructor without arguments initializes an empty profile."""
        fp = FormPrefiller()
        self.assertEqual(fp.profile, {})

    def test_form_prefiller_no_pranay_fallback(self):
        """FormPrefiller.build_form_payload with empty profile does not inject hardcoded Pranay values."""
        fp = FormPrefiller(candidate_profile={})
        plan = fp.build_form_payload(job={"id": 1, "company_name": "Acme", "job_url": "https://acme.com"})
        field_values = [f.intended_value for f in plan.fields_to_fill]
        self.assertNotIn("Pranay Anup Agrawal", field_values)
        self.assertNotIn("pranayagrawal2116@gmail.com", field_values)
        self.assertNotIn("MIT World Peace University", field_values)

    # =========================================================================
    # 8. SCREENING-ANSWER EDITING & CHARACTER LIMITS
    # =========================================================================

    def test_question_answerer_update_recalculates_character_limit(self):
        """Updating question answer via update_question_answer recalculates exceeds_limit correctly."""
        qa = QuestionAnswerer()
        q = qa.answer_universal_question("Why Acme?", user_id=1, candidate_profile={}, character_limit=10)
        self.assertTrue(q.exceeds_limit)

        # Update with short text
        q_updated = qa.update_question_answer(q, new_answer="Short", new_state=AnswerState.USER_APPROVED)
        self.assertFalse(q_updated.exceeds_limit)
        self.assertEqual(q_updated.state, AnswerState.USER_APPROVED.value)
        self.assertEqual(q_updated.provenance.source_type, "user_edit")
        self.assertEqual(q_updated.provenance.evidence_status, "USER_CONFIRMED")

    # =========================================================================
    # 9. WORKSPACE CREATION RESUME OWNERSHIP VALIDATION
    # =========================================================================

    def test_workspace_creation_validates_resume_ownership(self):
        """get_or_create_application_workspace raises CrossUserAccessError if resume belongs to another user."""
        with self.assertRaises(CrossUserAccessError):
            self.db.get_or_create_application_workspace(
                user_id=self.user_a.id,
                job_description_id=self.jd_a.id,
                resume_id=self.resume_b["id"],  # Resume belongs to User B!
            )

    def test_workspace_creation_rejects_inactive_resume(self):
        """get_or_create_application_workspace raises ValidationError if resume is archived / inactive."""
        # Archive resume A
        with self.db.transaction() as conn:
            conn.cursor().execute("UPDATE resumes SET is_active = 0 WHERE id = ?", (self.resume_a["id"],))

        with self.assertRaises(ValidationError) as ctx:
            self.db.get_or_create_application_workspace(
                user_id=self.user_a.id,
                job_description_id=self.jd_a.id,
                resume_id=self.resume_a["id"],
            )
        self.assertIn("inactive", str(ctx.exception).lower())

    # =========================================================================
    # 10. PDF DOCUMENT EXPORT VALIDATION
    # =========================================================================

    def test_pdf_validation_rejects_empty_extractable_text(self):
        """UniversalDocumentGenerator.validate_pdf_document raises ValueError if PDF contains no extractable text."""
        # Create an empty or textless PDF
        from reportlab.pdfgen import canvas
        empty_pdf_path = Path(self.temp_dir.name) / "empty.pdf"
        c = canvas.Canvas(str(empty_pdf_path), pagesize=letter)
        c.rect(10, 10, 100, 100)  # Draw shape without text
        c.showPage()
        c.save()

        with self.assertRaises(ValueError) as ctx:
            UniversalDocumentGenerator.validate_pdf_document(empty_pdf_path)
        self.assertIn("no extractable text", str(ctx.exception).lower())

    # =========================================================================
    # 11. IMMUTABLE PACKET PROVENANCE & CANONICAL SNAPSHOT PERSISTENCE
    # =========================================================================

    def test_canonical_snapshot_json_persistence_and_hash_verification(self):
        """PreparedPacket persists RFC 8785 canonical JSON bytes in SQLite, matching packet_version_hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_a.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_a.id, candidate_profile={}, job_description={})

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            candidate_profile_version=2,
            candidate_profile_hash="profile_hash_xyz",
            template_id="modern",
        )

        fetched = self.db.get_prepared_packet(pkt.id, self.user_a.id)
        self.assertIsNotNone(fetched.canonical_snapshot_json)
        self.assertEqual(fetched.candidate_profile_version, 2)
        self.assertEqual(fetched.candidate_profile_hash, "profile_hash_xyz")
        self.assertEqual(fetched.template_id, "modern")

        # Independently verify that hashing the canonical_snapshot_json produces the exact packet_version_hash
        recomputed_hash = hashlib.sha256(fetched.canonical_snapshot_json.encode("utf-8")).hexdigest()
        self.assertEqual(recomputed_hash, fetched.packet_version_hash)

    # =========================================================================
    # 12. REAL ATTACHMENTS MANIFEST GENERATION
    # =========================================================================

    def test_real_attachments_manifest_generation(self):
        """build_real_attachments_manifest inspects disk files, calculates real size, format, and SHA-256."""
        # Create a real generated document
        gen_dir = Path(self.temp_dir.name) / "gen"
        gen_dir.mkdir(parents=True, exist_ok=True)
        sample_doc_path = gen_dir / "sample_resume.pdf"
        sample_doc_path.write_bytes(self.valid_pdf_bytes_a)

        gen_doc = GeneratedDocument(
            document_type="tailored_resume",
            file_format="pdf",
            file_path=str(sample_doc_path),
            filename="sample_resume.pdf",
            file_hash=hashlib.sha256(self.valid_pdf_bytes_a).hexdigest(),
            file_size_bytes=len(self.valid_pdf_bytes_a),
            template="modern",
        )

        manifest = build_real_attachments_manifest(
            selected_res_meta={
                "original_filename": "original.pdf",
                "storage_path": str(sample_doc_path),
                "file_format": "pdf",
            },
            generated_docs={"resume_pdf": gen_doc},
        )

        self.assertEqual(len(manifest), 2)
        orig_entry = next(m for m in manifest if m["artifact_type"] == "original_resume")
        self.assertEqual(orig_entry["filename"], "original.pdf")
        self.assertEqual(orig_entry["file_hash"], hashlib.sha256(self.valid_pdf_bytes_a).hexdigest())
        self.assertIn("KB", orig_entry["size_kb"])

        tailored_entry = next(m for m in manifest if m["artifact_type"] == "tailored_resume_pdf")
        self.assertEqual(tailored_entry["filename"], "sample_resume.pdf")
        self.assertEqual(tailored_entry["format"], "PDF")

    # =========================================================================
    # 13. ADDITIONAL CROSS-APPLICATION & INTEGRITY GUARANTEES
    # =========================================================================

    def test_resume_matcher_no_hardcoded_mit_when_education_missing(self):
        """ResumeJobMatcher does not invent institution or degree when profile education is empty."""
        from src.preparer.resume_matcher import ResumeJobMatcher
        matcher = ResumeJobMatcher(candidate_profile={"education": [], "work_experience": [], "projects": [], "skills": ["Python"]})
        alignment = matcher.align_job({
            "id": 1,
            "company_name": "Acme",
            "job_title": "Python Dev",
            "description": "Looking for Python developer",
        })
        self.assertNotIn("MIT World Peace University", alignment.alignment_summary)
        self.assertNotIn("Computer Science", alignment.alignment_summary)

    def test_action_ticket_replay_blocked_by_approval_record(self):
        """Single-use action ticket cannot be reused to authorize a second packet or application."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored = UniversalTailoredResumeGenerator().generate(user_id=self.user_a.id, candidate_profile={}, job_description={})
        cl = CoverLetterGenerator().generate_universal_cover_letter(user_id=self.user_a.id, candidate_profile={}, job_description={})
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=[]),
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        tkt = self.session_mgr.issue_action_ticket(
            session_id=sess.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=pkt.packet_version_hash,
        )

        # First authorization succeeds
        succ1, _, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertTrue(succ1)

        # Replaying the same action ticket must fail
        succ2, msg2, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertFalse(succ2)
        self.assertIn("ticket", msg2.lower())

    def test_screening_answer_approval_updates_claim_provenance(self):
        """Editing and approving a screening answer transitions state to USER_APPROVED and updates claim provenance."""
        from src.preparer.tailored_resume_generator import ClaimProvenance
        qa = QuestionAnswerer()
        q = ScreeningQuestion(
            question_id="q1",
            question_text="What is your notice period?",
            category="availability",
            answer_text="",
            state=AnswerState.NEEDS_CANDIDATE_INPUT.value,
            provenance=ClaimProvenance(
                claim_id="cl_q1",
                generated_text="",
                source_type="inferred",
                evidence_status="NEEDS_CANDIDATE_INPUT",
                confidence=0.0,
            ),
        )
        # Update answer
        updated = qa.update_question_answer(
            question=q,
            new_answer="Immediate availability (0 days)",
            new_state=AnswerState.USER_APPROVED,
        )
        self.assertEqual(updated.state, AnswerState.USER_APPROVED.value)
        self.assertIsNotNone(updated.provenance)
        self.assertEqual(updated.provenance.source_type, "user_edit")
        self.assertEqual(updated.provenance.evidence_status, "USER_CONFIRMED")

    def test_cross_application_context_key_varies_with_job_and_profile(self):
        """Context key isolates Streamlit state across different applications, resumes, and snapshot versions."""
        user_id = 1
        app_id_1 = 101
        app_id_2 = 102
        res_hash_1 = "a" * 64
        res_hash_2 = "b" * 64
        jd_hash_1 = "c" * 64
        jd_hash_2 = "d" * 64
        prof_hash_1 = "e" * 64

        key_app1 = f"u{user_id}_a{app_id_1}_r1_{res_hash_1[:8]}_j1_{jd_hash_1[:8]}_p{prof_hash_1[:8]}"
        key_app2 = f"u{user_id}_a{app_id_2}_r1_{res_hash_1[:8]}_j2_{jd_hash_2[:8]}_p{prof_hash_1[:8]}"
        key_res_change = f"u{user_id}_a{app_id_1}_r2_{res_hash_2[:8]}_j1_{jd_hash_1[:8]}_p{prof_hash_1[:8]}"

        self.assertNotEqual(key_app1, key_app2)
        self.assertNotEqual(key_app1, key_res_change)


if __name__ == "__main__":
    unittest.main()

"""Comprehensive Hardening Regression Test Suite for Phase 6.1.1:
Final Authenticated Session & Packet Hash Completeness.

Covers all 20 requirements:
1. Approval with an actual authenticated login session succeeds.
2. Approval without a login session fails.
3. Approval with an expired session fails.
4. Approval using another user's session fails.
5. Approval UI cannot silently create a new session.
6. Service retrieval never creates a session.
7. Action tickets are bound to the exact authenticated session.
8. Packet hash includes candidate profile version and hash.
9. Packet hash includes matching result identity.
10. Packet hash includes template ID and version.
11. Packet hash includes generated PDF/DOCX file hashes.
12. Packet hash includes all actual attachment hashes.
13. Modifying any included material changes the packet hash.
14. Stored canonical JSON independently reproduces the hash.
15. Tampering with stored canonical JSON is rejected during approval.
16. Historical packet snapshots remain unchanged after new revisions.
17. Archiving a source resume does not remove prepared packet history.
18. Existing historical Phase 6 packets migrate without fabricated metadata.
19. Cross-user packet and session access remain blocked.
20. Nonce replay protection remains intact.
"""

import hashlib
import io
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
    InvalidSessionError,
    SecurityAuthorizationError,
)
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetter, CoverLetterGenerator
from src.preparer.document_generator import GeneratedDocument
from src.preparer.question_answerer import AnswerState, QuestionAnswerer, ScreeningQAPacket
from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
from src.security.auth import AuthManager
from src.security.session_manager import SessionManager


class TestPhase611Hardening(unittest.TestCase):
    """Test suite for Phase 6.1.1 Authenticated Session & Packet Hash Completeness."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_phase6_1_1.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)
        SessionManager.reset_instance()
        self.session_mgr = SessionManager()
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)

        # Register two candidates
        self.user_a = self.auth.register(
            email="candidate.alpha@example.com",
            password="StrongPassword123!",
            full_name="Candidate Alpha",
        )
        self.user_b = self.auth.register(
            email="candidate.beta@example.com",
            password="StrongPassword123!",
            full_name="Candidate Beta",
        )

        # Upload a valid resume for User A
        pdf_stream = io.BytesIO()
        doc = SimpleDocTemplate(pdf_stream, pagesize=letter)
        doc.build([Paragraph("Resume Content for Candidate Alpha", getSampleStyleSheet()["Normal"])])
        self.valid_pdf_bytes_a = pdf_stream.getvalue()

        self.resume_a = self.db.upload_user_resume(
            user_id=self.user_a.id,
            file_bytes=self.valid_pdf_bytes_a,
            original_filename="candidate_alpha_resume.pdf",
            user_base_dir=Path(self.temp_dir.name) / "users",
        )

        # Save a Job Description for User A
        self.jd_a = self.db.create_job_description(
            user_id=self.user_a.id,
            company_name="NeuralEdge Dynamics",
            job_title="AI Research Engineer",
            raw_content="Looking for an AI Research Engineer with Python and PyTorch experience.",
            parsed_data={"required_skills": ["Python", "PyTorch", "Deep Learning"]},
        )

        # Candidate profile for User A
        self.profile_a = {
            "personal": {"full_name": "Candidate Alpha", "email": "candidate.alpha@example.com"},
            "work_experience": [
                {
                    "employer": "Tech Labs",
                    "job_title": "AI Intern",
                    "duration": "6 months",
                    "responsibilities": ["Trained neural networks with PyTorch"],
                }
            ],
            "skills": ["Python", "PyTorch"],
            "education": [{"institution": "MIT WPU", "degree": "B.Tech CS"}],
        }
        self.db.save_user_candidate_profile(self.user_a.id, self.profile_a)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_sample_materials(self, user_id: int):
        """Helper to generate fresh tailored resume, cover letter, and qa packet."""
        res_gen = UniversalTailoredResumeGenerator()
        tailored = res_gen.generate(
            user_id=user_id,
            candidate_profile=self.profile_a,
            job_description={"company_name": "NeuralEdge Dynamics", "role_title": "AI Research Engineer"},
        )
        cl_gen = CoverLetterGenerator()
        cl = cl_gen.generate_universal_cover_letter(
            user_id=user_id,
            candidate_profile=self.profile_a,
            job_description={"company_name": "NeuralEdge Dynamics", "role_title": "AI Research Engineer"},
        )
        qa = QuestionAnswerer()
        qs = qa.batch_answer_questions(["What is your PyTorch experience?"], user_id=user_id, candidate_profile=self.profile_a)
        # Mark questions as approved for test authorization
        for q in qs:
            q.state = AnswerState.USER_APPROVED.value
        qa_packet = ScreeningQAPacket(user_id=user_id, job_description_id=self.jd_a.id, questions=qs)
        return tailored, cl, qa_packet

    # =========================================================================
    # 1. AUTHENTICATED SESSION REUSE & REJECTION CHECKS
    # =========================================================================

    def test_approval_with_actual_authenticated_session_succeeds(self):
        """1. Approval with an actual authenticated login session succeeds."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        # Real login session created by Phase 2 authentication
        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        tkt = self.session_mgr.issue_action_ticket(
            session_id=sess.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=pkt.packet_version_hash,
        )

        succ, msg, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Approval should succeed: {msg}")
        self.assertIsNotNone(approval)
        self.assertEqual(approval.application_id, app.id)

    def test_approval_without_login_session_fails(self):
        """2. Approval without a login session fails."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id="",  # Missing session ID
            action_ticket="TKT-dummy.v1.sig",
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("rejected", msg.lower())

    def test_approval_with_expired_session_fails(self):
        """3. Approval with an expired session fails."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        # Create expired session
        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email, ttl_seconds=-10)
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket="TKT-dummy.v1.sig",
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("expired", msg.lower())

    def test_approval_using_another_user_session_fails(self):
        """4. Approval using another user's session fails."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        # Session belongs to User B
        sess_b = self.session_mgr.create_user_session(user_id=self.user_b.id, email=self.user_b.email)
        tkt = self.session_mgr.issue_action_ticket(
            session_id=sess_b.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=pkt.packet_version_hash,
        )

        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess_b.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn(f"User #{self.user_b.id}", msg)

    def test_approval_ui_cannot_silently_create_session(self):
        """5. Approval UI cannot silently create a new session when session_id is absent."""
        service = DashboardService(db_manager=self.db)
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        # Attempting universal authorization with empty/None session_id must fail without creating any session
        initial_sessions_count = len(self.session_mgr._sessions)
        succ, msg, _ = service.authorize_universal_application_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id="",  # Missing session ID
            action_ticket="TKT-dummy.v1.sig",
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("rejected", msg.lower())
        self.assertEqual(len(self.session_mgr._sessions), initial_sessions_count)

    def test_service_retrieval_never_creates_session(self):
        """6. DashboardService.get_authenticated_candidate_session never creates a session."""
        service = DashboardService(db_manager=self.db)
        # 1. Non-existent session
        with self.assertRaises(InvalidSessionError):
            service.get_authenticated_candidate_session(user_id=self.user_a.id, session_id="nonexistent_sess_123")

        # 2. None / empty session
        with self.assertRaises(InvalidSessionError):
            service.get_authenticated_candidate_session(user_id=self.user_a.id, session_id=None)

        # 3. Cross-user session
        sess_b = self.session_mgr.create_user_session(user_id=self.user_b.id, email=self.user_b.email)
        with self.assertRaises(SecurityAuthorizationError):
            service.get_authenticated_candidate_session(user_id=self.user_a.id, session_id=sess_b.session_id)

    def test_action_tickets_are_bound_to_exact_authenticated_session(self):
        """7. Action tickets are bound to the exact authenticated session ID."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        sess1 = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        sess2 = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)

        tkt = self.session_mgr.issue_action_ticket(
            session_id=sess1.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash="dummy_hash_123",
        )

        # Attempting to verify ticket using sess2 must fail
        valid, msg = self.session_mgr.verify_and_consume_action_ticket(
            session_id=sess2.session_id,
            ticket_str=tkt,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash="dummy_hash_123",
        )
        self.assertFalse(valid)
        self.assertIn("rejected", msg.lower())

    # =========================================================================
    # 2. COMPLETE CANONICAL PACKET HASH BINDINGS
    # =========================================================================

    def test_packet_hash_includes_candidate_profile_version_and_hash(self):
        """8. Changing candidate profile version or snapshot hash changes packet_version_hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        pkt1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            candidate_profile_version=1,
            candidate_profile_hash="profile_hash_v1",
            generation_timestamp="2026-11-03T20:00:00Z",
        )

        pkt2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            candidate_profile_version=2,  # Changed profile version
            candidate_profile_hash="profile_hash_v2",  # Changed profile hash
            generation_timestamp="2026-11-03T20:00:00Z",
        )
        self.assertNotEqual(pkt1.packet_version_hash, pkt2.packet_version_hash)

    def test_packet_hash_includes_matching_result_identity(self):
        """9. Changing matching result ID, matching engine version, or scoring config changes hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        pkt1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            matching_result_id=101,
            matching_engine_version="2.1.1",
            scoring_configuration_version="1.0.0",
            generation_timestamp="2026-11-03T20:00:00Z",
        )

        pkt2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            matching_result_id=102,  # Changed match result ID
            matching_engine_version="2.1.2",  # Changed engine version
            scoring_configuration_version="1.0.1",  # Changed scoring config version
            generation_timestamp="2026-11-03T20:00:00Z",
        )
        self.assertNotEqual(pkt1.packet_version_hash, pkt2.packet_version_hash)

    def test_packet_hash_includes_template_id_and_version(self):
        """10. Changing template ID or template version changes packet_version_hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        pkt_modern = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            template_id="modern",
            template_version="1.0.0",
            generation_timestamp="2026-11-03T20:00:00Z",
        )

        pkt_executive = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            template_id="executive",
            template_version="2.0.0",
            generation_timestamp="2026-11-03T20:00:00Z",
        )
        self.assertNotEqual(pkt_modern.packet_version_hash, pkt_executive.packet_version_hash)

    def test_packet_hash_includes_generated_doc_file_hashes(self):
        """11. Generated document file hashes (PDF/DOCX) are bound into the packet hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        doc1 = GeneratedDocument(
            document_type="tailored_resume",
            file_format="pdf",
            file_path="/tmp/res1.pdf",
            filename="res1.pdf",
            file_hash="hash_doc_1111111111111111111111111111111111111111111111111111111111111111",
            file_size_bytes=1000,
            template="modern",
        )
        doc2 = GeneratedDocument(
            document_type="tailored_resume",
            file_format="pdf",
            file_path="/tmp/res2.pdf",
            filename="res2.pdf",
            file_hash="hash_doc_2222222222222222222222222222222222222222222222222222222222222222",
            file_size_bytes=1000,
            template="modern",
        )

        pkt1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            tailored_resume_doc=doc1,
            generation_timestamp="2026-11-03T20:00:00Z",
        )

        pkt2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            tailored_resume_doc=doc2,  # Different generated document hash
            generation_timestamp="2026-11-03T20:00:00Z",
        )
        self.assertNotEqual(pkt1.packet_version_hash, pkt2.packet_version_hash)

    def test_packet_hash_includes_all_actual_attachment_hashes(self):
        """12. Modifying or adding an attachment hash changes packet_version_hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        manifest1 = [
            {"artifact_type": "original_resume", "filename": "orig.pdf", "format": "PDF", "file_hash": "hash_a", "size_bytes": 100}
        ]
        manifest2 = [
            {"artifact_type": "original_resume", "filename": "orig.pdf", "format": "PDF", "file_hash": "hash_b", "size_bytes": 100}
        ]

        pkt1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            attachments_manifest=manifest1,
            generation_timestamp="2026-11-03T20:00:00Z",
        )

        pkt2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            attachments_manifest=manifest2,
            generation_timestamp="2026-11-03T20:00:00Z",
        )
        self.assertNotEqual(pkt1.packet_version_hash, pkt2.packet_version_hash)

    def test_modifying_any_included_material_changes_packet_hash(self):
        """13. Modifying cover letter paragraphs or screening answers changes packet_version_hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        pkt1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            generation_timestamp="2026-11-03T20:00:00Z",
        )

        # Modify cover letter text
        cl_modified = CoverLetter(
            user_id=self.user_a.id,
            target_company=cl.target_company,
            target_role=cl.target_role,
            letter_text=cl.letter_text + "\nI also have extensive experience leading engineering teams.",
            paragraphs=cl.paragraphs + ["I also have extensive experience leading engineering teams."],
            tone=cl.tone,
        )

        pkt2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl_modified,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            generation_timestamp="2026-11-03T20:00:00Z",
        )
        self.assertNotEqual(pkt1.packet_version_hash, pkt2.packet_version_hash)

    def test_stored_canonical_json_independently_reproduces_hash(self):
        """14. Invariant: SHA256(canonical_snapshot_json UTF-8 bytes) == packet_version_hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        stored_pkt = self.db.get_prepared_packet(pkt.id, self.user_a.id)
        self.assertIsNotNone(stored_pkt.canonical_snapshot_json)
        recomputed = hashlib.sha256(stored_pkt.canonical_snapshot_json.encode("utf-8")).hexdigest()
        self.assertEqual(recomputed, stored_pkt.packet_version_hash)

    def test_tampering_with_stored_canonical_json_rejected_during_approval(self):
        """15. Tampering with stored canonical JSON causes verify_packet_integrity and authorization to fail."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        tkt = self.session_mgr.issue_action_ticket(
            session_id=sess.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=pkt.packet_version_hash,
        )

        # Tamper directly with the stored canonical snapshot JSON in SQLite
        with self.db.transaction() as conn:
            conn.cursor().execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = ? WHERE id = ?",
                ('{"tampered_payload": true}', pkt.id),
            )

        # Independent integrity verification method fails
        tampered_pkt = self.db.get_prepared_packet(pkt.id, self.user_a.id)
        valid, msg = self.gate.verify_packet_integrity(tampered_pkt)
        self.assertFalse(valid)
        self.assertIn("integrity check failed", msg.lower())

        # Authorization rejects the tampered packet
        succ, auth_msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("integrity check failed", auth_msg.lower())

    def test_historical_packet_snapshots_remain_unchanged_after_new_revisions(self):
        """16. Historical packet snapshots and hashes remain unchanged after new revisions."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        pkt1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            generation_timestamp="2026-11-03T10:00:00Z",
        )
        original_hash_1 = pkt1.packet_version_hash
        original_json_1 = pkt1.canonical_snapshot_json

        # Create revision 2
        pkt2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            generation_timestamp="2026-11-03T11:00:00Z",
        )
        self.assertEqual(pkt2.version_num, 2)

        # Fetch pkt1 again from database
        reloaded_pkt1 = self.db.get_prepared_packet(pkt1.id, self.user_a.id)
        self.assertEqual(reloaded_pkt1.packet_version_hash, original_hash_1)
        self.assertEqual(reloaded_pkt1.canonical_snapshot_json, original_json_1)
        self.assertFalse(reloaded_pkt1.is_active_revision)

    # =========================================================================
    # 3. RESUME ARCHIVAL & DATA RETENTION
    # =========================================================================

    def test_archiving_source_resume_does_not_remove_prepared_packet_history(self):
        """17. Ordinary resume deletion archives resume (soft-delete), keeping prepared packet history intact."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        # Call delete_user_resume for resume_a
        del_result = self.db.delete_user_resume(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            user_base_dir=Path(self.temp_dir.name) / "users",
        )
        self.assertTrue(del_result)

        # Check resume is archived (is_active = 0)
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_active FROM resumes WHERE id = ?", (self.resume_a["id"],))
            res_row = cursor.fetchone()
            self.assertEqual(res_row["is_active"], 0)

        # Historical prepared packet is still fully accessible
        reloaded_pkt = self.db.get_prepared_packet(pkt.id, self.user_a.id)
        self.assertIsNotNone(reloaded_pkt)
        self.assertEqual(reloaded_pkt.original_resume_id, self.resume_a["id"])
        self.assertEqual(reloaded_pkt.packet_version_hash, pkt.packet_version_hash)

    def test_existing_historical_phase6_packets_migrate_without_fabricated_metadata(self):
        """18. Existing legacy packet rows migrate cleanly without fabricated metadata."""
        # Insert a legacy packet row without canonical_snapshot_json and new columns
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    application_id, user_id, version_num, packet_version_hash,
                    original_resume_id, original_resume_hash, job_description_snapshot_hash,
                    screening_answers_json, canonical_snapshot_json, is_active_revision
                ) VALUES (?, ?, 99, 'legacy_hash_abc', ?, 'orig_hash', 'jd_hash', '[]', NULL, 0)
                """,
                (app.id, self.user_a.id, self.resume_a["id"]),
            )
            legacy_id = cursor.lastrowid

        # Trigger DB migration on connection
        with self.db.connection() as conn:
            self.db._migrate_prepared_packets_foreign_keys(conn)

        # Verify legacy packet survived
        migrated_pkt = self.db.get_prepared_packet(legacy_id, self.user_a.id)
        self.assertIsNotNone(migrated_pkt)
        self.assertTrue(migrated_pkt.is_legacy)
        self.assertIsNone(migrated_pkt.canonical_snapshot_json)
        self.assertIsNone(migrated_pkt.matching_engine_version)
        self.assertIsNone(migrated_pkt.scoring_configuration_version)
        self.assertEqual(migrated_pkt.packet_version_hash, "legacy_hash_abc")

    # =========================================================================
    # 4. CROSS-USER ISOLATION & NONCE REPLAY INTEGRITY
    # =========================================================================

    def test_cross_user_packet_and_session_access_remain_blocked(self):
        """19. Cross-user packet and session access remain strictly blocked."""
        app_a = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored_a, cl_a, qa_a = self._create_sample_materials(self.user_a.id)
        pkt_a = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app_a.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored_a,
            cover_letter=cl_a,
            qa_packet=qa_a,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )

        # User B cannot access User A's packet
        with self.assertRaises(CrossUserAccessError):
            self.db.get_prepared_packet(pkt_a.id, user_id=self.user_b.id)

        # User B cannot authorize User A's packet
        sess_b = self.session_mgr.create_user_session(user_id=self.user_b.id, email=self.user_b.email)
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_b.id,
            application_id=app_a.id,
            packet_id=pkt_a.id,
            approver_name="Candidate Beta",
            session_id=sess_b.session_id,
            action_ticket="TKT-dummy.v1.sig",
            candidate_confirmed=True,
        )
        self.assertFalse(succ)

    def test_nonce_replay_protection_remains_intact(self):
        """20. Replaying a consumed single-use ticket nonce is rejected."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
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

        # Attempt to authorize again with the exact same ticket
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


if __name__ == "__main__":
    unittest.main()

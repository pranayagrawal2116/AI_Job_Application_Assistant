"""Comprehensive Hardening Regression Test Suite for Phase 6.1.2:
Approval Session Enforcement & Complete Canonical Packet Integrity.

Covers all 24 required specifications:
1. Approval succeeds using an actual Phase 2 authenticated login session.
2. Missing session ID blocks approval.
3. Expired login session blocks approval.
4. Revoked login session blocks approval.
5. Another user's session blocks approval.
6. Approval does not call authenticate_candidate().
7. Approval does not call create_user_session().
8. Service session retrieval does not create a session.
9. Approval ticket uses the exact login session ID.
10. Canonical payload includes candidate profile version and hash.
11. Canonical payload includes matching result and scoring provenance.
12. Canonical payload includes resume version.
13. Canonical payload includes job-description ID and snapshot hash.
14. Canonical payload includes all generated document hashes.
15. Canonical payload includes attachment hashes and sizes.
16. Changing any included metadata changes packet hash.
17. Stored canonical bytes independently reproduce packet hash.
18. Altered canonical snapshot is rejected before approval.
19. Altered stored packet hash is rejected.
20. Historical packets remain unchanged.
21. Legacy packets are not given fabricated complete provenance.
22. Archived resumes preserve packet history.
23. Existing nonce replay protection still succeeds in rejecting replay.
24. Cross-user approval remains impossible.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import InvalidSessionError
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetterGenerator
from src.preparer.document_generator import GeneratedDocument
from src.preparer.question_answerer import AnswerState, QuestionAnswerer, ScreeningQAPacket
from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
from src.security.auth import AuthManager
from src.security.session_manager import SessionManager


class TestPhase612Hardening(unittest.TestCase):
    """Test suite for Phase 6.1.2 Approval Session Enforcement & Complete Canonical Packet Integrity."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_phase6_1_2.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)
        SessionManager.reset_instance()
        self.session_mgr = SessionManager()
        self.service = DashboardService(db_manager=self.db)
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
            company_name="Apex Neural AI",
            job_title="ML Research Engineer",
            raw_content="Looking for an ML Research Engineer with Python and PyTorch experience.",
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
            job_description={"company_name": "Apex Neural AI", "role_title": "ML Research Engineer"},
        )
        cl_gen = CoverLetterGenerator()
        cl = cl_gen.generate_universal_cover_letter(
            user_id=user_id,
            candidate_profile=self.profile_a,
            job_description={"company_name": "Apex Neural AI", "role_title": "ML Research Engineer"},
        )
        qa = QuestionAnswerer()
        qs = qa.batch_answer_questions(["Do you have experience with PyTorch?"], user_id=user_id, candidate_profile=self.profile_a)
        for q in qs:
            q.state = AnswerState.USER_APPROVED.value
        qa_packet = ScreeningQAPacket(user_id=user_id, job_description_id=self.jd_a.id, questions=qs)
        return tailored, cl, qa_packet

    # -------------------------------------------------------------------------
    # 1. Approval succeeds using actual Phase 2 authenticated login session
    # -------------------------------------------------------------------------
    def test_1_approval_succeeds_using_actual_phase2_authenticated_login_session(self):
        """1. Approval succeeds using an actual Phase 2 authenticated login session."""
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
        sess_a = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        tkt = self.service.issue_approval_ticket(sess_a.session_id, app.id, pkt.packet_version_hash)

        succ, msg, approval = self.service.authorize_universal_application_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess_a.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Approval failed: {msg}")
        self.assertIsNotNone(approval)
        self.assertEqual(approval.approver_name, "Candidate Alpha")

    # -------------------------------------------------------------------------
    # 2. Missing session ID blocks approval
    # -------------------------------------------------------------------------
    def test_2_missing_session_id_blocks_approval(self):
        """2. Missing session ID blocks approval."""
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

        succ, msg, _ = self.service.authorize_universal_application_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id="",  # Empty session ID
            action_ticket="TKT-dummy.v1.sig",
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("rejected", msg.lower())

    # -------------------------------------------------------------------------
    # 3. Expired login session blocks approval
    # -------------------------------------------------------------------------
    def test_3_expired_login_session_blocks_approval(self):
        """3. Expired login session blocks approval."""
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
        sess.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)  # Expired

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

    # -------------------------------------------------------------------------
    # 4. Revoked login session blocks approval
    # -------------------------------------------------------------------------
    def test_4_revoked_login_session_blocks_approval(self):
        """4. Revoked login session blocks approval."""
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
        sess.is_active = False  # Revoked/deactivated

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
        self.assertIn("rejected", msg.lower())

    # -------------------------------------------------------------------------
    # 5. Another user's session blocks approval
    # -------------------------------------------------------------------------
    def test_5_another_user_session_blocks_approval(self):
        """5. Another user's session blocks approval."""
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

        # User B session
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

    # -------------------------------------------------------------------------
    # 6. Approval does not call authenticate_candidate()
    # -------------------------------------------------------------------------
    def test_6_approval_does_not_call_authenticate_candidate(self):
        """6. Approval does not call authenticate_candidate()."""
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
        tkt = self.service.issue_approval_ticket(sess.session_id, app.id, pkt.packet_version_hash)

        with patch.object(self.session_mgr, "authenticate_candidate") as mock_auth:
            self.gate.authorize_universal_packet(
                user_id=self.user_a.id,
                application_id=app.id,
                packet_id=pkt.id,
                approver_name="Candidate Alpha",
                session_id=sess.session_id,
                action_ticket=tkt,
                candidate_confirmed=True,
            )
            mock_auth.assert_not_called()

    # -------------------------------------------------------------------------
    # 7. Approval does not call create_user_session()
    # -------------------------------------------------------------------------
    def test_7_approval_does_not_call_create_user_session(self):
        """7. Approval does not call create_user_session()."""
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
        tkt = self.service.issue_approval_ticket(sess.session_id, app.id, pkt.packet_version_hash)

        with patch.object(self.session_mgr, "create_user_session") as mock_create:
            self.gate.authorize_universal_packet(
                user_id=self.user_a.id,
                application_id=app.id,
                packet_id=pkt.id,
                approver_name="Candidate Alpha",
                session_id=sess.session_id,
                action_ticket=tkt,
                candidate_confirmed=True,
            )
            mock_create.assert_not_called()

    # -------------------------------------------------------------------------
    # 8. Service session retrieval does not create a session
    # -------------------------------------------------------------------------
    def test_8_service_session_retrieval_does_not_create_session(self):
        """8. DashboardService.get_authenticated_candidate_session does not create a session."""
        initial_count = len(self.session_mgr._sessions)
        with self.assertRaises(InvalidSessionError):
            self.service.get_authenticated_candidate_session(
                user_id=self.user_a.id,
                session_id="nonexistent_session_9999",
            )
        self.assertEqual(len(self.session_mgr._sessions), initial_count)

    # -------------------------------------------------------------------------
    # 9. Approval ticket uses exact login session ID
    # -------------------------------------------------------------------------
    def test_9_approval_ticket_uses_exact_login_session_id(self):
        """9. Approval ticket uses the exact login session ID."""
        sess_a = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        sess_b = self.session_mgr.create_user_session(user_id=self.user_b.id, email=self.user_b.email)

        ticket = self.service.issue_approval_ticket(
            session_id=sess_a.session_id,
            job_id=10,
            packet_hash="test_packet_hash_123",
        )
        # Attempt to verify using session B must fail
        valid, msg = self.session_mgr.verify_and_consume_action_ticket(
            session_id=sess_b.session_id,
            ticket_str=ticket,
            action_type="HUMAN_APPROVAL",
            application_id=10,
            packet_hash="test_packet_hash_123",
        )
        self.assertFalse(valid)
        self.assertIn("rejected", msg.lower())

    # -------------------------------------------------------------------------
    # 10. Canonical payload includes candidate profile version and hash
    # -------------------------------------------------------------------------
    def test_10_canonical_payload_includes_candidate_profile_version_and_hash(self):
        """10. Canonical payload includes candidate profile version/hash."""
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
            candidate_profile_version=3,
            candidate_profile_hash="profile_sha256_mock_hash",
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(snapshot["candidate_profile_version"], 3)
        self.assertEqual(snapshot["candidate_profile_hash"], "profile_sha256_mock_hash")

    # -------------------------------------------------------------------------
    # 11. Canonical payload includes matching result and scoring provenance
    # -------------------------------------------------------------------------
    def test_11_canonical_payload_includes_matching_result_and_scoring_provenance(self):
        """11. Canonical payload includes matching result and scoring provenance."""
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
            matching_result_id=42,
            matching_engine_version="2.1.1",
            scoring_profile="healthcare_clinical",
            scoring_config_version="1.2.0",
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(snapshot["matching_result_id"], 42)
        self.assertEqual(snapshot["matching_engine_version"], "2.1.1")
        self.assertEqual(snapshot["scoring_profile"], "healthcare_clinical")
        self.assertEqual(snapshot["scoring_config_version"], "1.2.0")

    # -------------------------------------------------------------------------
    # 12. Canonical payload includes resume version
    # -------------------------------------------------------------------------
    def test_12_canonical_payload_includes_resume_version(self):
        """12. Canonical payload includes resume version."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            original_resume_version_num=2,
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(snapshot["original_resume_id"], self.resume_a["id"])
        self.assertEqual(snapshot["original_resume_version_num"], 2)
        self.assertEqual(snapshot["original_resume_file_hash"], self.resume_a["file_hash"])

    # -------------------------------------------------------------------------
    # 13. Canonical payload includes job-description ID and snapshot hash
    # -------------------------------------------------------------------------
    def test_13_canonical_payload_includes_job_description_id_and_snapshot_hash(self):
        """13. Canonical payload includes job-description ID and snapshot hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            job_description_id=self.jd_a.id,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(snapshot["job_description_id"], self.jd_a.id)
        self.assertEqual(snapshot["job_description_snapshot_hash"], self.jd_a.snapshot_hash)

    # -------------------------------------------------------------------------
    # 14. Canonical payload includes all generated document hashes
    # -------------------------------------------------------------------------
    def test_14_canonical_payload_includes_all_generated_document_hashes(self):
        """14. Canonical payload includes all generated document hashes."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        res_pdf = GeneratedDocument("resume", "pdf", "/tmp/res.pdf", "res.pdf", "hash_res_pdf_123", 1024, "Modern")
        res_docx = GeneratedDocument("resume", "docx", "/tmp/res.docx", "res.docx", "hash_res_docx_456", 2048, "Modern")
        cl_pdf = GeneratedDocument("cover_letter", "pdf", "/tmp/cl.pdf", "cl.pdf", "hash_cl_pdf_789", 1024, "Modern")
        cl_docx = GeneratedDocument("cover_letter", "docx", "/tmp/cl.docx", "cl.docx", "hash_cl_docx_012", 2048, "Modern")

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            tailored_resume_pdf_doc=res_pdf,
            tailored_resume_docx_doc=res_docx,
            cover_letter_pdf_doc=cl_pdf,
            cover_letter_docx_doc=cl_docx,
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(snapshot["tailored_resume_pdf_hash"], "hash_res_pdf_123")
        self.assertEqual(snapshot["tailored_resume_docx_hash"], "hash_res_docx_456")
        self.assertEqual(snapshot["cover_letter_pdf_hash"], "hash_cl_pdf_789")
        self.assertEqual(snapshot["cover_letter_docx_hash"], "hash_cl_docx_012")

    # -------------------------------------------------------------------------
    # 15. Canonical payload includes attachment hashes and sizes
    # -------------------------------------------------------------------------
    def test_15_canonical_payload_includes_attachment_hashes_and_sizes(self):
        """15. Canonical payload includes attachment hashes and sizes."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        manifest = [
            {
                "artifact_type": "tailored_resume_pdf",
                "stored_filename": "resume.pdf",
                "document_format": "pdf",
                "file_size_bytes": 10240,
                "sha256_hash": "sha256_attach_1",
                "source_record_version": 1,
                "creation_timestamp": "2026-11-03T12:00:00Z",
            }
        ]
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            attachments_manifest=manifest,
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(len(snapshot["attachments_manifest"]), 1)
        self.assertEqual(snapshot["attachments_manifest"][0]["file_size_bytes"], 10240)
        self.assertEqual(snapshot["attachments_manifest"][0]["sha256_hash"], "sha256_attach_1")

    # -------------------------------------------------------------------------
    # 16. Changing any included metadata changes packet hash
    # -------------------------------------------------------------------------
    def test_16_changing_any_included_metadata_changes_packet_hash(self):
        """16. Changing any included metadata changes packet hash."""
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
            scoring_profile="general",
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
            scoring_profile="technical_dense",
        )
        self.assertNotEqual(pkt1.packet_version_hash, pkt2.packet_version_hash)

    # -------------------------------------------------------------------------
    # 17. Stored canonical bytes independently reproduce packet hash
    # -------------------------------------------------------------------------
    def test_17_stored_canonical_bytes_independently_reproduce_packet_hash(self):
        """17. Stored canonical bytes independently reproduce packet hash."""
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
        recomputed = hashlib.sha256(pkt.canonical_snapshot_json.encode("utf-8")).hexdigest()
        self.assertEqual(recomputed, pkt.packet_version_hash)

    # -------------------------------------------------------------------------
    # 18. Altered canonical snapshot is rejected before approval
    # -------------------------------------------------------------------------
    def test_18_altered_canonical_snapshot_is_rejected_before_approval(self):
        """18. Altered canonical snapshot is rejected before approval."""
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
        tkt = self.service.issue_approval_ticket(sess.session_id, app.id, pkt.packet_version_hash)

        # Tamper directly in SQLite
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = '{\"tampered\": true}' WHERE id = ?",
                (pkt.id,),
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
        self.assertIn("Integrity check failed", msg)

    # -------------------------------------------------------------------------
    # 19. Altered stored packet hash is rejected
    # -------------------------------------------------------------------------
    def test_19_altered_stored_packet_hash_is_rejected(self):
        """19. Altered stored packet hash is rejected."""
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
        tkt = self.service.issue_approval_ticket(sess.session_id, app.id, pkt.packet_version_hash)

        # Tamper with stored packet_version_hash
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE prepared_packets SET packet_version_hash = 'tampered_hash_value_123' WHERE id = ?",
                (pkt.id,),
            )

        valid, msg, _ = self.service.verify_prepared_packet_integrity(pkt.id, self.user_a.id)
        self.assertFalse(valid)
        self.assertIn("Integrity check failed", msg)

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
        self.assertIn("Integrity check failed", auth_msg)

    # -------------------------------------------------------------------------
    # 20. Historical packets remain unchanged
    # -------------------------------------------------------------------------
    def test_20_historical_packets_remain_unchanged(self):
        """20. Historical packets remain unchanged after subsequent revisions."""
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
            template_id="modern",
        )
        saved_snapshot1 = pkt1.canonical_snapshot_json
        saved_hash1 = pkt1.packet_version_hash

        pkt2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            template_id="technical",
        )

        # Inspect pkt1 from database
        reloaded_pkt1 = self.db.get_prepared_packet(pkt1.id, self.user_a.id)
        self.assertEqual(reloaded_pkt1.canonical_snapshot_json, saved_snapshot1)
        self.assertEqual(reloaded_pkt1.packet_version_hash, saved_hash1)
        self.assertFalse(reloaded_pkt1.is_active_revision)
        self.assertTrue(pkt2.is_active_revision)

    # -------------------------------------------------------------------------
    # 21. Legacy packets are not given fabricated complete provenance
    # -------------------------------------------------------------------------
    def test_21_legacy_packets_are_not_given_fabricated_complete_provenance(self):
        """21. Legacy packets are not given fabricated complete provenance."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        # Create legacy packet with canonical_snapshot_json = None
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    application_id, user_id, version_num, packet_version_hash,
                    original_resume_id, original_resume_hash, job_description_snapshot_hash,
                    screening_answers_json, canonical_snapshot_json, is_active_revision
                ) VALUES (?, ?, 1, 'legacy_hash_abc', ?, ?, ?, '[]', NULL, 1)
                """,
                (app.id, self.user_a.id, self.resume_a["id"], self.resume_a["file_hash"], self.jd_a.snapshot_hash),
            )
            legacy_id = cursor.lastrowid

        legacy_pkt = self.db.get_prepared_packet(legacy_id, self.user_a.id)
        self.assertTrue(legacy_pkt.is_legacy)
        self.assertIsNone(legacy_pkt.canonical_snapshot_json)

        valid, msg, _ = self.service.verify_prepared_packet_integrity(legacy_id, self.user_a.id)
        self.assertFalse(valid)
        self.assertIn("Legacy packet record", msg)

    # -------------------------------------------------------------------------
    # 22. Archived resumes preserve packet history
    # -------------------------------------------------------------------------
    def test_22_archived_resumes_preserve_packet_history(self):
        """22. Archived resumes preserve prepared packet history."""
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

        # Deleting resume with linked packet must archive it (is_active=0) without deleting packet
        res_archived = self.db.delete_user_resume(user_id=self.user_a.id, resume_id=self.resume_a["id"])
        self.assertTrue(res_archived)

        # Packet still exists in SQLite
        reloaded_pkt = self.db.get_prepared_packet(pkt.id, self.user_a.id)
        self.assertIsNotNone(reloaded_pkt)
        self.assertEqual(reloaded_pkt.original_resume_id, self.resume_a["id"])

    # -------------------------------------------------------------------------
    # 23. Existing nonce replay protection still succeeds in rejecting replay
    # -------------------------------------------------------------------------
    def test_23_existing_nonce_replay_protection_still_rejects_replay(self):
        """23. Existing nonce replay protection still succeeds in rejecting replay."""
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
        ticket = self.service.issue_approval_ticket(sess.session_id, app.id, pkt.packet_version_hash)

        # First authorization succeeds
        succ1, msg1, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ1)

        # Second authorization with same consumed ticket fails
        succ2, msg2, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=sess.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ2)
        self.assertIn("rejected", msg2.lower())

    # -------------------------------------------------------------------------
    # 24. Cross-user approval remains impossible
    # -------------------------------------------------------------------------
    def test_24_cross_user_approval_remains_impossible(self):
        """24. Cross-user approval remains impossible."""
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

        sess_b = self.session_mgr.create_user_session(user_id=self.user_b.id, email=self.user_b.email)
        tkt_b = self.service.issue_approval_ticket(sess_b.session_id, app.id, pkt.packet_version_hash)

        # User B attempts to approve User A's packet
        succ, msg, _ = self.service.authorize_universal_application_packet(
            user_id=self.user_b.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Beta",
            session_id=sess_b.session_id,
            action_ticket=tkt_b,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("rejected", msg.lower())


if __name__ == "__main__":
    unittest.main()

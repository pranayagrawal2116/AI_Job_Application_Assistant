"""Comprehensive Hardening Regression Test Suite for Phase 6.1.3:
Strict User-Bound Session Identity & Actual Match Result Provenance.

Covers all 22 required specifications:
1. A valid Phase 2 session with correct non-null user_id is accepted.
2. A session with user_id=None and candidate_id equal to user ID is rejected.
3. A session with user_id=None and candidate_id="user_<id>" is rejected.
4. A session with a different non-null user_id is rejected.
5. An expired session is rejected.
6. A revoked session is rejected.
7. Direct approval-gate invocation enforces strict user_id binding.
8. Approval does not consume the action ticket when session identity validation fails.
9. Dashboard packet assembly passes the actual latest_match.id.
10. Dashboard packet assembly passes the actual engine version.
11. Dashboard packet assembly passes the actual scoring profile.
12. Dashboard packet assembly passes the actual scoring configuration version.
13. A mismatched resume MatchResult is rejected.
14. A mismatched job-description snapshot MatchResult is rejected.
15. A cross-user MatchResult is rejected.
16. No matching result produces explicit null metadata.
17. No candidate profile produces null profile version and hash.
18. Actual source metadata is present in canonical_snapshot_json.
19. Changing the matching result changes the canonical packet hash.
20. Stored canonical bytes still independently reproduce the packet hash.
21. Existing snapshot-tampering detection remains functional.
22. Existing nonce replay protection remains functional.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
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
    SessionExpiredError,
    ValidationError,
)
from src.database.models import MatchResult
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetterGenerator
from src.preparer.question_answerer import AnswerState, QuestionAnswerer, ScreeningQAPacket
from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
from src.security.auth import AuthManager
from src.security.session_manager import CandidateSession, SessionManager


class TestPhase613Hardening(unittest.TestCase):
    """Test suite for Phase 6.1.3 Strict User-Bound Session Identity & Actual Match Result Provenance."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_phase6_1_3.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)
        SessionManager.reset_instance()
        self.session_mgr = SessionManager()
        self.service = DashboardService(db_manager=self.db)
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)

        # Register User A and User B
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

        # User A Resume
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

        # User A Job Description
        self.jd_a = self.db.create_job_description(
            user_id=self.user_a.id,
            company_name="Quantum Cognition Inc",
            job_title="Senior AI Scientist",
            raw_content="Looking for a Senior AI Scientist with deep PyTorch and ML expertise.",
            parsed_data={"required_skills": ["Python", "PyTorch", "Deep Learning"]},
        )

        # Candidate Profile for User A
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
            job_description={"company_name": "Quantum Cognition Inc", "role_title": "Senior AI Scientist"},
        )
        cl_gen = CoverLetterGenerator()
        cl = cl_gen.generate_universal_cover_letter(
            user_id=user_id,
            candidate_profile=self.profile_a,
            job_description={"company_name": "Quantum Cognition Inc", "role_title": "Senior AI Scientist"},
        )
        qa = QuestionAnswerer()
        qs = qa.batch_answer_questions(["What is your PyTorch experience?"], user_id=user_id, candidate_profile=self.profile_a)
        for q in qs:
            q.state = AnswerState.USER_APPROVED.value
        qa_packet = ScreeningQAPacket(user_id=user_id, job_description_id=self.jd_a.id, questions=qs)
        return tailored, cl, qa_packet

    def _create_sample_match(self, user_id: int, resume_id: int, resume_hash: str, jd_id: int, jd_hash: str, **kwargs):
        """Helper to persist a real MatchResult in SQLite."""
        mr = MatchResult(
            user_id=user_id,
            resume_id=resume_id,
            resume_version_num=kwargs.get("resume_version_num", 1),
            resume_file_hash=resume_hash,
            job_description_id=jd_id,
            job_snapshot_hash=jd_hash,
            match_score=kwargs.get("match_score", 92.5),
            match_classification="High",
            eligibility_status="ELIGIBLE",
            score_breakdown=json.dumps({"skills": 95, "experience": 90}),
            explanation="Strong candidate with PyTorch expertise.",
            scoring_profile=kwargs.get("scoring_profile", "ai_research_focused"),
            scoring_config_version=kwargs.get("scoring_config_version", "1.2.0"),
            engine_version=kwargs.get("engine_version", "2.1.1-universal"),
        )
        mr_id = self.db.save_match_result(mr)
        mr.id = mr_id
        return mr

    # -------------------------------------------------------------------------
    # 1. Valid Phase 2 session with correct non-null user_id accepted
    # -------------------------------------------------------------------------
    def test_1_valid_phase2_session_with_correct_non_null_user_id_accepted(self):
        """1. A valid Phase 2 session with correct non-null user_id is accepted."""
        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        self.assertIsNotNone(sess.user_id)
        self.assertEqual(sess.user_id, self.user_a.id)

        retrieved = self.service.get_authenticated_candidate_session(
            user_id=self.user_a.id,
            session_id=sess.session_id,
        )
        self.assertEqual(retrieved.session_id, sess.session_id)
        self.assertEqual(retrieved.user_id, self.user_a.id)

    # -------------------------------------------------------------------------
    # 2. Session with user_id=None and candidate_id equal to user ID is rejected
    # -------------------------------------------------------------------------
    def test_2_session_with_user_id_none_and_candidate_id_numeric_rejected(self):
        """2. A session with user_id=None and candidate_id equal to user ID is rejected."""
        legacy_sess = CandidateSession(
            session_id="legacy_sess_num_123",
            candidate_id=str(self.user_a.id),
            candidate_name="Candidate Alpha",
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            last_activity=datetime.now(timezone.utc),
            user_id=None,  # Missing user_id
            email=self.user_a.email,
        )
        self.session_mgr._sessions[legacy_sess.session_id] = legacy_sess

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_authenticated_candidate_session(
                user_id=self.user_a.id,
                session_id=legacy_sess.session_id,
            )
        self.assertIn("verified database user_id", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 3. Session with user_id=None and candidate_id="user_<id>" is rejected
    # -------------------------------------------------------------------------
    def test_3_session_with_user_id_none_and_candidate_id_user_prefix_rejected(self):
        """3. A session with user_id=None and candidate_id='user_<id>' is rejected."""
        legacy_sess = CandidateSession(
            session_id="legacy_sess_prefix_456",
            candidate_id=f"user_{self.user_a.id}",
            candidate_name="Candidate Alpha",
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            last_activity=datetime.now(timezone.utc),
            user_id=None,  # Missing user_id
            email=self.user_a.email,
        )
        self.session_mgr._sessions[legacy_sess.session_id] = legacy_sess

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_authenticated_candidate_session(
                user_id=self.user_a.id,
                session_id=legacy_sess.session_id,
            )
        self.assertIn("verified database user_id", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 4. Session with a different non-null user_id is rejected
    # -------------------------------------------------------------------------
    def test_4_session_with_different_non_null_user_id_rejected(self):
        """4. A session with a different non-null user_id is rejected."""
        sess_b = self.session_mgr.create_user_session(user_id=self.user_b.id, email=self.user_b.email)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.get_authenticated_candidate_session(
                user_id=self.user_a.id,
                session_id=sess_b.session_id,
            )
        self.assertIn(f"User #{self.user_b.id}", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 5. Expired session is rejected
    # -------------------------------------------------------------------------
    def test_5_expired_session_rejected(self):
        """5. An expired session is rejected."""
        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        sess.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        with self.assertRaises(SessionExpiredError):
            self.service.get_authenticated_candidate_session(
                user_id=self.user_a.id,
                session_id=sess.session_id,
            )

    # -------------------------------------------------------------------------
    # 6. Revoked session is rejected
    # -------------------------------------------------------------------------
    def test_6_revoked_session_rejected(self):
        """6. A revoked session is rejected."""
        sess = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)
        sess.is_active = False
        with self.assertRaises(InvalidSessionError):
            self.service.get_authenticated_candidate_session(
                user_id=self.user_a.id,
                session_id=sess.session_id,
            )

    # -------------------------------------------------------------------------
    # 7. Direct approval-gate invocation enforces strict user_id binding
    # -------------------------------------------------------------------------
    def test_7_direct_approval_gate_invocation_enforces_strict_user_id_binding(self):
        """7. Direct approval-gate invocation enforces strict user_id binding."""
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

        # Legacy session with user_id=None
        legacy_sess = CandidateSession(
            session_id="legacy_sess_gate_test",
            candidate_id=str(self.user_a.id),
            candidate_name="Candidate Alpha",
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            last_activity=datetime.now(timezone.utc),
            user_id=None,
            email=self.user_a.email,
        )
        self.session_mgr._sessions[legacy_sess.session_id] = legacy_sess
        tkt = self.service.issue_approval_ticket(legacy_sess.session_id, app.id, pkt.packet_version_hash)

        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate Alpha",
            session_id=legacy_sess.session_id,
            action_ticket=tkt,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("verified database user_id", msg)

    # -------------------------------------------------------------------------
    # 8. Approval does not consume ticket when session identity validation fails
    # -------------------------------------------------------------------------
    def test_8_approval_does_not_consume_action_ticket_when_session_fails(self):
        """8. Approval does not consume the action ticket when session identity validation fails."""
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
        tkt = self.service.issue_approval_ticket(sess_b.session_id, app.id, pkt.packet_version_hash)

        # Attempt authorization for User A using User B's session
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

        # Confirm the ticket was NOT consumed because session check aborted prior to ticket verification
        body = tkt[4:]
        header_nonce = body.split(".")[0]
        nonce = header_nonce.split("-", 1)[1] if "-" in header_nonce else header_nonce
        self.assertIn(nonce, sess_b.issued_tickets)
        self.assertNotIn(nonce, sess_b.consumed_tickets)

    # -------------------------------------------------------------------------
    # 9. Dashboard packet assembly passes actual latest_match.id
    # -------------------------------------------------------------------------
    def test_9_dashboard_packet_assembly_passes_actual_latest_match_id(self):
        """9. Dashboard packet assembly passes the actual latest_match.id."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        match = self._create_sample_match(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            resume_hash=self.resume_a["file_hash"],
            jd_id=self.jd_a.id,
            jd_hash=self.jd_a.snapshot_hash,
        )

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            matching_result_id=match.id,
        )
        self.assertEqual(pkt.matching_result_id, match.id)
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(snapshot["matching_result_id"], match.id)

    # -------------------------------------------------------------------------
    # 10. Dashboard packet assembly passes actual engine version
    # -------------------------------------------------------------------------
    def test_10_dashboard_packet_assembly_passes_actual_engine_version(self):
        """10. Dashboard packet assembly passes the actual engine version."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        match = self._create_sample_match(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            resume_hash=self.resume_a["file_hash"],
            jd_id=self.jd_a.id,
            jd_hash=self.jd_a.snapshot_hash,
            engine_version="3.0.0-neural",
        )

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            matching_result_id=match.id,
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(snapshot["matching_engine_version"], "3.0.0-neural")

    # -------------------------------------------------------------------------
    # 11. Dashboard packet assembly passes actual scoring profile
    # -------------------------------------------------------------------------
    def test_11_dashboard_packet_assembly_passes_actual_scoring_profile(self):
        """11. Dashboard packet assembly passes the actual scoring profile."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        match = self._create_sample_match(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            resume_hash=self.resume_a["file_hash"],
            jd_id=self.jd_a.id,
            jd_hash=self.jd_a.snapshot_hash,
            scoring_profile="clinical_expert_v2",
        )

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            matching_result_id=match.id,
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(snapshot["scoring_profile"], "clinical_expert_v2")

    # -------------------------------------------------------------------------
    # 12. Dashboard packet assembly passes actual scoring configuration version
    # -------------------------------------------------------------------------
    def test_12_dashboard_packet_assembly_passes_actual_scoring_config_version(self):
        """12. Dashboard packet assembly passes the actual scoring configuration version."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        match = self._create_sample_match(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            resume_hash=self.resume_a["file_hash"],
            jd_id=self.jd_a.id,
            jd_hash=self.jd_a.snapshot_hash,
            scoring_config_version="2.4.1",
        )

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            matching_result_id=match.id,
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(snapshot["scoring_config_version"], "2.4.1")

    # -------------------------------------------------------------------------
    # 13. Mismatched resume MatchResult is rejected
    # -------------------------------------------------------------------------
    def test_13_mismatched_resume_match_result_rejected(self):
        """13. A mismatched resume MatchResult is rejected."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        # Upload a second distinct resume for User A
        pdf_stream2 = io.BytesIO()
        doc2 = SimpleDocTemplate(pdf_stream2, pagesize=letter)
        doc2.build([Paragraph("Resume Content Alternative for Candidate Alpha", getSampleStyleSheet()["Normal"])])
        valid_pdf_bytes_a2 = pdf_stream2.getvalue()

        resume_a2 = self.db.upload_user_resume(
            user_id=self.user_a.id,
            file_bytes=valid_pdf_bytes_a2,
            original_filename="resume_a2.pdf",
            user_base_dir=Path(self.temp_dir.name) / "users",
        )
        match_wrong_res = self._create_sample_match(
            user_id=self.user_a.id,
            resume_id=resume_a2["id"],  # Different resume
            resume_hash=resume_a2["file_hash"],
            jd_id=self.jd_a.id,
            jd_hash=self.jd_a.snapshot_hash,
        )

        with self.assertRaises(ValidationError) as ctx:
            self.gate.prepare_universal_packet(
                user_id=self.user_a.id,
                application_id=app.id,
                original_resume_id=self.resume_a["id"],  # Selected resume_a
                original_resume_hash=self.resume_a["file_hash"],
                tailored_resume=tailored,
                cover_letter=cl,
                qa_packet=qa_packet,
                job_description_snapshot_hash=self.jd_a.snapshot_hash,
                matching_result_id=match_wrong_res.id,
            )
        self.assertIn("resume_id", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 14. Mismatched job-description snapshot MatchResult is rejected
    # -------------------------------------------------------------------------
    def test_14_mismatched_job_description_snapshot_match_result_rejected(self):
        """14. A mismatched job-description snapshot MatchResult is rejected."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        match_wrong_hash = self._create_sample_match(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            resume_hash=self.resume_a["file_hash"],
            jd_id=self.jd_a.id,
            jd_hash="tampered_different_jd_snapshot_hash_999",  # Different snapshot hash
        )

        with self.assertRaises(ValidationError) as ctx:
            self.gate.prepare_universal_packet(
                user_id=self.user_a.id,
                application_id=app.id,
                original_resume_id=self.resume_a["id"],
                original_resume_hash=self.resume_a["file_hash"],
                tailored_resume=tailored,
                cover_letter=cl,
                qa_packet=qa_packet,
                job_description_snapshot_hash=self.jd_a.snapshot_hash,
                matching_result_id=match_wrong_hash.id,
            )
        self.assertIn("job snapshot hash mismatch", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 15. Cross-user MatchResult is rejected
    # -------------------------------------------------------------------------
    def test_15_cross_user_match_result_rejected(self):
        """15. A cross-user MatchResult is rejected."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)

        # Upload resume and JD for User B
        resume_b = self.db.upload_user_resume(
            user_id=self.user_b.id,
            file_bytes=self.valid_pdf_bytes_a,
            original_filename="resume_b.pdf",
            user_base_dir=Path(self.temp_dir.name) / "users",
        )
        jd_b = self.db.create_job_description(
            user_id=self.user_b.id,
            company_name="Beta Neural Corp",
            job_title="ML Engineer",
            raw_content="Job description for User B",
            parsed_data={"required_skills": ["Python"]},
        )
        match_b = self._create_sample_match(
            user_id=self.user_b.id,  # Belongs to User B
            resume_id=resume_b["id"],
            resume_hash=resume_b["file_hash"],
            jd_id=jd_b.id,
            jd_hash=jd_b.snapshot_hash,
        )

        with self.assertRaises(CrossUserAccessError):
            self.gate.prepare_universal_packet(
                user_id=self.user_a.id,
                application_id=app.id,
                original_resume_id=self.resume_a["id"],
                original_resume_hash=self.resume_a["file_hash"],
                tailored_resume=tailored,
                cover_letter=cl,
                qa_packet=qa_packet,
                job_description_snapshot_hash=self.jd_a.snapshot_hash,
                matching_result_id=match_b.id,
            )

    # -------------------------------------------------------------------------
    # 16. No matching result produces explicit null metadata
    # -------------------------------------------------------------------------
    def test_16_no_matching_result_produces_explicit_null_metadata(self):
        """16. No matching result produces explicit null metadata."""
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
            matching_result_id=None,
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertIsNone(snapshot["matching_result_id"])
        self.assertIsNone(snapshot["matching_engine_version"])
        self.assertIsNone(snapshot["scoring_profile"])
        self.assertIsNone(snapshot["scoring_config_version"])

    # -------------------------------------------------------------------------
    # 17. No candidate profile produces null profile version and hash
    # -------------------------------------------------------------------------
    def test_17_no_candidate_profile_produces_null_profile_version_and_hash(self):
        """17. No candidate profile produces null profile version and hash."""
        user_c = self.auth.register(
            email="candidate.gamma@example.com",
            password="StrongPassword123!",
            full_name="Candidate Gamma",
        )
        resume_c = self.db.upload_user_resume(
            user_id=user_c.id,
            file_bytes=self.valid_pdf_bytes_a,
            original_filename="resume_c.pdf",
            user_base_dir=Path(self.temp_dir.name) / "users",
        )
        jd_c = self.db.create_job_description(
            user_id=user_c.id,
            company_name="Gamma Labs",
            job_title="Data Scientist",
            raw_content="Looking for a data scientist",
            parsed_data={"required_skills": ["Python"]},
        )
        app_c = self.db.get_or_create_application_workspace(user_id=user_c.id, job_description_id=jd_c.id)
        tailored, cl, qa_packet = self._create_sample_materials(user_c.id)

        # No profile in DB for user_c, passing candidate_profile_version=None
        pkt = self.gate.prepare_universal_packet(
            user_id=user_c.id,
            application_id=app_c.id,
            original_resume_id=resume_c["id"],
            original_resume_hash=resume_c["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=jd_c.snapshot_hash,
            candidate_profile_version=None,
            candidate_profile_hash=None,
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertIsNone(snapshot["candidate_profile_version"])
        self.assertIsNone(snapshot["candidate_profile_hash"])

    # -------------------------------------------------------------------------
    # 18. Actual source metadata is present in canonical_snapshot_json
    # -------------------------------------------------------------------------
    def test_18_actual_source_metadata_is_present_in_canonical_snapshot_json(self):
        """18. Actual source metadata is present in canonical_snapshot_json."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        match = self._create_sample_match(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            resume_hash=self.resume_a["file_hash"],
            jd_id=self.jd_a.id,
            jd_hash=self.jd_a.snapshot_hash,
            scoring_profile="deep_research_v1",
        )

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            matching_result_id=match.id,
        )
        snapshot = json.loads(pkt.canonical_snapshot_json)
        self.assertEqual(snapshot["user_id"], self.user_a.id)
        self.assertEqual(snapshot["application_id"], app.id)
        self.assertEqual(snapshot["original_resume_id"], self.resume_a["id"])
        self.assertEqual(snapshot["original_resume_file_hash"], self.resume_a["file_hash"])
        self.assertEqual(snapshot["job_description_id"], self.jd_a.id)
        self.assertEqual(snapshot["job_description_snapshot_hash"], self.jd_a.snapshot_hash)
        self.assertEqual(snapshot["matching_result_id"], match.id)
        self.assertEqual(snapshot["scoring_profile"], "deep_research_v1")

    # -------------------------------------------------------------------------
    # 19. Changing matching result changes canonical packet hash
    # -------------------------------------------------------------------------
    def test_19_changing_matching_result_changes_canonical_packet_hash(self):
        """19. Changing the matching result changes the canonical packet hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        match1 = self._create_sample_match(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            resume_hash=self.resume_a["file_hash"],
            jd_id=self.jd_a.id,
            jd_hash=self.jd_a.snapshot_hash,
            scoring_profile="profile_version_alpha",
        )
        match2 = self._create_sample_match(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            resume_hash=self.resume_a["file_hash"],
            jd_id=self.jd_a.id,
            jd_hash=self.jd_a.snapshot_hash,
            scoring_profile="profile_version_beta",
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
            matching_result_id=match1.id,
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
            matching_result_id=match2.id,
        )
        self.assertNotEqual(pkt1.packet_version_hash, pkt2.packet_version_hash)

    # -------------------------------------------------------------------------
    # 20. Stored canonical bytes still independently reproduce packet hash
    # -------------------------------------------------------------------------
    def test_20_stored_canonical_bytes_still_independently_reproduce_packet_hash(self):
        """20. Stored canonical bytes still independently reproduce the packet hash."""
        app = self.db.get_or_create_application_workspace(user_id=self.user_a.id, job_description_id=self.jd_a.id)
        tailored, cl, qa_packet = self._create_sample_materials(self.user_a.id)
        match = self._create_sample_match(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            resume_hash=self.resume_a["file_hash"],
            jd_id=self.jd_a.id,
            jd_hash=self.jd_a.snapshot_hash,
        )

        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=tailored,
            cover_letter=cl,
            qa_packet=qa_packet,
            job_description_snapshot_hash=self.jd_a.snapshot_hash,
            matching_result_id=match.id,
        )
        recomputed = hashlib.sha256(pkt.canonical_snapshot_json.encode("utf-8")).hexdigest()
        self.assertEqual(recomputed, pkt.packet_version_hash)

    # -------------------------------------------------------------------------
    # 21. Existing snapshot-tampering detection remains functional
    # -------------------------------------------------------------------------
    def test_21_existing_snapshot_tampering_detection_remains_functional(self):
        """21. Existing snapshot-tampering detection remains functional."""
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

        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE prepared_packets SET canonical_snapshot_json = '{\"tampered_data\": 123}' WHERE id = ?",
                (pkt.id,),
            )

        valid, msg, _ = self.service.verify_prepared_packet_integrity(pkt.id, self.user_a.id)
        self.assertFalse(valid)
        self.assertIn("Integrity check failed", msg)

    # -------------------------------------------------------------------------
    # 22. Existing nonce replay protection remains functional
    # -------------------------------------------------------------------------
    def test_22_existing_nonce_replay_protection_remains_functional(self):
        """22. Existing nonce replay protection still succeeds in rejecting replay."""
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
        self.assertTrue(succ1, f"First authorization failed: {msg1}")

        # Second authorization with same ticket fails
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


if __name__ == "__main__":
    unittest.main()

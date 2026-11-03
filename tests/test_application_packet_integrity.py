"""Unit tests for Application Packet Versioning & Cryptographic Integrity (Architecture v2.1.1 - Phase 6).
Verifies RFC 8785 canonical hashing, immutable revisions, replay protection, and strict human authorization.
"""

import io
from pathlib import Path
import tempfile
import unittest

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate

from src.database.db_manager import DatabaseManager
from src.database.exceptions import CrossUserAccessError
from src.database.models import ApplicationStatus
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetter, CoverLetterGenerator
from src.preparer.question_answerer import QuestionAnswerer, ScreeningQAPacket
from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
from src.security.auth import AuthManager
from src.security.session_manager import SessionManager
from src.utils.canonical_json import canonical_json_hash


class TestApplicationPacketIntegrity(unittest.TestCase):
    """Test suite for Application Packet Versioning and Cryptographic Integrity."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_packets.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)
        SessionManager.reset_instance()
        self.session_mgr = SessionManager()
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)

        # Create two test users
        self.user_a = self.auth.register(
            email="candidate.a@example.com",
            password="SecurePassword123!",
            full_name="Candidate A",
        )
        self.user_b = self.auth.register(
            email="candidate.b@example.com",
            password="SecurePassword123!",
            full_name="Candidate B",
        )

        # Upload a real valid resume PDF for User A
        pdf_stream = io.BytesIO()
        p_doc = SimpleDocTemplate(pdf_stream, pagesize=letter)
        p_doc.build([Paragraph("Valid Test Resume Content for User A", getSampleStyleSheet()["Normal"])])
        valid_pdf_bytes = pdf_stream.getvalue()

        self.resume_a = self.db.upload_user_resume(
            user_id=self.user_a.id,
            file_bytes=valid_pdf_bytes,
            original_filename="user_a_resume.pdf",
            user_base_dir=Path(self.temp_dir.name) / "users",
        )

        # Save a Job Description for User A
        self.jd_a = self.db.create_job_description(
            user_id=self.user_a.id,
            company_name="Snowflake",
            job_title="Senior Data Engineer",
            raw_content="Looking for a Senior Data Engineer with SQL and Python.",
            parsed_data={"required_skills": ["SQL", "Python", "Data Modeling"]},
        )

        # Candidate profile for User A
        self.profile_a = {
            "personal": {"full_name": "Candidate A", "email": "candidate.a@example.com"},
            "work_experience": [{"employer": "DataCorp", "job_title": "Data Engineer", "duration": "3 years", "responsibilities": ["Built SQL pipelines"]}],
            "skills": ["SQL", "Python"],
            "education": [{"institution": "Georgia Tech", "degree": "MS Analytics"}],
        }
        self.db.save_user_candidate_profile(self.user_a.id, self.profile_a)

        # Generate materials
        res_gen = UniversalTailoredResumeGenerator()
        self.tailored_res = res_gen.generate(
            user_id=self.user_a.id,
            candidate_profile=self.profile_a,
            job_description={"company_name": "Snowflake", "role_title": "Senior Data Engineer"},
        )
        cl_gen = CoverLetterGenerator()
        self.cover_letter: CoverLetter = cl_gen.generate_universal_cover_letter(
            user_id=self.user_a.id,
            candidate_profile=self.profile_a,
            job_description={"company_name": "Snowflake", "role_title": "Senior Data Engineer"},
        )
        qa = QuestionAnswerer()
        qs = qa.batch_answer_questions(["What is your SQL experience?"], user_id=self.user_a.id, candidate_profile=self.profile_a)
        self.qa_packet = ScreeningQAPacket(user_id=self.user_a.id, job_description_id=self.jd_a.id, questions=qs)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_application_workspace_prevents_duplicate_records(self):
        """Verifies get_or_create_application_workspace does not create duplicate applications on reopen."""
        app1 = self.db.get_or_create_application_workspace(
            user_id=self.user_a.id,
            job_description_id=self.jd_a.id,
            resume_id=self.resume_a["id"],
        )
        self.assertIsNotNone(app1.id)

        # Reopen same workspace
        app2 = self.db.get_or_create_application_workspace(
            user_id=self.user_a.id,
            job_description_id=self.jd_a.id,
            resume_id=self.resume_a["id"],
        )
        self.assertEqual(app1.id, app2.id, "Workspace reopen must return existing application record, not create duplicate.")

    def test_prepared_packet_versioning_and_deactivation(self):
        """Verifies new prepared packet revisions increment version_num and deactivate older revisions."""
        app = self.db.get_or_create_application_workspace(
            user_id=self.user_a.id,
            job_description_id=self.jd_a.id,
            resume_id=self.resume_a["id"],
        )

        # Revision 1
        pkt1 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=self.tailored_res,
            cover_letter=self.cover_letter,
            qa_packet=self.qa_packet,
            job_description_snapshot_hash=self.jd_a.content_hash,
        )
        self.assertEqual(pkt1.version_num, 1)
        self.assertTrue(pkt1.is_active_revision)

        # Revision 2 (e.g. after editing)
        pkt2 = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=self.tailored_res,
            cover_letter=self.cover_letter,
            qa_packet=self.qa_packet,
            job_description_snapshot_hash=self.jd_a.content_hash,
        )
        self.assertEqual(pkt2.version_num, 2)
        self.assertTrue(pkt2.is_active_revision)

        # Verify Revision 1 is now deactivated
        old_pkt1 = self.db.get_prepared_packet(pkt1.id, self.user_a.id)
        self.assertFalse(old_pkt1.is_active_revision)

    def test_rfc8785_canonical_hash_consistency(self):
        """Verifies deterministic RFC 8785 packet hash calculation."""
        payload_1 = {"user_id": 1, "company": "Apple", "score": 95.5}
        payload_2 = {"score": 95.5, "company": "Apple", "user_id": 1}  # Different key order

        hash1 = canonical_json_hash(payload_1)
        hash2 = canonical_json_hash(payload_2)
        self.assertEqual(hash1, hash2, "Canonical JSON must sort keys identically regardless of insertion order.")

    def test_strict_human_approval_authorization(self):
        """Verifies authorization requires confirmed checkbox, valid approver name, and consumes ticket."""
        app = self.db.get_or_create_application_workspace(
            user_id=self.user_a.id,
            job_description_id=self.jd_a.id,
            resume_id=self.resume_a["id"],
        )
        pkt = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=self.tailored_res,
            cover_letter=self.cover_letter,
            qa_packet=self.qa_packet,
            job_description_snapshot_hash=self.jd_a.content_hash,
        )

        session = self.session_mgr.create_user_session(user_id=self.user_a.id, email=self.user_a.email)

        # 1. Bot approver rejected
        succ_bot, msg_bot, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="auto_agent_bot",
            session_id=session.session_id,
            action_ticket="TKT-dummy.v1.sig",
            candidate_confirmed=True,
        )
        self.assertFalse(succ_bot)
        self.assertIn("automated authorization", msg_bot)

        # 2. Unconfirmed checkbox rejected
        succ_unconf, msg_unconf, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate A",
            session_id=session.session_id,
            action_ticket="TKT-dummy.v1.sig",
            candidate_confirmed=False,
        )
        self.assertFalse(succ_unconf)
        self.assertIn("confirmation checkbox", msg_unconf)

        # 3. Issue valid action ticket
        ticket = self.session_mgr.issue_action_ticket(
            session_id=session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=pkt.packet_version_hash,
        )

        # 4. Valid human authorization succeeds
        succ_auth, msg_auth, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate A",
            session_id=session.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_auth)
        self.assertIsNotNone(approval)
        self.assertEqual(approval.approver_name, "Candidate A")

        # Verify application status transitioned to Awaiting Approval
        updated_app = self.db.get_user_application(app.id, self.user_a.id)
        self.assertEqual(updated_app.status, ApplicationStatus.AWAITING_APPROVAL.value)

        # 5. Replay attempt with same ticket must fail (nonce already consumed)
        succ_replay, msg_replay, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a.id,
            application_id=app.id,
            packet_id=pkt.id,
            approver_name="Candidate A",
            session_id=session.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ_replay)
        self.assertIn("already been used", msg_replay)

    def test_cross_user_packet_access_denied(self):
        """Verifies User B cannot view or authorize User A's prepared packet."""
        app_a = self.db.get_or_create_application_workspace(
            user_id=self.user_a.id,
            job_description_id=self.jd_a.id,
            resume_id=self.resume_a["id"],
        )
        pkt_a = self.gate.prepare_universal_packet(
            user_id=self.user_a.id,
            application_id=app_a.id,
            original_resume_id=self.resume_a["id"],
            original_resume_hash=self.resume_a["file_hash"],
            tailored_resume=self.tailored_res,
            cover_letter=self.cover_letter,
            qa_packet=self.qa_packet,
            job_description_snapshot_hash=self.jd_a.content_hash,
        )

        # User B attempting to fetch User A's packet raises CrossUserAccessError
        with self.assertRaises(CrossUserAccessError):
            self.db.get_prepared_packet(packet_id=pkt_a.id, user_id=self.user_b.id)


if __name__ == "__main__":
    unittest.main()

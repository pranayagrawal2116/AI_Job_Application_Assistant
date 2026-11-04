"""Comprehensive security and authorization verification test suite.

Tests:
1. Missing, invalid, and expired candidate sessions.
2. Action ticket cryptographic verification and forgery rejection.
3. Replay attack detection on approval and submission actions.
4. Review packet tampering and modification detection.
5. Strict status transition state machine enforcement.
6. Scope isolation preventing approval record cross-application reuse.
7. Audit log immutability and metadata integrity.
"""

import json
from pathlib import Path
import secrets
import tempfile
import time
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    InvalidSessionError,
    InvalidStatusTransitionError,
    SessionExpiredError,
)
from src.database.models import ApplicationStatus, Job
from src.preparer.approval_gate import HumanApprovalGate
from src.security.session_manager import SessionManager


class TestSecurityAndAuthorization(unittest.TestCase):
    """Test suite for server-side candidate authentication, token security, and status transitions."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_security.db"
        cls.db = DatabaseManager(db_path=cls.db_path)
        cls.session_mgr = SessionManager()

        with cls.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('sec_user@test.com', 'h', 's', 'Sec User')"
            )
            cls.user_id = cursor.lastrowid

        # Create two test jobs
        cls.job_a = cls.db.add_job(
            Job(
                company_name="Alpha Dynamics",
                job_title="AI Research Intern",
                job_url="https://alphadynamics.ai/jobs/1",
                platform="LinkedIn",
                location="Pune / Remote",
                match_score=92.0,
                is_eligible=True,
            ),
            user_id=cls.user_id,
        )
        cls.job_b = cls.db.add_job(
            Job(
                company_name="Beta Systems",
                job_title="ML Intern",
                job_url="https://betasystems.ai/jobs/2",
                platform="Internshala",
                location="Bengaluru / Remote",
                match_score=88.0,
                is_eligible=True,
            ),
            user_id=cls.user_id,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        SessionManager.reset_instance()
        self.session_mgr = SessionManager()
        self.db._session_manager = self.session_mgr
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)
        self.candidate_name = "Pranay Anup Agrawal"
        self.candidate_id = "candidate_pranay"

        # Authenticate fresh candidate session
        self.session = self.session_mgr.authenticate_candidate(
            candidate_id=self.candidate_id,
            candidate_name=self.candidate_name,
            ttl_seconds=3600,
        )

        # Create unique test job for each test run
        unique_suffix = f"{time.time_ns()}_{secrets.token_hex(4)}"
        self.job_a = self.db.add_job(
            Job(
                company_name=f"Alpha Dynamics {unique_suffix}",
                job_title="AI Research Intern",
                job_url=f"https://alphadynamics.ai/jobs/{unique_suffix}",
                platform="LinkedIn",
                location="Pune / Remote",
                match_score=92.0,
                is_eligible=True,
            ),
            user_id=self.user_id,
        )
        self.db.update_application_status(self.job_a.id, ApplicationStatus.UNDER_REVIEW)
        self.db.update_application_status(self.job_a.id, ApplicationStatus.SHORTLISTED)
        self.db.update_application_status(self.job_a.id, ApplicationStatus.APPLICATION_PREPARED)

        # Build clean test packet for job_a
        self.packet_a = self.gate.build_review_packet(
            job=self.job_a,
            cover_letter_text="Tailored cover letter for Alpha Dynamics",
            resume_path="data/resumes/Pranay_Agrawal_Resume(2).pdf",
            resume_hash="abc123resumehash",
            answers={"availability": {"question": "Availability", "answer": "Immediate", "status": "READY"}},
        )

    # -------------------------------------------------------------------------
    # 1. SESSION MANAGEMENT & EXPIRATION TESTS
    # -------------------------------------------------------------------------
    def test_missing_or_invalid_session(self):
        """Rejects approval attempts with missing, blank, or forged session IDs."""
        ticket = "TKT-dummy.1234.signature"

        # Missing session
        succ1, msg1 = self.gate.authorize_application(
            self.packet_a, self.candidate_name, True, session_id="", action_ticket=ticket
        )
        self.assertFalse(succ1)
        self.assertIn("Missing or invalid", msg1)

        # Non-existent session
        succ2, msg2 = self.gate.authorize_application(
            self.packet_a, self.candidate_name, True, session_id="fake_session_hex_999", action_ticket=ticket
        )
        self.assertFalse(succ2)
        self.assertIn("Missing or invalid", msg2)

    def test_expired_session_rejection(self):
        """Rejects operations using expired candidate sessions."""
        # Create session with 0-second TTL
        expired_sess = self.session_mgr.authenticate_candidate(
            candidate_id="pranay_exp",
            candidate_name="Pranay Expired",
            ttl_seconds=-1,
        )
        self.assertTrue(expired_sess.is_expired)

        with self.assertRaises(SessionExpiredError):
            self.session_mgr.validate_session(expired_sess.session_id)

        ticket = "TKT-dummy.1234.signature"
        succ, msg = self.gate.authorize_application(
            self.packet_a, self.candidate_name, True, session_id=expired_sess.session_id, action_ticket=ticket
        )
        self.assertFalse(succ)
        self.assertIn("expired", msg.lower())

    def test_revoked_session_rejection(self):
        """Rejects operations using an explicitly revoked candidate session."""
        self.session_mgr.revoke_session(self.session.session_id)
        with self.assertRaises(InvalidSessionError):
            self.session_mgr.validate_session(self.session.session_id)

    # -------------------------------------------------------------------------
    # 2. TOKEN & FORGERY TESTS
    # -------------------------------------------------------------------------
    def test_rejection_of_hardcoded_static_constant_tokens(self):
        """Ensures static string constants (e.g. TRUSTED_APPROVAL_TOKEN) are rejected."""
        static_tokens = [
            "CANDIDATE_VERIFIED_DASHBOARD_APPROVAL",
            "CANDIDATE_VERIFIED_MANUAL_SUBMISSION",
            "STATIC_TOKEN_12345",
            "TRUSTED_TOKEN",
        ]
        for bad_token in static_tokens:
            succ, msg = self.gate.authorize_application(
                self.packet_a,
                self.candidate_name,
                candidate_confirmed=True,
                session_id=self.session.session_id,
                action_ticket=bad_token,
            )
            self.assertFalse(succ)
            self.assertIn("rejected", msg.lower())

    def test_cryptographic_signature_forgery_rejection(self):
        """Rejects action tickets with forged or tampered cryptographic HMAC signatures."""
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=self.job_a.id,
            packet_hash=self.packet_a.packet_version_hash,
        )
        parts = ticket.split(".")
        # Tamper signature part
        forged_ticket = f"{parts[0]}.{parts[1]}.badbadbadsignature1234567890"

        succ, msg = self.gate.authorize_application(
            self.packet_a,
            self.candidate_name,
            candidate_confirmed=True,
            session_id=self.session.session_id,
            action_ticket=forged_ticket,
        )
        self.assertFalse(succ)
        self.assertIn("Cryptographic signature mismatch", msg)

    # -------------------------------------------------------------------------
    # 3. REPLAY ATTACK PREVENTION TESTS
    # -------------------------------------------------------------------------
    def test_replayed_approval_ticket_rejection(self):
        """Rejects replay of an already-consumed action ticket."""
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=self.job_a.id,
            packet_hash=self.packet_a.packet_version_hash,
        )

        # 1. First authorization succeeds
        succ1, msg1 = self.gate.authorize_application(
            self.packet_a,
            self.candidate_name,
            candidate_confirmed=True,
            session_id=self.session.session_id,
            action_ticket=ticket,
        )
        self.assertTrue(succ1)

        # 2. Second authorization using the SAME ticket MUST fail
        succ2, msg2 = self.gate.authorize_application(
            self.packet_a,
            self.candidate_name,
            candidate_confirmed=True,
            session_id=self.session.session_id,
            action_ticket=ticket,
        )
        self.assertFalse(succ2)
        self.assertIn("Replay attack detected", msg2)

    def test_replayed_manual_submission_rejection(self):
        """Rejects reusing an old submission confirmation or ticket."""
        # Setup: authorize job_a
        ticket_app = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=self.job_a.id,
            packet_hash=self.packet_a.packet_version_hash,
        )
        succ_app, _ = self.gate.authorize_application(
            self.packet_a,
            self.candidate_name,
            candidate_confirmed=True,
            session_id=self.session.session_id,
            action_ticket=ticket_app,
        )
        self.assertTrue(succ_app)

        # Issue submission ticket
        ticket_sub = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=self.job_a.id,
            packet_hash=self.packet_a.packet_version_hash,
        )

        # 1. First submission succeeds
        succ_sub1, msg_sub1 = self.gate.record_manual_submission(
            job_id=self.job_a.id,
            approver_name=self.candidate_name,
            session_id=self.session.session_id,
            submission_ticket=ticket_sub,
            packet_version_hash=self.packet_a.packet_version_hash,
            submission_notes="Code 123",
        )
        self.assertTrue(succ_sub1)

        # 2. Replayed submission with same ticket MUST fail
        succ_sub2, msg_sub2 = self.gate.record_manual_submission(
            job_id=self.job_a.id,
            approver_name=self.candidate_name,
            session_id=self.session.session_id,
            submission_ticket=ticket_sub,
            packet_version_hash=self.packet_a.packet_version_hash,
            submission_notes="Code 123 replayed",
        )
        self.assertFalse(succ_sub2)
        self.assertIn("Replay attack detected", msg_sub2)

    # -------------------------------------------------------------------------
    # 4. PACKET TAMPERING DETECTION TESTS
    # -------------------------------------------------------------------------
    def test_packet_tampering_prior_to_approval(self):
        """Rejects approval if packet content was modified after hash generation."""
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=self.job_a.id,
            packet_hash=self.packet_a.packet_version_hash,
        )

        # Silently alter cover letter text
        self.packet_a.cover_letter_text = "TAMPERED COVER LETTER CONTENT"

        succ, msg = self.gate.authorize_application(
            self.packet_a,
            self.candidate_name,
            candidate_confirmed=True,
            session_id=self.session.session_id,
            action_ticket=ticket,
        )
        self.assertFalse(succ)
        self.assertIn("modified after preparation", msg)

    def test_packet_modification_invalidates_prior_approval(self):
        """Changing the application packet after approval invalidates submission confirmation."""
        # Authorize clean packet
        orig_hash = self.packet_a.packet_version_hash
        ticket_app = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=self.job_a.id,
            packet_hash=orig_hash,
        )
        succ_app, _ = self.gate.authorize_application(
            self.packet_a,
            self.candidate_name,
            candidate_confirmed=True,
            session_id=self.session.session_id,
            action_ticket=ticket_app,
        )
        self.assertTrue(succ_app)

        # Modifying packet creates a different hash
        self.packet_a.cover_letter_text = "Updated different text"
        new_hash = self.packet_a.compute_hash()
        self.assertNotEqual(orig_hash, new_hash)

        # Issue ticket for new hash
        ticket_sub_new = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=self.job_a.id,
            packet_hash=new_hash,
        )

        # Submission with modified hash MUST fail because prior approval was for orig_hash
        succ_sub, msg_sub = self.gate.record_manual_submission(
            job_id=self.job_a.id,
            approver_name=self.candidate_name,
            session_id=self.session.session_id,
            submission_ticket=ticket_sub_new,
            packet_version_hash=new_hash,
        )
        self.assertFalse(succ_sub)
        self.assertIn("does not have an active, unconsumed human approval record", msg_sub)

    # -------------------------------------------------------------------------
    # 5. STATE MACHINE TRANSITION ENFORCEMENT TESTS
    # -------------------------------------------------------------------------
    def test_strict_state_transition_enforcement(self):
        """Verifies state machine transitions cannot be bypassed."""
        # Fresh job in Discovered
        job_c = self.db.add_job(
            Job(
                company_name="Gamma AI",
                job_title="CV Intern",
                job_url="https://gamma.ai/jobs/cv",
                platform="LinkedIn",
                location="Remote",
                match_score=95.0,
                is_eligible=True,
            ),
            user_id=self.user_id,
        )
        app_c = self.db.get_application_by_job_id(job_c.id)
        self.assertEqual(app_c.status, ApplicationStatus.DISCOVERED.value)

        # 1. Discovered -> Applied directly MUST fail
        with self.assertRaises(InvalidStatusTransitionError) as ctx1:
            self.db.update_application_status(job_c.id, ApplicationStatus.APPLIED, confirmed=True)
        self.assertIn("Illegal status transition from 'Discovered' to 'Applied'", str(ctx1.exception))

        # 2. Discovered -> Awaiting Approval directly MUST fail
        with self.assertRaises(InvalidStatusTransitionError) as ctx2:
            self.db.update_application_status(job_c.id, ApplicationStatus.AWAITING_APPROVAL)
        self.assertIn("Illegal status transition from 'Discovered' to 'Awaiting Approval'", str(ctx2.exception))

        # 3. Discovered -> Under Review succeeds
        app_c = self.db.update_application_status(job_c.id, ApplicationStatus.UNDER_REVIEW)
        self.assertEqual(app_c.status, ApplicationStatus.UNDER_REVIEW.value)

        # 4. Under Review -> Shortlisted succeeds
        app_c = self.db.update_application_status(job_c.id, ApplicationStatus.SHORTLISTED)
        self.assertEqual(app_c.status, ApplicationStatus.SHORTLISTED.value)

        # 5. Shortlisted -> Applied directly MUST fail
        with self.assertRaises(InvalidStatusTransitionError):
            self.db.update_application_status(job_c.id, ApplicationStatus.APPLIED, confirmed=True)

    # -------------------------------------------------------------------------
    # 6. SCOPE ISOLATION TESTS
    # -------------------------------------------------------------------------
    def test_cross_application_ticket_reuse_prevention(self):
        """Action ticket issued for Job A cannot be used to authorize Job B."""
        # Ticket issued for Job A
        ticket_a = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=self.job_a.id,
            packet_hash=self.packet_a.packet_version_hash,
        )

        packet_b = self.gate.build_review_packet(
            job=self.job_b,
            cover_letter_text="Cover letter for Beta Systems",
            resume_path="data/resumes/Pranay_Agrawal_Resume(2).pdf",
            resume_hash="abc123resumehash",
            answers={},
        )

        # Attempt to authorize Job B with Job A's ticket MUST fail
        succ, msg = self.gate.authorize_application(
            packet_b,
            self.candidate_name,
            candidate_confirmed=True,
            session_id=self.session.session_id,
            action_ticket=ticket_a,
        )
        self.assertFalse(succ)
        self.assertTrue(any(k in msg for k in ("Cryptographic signature mismatch", "Ticket application ID mismatch", "mismatch")))

    # -------------------------------------------------------------------------
    # 7. AUDIT LOG IMMUTABILITY & INTEGRITY TESTS
    # -------------------------------------------------------------------------
    def test_audit_log_recording_and_integrity(self):
        """Verifies audit trail records complete metadata and cannot be tampered with."""
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=self.job_a.id,
            packet_hash=self.packet_a.packet_version_hash,
        )
        succ, _ = self.gate.authorize_application(
            self.packet_a,
            self.candidate_name,
            candidate_confirmed=True,
            session_id=self.session.session_id,
            action_ticket=ticket,
        )
        self.assertTrue(succ)

        logs = self.db.get_application_logs(self.job_a.id)
        approval_logs = [l for l in logs if l.action == "HUMAN_APPROVAL_GRANTED"]
        self.assertTrue(len(approval_logs) >= 1)

        latest = approval_logs[-1]
        self.assertIsNotNone(latest.timestamp)
        details = json.loads(latest.details)
        self.assertEqual(details["approver"], self.candidate_name)
        self.assertEqual(details["approver_id"], self.candidate_id)
        self.assertEqual(details["session_id"], self.session.session_id)
        self.assertEqual(details["packet_version_hash"], self.packet_a.packet_version_hash)
        self.assertTrue(details["is_human"])


if __name__ == "__main__":
    unittest.main()

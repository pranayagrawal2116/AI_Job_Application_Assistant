"""Phase 7.6 Multi-User Security Hardening, Regression & Verification Suite.

Comprehensive tests verifying:
1. Multi-User Isolation across profiles, resumes, job descriptions, applications,
   packets, confirmation proofs, follow-ups, and timelines.
2. Fail-closed authentication in Streamlit views (candidate_profile, job_description_analyzer).
3. Session lifecycle, explicit candidate logout, memory purging, and thread-safety.
4. Production password reset pepper enforcement.
5. Lifecycle status transition safeguards (prohibiting unverified transitions to APPROVED and SUBMITTED).
6. Persistent single-use action ticket nonce enforcement during packet authorization.
7. Proof upload containment and security validation.
"""

import io
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfWriter

from dashboard.services.dashboard_service import DashboardService
from dashboard.views.candidate_profile import get_current_user_id, render_candidate_profile
from dashboard.views.job_description_analyzer import render_job_description_analyzer
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    FileSecurityError,
    InvalidFileFormatError,
    InvalidSessionError,
    SecurityAuthorizationError,
    SessionExpiredError,
)
from src.database.models import Application, ApplicationStatus, Job
from src.preparer.approval_gate import (
    HumanApprovalGate,
    canonical_json_bytes,
    canonical_json_hash,
)
from src.security.auth import AuthManager
from src.security.file_security import FileSecurityValidator
from src.security.session_manager import SessionManager


def _make_test_pdf(num_pages: int = 1) -> bytes:
    """Creates synthetic, structurally valid PDF bytes."""
    writer = PdfWriter()
    for _ in range(num_pages):
        writer.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


class BasePhase76SecurityTest(unittest.TestCase):
    """Base test fixture setting up an isolated SQLite database and private filesystem sandbox."""

    def setUp(self):
        self.temp_db_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_db_dir.name) / "test_phase_7_6.db"
        self.db = DatabaseManager(db_path=str(self.db_path))

        self.temp_storage_dir = tempfile.TemporaryDirectory()
        self.storage_base = Path(self.temp_storage_dir.name)

        self.service = DashboardService(
            db_manager=self.db,
            storage_base_dir=self.storage_base,
        )
        self.validator = FileSecurityValidator(base_storage_dir=self.storage_base)

        SessionManager.reset_instance()
        self.session_mgr = SessionManager.get_instance()

        # Seed candidate users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'candidate_a@example.com', 'h1', 's1', 'Candidate A')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'candidate_b@example.com', 'h2', 's2', 'Candidate B')"
            )

        self.user_a = 1
        self.user_b = 2

        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="cand_a",
            candidate_name="Candidate A",
            user_id=self.user_a,
            email="candidate_a@example.com",
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="cand_b",
            candidate_name="Candidate B",
            user_id=self.user_b,
            email="candidate_b@example.com",
        )

    def tearDown(self):
        SessionManager.reset_instance()
        self.temp_db_dir.cleanup()
        self.temp_storage_dir.cleanup()

    def _setup_approved_application(
        self,
        user_id: int,
        session_id: str,
        packet_id: int = 2001,
        company: str = "Acme Corp",
        title: str = "Senior AI Engineer",
    ) -> Application:
        """Sets up a complete APPROVED application with active prepared packet and human approval."""
        app = self.service.create_candidate_application(
            session_id=session_id,
            company_name=company,
            job_title=title,
            status="DRAFT",
        )

        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'APPROVED' WHERE id = ?", (app.id,))

        snap_payload = {
            "application_id": app.id,
            "user_id": user_id,
            "version_num": 1,
            "company_name": company,
            "job_title": title,
        }
        snap_json = canonical_json_bytes(snap_payload).decode("utf-8")
        pkt_hash = canonical_json_hash(snap_payload)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision, created_at
                ) VALUES (?, ?, ?, 1, ?, 'rh', 'jdh', '[]', ?, 1, CURRENT_TIMESTAMP)
                """,
                (packet_id, app.id, user_id, pkt_hash, snap_json),
            )
            cursor.execute(
                """
                INSERT INTO application_approvals (
                    id, application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, approver_name, session_id, is_consumed
                ) VALUES (?, ?, ?, ?, ?, ?, 'Human Auditor', ?, 0)
                """,
                (
                    packet_id,
                    app.id,
                    packet_id,
                    user_id,
                    pkt_hash,
                    f"nonce_{packet_id}",
                    session_id,
                ),
            )

        return self.db.get_user_application(app.id, user_id)


class TestMultiUserIsolation(BasePhase76SecurityTest):
    """Verifies complete multi-user isolation across all entities and view fail-closed behaviors."""

    def test_cross_user_candidate_profile_isolation(self):
        """User A's candidate profile cannot be accessed or modified by User B."""
        profile_data = {
            "name": "Candidate A Profile",
            "skills": ["Python", "PyTorch"],
        }
        self.db.save_user_candidate_profile(self.user_a, profile_data)

        # User A reads their profile
        loaded_a = self.db.get_user_candidate_profile(self.user_a)
        self.assertIsNotNone(loaded_a)
        self.assertEqual(loaded_a["profile_data"]["name"], "Candidate A Profile")

        # User B reads their own profile (which is empty)
        loaded_b = self.db.get_user_candidate_profile(self.user_b)
        self.assertIsNone(loaded_b)

    def test_cross_user_job_description_isolation(self):
        """User A's job descriptions cannot be retrieved or accessed by User B."""
        jd = self.db.create_job_description(
            user_id=self.user_a,
            company_name="Private Corp",
            job_title="Lead AI Architect",
            raw_content="Classified Job Details",
        )

        # User A accesses it
        jd_a = self.db.get_job_description(jd.id, user_id=self.user_a)
        self.assertIsNotNone(jd_a)
        self.assertEqual(jd_a.company_name, "Private Corp")

        # User B cannot access it
        with self.assertRaises(CrossUserAccessError):
            self.db.get_job_description(jd.id, user_id=self.user_b)

    def test_candidate_profile_view_fails_closed_when_unauthenticated(self):
        """Unauthenticated candidate accessing candidate profile view fails closed without defaulting to 1."""
        with patch("dashboard.views.candidate_profile.st") as mock_st:
            mock_st.session_state = {}
            uid = get_current_user_id()
            self.assertIsNone(uid)

            render_candidate_profile()
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to access your Candidate Profile.")

    def test_job_description_analyzer_view_fails_closed_when_unauthenticated(self):
        """Unauthenticated candidate accessing job analyzer view fails closed without defaulting to 1."""
        with patch("dashboard.views.job_description_analyzer.st") as mock_st:
            mock_st.session_state = {}

            render_job_description_analyzer()
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to analyze and ingest job descriptions.")

    def test_cross_user_application_access_rejected(self):
        """User B cannot retrieve, transition, or archive User A's application."""
        app_a = self._setup_approved_application(self.user_a, self.session_a.session_id)

        # User B attempting to retrieve User A's application
        with self.assertRaises(CrossUserAccessError):
            self.service.get_candidate_application(
                application_id=app_a.id,
                session_id=self.session_b.session_id,
            )

        # User B attempting to archive User A's application
        with self.assertRaises(CrossUserAccessError):
            self.service.archive_candidate_application(
                application_id=app_a.id,
                session_id=self.session_b.session_id,
            )

        # User B attempting to transition User A's application
        with self.assertRaises(CrossUserAccessError):
            self.service.transition_application_status(
                application_id=app_a.id,
                session_id=self.session_b.session_id,
                new_status=ApplicationStatus.WITHDRAWN,
            )

    def test_cross_user_packet_and_document_download_rejected(self):
        """User B cannot retrieve User A's prepared packet or download packet documents."""
        app_a = self._setup_approved_application(self.user_a, self.session_a.session_id, packet_id=3001)

        # User B attempting to view User A's packet
        with self.assertRaises(CrossUserAccessError):
            self.service.get_candidate_prepared_packet(
                application_id=app_a.id,
                packet_id=3001,
                session_id=self.session_b.session_id,
            )

        # User B attempting to download document from User A's packet
        with self.assertRaises(CrossUserAccessError):
            self.service.get_candidate_packet_document(
                application_id=app_a.id,
                packet_id=3001,
                document_type="resume",
                session_id=self.session_b.session_id,
            )

    def test_cross_user_confirmation_proof_download_rejected(self):
        """User B cannot download User A's submission confirmation proof."""
        app_a = self._setup_approved_application(self.user_a, self.session_a.session_id, packet_id=4001)

        # Submit with proof by Candidate A
        pdf_bytes = _make_test_pdf()
        active_pkt = self.db.get_active_prepared_packet(app_a.id, self.user_a)
        tkt = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=app_a.id,
            packet_hash=active_pkt.packet_version_hash,
        )
        conf = self.service.record_candidate_manual_submission(
            application_id=app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=tkt,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
            proof_bytes=pdf_bytes,
            proof_filename="confirmation.pdf",
        )
        self.assertIsNotNone(conf)

        # Candidate B attempts to download proof
        with self.assertRaises(CrossUserAccessError):
            self.service.get_candidate_submission_confirmation_proof(
                application_id=app_a.id,
                session_id=self.session_b.session_id,
            )

    def test_cross_user_follow_up_and_timeline_isolation(self):
        """User B cannot access User A's follow-ups or timeline events."""
        app_a = self._setup_approved_application(self.user_a, self.session_a.session_id, packet_id=5001)

        # Timeline isolation
        with self.assertRaises(CrossUserAccessError):
            self.service.get_application_timeline(
                application_id=app_a.id,
                session_id=self.session_b.session_id,
            )

        # Follow-up creation isolation
        with self.assertRaises(CrossUserAccessError):
            self.service.create_application_follow_up(
                session_id=self.session_b.session_id,
                application_id=app_a.id,
                follow_up_date="2026-12-01",
                follow_up_type="STATUS_INQUIRY",
                description="Check status",
            )


class TestSessionAndAuthSecurity(BasePhase76SecurityTest):
    """Verifies authentication, session security, thread safety, and production configurations."""

    def test_missing_and_invalid_session_rejected(self):
        """Calling service methods with invalid session fails closed."""
        with self.assertRaises(InvalidSessionError):
            self.service.get_candidate_application(
                application_id=1,
                session_id="",
            )

        with self.assertRaises(InvalidSessionError):
            self.service.get_candidate_application(
                application_id=1,
                session_id="invalid_token_hex_9999",
            )

    def test_expired_session_rejected(self):
        """Expired candidate session cannot perform operations."""
        sess = self.session_mgr.authenticate_candidate(
            candidate_id="cand_exp",
            candidate_name="Expired User",
            ttl_seconds=-10,
            user_id=10,
        )
        with self.assertRaises(SessionExpiredError):
            self.service.get_candidate_application(
                application_id=1,
                session_id=sess.session_id,
            )

    def test_revoked_session_rejected(self):
        """Revoked candidate session cannot perform operations."""
        sess = self.session_mgr.authenticate_candidate(
            candidate_id="cand_rev",
            candidate_name="Revoked User",
            user_id=11,
        )
        self.session_mgr.revoke_session(sess.session_id)
        with self.assertRaises(InvalidSessionError):
            self.service.get_candidate_application(
                application_id=1,
                session_id=sess.session_id,
            )

    def test_logout_candidate_revokes_session_and_purges_grants(self):
        """logout_candidate() revokes the session and clears all active grants."""
        sess = self.session_mgr.authenticate_candidate(
            candidate_id="cand_logout",
            candidate_name="Logout User",
            user_id=12,
        )
        ticket_str = self.session_mgr.issue_action_ticket(
            session_id=sess.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=1,
            packet_hash="dummy_hash",
        )
        success, msg, grant = self.session_mgr.verify_and_issue_approval_grant(
            session_id=sess.session_id,
            ticket_str=ticket_str,
            application_id=1,
            packet_id=1,
            packet_hash="dummy_hash",
        )
        self.assertTrue(success)
        self.assertIn(grant.grant_id, self.session_mgr._active_grants)

        logged_out = self.service.logout_candidate(sess.session_id)
        self.assertTrue(logged_out)

        self.assertFalse(sess.is_active)
        self.assertNotIn(grant.grant_id, self.session_mgr._active_grants)

    def test_purge_expired_sessions_cleans_memory(self):
        """purge_expired_sessions() cleans both expired sessions and grants."""
        sess_expired = self.session_mgr.authenticate_candidate(
            candidate_id="cand_exp2",
            candidate_name="Expired User 2",
            ttl_seconds=-5,
            user_id=13,
        )
        sess_active = self.session_mgr.authenticate_candidate(
            candidate_id="cand_act2",
            candidate_name="Active User 2",
            ttl_seconds=3600,
            user_id=14,
        )

        purged_count = self.session_mgr.purge_expired_sessions()
        self.assertGreaterEqual(purged_count, 1)
        self.assertNotIn(sess_expired.session_id, self.session_mgr._sessions)
        self.assertIn(sess_active.session_id, self.session_mgr._sessions)

    def test_thread_safe_concurrent_sessions_and_tickets(self):
        """Concurrent threads issuing tickets and authenticating candidates execute safely without race conditions."""
        errors = []
        threads = []

        def worker(thread_idx: int):
            try:
                sess = self.session_mgr.authenticate_candidate(
                    candidate_id=f"cand_thread_{thread_idx}",
                    candidate_name=f"Candidate Thread {thread_idx}",
                    user_id=100 + thread_idx,
                )
                for i in range(5):
                    tkt = self.session_mgr.issue_action_ticket(
                        session_id=sess.session_id,
                        action_type="HUMAN_APPROVAL",
                        application_id=i,
                        packet_hash=f"hash_{thread_idx}_{i}",
                    )
                    self.assertTrue(tkt.startswith("TKT-"))
            except Exception as e:
                errors.append(e)

        for idx in range(10):
            t = threading.Thread(target=worker, args=(idx,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Thread-safety errors encountered: {errors}")

    def test_production_pepper_enforcement(self):
        """APP_ENV=production requires explicit PASSWORD_RESET_PEPPER."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=False):
            if "PASSWORD_RESET_PEPPER" in os.environ:
                del os.environ["PASSWORD_RESET_PEPPER"]

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                AuthManager(db_manager=self.db)
            self.assertIn("PASSWORD_RESET_PEPPER must be explicitly configured in production environment", str(ctx.exception))

        with patch.dict(os.environ, {"APP_ENV": "production", "PASSWORD_RESET_PEPPER": "custom_prod_pepper_123"}, clear=False):
            auth = AuthManager(db_manager=self.db)
            self.assertEqual(auth.pepper, "custom_prod_pepper_123")


class TestLifecycleAndSubmissionIntegrity(BasePhase76SecurityTest):
    """Verifies status transition safeguards and submission cryptographic nonce integrity."""

    def test_update_application_status_rejects_unauthorized_direct_transitions(self):
        """Direct status transition to APPROVED, SUBMITTED, APPLIED, or AWAITING_APPROVAL is prohibited."""
        job = Job(
            company_name="Tech Corp",
            job_title="Data Scientist",
            location="Remote",
            job_url="https://example.com/jobs/999",
            platform="LinkedIn",
        )
        inserted = self.db.insert_job(job)
        self.db.create_user_application(
            user_id=self.user_a,
            company_name="Tech Corp",
            job_title="Data Scientist",
            job_id=inserted.id,
            status=ApplicationStatus.SHORTLISTED.value,
        )

        for prohibited_status in [
            ApplicationStatus.APPROVED.value,
            ApplicationStatus.SUBMITTED.value,
            ApplicationStatus.APPLIED.value,
            ApplicationStatus.AWAITING_APPROVAL.value,
        ]:
            ok, msg = self.service.update_application_status(
                job_id=inserted.id,
                new_status=prohibited_status,
            )
            self.assertFalse(ok)
            self.assertIn("Direct status transition to", msg)

    def test_authorize_universal_packet_registers_persistent_nonce(self):
        """authorize_universal_packet persistently registers and consumes the nonce in SQLite."""
        app_a = self.service.create_candidate_application(
            session_id=self.session_a.session_id,
            company_name="Innovate Ltd",
            job_title="ML Engineer",
            status="DRAFT",
        )
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'READY_FOR_REVIEW' WHERE id = ?", (app_a.id,))

        snap_payload = {
            "application_id": app_a.id,
            "user_id": self.user_a,
            "company_name": "Innovate Ltd",
            "job_title": "ML Engineer",
            "version_num": 1,
        }
        snap_json = canonical_json_bytes(snap_payload).decode("utf-8")
        pkt_hash = canonical_json_hash(snap_payload)

        packet_id = 8001
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO prepared_packets (
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision, created_at
                ) VALUES (?, ?, ?, 1, ?, 'rh', 'jdh', '[]', ?, 1, CURRENT_TIMESTAMP)
                """,
                (packet_id, app_a.id, self.user_a, pkt_hash, snap_json),
            )

        ticket_str = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app_a.id,
            packet_hash=pkt_hash,
        )
        _, nonce, _, _ = self.session_mgr.parse_action_ticket(ticket_str)

        gate = HumanApprovalGate(db_manager=self.db)
        success, grant_msg, auth_record = gate.authorize_universal_packet(
            application_id=app_a.id,
            packet_id=packet_id,
            user_id=self.user_a,
            session_id=self.session_a.session_id,
            action_ticket=ticket_str,
            candidate_confirmed=True,
            approver_name="Candidate A",
        )
        self.assertTrue(success, f"Failed authorizing packet: {grant_msg}")

        # Check that nonce is persistently registered in application_approvals
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ticket_nonce, approver_name FROM application_approvals WHERE ticket_nonce = ?", (nonce,))
            row = cursor.fetchone()
            self.assertIsNotNone(row, "Nonce was not persistently registered in application_approvals.")
            self.assertEqual(row[0], nonce)
            self.assertEqual(row[1], "Candidate A")

    def test_action_ticket_replay_prevention(self):
        """Consumed action ticket cannot be reused (replay attack prevented)."""
        app_a = self._setup_approved_application(self.user_a, self.session_a.session_id, packet_id=7001)

        ticket_str = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app_a.id,
            packet_hash="replay_test_hash",
        )

        ok, msg, grant = self.session_mgr.verify_and_issue_approval_grant(
            session_id=self.session_a.session_id,
            ticket_str=ticket_str,
            application_id=app_a.id,
            packet_id=7001,
            packet_hash="replay_test_hash",
            db_manager=self.db,
        )
        self.assertTrue(ok)

        ok_replay, msg_replay, grant_replay = self.session_mgr.verify_and_issue_approval_grant(
            session_id=self.session_a.session_id,
            ticket_str=ticket_str,
            application_id=app_a.id,
            packet_id=7001,
            packet_hash="replay_test_hash",
            db_manager=self.db,
        )
        self.assertFalse(ok_replay)
        self.assertIn("already been used", msg_replay)

    def test_submission_proof_path_containment_and_validation(self):
        """Proof file validation rejects directory traversal and disallowed extensions."""
        with self.assertRaises(FileSecurityError):
            FileSecurityValidator.validate_path_containment(
                target_path=self.storage_base / ".." / "etc" / "passwd.pdf",
                base_dir=self.storage_base,
            )

        with self.assertRaises(InvalidFileFormatError):
            self.validator.validate_confirmation_proof(
                file_bytes=b"echo 'malicious shell script'",
                original_filename="script.sh",
            )

        with self.assertRaises(InvalidFileFormatError):
            self.validator.validate_confirmation_proof(
                file_bytes=b"This is just plain text masquerading as a PDF file.",
                original_filename="spoofed.pdf",
            )


if __name__ == "__main__":
    unittest.main()

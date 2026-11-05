"""Phase 7.6.1 Security Remediation, Session Lock Consistency & CI Verification Tests.

Verifies:
1. SessionManager lock hierarchy and resolution of the lock-order inversion between
   self._session_lock (Level 1) and self._grant_lock (Level 2).
2. Concurrency without deadlock during race conditions between approval grant consumption
   and session revocation / purge.
3. Server-side session authentication enforcement across Streamlit dashboard views
   (Candidate Profile, Job Description Analyzer, Application Preparer, Resume Match Analysis).
4. Pepper configuration hardening in AuthManager across development, test, production,
   and unrecognized environments.
"""

import os
import tempfile
import threading
import unittest
from typing import Any, Tuple
from unittest.mock import MagicMock, patch

from dashboard.services.dashboard_service import DashboardService
from dashboard.views.application_preparer import (
    get_current_user_id as preparer_get_uid,
    render_application_preparer,
)
from dashboard.views.candidate_profile import get_current_user_id as profile_get_uid
from dashboard.views.candidate_profile import render_candidate_profile
from dashboard.views.job_description_analyzer import render_job_description_analyzer
from dashboard.views.resume_match_analysis import render_resume_match_analysis
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    InvalidSessionError,
    SecurityAuthorizationError,
    TicketAlreadyConsumedError,
)
from src.security.auth import DEFAULT_PWD_PEPPER, AuthManager
from src.security.session_manager import SessionManager


class TestSessionLockConsistencyAndDeadlockPrevention(unittest.TestCase):
    """Deterministic concurrency and lock ordering tests for SessionManager."""

    def setUp(self):
        SessionManager.reset_instance()
        self.session_mgr = SessionManager.get_instance()

    def tearDown(self):
        SessionManager.reset_instance()

    def _issue_test_grant(self, user_id: int = 1, app_id: int = 101, packet_id: int = 201) -> Tuple[Any, Any]:
        """Helper to create an authenticated session and issue a valid approval grant."""
        session = self.session_mgr.authenticate_candidate(
            candidate_id=f"cand_{user_id}",
            candidate_name=f"Candidate {user_id}",
            user_id=user_id,
            email=f"cand{user_id}@example.com",
        )
        packet_hash = "test_pkt_hash_deadlock_check"
        tkt = self.session_mgr.issue_action_ticket(
            session_id=session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app_id,
            packet_hash=packet_hash,
        )
        success, msg, grant = self.session_mgr.verify_and_issue_approval_grant(
            session_id=session.session_id,
            ticket_str=tkt,
            application_id=app_id,
            packet_id=packet_id,
            packet_hash=packet_hash,
            approver_name="Candidate Auditor",
        )
        self.assertTrue(success, f"Grant issuance failed: {msg}")
        return session, grant

    def test_lock_hierarchy_specification(self):
        """Asserts that SessionManager explicitly defines RLock for both session and grant locks."""
        self.assertIsInstance(self.session_mgr._session_lock, type(threading.RLock()))
        self.assertIsInstance(self.session_mgr._grant_lock, type(threading.RLock()))

    def test_concurrent_grant_consume_and_revoke_session_no_deadlock(self):
        """Racing verify_and_consume_approval_grant against revoke_session never deadlocks."""
        session, grant = self._issue_test_grant(user_id=1, app_id=101)

        barrier = threading.Barrier(2)
        consume_result = {}
        revoke_result = {}

        def worker_consume():
            barrier.wait()
            try:
                succ, msg = self.session_mgr.verify_and_consume_approval_grant(grant)
                consume_result["success"] = succ
                consume_result["msg"] = msg
            except (SecurityAuthorizationError, InvalidSessionError, TicketAlreadyConsumedError) as err:
                consume_result["error"] = err

        def worker_revoke():
            barrier.wait()
            res = self.session_mgr.revoke_session(session.session_id)
            revoke_result["revoked"] = res

        t1 = threading.Thread(target=worker_consume, name="Worker-Consume")
        t2 = threading.Thread(target=worker_revoke, name="Worker-Revoke")

        t1.start()
        t2.start()

        # Both threads must terminate cleanly within a bounded 3.0s timeout
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        self.assertFalse(t1.is_alive(), "Worker-Consume deadlocked!")
        self.assertFalse(t2.is_alive(), "Worker-Revoke deadlocked!")
        self.assertTrue(revoke_result.get("revoked", False))

        # Either consumption succeeded before revocation, or failed closed after revocation
        has_outcome = "success" in consume_result or "error" in consume_result
        self.assertTrue(has_outcome, "Consume worker had no outcome recorded.")

    def test_concurrent_grant_consume_and_revoke_user_sessions_no_deadlock(self):
        """Racing verify_and_consume_approval_grant against revoke_user_sessions never deadlocks."""
        session, grant = self._issue_test_grant(user_id=2, app_id=102)

        barrier = threading.Barrier(2)
        consume_result = {}
        revoke_result = {}

        def worker_consume():
            barrier.wait()
            try:
                succ, msg = self.session_mgr.verify_and_consume_approval_grant(grant)
                consume_result["success"] = succ
                consume_result["msg"] = msg
            except (SecurityAuthorizationError, InvalidSessionError, TicketAlreadyConsumedError) as err:
                consume_result["error"] = err

        def worker_revoke_user():
            barrier.wait()
            count = self.session_mgr.revoke_user_sessions(user_id=2)
            revoke_result["count"] = count

        t1 = threading.Thread(target=worker_consume, name="Worker-Consume-User")
        t2 = threading.Thread(target=worker_revoke_user, name="Worker-Revoke-User")

        t1.start()
        t2.start()

        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        self.assertFalse(t1.is_alive(), "Worker-Consume-User deadlocked!")
        self.assertFalse(t2.is_alive(), "Worker-Revoke-User deadlocked!")
        self.assertEqual(revoke_result.get("count"), 1)

    def test_concurrent_grant_consume_and_purge_expired_no_deadlock(self):
        """Racing grant consumption against purge_expired_sessions terminates without deadlock."""
        session, grant = self._issue_test_grant(user_id=3, app_id=103)

        barrier = threading.Barrier(2)
        consume_result = {}
        purge_result = {}

        def worker_consume():
            barrier.wait()
            try:
                succ, msg = self.session_mgr.verify_and_consume_approval_grant(grant)
                consume_result["success"] = succ
            except Exception as err:
                consume_result["error"] = err

        def worker_purge():
            barrier.wait()
            purged = self.session_mgr.purge_expired_sessions()
            purge_result["purged"] = purged

        t1 = threading.Thread(target=worker_consume, name="Worker-Consume-Purge")
        t2 = threading.Thread(target=worker_purge, name="Worker-Purge")

        t1.start()
        t2.start()

        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        self.assertFalse(t1.is_alive(), "Worker-Consume-Purge deadlocked!")
        self.assertFalse(t2.is_alive(), "Worker-Purge deadlocked!")

    def test_high_concurrency_stress_grants_and_revocations(self):
        """Stress tests 10 concurrent threads executing grant validation and revocations simultaneously."""
        threads = []
        barrier = threading.Barrier(10)

        for i in range(5):
            sess, grt = self._issue_test_grant(user_id=100 + i, app_id=1000 + i)

            def worker_c(g=grt):
                barrier.wait()
                try:
                    self.session_mgr.verify_and_consume_approval_grant(g)
                except Exception:
                    pass

            def worker_r(s_id=sess.session_id):
                barrier.wait()
                try:
                    self.session_mgr.revoke_session(s_id)
                except Exception:
                    pass

            t_c = threading.Thread(target=worker_c)
            t_r = threading.Thread(target=worker_r)
            threads.extend([t_c, t_r])

        for t in threads:
            t.start()

        for t in threads:
            t.join(timeout=4.0)
            self.assertFalse(t.is_alive(), f"Thread {t.name} deadlocked during stress test!")


class TestServerSideSessionValidationInViews(unittest.TestCase):
    """Verifies that Streamlit dashboard views enforce active server-side sessions and fail closed."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = DatabaseManager(db_path=self.temp_db.name)
        self.service = DashboardService(db_manager=self.db)
        DashboardService._instance = self.service

        SessionManager.reset_instance()
        self.session_mgr = SessionManager.get_instance()

        # Create valid session for user 1
        self.valid_session = self.session_mgr.authenticate_candidate(
            candidate_id="1",
            candidate_name="Alice Candidate",
            user_id=1,
            email="alice@example.com",
        )

    def tearDown(self):
        DashboardService._instance = None
        SessionManager.reset_instance()
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_candidate_profile_unauthenticated_fails_closed(self):
        """Unauthenticated request (empty session_state) fails closed with error banner."""
        mock_st = MagicMock()
        mock_st.session_state = {}

        uid = profile_get_uid()
        self.assertIsNone(uid)

        with patch("dashboard.views.candidate_profile.st", mock_st):
            render_candidate_profile()
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to access your Candidate Profile.")

    def test_candidate_profile_spoofed_user_id_without_session_fails_closed(self):
        """Spoofed user_id in session_state without a valid server session fails closed."""
        mock_st = MagicMock()
        mock_st.session_state = {"user_id": 1, "authenticated_user_id": 1}

        with patch("dashboard.views.candidate_profile.st", mock_st):
            uid = profile_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to access your Candidate Profile.")

    def test_candidate_profile_invalid_session_fails_closed(self):
        """Invalid session token in session_state fails closed."""
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": "invalid_session_hex_99999"}

        with patch("dashboard.views.candidate_profile.st", mock_st):
            uid = profile_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to access your Candidate Profile.")

    def test_candidate_profile_expired_session_fails_closed(self):
        """Expired session fails closed with re-authentication required error."""
        expired = self.session_mgr.authenticate_candidate(
            candidate_id="2",
            candidate_name="Bob Expired",
            user_id=2,
            ttl_seconds=-10,
        )
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": expired.session_id, "user_id": 2}

        with patch("dashboard.views.candidate_profile.st", mock_st):
            uid = profile_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to access your Candidate Profile.")

    def test_candidate_profile_revoked_session_fails_closed(self):
        """Revoked session fails closed."""
        rev = self.session_mgr.authenticate_candidate(
            candidate_id="3",
            candidate_name="Charlie Revoked",
            user_id=3,
        )
        self.session_mgr.revoke_session(rev.session_id)
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": rev.session_id, "user_id": 3}

        with patch("dashboard.views.candidate_profile.st", mock_st):
            uid = profile_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to access your Candidate Profile.")

    def test_candidate_profile_cross_user_spoofing_fails_closed(self):
        """Session belonging to user 1 combined with user_id 2 fails closed (CrossUserAccessError)."""
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": self.valid_session.session_id, "user_id": 2}

        with patch("dashboard.views.candidate_profile.st", mock_st):
            uid = profile_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to access your Candidate Profile.")

    def test_candidate_profile_valid_session_succeeds(self):
        """Legitimate active session resolves successfully to the candidate user ID."""
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": self.valid_session.session_id}

        with patch("dashboard.views.candidate_profile.st", mock_st):
            uid = profile_get_uid()
            self.assertEqual(uid, 1)

    def test_job_description_analyzer_unauthenticated_fails_closed(self):
        """Job Description Analyzer view fails closed when unauthenticated."""
        mock_st = MagicMock()
        mock_st.session_state = {}

        with patch("dashboard.views.job_description_analyzer.st", mock_st):
            render_job_description_analyzer()
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to analyze and ingest job descriptions.")

    def test_job_description_analyzer_spoofed_user_id_fails_closed(self):
        """Job Description Analyzer view rejects spoofed user_id without valid session."""
        mock_st = MagicMock()
        mock_st.session_state = {"user_id": 1}

        with patch("dashboard.views.job_description_analyzer.st", mock_st):
            render_job_description_analyzer()
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to analyze and ingest job descriptions.")

    def test_job_description_analyzer_valid_session_succeeds(self):
        """Job Description Analyzer view renders successfully with valid active session."""
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": self.valid_session.session_id}
        mock_st.tabs.return_value = (MagicMock(), MagicMock(), MagicMock(), MagicMock())
        mock_st.columns.return_value = (MagicMock(), MagicMock())
        mock_st.button.return_value = False
        mock_st.form_submit_button.return_value = False

        with patch("dashboard.views.job_description_analyzer.st", mock_st):
            render_job_description_analyzer()
            mock_st.error.assert_not_called()
            mock_st.tabs.assert_called_once()

    def test_application_preparer_unauthenticated_fails_closed(self):
        """Application Preparer view fails closed when unauthenticated."""
        mock_st = MagicMock()
        mock_st.session_state = {}

        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertIsNone(uid)
            render_application_preparer()
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

    def test_resume_match_analysis_unauthenticated_fails_closed(self):
        """Resume Match Analysis view fails closed when unauthenticated."""
        mock_st = MagicMock()
        mock_st.session_state = {}

        with patch("dashboard.views.resume_match_analysis.st", mock_st):
            render_resume_match_analysis()
            mock_st.error.assert_called_with("⚠️ Authentication required: You must be logged in to access Resume Match Analysis.")


class TestApplicationPreparerServerSessionAuthentication(unittest.TestCase):
    """Specific regression test suite verifying server session enforcement in Application Preparer (Phase 7.6.1.2).

    Verifies:
    1. Empty session state rejects access and fails closed.
    2. user_id only (without session_id) is rejected and fails closed.
    3. authenticated_user_id only (without session_id) is rejected and fails closed.
    4. Both user-ID fields present without session_id are rejected and fail closed.
    5. Invalid session_id is rejected and fails closed.
    6. Expired session is rejected and fails closed.
    7. Revoked session is rejected and fails closed.
    8. User-ID mismatch (cross-user spoofing) is rejected and fails closed.
    9. Valid authenticated session successfully resolves the candidate user ID.
    10. Actual render_application_preparer() entry point performs NO candidate data access
        (no JD fetching, no resume fetching, no profile fetching, no tab rendering) when unauthenticated.
    """

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = DatabaseManager(db_path=self.temp_db.name)
        self.service = DashboardService(db_manager=self.db)
        DashboardService._instance = self.service

        SessionManager.reset_instance()
        self.session_mgr = SessionManager.get_instance()

        # Create valid session for user 1
        self.valid_session = self.session_mgr.authenticate_candidate(
            candidate_id="1",
            candidate_name="Alice Candidate",
            user_id=1,
            email="alice@example.com",
        )

    def tearDown(self):
        DashboardService._instance = None
        SessionManager.reset_instance()
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_empty_session_state_fails_closed(self):
        """Empty session state must fail closed and return None."""
        mock_st = MagicMock()
        mock_st.session_state = {}

        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

    def test_user_id_only_without_session_id_fails_closed(self):
        """user_id only in session_state without session_id must fail closed and return None."""
        mock_st = MagicMock()
        mock_st.session_state = {"user_id": 1}

        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

    def test_authenticated_user_id_only_without_session_id_fails_closed(self):
        """authenticated_user_id only in session_state without session_id must fail closed and return None."""
        mock_st = MagicMock()
        mock_st.session_state = {"authenticated_user_id": 1}

        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

    def test_both_user_id_fields_present_without_session_id_fails_closed(self):
        """Both user_id and authenticated_user_id present without session_id must fail closed and return None."""
        mock_st = MagicMock()
        mock_st.session_state = {"user_id": 1, "authenticated_user_id": 1}

        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

    def test_invalid_session_id_fails_closed(self):
        """Invalid session ID in session_state must fail closed and return None."""
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": "invalid_session_hex_deadbeef"}

        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

    def test_expired_session_fails_closed(self):
        """Expired session must fail closed and return None."""
        expired = self.session_mgr.authenticate_candidate(
            candidate_id="2",
            candidate_name="Bob Expired",
            user_id=2,
            ttl_seconds=-10,
        )
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": expired.session_id, "user_id": 2}

        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

    def test_revoked_session_fails_closed(self):
        """Revoked session must fail closed and return None."""
        rev = self.session_mgr.authenticate_candidate(
            candidate_id="3",
            candidate_name="Charlie Revoked",
            user_id=3,
        )
        self.session_mgr.revoke_session(rev.session_id)
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": rev.session_id, "user_id": 3}

        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

    def test_user_id_mismatch_fails_closed(self):
        """Client user_id mismatching session user_id must fail closed and return None."""
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": self.valid_session.session_id, "user_id": 999}

        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

        # Also test with authenticated_user_id
        mock_st.session_state = {"session_id": self.valid_session.session_id, "authenticated_user_id": 999}
        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertIsNone(uid)
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

    def test_valid_authenticated_session_succeeds(self):
        """Valid active session in session_state successfully resolves the candidate user ID."""
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": self.valid_session.session_id, "user_id": 1}

        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertEqual(uid, 1)

        # Also test with authenticated_session_id alias
        mock_st.session_state = {"authenticated_session_id": self.valid_session.session_id}
        with patch("dashboard.views.application_preparer.st", mock_st):
            uid = preparer_get_uid()
            self.assertEqual(uid, 1)

    def test_render_application_preparer_entry_point_blocks_candidate_data_access(self):
        """render_application_preparer() entry point performs NO candidate data access when authentication fails."""
        mock_st = MagicMock()
        # Spoofed user ID without session
        mock_st.session_state = {"user_id": 1, "authenticated_user_id": 1}

        with patch("dashboard.views.application_preparer.st", mock_st), \
             patch.object(self.service, "get_user_job_descriptions") as mock_get_jds, \
             patch.object(self.service, "get_user_resumes") as mock_get_resumes, \
             patch.object(self.db, "get_user_candidate_profile") as mock_get_profile:

            render_application_preparer()

            # Ensure authentication error was displayed
            mock_st.error.assert_called_with("🔒 Authentication required. Please sign in to prepare job applications.")

            # Ensure tabs were NEVER rendered
            mock_st.tabs.assert_not_called()

            # Ensure NO candidate-specific database reads occurred
            mock_get_jds.assert_not_called()
            mock_get_resumes.assert_not_called()
            mock_get_profile.assert_not_called()

    def test_render_application_preparer_entry_point_succeeds_with_valid_session(self):
        """render_application_preparer() renders tabs when authenticated with valid session."""
        mock_st = MagicMock()
        mock_st.session_state = {"session_id": self.valid_session.session_id, "user_id": 1}
        mock_st.tabs.return_value = tuple(MagicMock() for _ in range(8))
        mock_st.columns.return_value = (MagicMock(), MagicMock())
        mock_st.button.return_value = False
        mock_st.selectbox.return_value = None

        with patch("dashboard.views.application_preparer.st", mock_st), \
             patch.object(self.service, "get_user_job_descriptions", return_value=[]) as mock_get_jds, \
             patch.object(self.service, "get_user_resumes", return_value=[]) as mock_get_resumes:

            render_application_preparer()

            mock_st.error.assert_not_called()
            mock_st.tabs.assert_called_once()
            mock_get_jds.assert_called_once_with(user_id=1)
            mock_get_resumes.assert_called_once_with(user_id=1)


class TestAuthManagerPepperHardening(unittest.TestCase):
    """Verifies that AuthManager enforces explicit peppers across non-dev environments."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = DatabaseManager(db_path=self.temp_db.name)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    def test_production_without_pepper_raises_security_error(self):
        """APP_ENV=production without PASSWORD_RESET_PEPPER fails closed."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=False):
            if "PASSWORD_RESET_PEPPER" in os.environ:
                del os.environ["PASSWORD_RESET_PEPPER"]
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                AuthManager(db_manager=self.db)
            self.assertIn("PASSWORD_RESET_PEPPER must be explicitly configured in production environment", str(ctx.exception))

    def test_staging_without_pepper_raises_security_error(self):
        """APP_ENV=staging without PASSWORD_RESET_PEPPER fails closed."""
        with patch.dict(os.environ, {"APP_ENV": "staging"}, clear=False):
            if "PASSWORD_RESET_PEPPER" in os.environ:
                del os.environ["PASSWORD_RESET_PEPPER"]
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                AuthManager(db_manager=self.db)
            self.assertIn("PASSWORD_RESET_PEPPER must be explicitly configured in 'staging' environment", str(ctx.exception))

    def test_custom_environment_without_pepper_raises_security_error(self):
        """Unrecognized environment without PASSWORD_RESET_PEPPER fails closed."""
        with patch.dict(os.environ, {"APP_ENV": "uat"}, clear=False):
            if "PASSWORD_RESET_PEPPER" in os.environ:
                del os.environ["PASSWORD_RESET_PEPPER"]
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                AuthManager(db_manager=self.db)
            self.assertIn("PASSWORD_RESET_PEPPER must be explicitly configured in 'uat' environment", str(ctx.exception))

    def test_dev_and_test_environments_allow_default_pepper(self):
        """Development and test environments permit the default development pepper."""
        for env_name in ("development", "test", "dev"):
            with patch.dict(os.environ, {"APP_ENV": env_name}, clear=False):
                if "PASSWORD_RESET_PEPPER" in os.environ:
                    del os.environ["PASSWORD_RESET_PEPPER"]
                mgr = AuthManager(db_manager=self.db)
                self.assertEqual(mgr.pepper, DEFAULT_PWD_PEPPER)

    def test_explicit_pepper_succeeds_in_all_environments(self):
        """Explicit PASSWORD_RESET_PEPPER is respected regardless of APP_ENV."""
        custom_pepper = "super_secure_production_pepper_hex_value_12345"
        for env_name in ("production", "staging", "uat", "development"):
            with patch.dict(os.environ, {"APP_ENV": env_name, "PASSWORD_RESET_PEPPER": custom_pepper}, clear=False):
                mgr = AuthManager(db_manager=self.db)
                self.assertEqual(mgr.pepper, custom_pepper)


if __name__ == "__main__":
    unittest.main()

"""Comprehensive Multi-User Authentication, Session Management, and Security Test Suite.

Phase 2 Verification Matrix:
1. User registration & Argon2id hashing
2. User authentication & constant-time rejection
3. Account lockout (5 failed attempts, 15m duration)
4. Password reset (single-use salted SHA-256 tokens, 15m expiration, rate-limiting, session revocation)
5. Session management & CSRF protection (sliding expiration, session fixation defense)
6. Action tickets, persistent SQLite nonce consumption, and key rotation (Mode A & Mode B)
7. Multi-user database isolation & composite foreign keys
8. Data deletion & anonymized audit trail preservation
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    AccountLockedError,
    AuthenticationFailedError,
    CrossUserAccessError,
    DuplicateUserError,
    InvalidSessionError,
    InvalidTicketError,
    KeyRevokedError,
    SessionExpiredError,
    TicketAlreadyConsumedError,
    TokenAlreadyUsedError,
    TokenExpiredError,
    ValidationError,
)
from src.security.auth import AuthManager
from src.security.session_manager import KeyRotationManager, SessionManager


class TestUserRegistration(unittest.TestCase):
    """Test candidate registration, email normalization, and password security."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_auth.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_registration_success_and_argon2id(self):
        user = self.auth.register(
            email="Candidate.User@Example.Com",
            password="StrongPassword123!",
            full_name="Candidate User",
            profession_industry="Artificial Intelligence",
            career_level="Undergraduate",
        )
        self.assertEqual(user.email, "candidate.user@example.com")
        self.assertTrue(user.password_hash.startswith("$argon2id$") or user.password_hash.startswith("pbkdf2:sha256:"))
        self.assertEqual(user.account_status, "active")
        self.assertEqual(user.failed_login_attempts, 0)

    def test_duplicate_email_rejection_case_insensitive(self):
        self.auth.register(
            email="test.candidate@domain.com",
            password="ValidPass123!",
            full_name="First User",
        )
        with self.assertRaises(DuplicateUserError):
            self.auth.register(
                email="TEST.CANDIDATE@DOMAIN.COM",
                password="AnotherPass456!",
                full_name="Second User",
            )

    def test_password_complexity_rejections(self):
        # Too short (< 8 chars)
        with self.assertRaises(ValidationError):
            self.auth.register("u1@ex.com", "Short1!", "User One")
        # Missing uppercase
        with self.assertRaises(ValidationError):
            self.auth.register("u2@ex.com", "lowercase123!", "User Two")
        # Missing lowercase
        with self.assertRaises(ValidationError):
            self.auth.register("u3@ex.com", "UPPERCASE123!", "User Three")
        # Missing digit
        with self.assertRaises(ValidationError):
            self.auth.register("u4@ex.com", "NoDigitsHere!", "User Four")
        # Missing special symbol
        with self.assertRaises(ValidationError):
            self.auth.register("u5@ex.com", "NoSymbols1234", "User Five")

    def test_email_validation(self):
        with self.assertRaises(ValidationError):
            self.auth.register("", "ValidPass123!", "User")
        with self.assertRaises(ValidationError):
            self.auth.register("not-an-email", "ValidPass123!", "User")


class TestUserAuthentication(unittest.TestCase):
    """Test login authentication, constant-time rejection, and attempt counters."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_auth.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)
        self.user = self.auth.register(
            email="valid.user@example.com",
            password="CorrectPassword123!",
            full_name="Valid User",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_login_success(self):
        logged_in = self.auth.login("valid.user@example.com", "CorrectPassword123!")
        self.assertEqual(logged_in.id, self.user.id)
        self.assertEqual(logged_in.failed_login_attempts, 0)

    def test_wrong_password_rejection_and_counter(self):
        with self.assertRaises(AuthenticationFailedError):
            self.auth.login("valid.user@example.com", "WrongPassword123!")

        user_db = self.auth.get_user_by_email("valid.user@example.com")
        self.assertEqual(user_db.failed_login_attempts, 1)

    def test_unknown_email_constant_time_rejection(self):
        with self.assertRaises(AuthenticationFailedError) as ctx:
            self.auth.login("nonexistent@example.com", "SomePassword123!")
        self.assertIn("Invalid email or password", str(ctx.exception))


class TestAccountLockout(unittest.TestCase):
    """Test 5-attempt threshold and 15-minute lockout security."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_auth.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)
        self.user = self.auth.register(
            email="target.user@example.com",
            password="TargetPassword123!",
            full_name="Target User",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_five_failures_trigger_lockout(self):
        # 4 consecutive failures
        for i in range(1, 5):
            with self.assertRaises(AuthenticationFailedError):
                self.auth.login("target.user@example.com", f"WrongPass{i}!")
            u = self.auth.get_user_by_email("target.user@example.com")
            self.assertEqual(u.failed_login_attempts, i)
            self.assertIsNone(u.locked_until)

        # 5th failure triggers AccountLockedError
        with self.assertRaises(AccountLockedError) as ctx:
            self.auth.login("target.user@example.com", "WrongPass5!")
        self.assertTrue(ctx.exception.locked_until is not None)

        # Subsequent attempts while locked are immediately blocked, even with correct password
        with self.assertRaises(AccountLockedError):
            self.auth.login("target.user@example.com", "TargetPassword123!")

    def test_lockout_expiration_allows_login(self):
        # Lock account
        for _ in range(5):
            try:
                self.auth.login("target.user@example.com", "WrongPass!")
            except (AuthenticationFailedError, AccountLockedError):
                pass

        # Artificially expire the lock in the database
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        with self.db.transaction() as conn:
            conn.execute("UPDATE users SET locked_until = ? WHERE id = ?", (past_time, self.user.id))

        # Login with correct password now succeeds and resets counters
        logged_in = self.auth.login("target.user@example.com", "TargetPassword123!")
        self.assertEqual(logged_in.failed_login_attempts, 0)
        self.assertIsNone(logged_in.locked_until)


class TestPasswordReset(unittest.TestCase):
    """Test single-use salted SHA-256 password reset tokens, rate limits, and session purge."""

    def setUp(self):
        SessionManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_auth.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.session_mgr = SessionManager()
        self.auth = AuthManager(db_manager=self.db)
        self.user = self.auth.register(
            email="reset.user@example.com",
            password="OriginalPassword123!",
            full_name="Reset User",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_request_password_reset_and_raw_token_not_stored(self):
        generic_msg, raw_token = self.auth.request_password_reset("reset.user@example.com")
        self.assertIn("password reset instructions have been dispatched", generic_msg)
        self.assertIsNotNone(raw_token)

        # Inspect DB: raw token must NOT be in DB
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT token_hash, token_salt, is_used FROM password_reset_tokens WHERE user_id = ?", (self.user.id,))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertNotEqual(row["token_hash"], raw_token)
            self.assertEqual(row["is_used"], 0)

    def test_nonexistent_email_returns_identical_generic_message(self):
        msg, token = self.auth.request_password_reset("nonexistent.random@example.com")
        self.assertIn("password reset instructions have been dispatched", msg)
        self.assertIsNone(token)

    def test_rate_limiting_three_per_hour(self):
        # 3 requests succeed
        for _ in range(3):
            msg, token = self.auth.request_password_reset("reset.user@example.com", client_ip="192.168.1.1")
            self.assertIsNotNone(token)

        # 4th request rate-limited: returns generic response, issues no token
        msg, token = self.auth.request_password_reset("reset.user@example.com", client_ip="192.168.1.1")
        self.assertIn("password reset instructions have been dispatched", msg)
        self.assertIsNone(token)

    def test_successful_reset_and_replay_rejection(self):
        _, raw_token = self.auth.request_password_reset("reset.user@example.com")
        self.assertTrue(self.auth.reset_password(raw_token, "BrandNewPassword456!"))

        # Verify new password works
        user_new = self.auth.login("reset.user@example.com", "BrandNewPassword456!")
        self.assertEqual(user_new.id, self.user.id)

        # Replay attack: attempting to use the token again must fail
        with self.assertRaises(TokenAlreadyUsedError):
            self.auth.reset_password(raw_token, "AnotherNewPassword789!")

    def test_expired_token_rejection(self):
        _, raw_token = self.auth.request_password_reset("reset.user@example.com")

        # Set expiration in the past
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        with self.db.transaction() as conn:
            conn.execute("UPDATE password_reset_tokens SET expires_at = ? WHERE user_id = ?", (past, self.user.id))

        with self.assertRaises(TokenExpiredError):
            self.auth.reset_password(raw_token, "BrandNewPassword456!")

    def test_password_reset_invalidates_all_active_sessions(self):
        # Create active sessions
        sess1 = self.session_mgr.create_user_session(user_id=self.user.id, email=self.user.email)
        sess2 = self.session_mgr.create_user_session(user_id=self.user.id, email=self.user.email)
        self.assertIsNotNone(self.session_mgr.get_session(sess1.session_id))
        self.assertIsNotNone(self.session_mgr.get_session(sess2.session_id))

        # Reset password
        _, raw_token = self.auth.request_password_reset("reset.user@example.com")
        self.auth.reset_password(raw_token, "NewPassword999!")

        # All previous sessions must be revoked
        with self.assertRaises(InvalidSessionError):
            self.session_mgr.get_session(sess1.session_id)
        with self.assertRaises(InvalidSessionError):
            self.session_mgr.get_session(sess2.session_id)


class TestSessionManagementAndCSRF(unittest.TestCase):
    """Test candidate sessions, CSRF protection, and session fixation defense."""

    def setUp(self):
        SessionManager.reset_instance()
        self.session_mgr = SessionManager()

    def test_session_creation_and_csrf(self):
        session = self.session_mgr.create_user_session(user_id=1, email="test@example.com")
        self.assertTrue(len(session.session_id) >= 32)
        self.assertTrue(len(session.csrf_token) >= 32)

        # CSRF validation
        self.assertTrue(self.session_mgr.validate_csrf(session.session_id, session.csrf_token))
        self.assertFalse(self.session_mgr.validate_csrf(session.session_id, "forged_csrf_token"))
        self.assertFalse(self.session_mgr.validate_csrf(session.session_id, None))

    def test_session_sliding_expiration(self):
        session = self.session_mgr.create_user_session(user_id=1, email="test@example.com", ttl_seconds=3600)
        retrieved = self.session_mgr.get_session(session.session_id)
        self.assertEqual(retrieved.user_id, 1)

        # Simulate expiration
        session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        with self.assertRaises(SessionExpiredError):
            self.session_mgr.get_session(session.session_id)

    def test_session_fixation_prevention(self):
        session = self.session_mgr.create_user_session(user_id=1, email="test@example.com")
        old_id = session.session_id
        old_csrf = session.csrf_token

        new_session = self.session_mgr.regenerate_session_id(old_id)
        self.assertNotEqual(new_session.session_id, old_id)
        self.assertEqual(new_session.user_id, 1)
        self.assertEqual(new_session.csrf_token, old_csrf)

        # Old session ID must be invalidated
        with self.assertRaises(InvalidSessionError):
            self.session_mgr.get_session(old_id)

    def test_logout_revocation(self):
        session = self.session_mgr.create_user_session(user_id=1, email="test@example.com")
        self.session_mgr.revoke_session(session.session_id)
        with self.assertRaises(InvalidSessionError):
            self.session_mgr.get_session(session.session_id)


class TestActionTicketsAndKeyRotation(unittest.TestCase):
    """Test HMAC action tickets, graceful key rotation (Mode A), emergency revocation (Mode B),
    persistent SQLite nonce consumption, and concurrent multi-threaded execution.
    """

    def setUp(self):
        SessionManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_auth.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.session_mgr = SessionManager()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ticket_creation_and_verification(self):
        ticket = self.session_mgr.create_action_ticket(
            action_type="SUBMIT_APPLICATION",
            resource_id="app_100",
            packet_version_hash="a1b2c3d4",
            candidate_id="candidate_1",
            ttl_seconds=300,
        )
        self.assertTrue(ticket.startswith("TKT-v1-"))

        # Verification succeeds
        payload = self.session_mgr.verify_action_ticket(ticket, expected_action="SUBMIT_APPLICATION")
        self.assertEqual(payload["resource_id"], "app_100")
        self.assertEqual(payload["packet_version_hash"], "a1b2c3d4")

    def test_tampered_ticket_payload_rejected(self):
        ticket = self.session_mgr.create_action_ticket(
            action_type="SUBMIT_APPLICATION",
            resource_id="app_100",
            packet_version_hash="a1b2c3d4",
            ttl_seconds=300,
        )
        tampered_ticket = ticket.replace("app_100", "app_999")
        with self.assertRaises(InvalidTicketError):
            self.session_mgr.verify_action_ticket(tampered_ticket, expected_action="SUBMIT_APPLICATION")

    def test_key_rotation_mode_a_graceful_overlap(self):
        # 1. Create ticket under v1
        ticket_v1 = self.session_mgr.create_action_ticket(
            action_type="SUBMIT_APPLICATION",
            resource_id="app_100",
            ttl_seconds=300,
        )

        # 2. Rotate to v2 with Mode A (overlap_window = 300s)
        new_secret = "b" * 64
        self.session_mgr.key_rotation_mgr.rotate_keys(
            new_key_id="v2",
            new_secret=new_secret,
            mode=KeyRotationManager.MODE_GRACEFUL,
            overlap_window_seconds=300,
        )

        # Active key is now v2
        self.assertEqual(self.session_mgr.key_rotation_mgr.active_key_id, "v2")

        # Old ticket signed with v1 remains valid during overlap
        payload = self.session_mgr.verify_action_ticket(ticket_v1, expected_action="SUBMIT_APPLICATION")
        self.assertEqual(payload["resource_id"], "app_100")

        # Newly issued tickets use v2
        ticket_v2 = self.session_mgr.create_action_ticket(
            action_type="SUBMIT_APPLICATION",
            resource_id="app_200",
            ttl_seconds=300,
        )
        self.assertTrue(ticket_v2.startswith("TKT-v2-"))
        payload_v2 = self.session_mgr.verify_action_ticket(ticket_v2, expected_action="SUBMIT_APPLICATION")
        self.assertEqual(payload_v2["resource_id"], "app_200")

    def test_key_rotation_mode_b_emergency_revocation(self):
        # Create ticket under v1
        ticket_v1 = self.session_mgr.create_action_ticket(
            action_type="SUBMIT_APPLICATION",
            resource_id="app_100",
            ttl_seconds=300,
        )

        # Emergency rotation: v1 is revoked immediately
        new_secret = "c" * 64
        self.session_mgr.key_rotation_mgr.rotate_keys(
            new_key_id="v3",
            new_secret=new_secret,
            mode=KeyRotationManager.MODE_EMERGENCY,
        )

        # Old ticket must raise KeyRevokedError immediately
        with self.assertRaises(KeyRevokedError) as ctx:
            self.session_mgr.verify_action_ticket(ticket_v1, expected_action="SUBMIT_APPLICATION")
        self.assertEqual(ctx.exception.key_id, "v1")

    def test_persistent_sqlite_nonce_consumption_and_replay_rejection(self):
        ticket = self.session_mgr.create_action_ticket(
            action_type="SUBMIT_APPLICATION",
            resource_id="app_100",
            ttl_seconds=300,
        )
        payload = self.session_mgr.verify_action_ticket(ticket, expected_action="SUBMIT_APPLICATION")
        nonce = payload["nonce"]
        key_id = payload["key_id"]

        # First consumption must succeed
        self.assertFalse(self.db.is_nonce_consumed(nonce))
        self.db.consume_action_nonce_persistently(ticket_nonce=nonce, key_id=key_id, user_id=1)
        self.assertTrue(self.db.is_nonce_consumed(nonce))

        # Second consumption attempt (replay attack) must raise TicketAlreadyConsumedError
        with self.assertRaises(TicketAlreadyConsumedError):
            self.db.consume_action_nonce_persistently(ticket_nonce=nonce, key_id=key_id, user_id=1)

    def test_concurrent_duplicate_nonce_consumption_race_condition(self):
        """Simulate concurrent threads attempting to consume the exact same nonce simultaneously."""
        test_nonce = f"race_test_nonce_{time.time_ns()}"

        success_count = 0
        failure_count = 0

        def try_consume():
            try:
                self.db.consume_action_nonce_persistently(
                    ticket_nonce=test_nonce,
                    key_id="v1",
                    user_id=1,
                    action_type="SUBMIT_APPLICATION",
                )
                return True
            except TicketAlreadyConsumedError:
                return False

        # Execute 8 concurrent consumption attempts
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(try_consume) for _ in range(8)]
            results = [f.result() for f in futures]

        success_count = sum(1 for r in results if r is True)
        failure_count = sum(1 for r in results if r is False)

        # Exactly ONE must succeed; the remaining 7 must be cleanly rejected
        self.assertEqual(success_count, 1)
        self.assertEqual(failure_count, 7)
        self.assertTrue(self.db.is_nonce_consumed(test_nonce))


class TestMultiUserDatabaseIsolation(unittest.TestCase):
    """Test multi-user boundaries, cross-user relational isolation, and composite foreign key enforcement."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_auth.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)

        self.user_a = self.auth.register("user.a@example.com", "PasswordA123!", "User A")
        self.user_b = self.auth.register("user.b@example.com", "PasswordB123!", "User B")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_job_description_cross_user_isolation(self):
        jd_a = self.db.create_job_description(
            user_id=self.user_a.id,
            company_name="Company A",
            job_title="Engineer",
            raw_content="Job description text for user A",
        )
        self.assertEqual(jd_a.user_id, self.user_a.id)

        # User A can access it
        self.assertIsNotNone(self.db.get_job_description(jd_a.id, user_id=self.user_a.id))

        # User B attempting to access User A's job description raises CrossUserAccessError
        with self.assertRaises(CrossUserAccessError):
            self.db.get_job_description(jd_a.id, user_id=self.user_b.id)

    def test_resume_cross_user_isolation(self):
        res_a = self.db.create_user_resume(
            user_id=self.user_a.id,
            original_filename="resume_a.pdf",
            storage_filename="res_a.pdf",
            file_format="pdf",
            file_hash="hash_a",
            file_size_bytes=1024,
        )
        self.assertEqual(res_a["user_id"], self.user_a.id)

        # User B attempting to access User A's resume raises CrossUserAccessError
        with self.assertRaises(CrossUserAccessError):
            self.db.get_user_resume(res_a["id"], user_id=self.user_b.id)

        # User B attempting to create a version under User A's resume raises CrossUserAccessError
        with self.assertRaises(CrossUserAccessError):
            self.db.create_resume_version(
                resume_id=res_a["id"],
                user_id=self.user_b.id,
                version_num=2,
                snapshot_json="{}",
            )

    def test_cross_user_packet_association_rejected(self):
        # User A creates application and resume
        app_a = self.db.create_user_application(
            user_id=self.user_a.id,
            company_name="TechCorp",
            job_title="ML Specialist",
        )
        res_a = self.db.create_user_resume(
            user_id=self.user_a.id,
            original_filename="a_resume.pdf",
            storage_filename="a_resume.pdf",
            file_format="pdf",
            file_hash="a_hash",
            file_size_bytes=2048,
        )

        # User B creates application
        app_b = self.db.create_user_application(
            user_id=self.user_b.id,
            company_name="TechCorp",
            job_title="ML Specialist",
        )

        # Case 1: User B attempts to create prepared packet referencing User A's application
        with self.assertRaises(CrossUserAccessError):
            self.db.create_prepared_packet(
                application_id=app_a.id,
                user_id=self.user_b.id,
                packet_version_hash="packet_hash_b",
                original_resume_hash="res_hash",
                job_description_snapshot_hash="jd_hash",
                screening_answers={},
            )

        # Case 2: User B creates packet for their own application, but attempts to link User A's resume
        with self.assertRaises(CrossUserAccessError):
            self.db.create_prepared_packet(
                application_id=app_b.id,
                user_id=self.user_b.id,
                original_resume_id=res_a["id"],
                packet_version_hash="packet_hash_b2",
                original_resume_hash="res_hash",
                job_description_snapshot_hash="jd_hash",
                screening_answers={},
            )

    def test_sqlite_composite_foreign_key_constraint_enforcement(self):
        """Direct database insertion violating composite foreign key must fail at SQLite engine level."""
        app_a = self.db.create_user_application(
            user_id=self.user_a.id,
            company_name="DataCo",
            job_title="Data Scientist",
        )
        res_b = self.db.create_user_resume(
            user_id=self.user_b.id,
            original_filename="b_resume.pdf",
            storage_filename="b_resume.pdf",
            file_format="pdf",
            file_hash="b_hash",
            file_size_bytes=2048,
        )

        # Attempt raw SQL insert linking User A's prepared packet to User B's resume
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as conn:
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.execute(
                    """
                    INSERT INTO prepared_packets (
                        application_id, user_id, version_num, packet_version_hash,
                        original_resume_id, original_resume_hash, job_description_snapshot_hash,
                        screening_answers_json
                    ) VALUES (?, ?, 1, 'hash_violating', ?, 'orig_hash', 'jd_hash', '{}')
                    """,
                    (app_a.id, self.user_a.id, res_b["id"]),
                )


class TestDataDeletionAndAuditPreservation(unittest.TestCase):
    """Test user account deletion and immutable anonymized audit trail preservation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_auth.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)

        self.user = self.auth.register("deletion.target@example.com", "PasswordDel123!", "Deletion Candidate")
        self.jd = self.db.create_job_description(
            user_id=self.user.id,
            company_name="Cloud Corp",
            job_title="Backend Intern",
            raw_content="Detailed JD text",
        )
        self.app = self.db.create_user_application(
            user_id=self.user.id,
            company_name="Cloud Corp",
            job_title="Backend Intern",
            job_description_id=self.jd.id,
        )
        self.resume = self.db.create_user_resume(
            user_id=self.user.id,
            original_filename="my_resume.pdf",
            storage_filename="my_resume.pdf",
            file_format="pdf",
            file_hash="res_hash_del",
            file_size_bytes=4096,
        )
        self.packet = self.db.create_prepared_packet(
            application_id=self.app.id,
            user_id=self.user.id,
            original_resume_id=self.resume["id"],
            packet_version_hash="packet_hash_del",
            original_resume_hash="res_hash_del",
            job_description_snapshot_hash="jd_hash_del",
            screening_answers={"notice_period": "Immediate"},
        )
        # Record submission approval and application log via direct test fixture seeding
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO application_approvals (
                    application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, key_id, approver_name, session_id, approved_at, is_consumed
                ) VALUES (?, ?, ?, ?, ?, 'v1', 'Deletion Candidate', 'sess_del_123', CURRENT_TIMESTAMP, 0)
                """,
                (self.app.id, self.packet.id, self.user.id, "packet_hash_del", "del_nonce_123"),
            )
            cursor.execute("SELECT * FROM application_approvals WHERE id = ?", (cursor.lastrowid,))
            row = cursor.fetchone()
            from src.database.models import ApplicationApproval
            self.approval = ApplicationApproval(**dict(row))

            cursor.execute(
                """
                INSERT INTO application_logs (
                    application_id, user_id, action, details
                ) VALUES (?, ?, 'HUMAN_APPROVAL_GRANTED', '{"action": "HUMAN_APPROVAL_GRANTED", "approver": "Deletion Candidate"}')
                """,
                (self.app.id, self.user.id),
            )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_user_deletion_anonymizes_audit_logs_and_cascades_materials(self):
        user_id = self.user.id

        # Execute account data deletion
        self.assertTrue(self.db.delete_user_account_data(user_id))

        # 1. User record must be completely gone
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
            self.assertIsNone(cursor.fetchone())

            # 2. Resumes, job descriptions, applications, packets must be cascade-deleted
            cursor.execute("SELECT id FROM resumes WHERE user_id = ?", (user_id,))
            self.assertEqual(len(cursor.fetchall()), 0)
            cursor.execute("SELECT id FROM job_descriptions WHERE user_id = ?", (user_id,))
            self.assertEqual(len(cursor.fetchall()), 0)
            cursor.execute("SELECT id FROM applications WHERE user_id = ?", (user_id,))
            self.assertEqual(len(cursor.fetchall()), 0)
            cursor.execute("SELECT id FROM prepared_packets WHERE user_id = ?", (user_id,))
            self.assertEqual(len(cursor.fetchall()), 0)

            # 3. Application audit logs must be preserved with user_id=NULL and anonymized pseudonym
            # If application cascade-deleted, foreign key ON DELETE SET NULL on application_id preserves logs
            cursor.execute("SELECT * FROM application_logs WHERE anonymized_user_pseudonym IS NOT NULL")
            anon_logs = cursor.fetchall()
            self.assertTrue(len(anon_logs) >= 1)
            for row in anon_logs:
                self.assertIsNone(row["user_id"])
                self.assertTrue(row["anonymized_user_pseudonym"].startswith("ANON_USER_"))
                # PII check: details must have user_deleted flag
                det = json.loads(row["details"])
                self.assertEqual(det.get("user_deleted"), 1)


if __name__ == "__main__":
    unittest.main()

"""tests/test_phase_7_2_2_3_trusted_verifier.py

PHASE 7.2.2.3 — TRUSTED VERIFIER BINDING & APPROVAL GRANT IDENTITY INTEGRITY

Validates:
1. Elimination of caller-controlled verifier injection:
   - DatabaseManager rejects raw session_manager kwargs with SecurityAuthorizationError.
   - DatabaseManager rejects non-SessionManager verifier instances.
   - DatabaseManager enforces explicit verification before opening any SQLite write lock.
   - False-returning or None-returning verifiers fail closed and roll back.
2. Complete 12-attribute cryptographic HMAC grant identity:
   - approver_name is bound to HMAC signature via RFC 8785 canonical JSON bytes.
   - Tampering any attribute (approver_name, grant_id, user_id, session_id,
     application_id, packet_id, packet_version_hash, ticket_nonce, issued_at, expires_at)
     fails cryptographic verification.
   - Submitted grant is checked against complete registered grant in active storage.
3. Thread-safe single-use grant consumption:
   - Concurrent threads attempting to consume the same grant result in exactly
     one success and one TicketAlreadyConsumedError / SecurityAuthorizationError.
   - Atomicity and event chain integrity are strictly preserved.
"""

import concurrent.futures
import os
import tempfile
import unittest
from unittest.mock import patch

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    SecurityAuthorizationError,
    TicketAlreadyConsumedError,
)
from src.database.models import ApplicationApproval, ApplicationStatus, VerifiedApprovalGrant
from src.preparer.approval_gate import HumanApprovalGate
from src.security.session_manager import SessionManager
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash


class BaseTrustedVerifierTestCase(unittest.TestCase):
    """Base setup for Phase 7.2.2.3 verifier binding and grant identity tests."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_trusted_verifier.db")
        self.session_mgr = SessionManager.get_instance()
        self.db = DatabaseManager(self.db_path, session_manager=self.session_mgr)
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'alice.candidate@example.com', 'h1', 's1', 'Alice Candidate')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'bob.candidate@example.com', 'h2', 's2', 'Bob Candidate')"
            )
        self.user_a = 1
        self.user_b = 2

        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="cand_alice",
            candidate_name="Alice Candidate",
            user_id=self.user_a,
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="cand_bob",
            candidate_name="Bob Candidate",
            user_id=self.user_b,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _setup_app_and_packet(self, user_id: int, initial_status: str = "READY_FOR_REVIEW"):
        """Helper to create test job description, resume, application, and prepared packet."""
        jd = self.db.save_job_description_snapshot(
            user_id=user_id,
            company_name="Apex Global Technologies",
            job_title="Lead Data Engineer",
            raw_content="Build distributed pipelines with Spark and Python.",
        )
        res = self.db.create_user_resume(
            user_id=user_id,
            original_filename="resume.pdf",
            storage_filename="resume_stored.pdf",
            file_format="pdf",
            file_hash="dummy_hash_resume_abc123",
            file_size_bytes=2048,
        )
        app = self.db.create_user_application(
            user_id=user_id,
            company_name="Apex Global Technologies",
            job_title="Lead Data Engineer",
            status=initial_status,
            job_description_id=jd.id,
            resume_id=res["id"],
        )

        dummy_snapshot = {
            "application_id": app.id,
            "user_id": user_id,
            "job_description_id": jd.id,
            "original_resume_id": res["id"],
            "packet_version": 1,
            "tailored_resume": {"summary": "Experienced Data Engineer"},
            "cover_letter": "I am thrilled to apply for the Lead Data Engineer position.",
            "screening_answers": [],
            "attachments_manifest": [],
        }
        snap_bytes = canonical_json_bytes(dummy_snapshot)
        snap_hash = canonical_json_hash(dummy_snapshot)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision
                ) VALUES (?, ?, 1, ?, 'dummy_hash_resume_abc123', 'jd_snap_hash', '[]', ?, 1)
                """,
                (app.id, user_id, snap_hash, snap_bytes.decode("utf-8")),
            )
        packet = self.db.get_active_prepared_packet(app.id, user_id)
        return app, packet, snap_hash

    def _issue_valid_grant(self, app, packet, snap_hash, user_session, approver_name="Alice Candidate"):
        ticket = self.session_mgr.issue_action_ticket(
            session_id=user_session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        v_ok, v_msg, auth_grant = self.session_mgr.verify_and_issue_approval_grant(
            session_id=user_session.session_id,
            ticket_str=ticket,
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=snap_hash,
            approver_name=approver_name,
        )
        self.assertTrue(v_ok, f"Grant issuance failed: {v_msg}")
        return auth_grant


class TestSection3VerifierSubstitution(BaseTrustedVerifierTestCase):
    """Section 3: Verifier-substitution regression tests."""

    def test_verifier_substitution_false_returning(self):
        """Test A: Verifier returning (False, reason) raises SecurityAuthorizationError and rolls back."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        # Patch verify_and_consume_approval_grant on authentic SessionManager to return (False, ...)
        with patch.object(self.session_mgr, "verify_and_consume_approval_grant", return_value=(False, "Grant verification rejected by policy")):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db._authorize_application_packet_atomic(auth_grant=grant)
            self.assertIn("Verifier rejected grant", str(ctx.exception))

        # Verify no database state mutated
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT COUNT(*) FROM application_logs WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 0)
        app_check = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_check.status, "READY_FOR_REVIEW")

    def test_verifier_substitution_none_returning(self):
        """Test B: Verifier returning None raises SecurityAuthorizationError and rolls back."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        with patch.object(self.session_mgr, "verify_and_consume_approval_grant", return_value=None):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db._authorize_application_packet_atomic(auth_grant=grant)
            self.assertIn("Invalid verifier response format", str(ctx.exception))

        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 0)
        app_check = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_check.status, "READY_FOR_REVIEW")

    def test_verifier_substitution_forged_verifier_object(self):
        """Test C: Injecting a forged, non-SessionManager verifier is rejected at initialization."""
        class ForgedVerifier:
            def verify_and_consume_approval_grant(self, grant):
                return True, "All good!"

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            DatabaseManager(self.db_path, session_manager=ForgedVerifier())
        self.assertIn("Invalid verifier configuration", str(ctx.exception))

    def test_verifier_substitution_raw_verifier_injection(self):
        """Test D: Injecting a raw session_manager kwarg to _authorize_application_packet_atomic is rejected."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        class FakeVerifier:
            pass

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db._authorize_application_packet_atomic(
                auth_grant=grant,
                session_manager=FakeVerifier(),
            )
        self.assertIn("Raw parameter bypass rejected", str(ctx.exception))
        self.assertIn("session_manager", str(ctx.exception))

    def test_verifier_genuine_workflow_passes(self):
        """Test E: Genuine workflow passes with 1 approval, 1 log, status APPROVED, 1 event, valid event chain."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

        succ, msg, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Alice Candidate",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Authorization failed: {msg}")
        self.assertIsNotNone(approval)
        self.assertEqual(approval.application_id, app.id)
        self.assertEqual(approval.packet_id, packet.id)
        self.assertEqual(approval.approver_name, "Alice Candidate")

        # Status advanced to APPROVED
        app_check = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_check.status, ApplicationStatus.APPROVED.value)

        # 1 approval row
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 1)
            cursor.execute("SELECT COUNT(*) FROM application_logs WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 1)

        # Timeline event created and hash chain valid
        events = self.db.get_application_events(app.id, self.user_a)
        self.assertEqual(len(events), 2)  # APPLICATION_CREATED + PACKET_HUMAN_APPROVED
        self.assertEqual(events[-1].event_type, "PACKET_HUMAN_APPROVED")
        self.assertEqual(events[-1].new_status, ApplicationStatus.APPROVED.value)
        valid, chain_err = self.db.verify_application_event_chain(app.id, self.user_a, raise_on_error=True)
        self.assertTrue(valid)


class TestSection5GrantTampering(BaseTrustedVerifierTestCase):
    """Section 5: Grant tampering regression tests verifying complete 12-attribute identity."""

    def test_tamper_approver_name_rejected(self):
        """Test A: Altering approver_name fails verification."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a, approver_name="Alice Candidate")

        tampered = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=grant.user_id,
            session_id=grant.session_id,
            application_id=grant.application_id,
            packet_id=grant.packet_id,
            packet_version_hash=grant.packet_version_hash,
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name="Forged Hacker Name",
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=tampered)

    def test_tamper_grant_id_rejected(self):
        """Test B: Altering grant_id fails verification."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        tampered = VerifiedApprovalGrant(
            grant_id="forged_grant_id_999",
            user_id=grant.user_id,
            session_id=grant.session_id,
            application_id=grant.application_id,
            packet_id=grant.packet_id,
            packet_version_hash=grant.packet_version_hash,
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name=grant.approver_name,
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=tampered)

    def test_tamper_user_id_rejected(self):
        """Test C: Altering user_id fails verification."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        tampered = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=self.user_b,
            session_id=grant.session_id,
            application_id=grant.application_id,
            packet_id=grant.packet_id,
            packet_version_hash=grant.packet_version_hash,
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name=grant.approver_name,
        )
        with self.assertRaises((SecurityAuthorizationError, CrossUserAccessError)):
            self.db._authorize_application_packet_atomic(auth_grant=tampered)

    def test_tamper_session_id_rejected(self):
        """Test D: Altering session_id fails verification."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        tampered = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=grant.user_id,
            session_id=self.session_b.session_id,
            application_id=grant.application_id,
            packet_id=grant.packet_id,
            packet_version_hash=grant.packet_version_hash,
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name=grant.approver_name,
        )
        with self.assertRaises((SecurityAuthorizationError, CrossUserAccessError)):
            self.db._authorize_application_packet_atomic(auth_grant=tampered)

    def test_tamper_application_id_rejected(self):
        """Test E: Altering application_id fails verification."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        tampered = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=grant.user_id,
            session_id=grant.session_id,
            application_id=9999,
            packet_id=grant.packet_id,
            packet_version_hash=grant.packet_version_hash,
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name=grant.approver_name,
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=tampered)

    def test_tamper_packet_id_rejected(self):
        """Test F: Altering packet_id fails verification."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        tampered = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=grant.user_id,
            session_id=grant.session_id,
            application_id=grant.application_id,
            packet_id=8888,
            packet_version_hash=grant.packet_version_hash,
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name=grant.approver_name,
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=tampered)

    def test_tamper_packet_version_hash_rejected(self):
        """Test G: Altering packet_version_hash fails verification."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        tampered = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=grant.user_id,
            session_id=grant.session_id,
            application_id=grant.application_id,
            packet_id=grant.packet_id,
            packet_version_hash="forged_packet_version_hash_999",
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name=grant.approver_name,
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=tampered)

    def test_tamper_ticket_nonce_rejected(self):
        """Test H: Altering ticket_nonce fails verification."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        tampered = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=grant.user_id,
            session_id=grant.session_id,
            application_id=grant.application_id,
            packet_id=grant.packet_id,
            packet_version_hash=grant.packet_version_hash,
            ticket_nonce="forged_ticket_nonce_777",
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name=grant.approver_name,
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=tampered)

    def test_tamper_expiry_or_issued_at_rejected(self):
        """Test I: Altering expires_at or issued_at fails verification."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        tampered_exp = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=grant.user_id,
            session_id=grant.session_id,
            application_id=grant.application_id,
            packet_id=grant.packet_id,
            packet_version_hash=grant.packet_version_hash,
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at + 1000,
            grant_signature=grant.grant_signature,
            approver_name=grant.approver_name,
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=tampered_exp)

        tampered_iss = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=grant.user_id,
            session_id=grant.session_id,
            application_id=grant.application_id,
            packet_id=grant.packet_id,
            packet_version_hash=grant.packet_version_hash,
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at - 100,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name=grant.approver_name,
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=tampered_iss)

    def test_registered_grant_mismatch_rejected(self):
        """Test J: Valid grant_id with altered attributes fails registered-grant comparison."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        # Alter approver_name while keeping the real grant_id
        mismatched = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=grant.user_id,
            session_id=grant.session_id,
            application_id=grant.application_id,
            packet_id=grant.packet_id,
            packet_version_hash=grant.packet_version_hash,
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name="Tampered Candidate Name",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.session_mgr.verify_and_consume_approval_grant(mismatched)
        self.assertIn("Submitted grant does not match registered grant identity", str(ctx.exception))

    def test_genuine_grant_passes_exactly_once(self):
        """Test K: Genuine grant passes verification and second attempt raises TicketAlreadyConsumedError."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        approval = self.db._authorize_application_packet_atomic(auth_grant=grant)
        self.assertIsNotNone(approval)
        self.assertIsInstance(approval, ApplicationApproval)

        with self.assertRaises(TicketAlreadyConsumedError):
            self.db._authorize_application_packet_atomic(auth_grant=grant)


class TestSection6SingleUseConcurrency(BaseTrustedVerifierTestCase):
    """Section 6: Single-use concurrency safety with multi-threaded execution."""

    def test_concurrent_grant_consumption_exactly_one_succeeds(self):
        """Two concurrent threads attempting to consume the same grant result in 1 success and 1 rejection."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        grant = self._issue_valid_grant(app, packet, snap_hash, self.session_a)

        successes = []
        failures = []

        def _worker(thread_idx: int):
            try:
                # Use separate database manager connection to simulate real multi-client access
                worker_db = DatabaseManager(self.db_path, session_manager=self.session_mgr)
                approval = worker_db._authorize_application_packet_atomic(auth_grant=grant)
                successes.append((thread_idx, approval))
            except (TicketAlreadyConsumedError, SecurityAuthorizationError) as exc:
                failures.append((thread_idx, exc))
            except Exception as exc:
                failures.append((thread_idx, exc))

        # Run 2 concurrent worker threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(_worker, 1)
            f2 = executor.submit(_worker, 2)
            f1.result()
            f2.result()

        # Exactly 1 must succeed and 1 must fail
        self.assertEqual(len(successes), 1, f"Expected exactly 1 success, got {len(successes)}: {successes}")
        self.assertEqual(len(failures), 1, f"Expected exactly 1 failure, got {len(failures)}: {failures}")

        failure_exc = failures[0][1]
        self.assertIsInstance(
            failure_exc,
            (TicketAlreadyConsumedError, SecurityAuthorizationError),
            f"Failure exception must be TicketAlreadyConsumedError or SecurityAuthorizationError, got {type(failure_exc)}: {failure_exc}",
        )

        # Invariant checks on database
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 1)
            cursor.execute("SELECT COUNT(*) FROM application_logs WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 1)

        app_check = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_check.status, ApplicationStatus.APPROVED.value)

        # Timeline event count & hash chain valid
        events = self.db.get_application_events(app.id, self.user_a)
        self.assertEqual(len(events), 2)
        valid, _ = self.db.verify_application_event_chain(app.id, self.user_a, raise_on_error=True)
        self.assertTrue(valid)


if __name__ == "__main__":
    unittest.main()

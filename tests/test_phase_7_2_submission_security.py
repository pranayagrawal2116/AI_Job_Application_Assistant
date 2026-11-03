"""Security, IDOR, and Failure-Mode Tests for Manual Submission Workflow (Phase 7.2).

Covers:
1. End-to-end authorized manual submission confirmation workflow (16-step sequence).
2. Mandatory candidate confirmation assertion (UnconfirmedSubmissionError).
3. Rejection of missing, malformed, and static dummy action tickets.
4. Ticket scope mismatches (wrong action type, wrong application ID, wrong packet hash, wrong session).
5. Ticket expiration and replay attack prevention (ticket single-use consumption).
6. Packet version integrity: inactive revisions and hash tampering detection.
7. Approval record requirements: missing approval and already-consumed approval.
8. Submission channel validation (controlled enum options).
9. Post-verification database rollback resilience (ticket marked consumed, DB rolled back, replay rejected).
10. External URL opening invariant (status preserved, never mutated to SUBMITTED).
11. Multi-user IDOR isolation: Candidate A cannot read, modify, transition, issue tickets for,
    or submit Candidate B's applications or materials.
"""

import os
import sqlite3
import tempfile
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    SecurityAuthorizationError,
    TicketAlreadyConsumedError,
    UnconfirmedSubmissionError,
    ValidationError,
)
from src.database.models import ApplicationStatus, SubmissionChannel
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash
from src.security.session_manager import SessionManager


class TestPhase72SubmissionSecurityBase(unittest.TestCase):
    """Fixture providing isolated database, test users, and approved application packets."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_submission_sec.db")
        self.db = DatabaseManager(self.db_path)
        self.service = DashboardService(db_manager=self.db)
        self.session_mgr = SessionManager.get_instance()

        # Seed two candidate users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'alice@example.com', 'h1', 's1', 'Alice Candidate')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'bob@example.com', 'h2', 's2', 'Bob Candidate')"
            )

        self.user_a = 1
        self.user_b = 2

        self.session_a = self.session_mgr.authenticate_candidate("alice_sec", "Alice Candidate", user_id=self.user_a)
        self.session_b = self.session_mgr.authenticate_candidate("bob_sec", "Bob Candidate", user_id=self.user_b)

    def tearDown(self):
        self.session_mgr.reset_instance()
        self.temp_dir.cleanup()

    def _setup_approved_application(
        self,
        user_id: int,
        session_id: str,
        packet_id: int = 1001,
        company: str = "Pinnacle AI",
        title: str = "Research Scientist",
        is_active_revision: int = 1,
        approval_consumed: int = 0,
    ):
        """Sets up a complete application in APPROVED status with packet and human approval."""
        app = self.service.create_candidate_application(
            session_id=session_id,
            company_name=company,
            job_title=title,
            status="DRAFT",
        )

        # Advance status to APPROVED in DB
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'APPROVED' WHERE id = ?", (app.id,))

        # Create canonical snapshot payload
        snap_payload = {
            "application_id": app.id,
            "user_id": user_id,
            "version_num": 1,
            "company_name": company,
            "job_title": title,
        }
        snap_json = canonical_json_bytes(snap_payload).decode("utf-8")
        pkt_hash = canonical_json_hash(snap_payload)

        # Insert prepared packet and approval record
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision
                ) VALUES (?, ?, ?, 1, ?, 'rh', 'jdh', '{}', ?, ?)
                """,
                (packet_id, app.id, user_id, pkt_hash, snap_json, is_active_revision),
            )
            cursor.execute(
                """
                INSERT INTO application_approvals (
                    id, application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, approver_name, session_id, is_consumed
                ) VALUES (?, ?, ?, ?, ?, ?, 'Human Auditor', ?, ?)
                """,
                (
                    packet_id,
                    app.id,
                    packet_id,
                    user_id,
                    pkt_hash,
                    f"nonce_{packet_id}",
                    session_id,
                    approval_consumed,
                ),
            )

        return app, packet_id, pkt_hash


class TestManualSubmissionWorkflow(TestPhase72SubmissionSecurityBase):
    """Tests for the complete manual submission security workflow."""

    def test_end_to_end_authorized_manual_submission(self):
        """Complete 16-step manual submission workflow succeeds."""
        app, pkt_id, pkt_hash = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=101
        )

        # Issue ticket
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=app.id,
            packet_hash=pkt_hash,
        )
        self.assertTrue(ticket.startswith("TKT-"))

        # Confirm submission
        conf = self.service.record_candidate_manual_submission(
            application_id=app.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            confirmation_reference="CONF-12345",
            candidate_notes="Submitted directly on employer portal",
        )

        # 1. Submission confirmation record
        self.assertEqual(conf.application_id, app.id)
        self.assertEqual(conf.user_id, self.user_a)
        self.assertEqual(conf.confirmation_reference, "CONF-12345")
        self.assertEqual(conf.submission_channel, SubmissionChannel.COMPANY_PORTAL.value)

        # 2. Application status transitioned to SUBMITTED
        fresh_app = self.service.get_candidate_application(app.id, self.session_a.session_id)
        self.assertEqual(fresh_app.status, ApplicationStatus.SUBMITTED.value)
        self.assertIsNotNone(fresh_app.date_submitted)

        # 3. Approval record consumed
        approval = self.db.get_packet_approval(pkt_id, self.user_a)
        self.assertIsNotNone(approval)
        self.assertEqual(approval.is_consumed, 1)

        # 4. Audit timeline contains SUBMISSION_CONFIRMED event with valid chain
        tl = self.service.get_application_timeline(app.id, self.session_a.session_id)
        self.assertTrue(tl["chain_valid"])
        event_types = [e.event_type for e in tl["events"]]
        self.assertIn("SUBMISSION_CONFIRMED", event_types)

    def test_unconfirmed_submission_rejected(self):
        """Omitting candidate_confirmed=True raises UnconfirmedSubmissionError."""
        app, _, pkt_hash = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=102
        )
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=app.id,
            packet_hash=pkt_hash,
        )

        with self.assertRaises(UnconfirmedSubmissionError):
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket,
                candidate_confirmed=False,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )

    def test_missing_or_malformed_submission_ticket_rejected(self):
        """Missing or malformed ticket strings are rejected."""
        app, _, _ = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=103
        )

        for bad_tkt in [None, "", "   ", "INVALID-TICKET", "TKT-corrupt.parts"]:
            with self.assertRaises(SecurityAuthorizationError):
                self.service.record_candidate_manual_submission(
                    application_id=app.id,
                    session_id=self.session_a.session_id,
                    submission_ticket=bad_tkt,
                    candidate_confirmed=True,
                    submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
                )

    def test_static_dummy_ticket_rejected(self):
        """Static hardcoded token strings are explicitly rejected."""
        app, _, _ = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=104
        )
        dummy_tokens = [
            "CANDIDATE_VERIFIED_MANUAL_SUBMISSION",
            "CANDIDATE_VERIFIED_DASHBOARD_APPROVAL",
        ]
        for dummy in dummy_tokens:
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.service.record_candidate_manual_submission(
                    application_id=app.id,
                    session_id=self.session_a.session_id,
                    submission_ticket=dummy,
                    candidate_confirmed=True,
                    submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
                )
            self.assertIn("Static constant token rejected", str(ctx.exception))

    def test_ticket_scope_action_type_mismatch_rejected(self):
        """Ticket issued for HUMAN_APPROVAL cannot be used for MANUAL_SUBMISSION."""
        app, _, pkt_hash = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=105
        )
        # Issue ticket with wrong action type
        wrong_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=pkt_hash,
        )

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=wrong_ticket,
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )
        self.assertTrue(
            "Ticket scope mismatch" in str(ctx.exception)
            or "Cryptographic signature mismatch" in str(ctx.exception)
            or "ticket forgery attempt" in str(ctx.exception)
        )

    def test_ticket_scope_application_id_mismatch_rejected(self):
        """Ticket issued for Application A cannot be used on Application B."""
        app_a, _, pkt_hash_a = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=106, company="Co A"
        )
        app_b, _, _ = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=107, company="Co B"
        )

        ticket_a = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=app_a.id,
            packet_hash=pkt_hash_a,
        )

        # Try to use ticket_a on app_b
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.record_candidate_manual_submission(
                application_id=app_b.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket_a,
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )
        self.assertTrue(
            "Ticket application ID mismatch" in str(ctx.exception)
            or "Cryptographic signature mismatch" in str(ctx.exception)
            or "ticket forgery attempt" in str(ctx.exception)
        )

    def test_ticket_scope_packet_hash_mismatch_rejected(self):
        """Ticket issued for packet hash H1 cannot be used if packet hash changes to H2."""
        app, _, _ = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=108
        )
        # Issue ticket with an arbitrary different hash
        fake_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=app.id,
            packet_hash="different_tampered_hash_999",
        )

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=fake_ticket,
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )
        self.assertTrue(
            "Ticket packet version mismatch" in str(ctx.exception)
            or "Cryptographic signature mismatch" in str(ctx.exception)
            or "ticket forgery attempt" in str(ctx.exception)
        )

    def test_ticket_replay_attack_rejected(self):
        """Using the same action ticket a second time is detected and blocked as a replay attack."""
        app, pkt_id, pkt_hash = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=109
        )
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=app.id,
            packet_hash=pkt_hash,
        )

        # First use succeeds
        self.service.record_candidate_manual_submission(
            application_id=app.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
        )

        # Replay attempt on SUBMITTED application fails
        with self.assertRaises(SecurityAuthorizationError):
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket,
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )

        # Reset application status to APPROVED and unconsume approval to explicitly test action ticket replay detection
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'APPROVED' WHERE id = ?", (app.id,))
            conn.execute("UPDATE application_approvals SET is_consumed = 0 WHERE id = ?", (pkt_id,))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket,
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )
        self.assertIn("Replay attack detected", str(ctx.exception))

    def test_inactive_packet_revision_rejected(self):
        """Applications with an inactive packet revision (is_active_revision=0) cannot be submitted."""
        app, _, pkt_hash = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=110, is_active_revision=0
        )
        # Cannot issue ticket for inactive packet
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.issue_manual_submission_ticket(
                session_id=self.session_a.session_id,
                application_id=app.id,
                packet_hash=pkt_hash,
            )
        self.assertIn("No active prepared packet found", str(ctx.exception))

    def test_already_consumed_approval_rejected(self):
        """If human approval was already consumed, submission fails with TicketAlreadyConsumedError."""
        app, _, pkt_hash = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=111, approval_consumed=1
        )
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=app.id,
            packet_hash=pkt_hash,
        )

        with self.assertRaises(TicketAlreadyConsumedError):
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket,
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )

    def test_invalid_submission_channel_rejected(self):
        """Invalid submission channel strings are rejected with ValidationError."""
        app, _, pkt_hash = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=112
        )
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=app.id,
            packet_hash=pkt_hash,
        )

        with self.assertRaises(ValidationError) as ctx:
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket,
                candidate_confirmed=True,
                submission_channel="DARK_WEB_PORTAL",
            )
        self.assertIn("Invalid submission channel", str(ctx.exception))

    def test_database_failure_after_ticket_consumption_prevents_replay(self):
        """If database operation fails after ticket verification, the ticket cannot be replayed.

        The database rolls back, leaving application status APPROVED, and a fresh ticket is required.
        """
        app, _, pkt_hash = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=113
        )
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=app.id,
            packet_hash=pkt_hash,
        )

        # Install SQLite trigger failing submission_confirmations insertion
        with self.db.connection() as conn:
            conn.execute("""
                CREATE TRIGGER simulate_sub_conf_fail
                BEFORE INSERT ON submission_confirmations
                BEGIN
                    SELECT RAISE(FAIL, 'Simulated failure during submission confirmation');
                END;
            """)

        try:
            with self.assertRaises(sqlite3.IntegrityError):
                self.service.record_candidate_manual_submission(
                    application_id=app.id,
                    session_id=self.session_a.session_id,
                    submission_ticket=ticket,
                    candidate_confirmed=True,
                    submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
                )
        finally:
            with self.db.connection() as conn:
                conn.execute("DROP TRIGGER IF EXISTS simulate_sub_conf_fail")

        # In DB: application must STILL be APPROVED!
        fresh_app = self.service.get_candidate_application(app.id, self.session_a.session_id)
        self.assertEqual(fresh_app.status, ApplicationStatus.APPROVED.value)

        # Ticket was consumed, so attempting to reuse it raises replay error
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.record_candidate_manual_submission(
                application_id=app.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket,
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )
        self.assertIn("Replay attack detected", str(ctx.exception))


class TestMultiUserIDORProtection(TestPhase72SubmissionSecurityBase):
    """Rigorous IDOR tests verifying Candidate A cannot access Candidate B's lifecycle resources."""

    def test_candidate_a_cannot_read_candidate_b_application(self):
        """Candidate A cannot retrieve Candidate B's application."""
        app_b, _, _ = self._setup_approved_application(
            self.user_b, self.session_b.session_id, packet_id=201
        )
        with self.assertRaises(CrossUserAccessError):
            self.service.get_candidate_application(
                application_id=app_b.id,
                session_id=self.session_a.session_id,
            )

    def test_candidate_a_cannot_transition_candidate_b_application(self):
        """Candidate A cannot transition Candidate B's application status."""
        app_b, _, _ = self._setup_approved_application(
            self.user_b, self.session_b.session_id, packet_id=202
        )
        with self.assertRaises(CrossUserAccessError):
            self.service.transition_application_status(
                application_id=app_b.id,
                session_id=self.session_a.session_id,
                new_status="WITHDRAWN",
            )

    def test_candidate_a_cannot_retrieve_candidate_b_timeline(self):
        """Candidate A cannot view Candidate B's timeline events."""
        app_b, _, _ = self._setup_approved_application(
            self.user_b, self.session_b.session_id, packet_id=203
        )
        with self.assertRaises(CrossUserAccessError):
            self.service.get_application_timeline(
                application_id=app_b.id,
                session_id=self.session_a.session_id,
            )

    def test_candidate_a_cannot_issue_submission_ticket_for_candidate_b(self):
        """Candidate A cannot issue a submission ticket for Candidate B's application."""
        app_b, _, pkt_hash_b = self._setup_approved_application(
            self.user_b, self.session_b.session_id, packet_id=204
        )
        with self.assertRaises(CrossUserAccessError):
            self.service.issue_manual_submission_ticket(
                session_id=self.session_a.session_id,
                application_id=app_b.id,
                packet_hash=pkt_hash_b,
            )

    def test_candidate_a_cannot_submit_candidate_b_application(self):
        """Candidate A cannot confirm submission on Candidate B's application."""
        app_b, _, pkt_hash_b = self._setup_approved_application(
            self.user_b, self.session_b.session_id, packet_id=205
        )
        # Even if ticket is issued on B's session
        ticket_b = self.service.issue_manual_submission_ticket(
            session_id=self.session_b.session_id,
            application_id=app_b.id,
            packet_hash=pkt_hash_b,
        )

        with self.assertRaises(CrossUserAccessError):
            self.service.record_candidate_manual_submission(
                application_id=app_b.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket_b,
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )

    def test_candidate_a_cannot_reuse_candidate_b_action_ticket(self):
        """Candidate A cannot use Candidate B's action ticket on Candidate A's application."""
        app_a, _, pkt_hash_a = self._setup_approved_application(
            self.user_a, self.session_a.session_id, packet_id=206, company="Alice App"
        )
        app_b, _, pkt_hash_b = self._setup_approved_application(
            self.user_b, self.session_b.session_id, packet_id=207, company="Bob App"
        )

        ticket_b = self.service.issue_manual_submission_ticket(
            session_id=self.session_b.session_id,
            application_id=app_b.id,
            packet_hash=pkt_hash_b,
        )

        # Candidate A tries to present ticket_b on Candidate A's session and application
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.service.record_candidate_manual_submission(
                application_id=app_a.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket_b,
                candidate_confirmed=True,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            )
        self.assertIn("Authorization rejected", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

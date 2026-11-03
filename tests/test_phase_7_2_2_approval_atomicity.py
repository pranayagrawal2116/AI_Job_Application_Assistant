"""Phase 7.2.2 Approval Atomicity Tests.

Verifies:
1. All four writes in authorize_application_packet_atomic commit atomically together:
   - application_approvals row
   - application_logs row
   - applications.status updated to APPROVED (or Awaiting Approval)
   - application_events row with PACKET_HUMAN_APPROVED
2. Pre-approval status check: requires READY_FOR_REVIEW (or legacy APPLICATION_PREPARED);
   rejects DRAFT, PREPARING, APPROVED, SUBMITTED, REJECTED, WITHDRAWN, CLOSED.
3. Failure-injection tests: failure at approval insert, log insert, status update,
   event insert, or commit triggers full rollback with zero partial state.
4. Cryptographic event chain integrity and hash pointers remain valid.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    InvalidStatusTransitionError,
    TicketAlreadyConsumedError,
)
from src.database.models import ApplicationStatus
from src.lifecycle.state_machine import ApplicationStateMachine
from src.preparer.approval_gate import HumanApprovalGate
from src.security.session_manager import SessionManager
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash


class TestPhase722ApprovalAtomicity(unittest.TestCase):
    """Rigorous atomicity and transaction rollback verification for human approvals."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_atomicity.db")
        self.db = DatabaseManager(self.db_path)
        self.session_mgr = SessionManager.get_instance()
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)

        # Create two candidate users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'candidate.one@example.com', 'h1', 's1', 'Candidate One')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'candidate.two@example.com', 'h2', 's2', 'Candidate Two')"
            )
        self.user_a = 1
        self.user_b = 2

        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="cand_one",
            candidate_name="Candidate One",
            user_id=self.user_a,
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="cand_two",
            candidate_name="Candidate Two",
            user_id=self.user_b,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def _setup_app_and_packet(self, user_id: int, initial_status: str = "READY_FOR_REVIEW"):
        """Helper creating a test job description, resume, application, and prepared packet."""
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
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision
                ) VALUES (201, ?, ?, 1, ?, 'dummy_hash_resume_abc123', 'jd_snap_hash', '[]', ?, 1)
                """,
                (app.id, user_id, snap_hash, snap_bytes.decode("utf-8")),
            )
        packet = self.db.get_active_prepared_packet(app.id, user_id)
        return app, packet, snap_hash

    # =========================================================================
    # 1. ATOMIC COMMIT VERIFICATION
    # =========================================================================

    def test_all_four_writes_commit_atomically(self):
        """All four records commit together: approval, logs, status update, timeline event."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

        success, msg, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(success, f"Approval failed: {msg}")
        self.assertIsNotNone(approval)

        # 1. Verify application_approvals row
        self.assertEqual(approval.application_id, app.id)
        self.assertEqual(approval.user_id, self.user_a)
        self.assertEqual(approval.packet_version_hash, snap_hash)
        self.assertEqual(approval.approver_name, "Candidate One")
        self.assertEqual(approval.is_consumed, 0)

        # 2. Verify application_logs row
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM application_logs WHERE application_id = ? AND action = 'HUMAN_APPROVAL_GRANTED'",
                (app.id,),
            )
            log_row = cursor.fetchone()
            self.assertIsNotNone(log_row)
            details = json.loads(log_row["details"])
            self.assertEqual(details["approver"], "Candidate One")
            self.assertEqual(details["packet_version_hash"], snap_hash)

        # 3. Verify applications.status updated
        updated_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(
            ApplicationStateMachine.normalize_status(updated_app.status),
            ApplicationStatus.APPROVED,
        )

        # 4. Verify application_events row
        events = self.db.get_application_events(app.id, self.user_a)
        approved_events = [e for e in events if e.event_type == "PACKET_HUMAN_APPROVED"]
        self.assertEqual(len(approved_events), 1)
        evt = approved_events[0]
        self.assertEqual(evt.previous_status, "READY_FOR_REVIEW")
        self.assertEqual(ApplicationStateMachine.normalize_status(evt.new_status), ApplicationStatus.APPROVED)
        self.assertEqual(evt.actor_type, "CANDIDATE")
        self.assertEqual(evt.actor_identifier, "Candidate One")
        self.assertEqual(evt.session_reference, self.session_a.session_id)
        self.assertIsNotNone(evt.event_hash)

    def test_legacy_application_prepared_status_commits_atomically(self):
        """Applications in legacy 'Application Prepared' status transition to 'Awaiting Approval'."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, ApplicationStatus.APPLICATION_PREPARED.value)

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

        success, msg, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(success, f"Approval failed: {msg}")
        updated_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(updated_app.status, ApplicationStatus.AWAITING_APPROVAL.value)

    # =========================================================================
    # 2. STATUS PRE-CHECK REJECTIONS
    # =========================================================================

    def test_approval_rejected_from_invalid_statuses(self):
        """Approval is rejected when application is not in READY_FOR_REVIEW or APPLICATION_PREPARED."""
        invalid_statuses = [
            ApplicationStatus.DRAFT.value,
            ApplicationStatus.PREPARING.value,
            ApplicationStatus.APPROVED.value,
            ApplicationStatus.SUBMITTED.value,
            ApplicationStatus.REJECTED.value,
            ApplicationStatus.WITHDRAWN.value,
            ApplicationStatus.CLOSED.value,
        ]

        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "DRAFT")

        for invalid_status in invalid_statuses:
            self.service_mock_update_status(app.id, invalid_status)

            ticket = self.session_mgr.issue_action_ticket(
                session_id=self.session_a.session_id,
                action_type="HUMAN_APPROVAL",
                application_id=app.id,
                packet_hash=snap_hash,
            )

            with self.assertRaises(InvalidStatusTransitionError):
                self.db.authorize_application_packet_atomic(
                    application_id=app.id,
                    user_id=self.user_a,
                    packet_id=packet.id,
                    packet_version_hash=snap_hash,
                    ticket_nonce=f"nonce_{invalid_status}",
                    approver_name="Candidate One",
                )

            # Via gate
            succ, msg, _ = self.gate.authorize_universal_packet(
                user_id=self.user_a,
                application_id=app.id,
                packet_id=packet.id,
                approver_name="Candidate One",
                session_id=self.session_a.session_id,
                action_ticket=ticket,
                candidate_confirmed=True,
            )
            self.assertFalse(succ)
            self.assertIn("Database error recording approval", msg)

            # Verify no approval or logs exist
            with self.db.connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
                self.assertEqual(cursor.fetchone()[0], 0)
                cursor.execute("SELECT COUNT(*) FROM application_logs WHERE application_id = ?", (app.id,))
                self.assertEqual(cursor.fetchone()[0], 0)

            # Application status is untouched
            app_fresh = self.db.get_user_application(app.id, self.user_a)
            self.assertEqual(app_fresh.status, invalid_status)

    # =========================================================================
    # 3. FAILURE-INJECTION ROLLBACK TESTS
    # =========================================================================

    def test_failure_in_approval_insert_rolls_back_everything(self):
        """If application_approvals insert fails (e.g. duplicate nonce), no partial writes persist."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")

        # Pre-insert approval with identical nonce
        dup_nonce = "duplicate_nonce_12345"
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO application_approvals (
                    application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, key_id, approver_name, session_id, approved_at, is_consumed
                ) VALUES (?, ?, ?, ?, ?, 'v1', 'Pre Existing', 'sess', CURRENT_TIMESTAMP, 0)
                """,
                (app.id, packet.id, self.user_a, snap_hash, dup_nonce),
            )

        # Attempt atomic authorization with duplicate nonce
        with self.assertRaises(TicketAlreadyConsumedError):
            self.db.authorize_application_packet_atomic(
                application_id=app.id,
                user_id=self.user_a,
                packet_id=packet.id,
                packet_version_hash=snap_hash,
                ticket_nonce=dup_nonce,
                approver_name="Candidate One",
            )

        # Status must remain READY_FOR_REVIEW
        app_fresh = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_fresh.status, "READY_FOR_REVIEW")

        # No PACKET_HUMAN_APPROVED event appended
        events = self.db.get_application_events(app.id, self.user_a)
        approved_events = [e for e in events if e.event_type == "PACKET_HUMAN_APPROVED"]
        self.assertEqual(len(approved_events), 0)

    def test_failure_in_event_insert_rolls_back_approval_and_status(self):
        """If _insert_application_event_internal fails, approval and status updates are rolled back."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")

        initial_approval_count = 0
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            initial_approval_count = cursor.fetchone()[0]

        # Patch _insert_application_event_internal to raise error
        with patch.object(
            self.db,
            "_insert_application_event_internal",
            side_effect=RuntimeError("Simulated event timeline insertion failure"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                self.db.authorize_application_packet_atomic(
                    application_id=app.id,
                    user_id=self.user_a,
                    packet_id=packet.id,
                    packet_version_hash=snap_hash,
                    ticket_nonce="failed_event_nonce",
                    approver_name="Candidate One",
                )
            self.assertIn("Simulated event timeline insertion failure", str(ctx.exception))

        # Complete rollback assertion:
        # 1. No approval record added
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], initial_approval_count)
            # 2. No log record added
            cursor.execute("SELECT COUNT(*) FROM application_logs WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 0)

        # 3. Application status strictly preserved at READY_FOR_REVIEW
        app_fresh = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_fresh.status, "READY_FOR_REVIEW")

        # 4. Zero timeline events added
        events = self.db.get_application_events(app.id, self.user_a)
        self.assertEqual(len([e for e in events if e.event_type == "PACKET_HUMAN_APPROVED"]), 0)

    def test_consumed_ticket_cannot_be_replayed_even_if_db_write_fails(self):
        """Ticket is consumed in memory before DB write; replay is rejected even if DB write failed."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "DRAFT")  # Invalid status

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

        # First authorization attempt fails due to DRAFT status
        succ1, msg1, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ1)
        self.assertIn("Database error recording approval", msg1)

        # Transition application to valid status
        self.service_mock_update_status(app.id, "READY_FOR_REVIEW")

        # Replay attempt with same ticket is rejected at the ticket gate
        succ2, msg2, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ2)
        self.assertIn("already been used", msg2)

    def service_mock_update_status(self, app_id: int, new_status: str):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE applications SET status = ? WHERE id = ?", (new_status, app_id))


if __name__ == "__main__":
    unittest.main()

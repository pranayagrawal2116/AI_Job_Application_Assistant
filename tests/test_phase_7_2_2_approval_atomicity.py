"""Phase 7.2.2 Approval Atomicity Tests.

Verifies:
1. All four writes in _authorize_application_packet_atomic commit atomically together:
   - application_approvals row
   - application_logs row
   - applications.status updated to APPROVED (or Awaiting Approval)
   - application_events row with PACKET_HUMAN_APPROVED
2. Pre-approval status check: requires READY_FOR_REVIEW (or legacy APPLICATION_PREPARED);
   rejects DRAFT, PREPARING, APPROVED, SUBMITTED, REJECTED, WITHDRAWN, CLOSED.
3. Trusted approval boundary & bypass closure:
   - No public authorize_application_packet_atomic method on DatabaseManager.
   - No arbitrary target_status parameter accepted.
   - Generic status transition cannot jump to APPROVED / Awaiting Approval.
   - Comprehensive action ticket validation on HumanApprovalGate.
4. Complete failure-injection tests across all 7 points of potential failure:
   - Test A: Approval-row insertion failure
   - Test B: Application-log insertion failure
   - Test C: Application status update failure
   - Test D: Event canonicalization failure
   - Test E: Event hash computation failure
   - Test F: Event insertion failure
   - Test G: Transaction commit failure
5. Full rollback verification on all 7 failure scenarios:
   - 0 approvals added
   - 0 logs added
   - status strictly preserved
   - 0 events added
   - pre-existing events unchanged
   - sequence numbers contiguous
   - hash chain valid
   - no false success
   - failed ticket cannot be replayed
   - fresh ticket retry succeeds
"""

import inspect
import json
import os
import sqlite3
import tempfile
from typing import Any
import unittest
from unittest.mock import patch

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    InvalidStatusTransitionError,
    SecurityAuthorizationError,
    TicketAlreadyConsumedError,
    ValidationError,
)
from src.database.models import ApplicationStatus, VerifiedApprovalGrant
from src.lifecycle.state_machine import ApplicationStateMachine
from src.preparer.approval_gate import HumanApprovalGate
from src.security.session_manager import SessionManager
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash


class TestPhase722ApprovalAtomicity(unittest.TestCase):
    """Rigorous atomicity, transaction rollback, and boundary closure verification for human approvals."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_atomicity.db")
        self.db = DatabaseManager(self.db_path)
        self.session_mgr = SessionManager.get_instance()
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)
        self.dashboard_service = DashboardService(db_manager=self.db)

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
                    application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision
                ) VALUES (?, ?, 1, ?, 'dummy_hash_resume_abc123', 'jd_snap_hash', '[]', ?, 1)
                """,
                (app.id, user_id, snap_hash, snap_bytes.decode("utf-8")),
            )
        packet = self.db.get_active_prepared_packet(app.id, user_id)
        return app, packet, snap_hash

    def _snapshot_application_events(self, app_id: int):
        events = self.db.get_application_events(app_id, self.user_a)
        return [
            {
                "id": e.id,
                "sequence_no": e.sequence_no,
                "event_type": e.event_type,
                "previous_status": e.previous_status,
                "new_status": e.new_status,
                "event_payload_json": e.event_payload_json,
                "created_at": e.created_at,
                "previous_event_hash": e.previous_event_hash,
                "event_hash": e.event_hash,
            }
            for e in events
        ]

    def _assert_approval_rolled_back_and_verifiable(
        self,
        app_id: int,
        initial_events_or_snapshot: Any,
        ticket: str,
        packet_id: int,
        snap_hash: str,
    ):
        """Common assertions for all failure-injection and rollback tests."""
        # 1. Zero approvals added
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app_id,))
            self.assertEqual(cursor.fetchone()[0], 0)

            # 2. Zero logs added for HUMAN_APPROVAL_GRANTED
            cursor.execute(
                "SELECT COUNT(*) FROM application_logs WHERE application_id = ? AND action = 'HUMAN_APPROVAL_GRANTED'",
                (app_id,),
            )
            self.assertEqual(cursor.fetchone()[0], 0)

        # 3. Status strictly preserved at exact original value
        app = self.db.get_user_application(app_id, self.user_a)
        self.assertEqual(app.status, "READY_FOR_REVIEW")

        # 4. Zero PACKET_HUMAN_APPROVED events
        events = self.db.get_application_events(app_id, self.user_a)
        self.assertEqual(len([e for e in events if e.event_type == "PACKET_HUMAN_APPROVED"]), 0)

        # 5. Pre-existing timeline events unchanged in count and attributes
        if isinstance(initial_events_or_snapshot, list):
            self.assertEqual(len(events), len(initial_events_or_snapshot))
            for current_evt, snap in zip(events, initial_events_or_snapshot):
                self.assertEqual(current_evt.id, snap["id"])
                self.assertEqual(current_evt.sequence_no, snap["sequence_no"])
                self.assertEqual(current_evt.event_type, snap["event_type"])
                self.assertEqual(current_evt.previous_status, snap["previous_status"])
                self.assertEqual(current_evt.new_status, snap["new_status"])
                self.assertEqual(current_evt.event_payload_json, snap["event_payload_json"])
                self.assertEqual(current_evt.created_at, snap["created_at"])
                self.assertEqual(current_evt.previous_event_hash, snap["previous_event_hash"])
                self.assertEqual(current_evt.event_hash, snap["event_hash"])
        else:
            self.assertEqual(len(events), initial_events_or_snapshot)

        # 6. Sequence numbers contiguous (1..N)
        seqs = [e.sequence_no for e in events]
        self.assertEqual(seqs, list(range(1, len(events) + 1)))

        # 7. Hash chain intact and cryptographically verifiable
        valid, err = self.db.verify_application_event_chain(app_id, self.user_a, raise_on_error=True)
        self.assertTrue(valid, f"Event chain verification failed: {err}")

        # 8 & 9. Failed ticket was consumed in memory and cannot be replayed
        succ_replay, msg_replay, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app_id,
            packet_id=packet_id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ_replay)
        self.assertTrue(
            "already been used" in msg_replay or "Database error" in msg_replay or "rejected" in msg_replay.lower()
        )

    # =========================================================================
    # 1. TRUSTED APPROVAL BOUNDARY & DIRECT BYPASS CLOSURE
    # =========================================================================

    def test_no_direct_public_database_approval_method(self):
        """DatabaseManager has NO public authorize_application_packet_atomic method."""
        self.assertFalse(
            hasattr(self.db, "authorize_application_packet_atomic"),
            "DatabaseManager must not expose a public authorize_application_packet_atomic method.",
        )
        self.assertTrue(
            hasattr(self.db, "_authorize_application_packet_atomic"),
            "DatabaseManager must provide an internal _authorize_application_packet_atomic method.",
        )

    def test_no_arbitrary_target_status_parameter(self):
        """_authorize_application_packet_atomic does not accept a target_status parameter."""
        sig = inspect.signature(self.db._authorize_application_packet_atomic)
        self.assertNotIn(
            "target_status",
            sig.parameters,
            "_authorize_application_packet_atomic must derive target_status internally and not accept it as an argument.",
        )

    def test_internal_method_requires_verified_context(self):
        """_authorize_application_packet_atomic requires a valid VerifiedApprovalGrant."""
        with self.assertRaises((SecurityAuthorizationError, ValidationError, ValueError)):
            self.db._authorize_application_packet_atomic(auth_context=None)

    def test_generic_transition_cannot_authorize_approval(self):
        """Generic transitions directly to APPROVED or Awaiting Approval raise SecurityAuthorizationError."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")

        # 1. StateMachine direct check
        with self.assertRaises(SecurityAuthorizationError):
            ApplicationStateMachine.validate_transition(
                current_status=ApplicationStatus.READY_FOR_REVIEW,
                new_status=ApplicationStatus.APPROVED,
            )

        # 2. DatabaseManager transition_application_status
        with self.assertRaises(SecurityAuthorizationError):
            self.db.transition_application_status(
                application_id=app.id,
                user_id=self.user_a,
                new_status=ApplicationStatus.APPROVED.value,
            )

        # 3. Caller-supplied bypass booleans are rejected
        with self.assertRaises(SecurityAuthorizationError):
            self.db.transition_application_status(
                application_id=app.id,
                user_id=self.user_a,
                new_status=ApplicationStatus.APPROVED.value,
                is_gate_authorized=True,
            )

        # 4. DashboardService transition_application_status
        with self.assertRaises(SecurityAuthorizationError):
            self.dashboard_service.transition_application_status(
                application_id=app.id,
                session_id=self.session_a.session_id,
                new_status=ApplicationStatus.APPROVED.value,
            )

    def test_approval_gate_ticket_validation_comprehensive(self):
        """HumanApprovalGate validates ticket format, signature, action, resource, hash, expiry, and revocation."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")

        # A. Missing or empty ticket
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket="",
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("Missing action ticket", msg)

        # B. Malformed ticket
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket="TKT-malformed-no-dots",
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("Malformed action ticket", msg)

        # C. Forged signature
        valid_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        parts = valid_ticket.split(".")
        forged_ticket = f"{parts[0]}.{parts[1]}.{'deadbeef' * 8}"
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=forged_ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertIn("forgery attempt", msg)

        # D. Wrong action type
        wrong_action_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="DATA_EXPORT",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=wrong_action_ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertTrue("rejected" in msg.lower() or "forgery" in msg.lower())

        # E. Wrong application ID
        wrong_app_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id + 999,
            packet_hash=snap_hash,
        )
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=wrong_app_ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertTrue("rejected" in msg.lower() or "forgery" in msg.lower())

        # F. Wrong packet hash
        wrong_hash_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash="different_packet_hash_xyz",
        )
        succ, msg, _ = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=wrong_hash_ticket,
            candidate_confirmed=True,
        )
        self.assertFalse(succ)
        self.assertTrue("rejected" in msg.lower() or "forgery" in msg.lower())

    # =========================================================================
    # 2. ATOMIC COMMIT VERIFICATION
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

            # Direct internal call with legitimate grant raises InvalidStatusTransitionError
            # when application is in an invalid status
            internal_ticket = self.session_mgr.issue_action_ticket(
                session_id=self.session_a.session_id,
                action_type="HUMAN_APPROVAL",
                application_id=app.id,
                packet_hash=snap_hash,
            )
            v_ok, v_msg, auth_grant = self.session_mgr.verify_and_issue_approval_grant(
                session_id=self.session_a.session_id,
                ticket_str=internal_ticket,
                application_id=app.id,
                packet_id=packet.id,
                packet_hash=snap_hash,
                approver_name="Candidate One",
            )
            self.assertTrue(v_ok, f"Grant issuance failed: {v_msg}")
            with self.assertRaises(InvalidStatusTransitionError):
                self.db._authorize_application_packet_atomic(
                    auth_grant=auth_grant,
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
    # 3. COMPLETE FAILURE-INJECTION ROLLBACK TESTS (TESTS A THROUGH G)
    # =========================================================================

    def test_failure_injection_a_approval_row_insert_fails(self):
        """Test A: If application_approvals insert fails, all writes rollback and retry succeeds."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        initial_events = self._snapshot_application_events(app.id)

        # Add trigger to fail approval insert
        with self.db.transaction() as conn:
            conn.execute(
                "CREATE TRIGGER fail_app_approval BEFORE INSERT ON application_approvals "
                "BEGIN SELECT RAISE(ABORT, 'Simulated approval insert failure'); END;"
            )

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

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
        self.assertIn("Simulated approval insert failure", msg)

        # Assert rollback invariants 1-9
        self._assert_approval_rolled_back_and_verifiable(
            app.id, initial_events, ticket, packet.id, snap_hash
        )

        # Remove trigger and retry with fresh ticket (assertion 10)
        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER fail_app_approval")

        fresh_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        succ_retry, msg_retry, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=fresh_ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_retry, f"Retry failed: {msg_retry}")
        self.assertIsNotNone(approval)

    def test_failure_injection_b_application_log_insert_fails(self):
        """Test B: If application_logs insert fails, all writes rollback and retry succeeds."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        initial_events = self._snapshot_application_events(app.id)

        # Add trigger to fail log insert
        with self.db.transaction() as conn:
            conn.execute(
                "CREATE TRIGGER fail_app_log BEFORE INSERT ON application_logs "
                "BEGIN SELECT RAISE(ABORT, 'Simulated log insert failure'); END;"
            )

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

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
        self.assertIn("Simulated log insert failure", msg)

        # Assert rollback invariants 1-9
        self._assert_approval_rolled_back_and_verifiable(
            app.id, initial_events, ticket, packet.id, snap_hash
        )

        # Drop trigger and retry with fresh ticket (assertion 10)
        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER fail_app_log")

        fresh_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        succ_retry, msg_retry, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=fresh_ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_retry, f"Retry failed: {msg_retry}")
        self.assertIsNotNone(approval)

    def test_failure_injection_c_status_update_fails(self):
        """Test C: If applications status update fails, all writes rollback and retry succeeds."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        initial_events = self._snapshot_application_events(app.id)

        # Add trigger to fail status update
        with self.db.transaction() as conn:
            conn.execute(
                "CREATE TRIGGER fail_status_update BEFORE UPDATE OF status ON applications "
                "BEGIN SELECT RAISE(ABORT, 'Simulated status update failure'); END;"
            )

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

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
        self.assertIn("Simulated status update failure", msg)

        # Assert rollback invariants 1-9
        self._assert_approval_rolled_back_and_verifiable(
            app.id, initial_events, ticket, packet.id, snap_hash
        )

        # Drop trigger and retry with fresh ticket (assertion 10)
        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER fail_status_update")

        fresh_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        succ_retry, msg_retry, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=fresh_ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_retry, f"Retry failed: {msg_retry}")
        self.assertIsNotNone(approval)

    def test_failure_injection_d_event_canonicalization_fails(self):
        """Test D: If event payload canonicalization fails, all writes rollback and retry succeeds."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        initial_events = self._snapshot_application_events(app.id)

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

        with patch(
            "src.database.db_manager.canonical_json_bytes",
            side_effect=RuntimeError("Simulated event canonicalization failure"),
        ):
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
            self.assertIn("Simulated event canonicalization failure", msg)

        # Assert rollback invariants 1-9
        self._assert_approval_rolled_back_and_verifiable(
            app.id, initial_events, ticket, packet.id, snap_hash
        )

        # Retry with fresh ticket (assertion 10)
        fresh_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        succ_retry, msg_retry, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=fresh_ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_retry, f"Retry failed: {msg_retry}")
        self.assertIsNotNone(approval)

    def test_failure_injection_e_event_hash_computation_fails(self):
        """Test E: If event hash computation fails, all writes rollback and retry succeeds."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        initial_events = self._snapshot_application_events(app.id)

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

        with patch(
            "src.database.db_manager.DatabaseManager.compute_event_hash",
            side_effect=RuntimeError("Simulated event hash computation failure"),
        ):
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
            self.assertIn("Simulated event hash computation failure", msg)

        # Assert rollback invariants 1-9
        self._assert_approval_rolled_back_and_verifiable(
            app.id, initial_events, ticket, packet.id, snap_hash
        )

        # Retry with fresh ticket (assertion 10)
        fresh_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        succ_retry, msg_retry, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=fresh_ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_retry, f"Retry failed: {msg_retry}")
        self.assertIsNotNone(approval)

    def test_failure_injection_f_event_insertion_fails(self):
        """Test F: If application_events insert fails, all writes rollback and retry succeeds."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        initial_events = self._snapshot_application_events(app.id)

        # Add trigger to fail event insert
        with self.db.transaction() as conn:
            conn.execute(
                "CREATE TRIGGER fail_app_events BEFORE INSERT ON application_events "
                "BEGIN SELECT RAISE(ABORT, 'Simulated event timeline insertion failure'); END;"
            )

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

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
        self.assertIn("Simulated event timeline insertion failure", msg)

        # Assert rollback invariants 1-9
        self._assert_approval_rolled_back_and_verifiable(
            app.id, initial_events, ticket, packet.id, snap_hash
        )

        # Drop trigger and retry with fresh ticket (assertion 10)
        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER fail_app_events")

        fresh_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        succ_retry, msg_retry, approval = self.gate.authorize_universal_packet(
            user_id=self.user_a,
            application_id=app.id,
            packet_id=packet.id,
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=fresh_ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_retry, f"Retry failed: {msg_retry}")
        self.assertIsNotNone(approval)

    def test_failure_injection_g_transaction_commit_fails(self):
        """Test G: If transaction COMMIT fails, all writes rollback and retry succeeds."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        initial_events = self._snapshot_application_events(app.id)

        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )

        # Wrap connection execute to simulate commit error once
        orig_get_connection = self.db.get_connection
        commit_failed = [False]

        class FailingCommitConnWrapper:
            def __init__(self, real_conn):
                self._real = real_conn

            def execute(self, sql, *params):
                if sql.strip().upper() == "COMMIT" and not commit_failed[0]:
                    commit_failed[0] = True
                    raise sqlite3.OperationalError("Simulated disk I/O error during commit")
                return self._real.execute(sql, *params)

            def cursor(self):
                return self._real.cursor()

            def close(self):
                return self._real.close()

            def __getattr__(self, name):
                return getattr(self._real, name)

        def failing_get_connection(*args, **kwargs):
            conn = orig_get_connection(*args, **kwargs)
            return FailingCommitConnWrapper(conn)

        with patch.object(self.db, "get_connection", side_effect=failing_get_connection):
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
            self.assertIn("Simulated disk I/O error during commit", msg)

            # Assert rollback invariants 1-9
            self._assert_approval_rolled_back_and_verifiable(
                app.id, initial_events, ticket, packet.id, snap_hash
            )

            # Retry with fresh ticket (assertion 10; commit_failed[0] is True, so next commit succeeds)
            fresh_ticket = self.session_mgr.issue_action_ticket(
                session_id=self.session_a.session_id,
                action_type="HUMAN_APPROVAL",
                application_id=app.id,
                packet_hash=snap_hash,
            )
            succ_retry, msg_retry, approval = self.gate.authorize_universal_packet(
                user_id=self.user_a,
                application_id=app.id,
                packet_id=packet.id,
                approver_name="Candidate One",
                session_id=self.session_a.session_id,
                action_ticket=fresh_ticket,
                candidate_confirmed=True,
            )
            self.assertTrue(succ_retry, f"Retry failed: {msg_retry}")
            self.assertIsNotNone(approval)

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

    # =========================================================================
    # 4. DIRECT-BYPASS REGRESSION TESTS (TESTS A THROUGH J)
    # =========================================================================

    def test_direct_bypass_rejection_raw_fields(self):
        """Test A: Raw field kwargs bypass without a VerifiedApprovalGrant is rejected before write lock."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(
                application_id=app.id,
                user_id=self.user_a,
                packet_id=packet.id,
                packet_version_hash=snap_hash,
                ticket_nonce="raw_bypass_nonce",
                key_id="v1",
                approver_name="Bypass Attacker",
                session_id=self.session_a.session_id,
            )
        # Verify no database state mutated
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT COUNT(*) FROM application_logs WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 0)
        app_check = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_check.status, "READY_FOR_REVIEW")

    def test_direct_bypass_rejection_missing_grant(self):
        """Test B: Calling _authorize_application_packet_atomic with auth_grant=None is rejected immediately."""
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(auth_grant=None)

    def test_direct_bypass_rejection_forged_grant(self):
        """Test C: Fabricating a VerifiedApprovalGrant directly with fake signature/grant_id is rejected."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        forged_grant = VerifiedApprovalGrant(
            grant_id="invented_grant_id_1234567890abcdef",
            user_id=self.user_a,
            session_id=self.session_a.session_id,
            application_id=app.id,
            packet_id=packet.id,
            packet_version_hash=snap_hash,
            ticket_nonce="invented_nonce_123",
            key_id="v1",
            action_type="HUMAN_APPROVAL",
            issued_at=int(os.environ.get("MOCK_TIME", 1700000000)),
            expires_at=int(os.environ.get("MOCK_TIME", 1700000000)) + 300,
            grant_signature="deadbeef" * 8,
            approver_name="Candidate One",
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(
                auth_grant=forged_grant,
            )
        # Verify 0 approvals exist
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 0)

    def test_direct_bypass_rejection_wrong_user_or_session(self):
        """Test D: An approval grant issued for User B cannot authorize User A's application."""
        app_a, packet_a, snap_hash_a = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        app_b, packet_b, snap_hash_b = self._setup_app_and_packet(self.user_b, "READY_FOR_REVIEW")

        ticket_b = self.session_mgr.issue_action_ticket(
            session_id=self.session_b.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app_b.id,
            packet_hash=snap_hash_b,
        )
        ok_b, msg_b, grant_b = self.session_mgr.verify_and_issue_approval_grant(
            session_id=self.session_b.session_id,
            ticket_str=ticket_b,
            application_id=app_b.id,
            packet_id=packet_b.id,
            packet_hash=snap_hash_b,
            approver_name="Candidate Two",
        )
        self.assertTrue(ok_b)

        # 1. Attacker tampers User B's grant to point to User A's application
        tampered_app_grant = VerifiedApprovalGrant(
            grant_id=grant_b.grant_id,
            user_id=grant_b.user_id,
            session_id=grant_b.session_id,
            application_id=app_a.id,
            packet_id=grant_b.packet_id,
            packet_version_hash=grant_b.packet_version_hash,
            ticket_nonce=grant_b.ticket_nonce,
            key_id=grant_b.key_id,
            action_type=grant_b.action_type,
            issued_at=grant_b.issued_at,
            expires_at=grant_b.expires_at,
            grant_signature=grant_b.grant_signature,
            approver_name=grant_b.approver_name,
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(
                auth_grant=tampered_app_grant,
            )

        # 2. Attacker tampers User B's grant to bind to User A's session
        tampered_sess_grant = VerifiedApprovalGrant(
            grant_id=grant_b.grant_id,
            user_id=self.user_b,
            session_id=self.session_a.session_id,
            application_id=app_b.id,
            packet_id=grant_b.packet_id,
            packet_version_hash=grant_b.packet_version_hash,
            ticket_nonce=grant_b.ticket_nonce,
            key_id=grant_b.key_id,
            action_type=grant_b.action_type,
            issued_at=grant_b.issued_at,
            expires_at=grant_b.expires_at,
            grant_signature=grant_b.grant_signature,
            approver_name=grant_b.approver_name,
        )
        with self.assertRaises((SecurityAuthorizationError, CrossUserAccessError)):
            self.db._authorize_application_packet_atomic(
                auth_grant=tampered_sess_grant,
            )

        app_a_check = self.db.get_user_application(app_a.id, self.user_a)
        self.assertEqual(app_a_check.status, "READY_FOR_REVIEW")

    def test_direct_bypass_rejection_wrong_application(self):
        """Test E: A grant issued for Application 1 cannot authorize Application 2."""
        app1, packet1, snap_hash1 = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        app2 = self.db.create_user_application(
            user_id=self.user_a,
            company_name="Second Company",
            job_title="Software Architect",
            status="READY_FOR_REVIEW",
        )

        ticket1 = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app1.id,
            packet_hash=snap_hash1,
        )
        ok1, msg1, grant1 = self.session_mgr.verify_and_issue_approval_grant(
            session_id=self.session_a.session_id,
            ticket_str=ticket1,
            application_id=app1.id,
            packet_id=packet1.id,
            packet_hash=snap_hash1,
            approver_name="Candidate One",
        )
        self.assertTrue(ok1)

        # Altering grant's application_id fails HMAC grant signature verification
        tampered_grant = VerifiedApprovalGrant(
            grant_id=grant1.grant_id,
            user_id=grant1.user_id,
            session_id=grant1.session_id,
            application_id=app2.id,
            packet_id=grant1.packet_id,
            packet_version_hash=grant1.packet_version_hash,
            ticket_nonce=grant1.ticket_nonce,
            key_id=grant1.key_id,
            action_type=grant1.action_type,
            issued_at=grant1.issued_at,
            expires_at=grant1.expires_at,
            grant_signature=grant1.grant_signature,
            approver_name=grant1.approver_name,
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(
                auth_grant=tampered_grant,
            )
        app2_check = self.db.get_user_application(app2.id, self.user_a)
        self.assertEqual(app2_check.status, "READY_FOR_REVIEW")

    def test_direct_bypass_rejection_wrong_packet_or_hash(self):
        """Test F: A grant with tampered packet hash or deactivated packet is rejected."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        ok, msg, grant = self.session_mgr.verify_and_issue_approval_grant(
            session_id=self.session_a.session_id,
            ticket_str=ticket,
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=snap_hash,
            approver_name="Candidate One",
        )
        self.assertTrue(ok)

        # Tampering with packet_version_hash causes HMAC grant signature verification to fail
        tampered_grant = VerifiedApprovalGrant(
            grant_id=grant.grant_id,
            user_id=grant.user_id,
            session_id=grant.session_id,
            application_id=grant.application_id,
            packet_id=grant.packet_id,
            packet_version_hash="tampered_different_packet_hash_xyz",
            ticket_nonce=grant.ticket_nonce,
            key_id=grant.key_id,
            action_type=grant.action_type,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            grant_signature=grant.grant_signature,
            approver_name=grant.approver_name,
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.db._authorize_application_packet_atomic(
                auth_grant=tampered_grant,
            )

    def test_direct_bypass_rejection_wrong_action_type(self):
        """Test G: Non-HUMAN_APPROVAL action tickets cannot issue an approval grant."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        export_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="DATA_EXPORT",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        ok, msg, grant = self.session_mgr.verify_and_issue_approval_grant(
            session_id=self.session_a.session_id,
            ticket_str=export_ticket,
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=snap_hash,
            approver_name="Candidate One",
        )
        self.assertFalse(ok)
        self.assertIn("Ticket scope mismatch", msg)
        self.assertIsNone(grant)

    def test_direct_bypass_rejection_grant_replay(self):
        """Test H: Once an approval grant is consumed, reusing it triggers TicketAlreadyConsumedError."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session_a.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=app.id,
            packet_hash=snap_hash,
        )
        ok, msg, grant = self.session_mgr.verify_and_issue_approval_grant(
            session_id=self.session_a.session_id,
            ticket_str=ticket,
            application_id=app.id,
            packet_id=packet.id,
            packet_hash=snap_hash,
            approver_name="Candidate One",
        )
        self.assertTrue(ok)

        # First consumption succeeds
        approval = self.db._authorize_application_packet_atomic(
            auth_grant=grant,
        )
        self.assertIsNotNone(approval)

        # Second consumption replay fails
        with self.assertRaises(TicketAlreadyConsumedError):
            self.db._authorize_application_packet_atomic(
                auth_grant=grant,
            )

    def test_legacy_public_method_rejection_record_packet_approval(self):
        """Test I: Direct call to record_packet_approval without VerifiedApprovalGrant is rejected."""
        app, packet, snap_hash = self._setup_app_and_packet(self.user_a, "READY_FOR_REVIEW")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_packet_approval(
                application_id=app.id,
                user_id=self.user_a,
                packet_id=packet.id,
                packet_version_hash=snap_hash,
                ticket_nonce="legacy_bypass_nonce",
                approver_name="Candidate One",
            )
        self.assertIn("prohibited", str(ctx.exception).lower())

    def test_valid_workflow_preservation_single_use_success(self):
        """Test J: Legitimate human approval workflow preserves all 4 records and passes event chain validation."""
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
            approver_name="Candidate One",
            session_id=self.session_a.session_id,
            action_ticket=ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ, f"Approval failed: {msg}")
        self.assertIsNotNone(approval)

        # Exactly 1 approval record
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM application_approvals WHERE application_id = ?", (app.id,))
            self.assertEqual(cursor.fetchone()[0], 1)

            # Exactly 1 log record with HUMAN_APPROVAL_GRANTED
            cursor.execute(
                "SELECT COUNT(*) FROM application_logs WHERE application_id = ? AND action = 'HUMAN_APPROVAL_GRANTED'",
                (app.id,),
            )
            self.assertEqual(cursor.fetchone()[0], 1)

        # Status updated to APPROVED
        app_fresh = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_fresh.status, ApplicationStatus.APPROVED.value)

        # Exactly 1 PACKET_HUMAN_APPROVED event
        events = self.db.get_application_events(app.id, self.user_a)
        approved_events = [e for e in events if e.event_type == "PACKET_HUMAN_APPROVED"]
        self.assertEqual(len(approved_events), 1)

        # Cryptographic chain valid
        valid, err = self.db.verify_application_event_chain(app.id, self.user_a, raise_on_error=True)
        self.assertTrue(valid, f"Chain verification failed: {err}")

    def service_mock_update_status(self, app_id: int, new_status: str):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE applications SET status = ? WHERE id = ?", (new_status, app_id))


if __name__ == "__main__":
    unittest.main()

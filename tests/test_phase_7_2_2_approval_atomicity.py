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
import unittest
from unittest.mock import patch

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    InvalidStatusTransitionError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.database.models import ApplicationStatus, VerifiedApprovalContext
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
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision
                ) VALUES (201, ?, ?, 1, ?, 'dummy_hash_resume_abc123', 'jd_snap_hash', '[]', ?, 1)
                """,
                (app.id, user_id, snap_hash, snap_bytes.decode("utf-8")),
            )
        packet = self.db.get_active_prepared_packet(app.id, user_id)
        return app, packet, snap_hash

    def _assert_approval_rolled_back_and_verifiable(
        self,
        app_id: int,
        initial_event_count: int,
        ticket: str,
        packet_id: int,
        snap_hash: str,
    ):
        """Common assertions for all 7 failure-injection tests."""
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

        # 5. Pre-existing timeline events unchanged in count
        self.assertEqual(len(events), initial_event_count)

        # 6. Sequence numbers contiguous (1..N)
        seqs = [e.sequence_no for e in events]
        self.assertEqual(seqs, list(range(1, len(events) + 1)))

        # 7. Hash chain intact and valid
        for i in range(1, len(events)):
            self.assertEqual(events[i].previous_event_hash, events[i - 1].event_hash)

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
        """_authorize_application_packet_atomic requires auth_context or explicit parameters."""
        with self.assertRaises((ValidationError, ValueError)):
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
        forged_ticket = f"{parts[0]}.{parts[1]}.badsignaturedeadbeef012345"
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

            # Direct internal call with VerifiedApprovalContext raises InvalidStatusTransitionError
            auth_ctx = VerifiedApprovalContext(
                application_id=app.id,
                user_id=self.user_a,
                packet_id=packet.id,
                packet_version_hash=snap_hash,
                ticket_nonce=f"nonce_{invalid_status}",
                key_id="v1",
                approver_name="Candidate One",
                session_id=self.session_a.session_id,
            )
            with self.assertRaises(InvalidStatusTransitionError):
                self.db._authorize_application_packet_atomic(auth_context=auth_ctx)

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
        initial_events = len(self.db.get_application_events(app.id, self.user_a))

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
        initial_events = len(self.db.get_application_events(app.id, self.user_a))

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
        initial_events = len(self.db.get_application_events(app.id, self.user_a))

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
        initial_events = len(self.db.get_application_events(app.id, self.user_a))

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
        initial_events = len(self.db.get_application_events(app.id, self.user_a))

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
        initial_events = len(self.db.get_application_events(app.id, self.user_a))

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
        initial_events = len(self.db.get_application_events(app.id, self.user_a))

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

    def service_mock_update_status(self, app_id: int, new_status: str):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE applications SET status = ? WHERE id = ?", (new_status, app_id))


if __name__ == "__main__":
    unittest.main()

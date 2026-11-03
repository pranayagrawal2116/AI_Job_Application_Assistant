"""Tests for Phase 7.1.3: Submission Confirmation Audit Consistency & Timestamp Integrity.

Covers:
1. Atomic submission confirmation corrections (multi-table atomicity within single transaction).
2. Failure injection tests verifying rollback of confirmation updates when event insertion fails.
3. Timestamp separation: candidate-provided submission timestamp is kept distinct from server UTC audit event created_at.
4. Corrected submission metadata history preservation (original submission_timestamp preserved, no approval reuse).
5. Audit event semantics (SUBMISSION_CONFIRMATION_RECORDED, SUBMISSION_CONFIRMED, SUBMISSION_CONFIRMATION_UPDATED).
"""

import json
import os
import sqlite3
import tempfile
import unittest
from typing import List
from unittest.mock import patch

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    ValidationError,
)
from src.database.models import Application, ApplicationEvent, ApplicationStatus, SubmissionChannel, SubmissionConfirmation


class TestPhase713Base(unittest.TestCase):
    """Base fixture providing an isolated temporary database with registered test users."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_audit_consistency.db")
        self.db = DatabaseManager(self.db_path)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'alice@example.com', 'h1', 's1', 'Alice')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (2, 'bob@example.com', 'h2', 's2', 'Bob')"
            )
            self.user_a = 1
            self.user_b = 2

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_application(self, user_id: int, status: str = "DRAFT", title: str = "Software Engineer") -> Application:
        return self.db.create_user_application(
            user_id=user_id,
            company_name="TechCorp",
            job_title=title,
            status=status,
        )

    def _create_packet_and_approval(
        self, application_id: int, user_id: int, packet_id: int = 101, is_consumed: int = 0
    ) -> str:
        pkt_hash = f"pkt_hash_{packet_id}"
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision
                ) VALUES (?, ?, ?, 1, ?, 'rh', 'jdh', '{}', 1)
                """,
                (packet_id, application_id, user_id, pkt_hash),
            )
            cursor.execute(
                """
                INSERT INTO application_approvals (
                    id, application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, approver_name, session_id, is_consumed
                ) VALUES (?, ?, ?, ?, ?, ?, 'Tester', 'sess_test', ?)
                """,
                (packet_id, application_id, packet_id, user_id, pkt_hash, f"nonce_{packet_id}", is_consumed),
            )
        return pkt_hash


class TestAtomicSubmissionConfirmationCorrections(TestPhase713Base):
    """Verifies that confirmation updates and their audit events execute atomically in a single transaction."""

    def test_valid_confirmation_correction_updates_record_and_appends_event(self):
        """A valid correction updates confirmation metadata and atomically records SUBMISSION_CONFIRMATION_UPDATED."""
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=101)

        conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=101,
            confirmation_reference="REF-ORIGINAL",
            candidate_notes="Initial submission notes",
            transition_status=True,
        )
        self.assertEqual(conf.confirmation_reference, "REF-ORIGINAL")

        # Correct confirmation
        corrected = self.db.correct_submission_confirmation(
            confirmation_id=conf.id,
            user_id=self.user_a,
            confirmation_reference="REF-CORRECTED-123",
            confirmation_doc_path="/path/to/confirmation.pdf",
            confirmation_doc_hash="sha256_mock_hash",
            candidate_notes="Updated candidate notes after portal receipt",
            submission_channel=SubmissionChannel.EMAIL.value,
        )

        self.assertEqual(corrected.id, conf.id)
        self.assertEqual(corrected.confirmation_reference, "REF-CORRECTED-123")
        self.assertEqual(corrected.confirmation_doc_path, "/path/to/confirmation.pdf")
        self.assertEqual(corrected.confirmation_doc_hash, "sha256_mock_hash")
        self.assertEqual(corrected.candidate_notes, "Updated candidate notes after portal receipt")
        self.assertEqual(corrected.submission_channel, SubmissionChannel.EMAIL.value)

        # Application status must remain unchanged in SUBMITTED
        app_fresh = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(app_fresh.status, ApplicationStatus.SUBMITTED.value)

        # Timeline event must be SUBMISSION_CONFIRMATION_UPDATED
        events = self.db.get_application_events(app.id, self.user_a)
        last_evt = events[-1]
        self.assertEqual(last_evt.event_type, "SUBMISSION_CONFIRMATION_UPDATED")
        self.assertIn("REF-CORRECTED-123", last_evt.event_payload_json)
        self.assertIn("/path/to/confirmation.pdf", last_evt.event_payload_json)

        # Entire hash chain must be 100% valid
        valid, msg = self.db.verify_application_event_chain(app.id, self.user_a)
        self.assertTrue(valid, msg)

    def test_cross_user_correction_rejected(self):
        """User B cannot correct User A's confirmation."""
        app = self._create_application(self.user_a, status=ApplicationStatus.DRAFT.value)
        conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.LINKEDIN.value,
            confirmation_reference="USER_A_CONF",
        )

        with self.assertRaises(CrossUserAccessError):
            self.db.correct_submission_confirmation(
                confirmation_id=conf.id,
                user_id=self.user_b,
                confirmation_reference="HACKED_REF",
            )

        # Verify confirmation in DB remains unchanged
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT confirmation_reference FROM submission_confirmations WHERE id = ?", (conf.id,))
            self.assertEqual(cursor.fetchone()["confirmation_reference"], "USER_A_CONF")

    def test_invalid_submission_channel_rejected(self):
        """Passing an invalid submission channel raises ValidationError."""
        app = self._create_application(self.user_a)
        conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
        )

        with self.assertRaises(ValidationError) as ctx:
            self.db.correct_submission_confirmation(
                confirmation_id=conf.id,
                user_id=self.user_a,
                submission_channel="INVALID_PORTAL",
            )
        self.assertIn("Invalid submission_channel", str(ctx.exception))

    def test_correction_does_not_consume_or_alter_approval_records(self):
        """Correcting a submission confirmation never consumes or reuses an approval ticket."""
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=201, is_consumed=0)

        # Create confirmation in storage mode (approval remains unconsumed)
        conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=201,
            transition_status=False,
        )

        # Approval is still unconsumed
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_consumed FROM application_approvals WHERE id = 201")
            self.assertEqual(cursor.fetchone()["is_consumed"], 0)

        # Correct confirmation
        self.db.correct_submission_confirmation(
            confirmation_id=conf.id,
            user_id=self.user_a,
            candidate_notes="Updated notes",
        )

        # Approval must STILL be unconsumed (correction does not touch approvals)
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_consumed FROM application_approvals WHERE id = 201")
            self.assertEqual(cursor.fetchone()["is_consumed"], 0)

    def test_correction_does_not_create_duplicate_confirmations(self):
        """Correcting a confirmation updates the existing record and does not create additional confirmations."""
        app = self._create_application(self.user_a)
        conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.LINKEDIN.value,
        )

        # Perform 3 sequential corrections
        self.db.correct_submission_confirmation(conf.id, self.user_a, candidate_notes="Note 1")
        self.db.correct_submission_confirmation(conf.id, self.user_a, candidate_notes="Note 2")
        self.db.correct_submission_confirmation(conf.id, self.user_a, candidate_notes="Note 3")

        # Must still have exactly 1 submission confirmation for this user and application
        confs = self.db.list_submission_confirmations(user_id=self.user_a, application_id=app.id)
        self.assertEqual(len(confs), 1)
        self.assertEqual(confs[0].candidate_notes, "Note 3")


class TestCorrectionFailureInjectionAndRollback(TestPhase713Base):
    """Verifies that failures at any point during submission confirmation correction trigger complete rollback."""

    def _assert_rollback_invariants(
        self,
        app_id: int,
        conf_id: int,
        orig_conf: SubmissionConfirmation,
        events_before: List[ApplicationEvent],
        approval_id: int = 101,
    ):
        """Enforces all 9 common failure-injection assertions from Phase 7.1.3.1 spec:
        1. Original confirmation_reference remains unchanged.
        2. Original candidate_notes remains unchanged.
        3. Original submission_channel remains unchanged.
        4. Original submission_timestamp remains unchanged.
        5. No SUBMISSION_CONFIRMATION_UPDATED event was appended.
        6. Event sequence numbers remain contiguous.
        7. verify_application_event_chain() succeeds.
        8. The original approval record remains unchanged.
        9. No swallowed exception or false success response occurs (verified by caller catching exception).
        """
        # 1-4. Confirmation fields remain unchanged
        conf_after = self.db.get_submission_confirmation(app_id, self.user_a)
        self.assertIsNotNone(conf_after)
        self.assertEqual(conf_after.confirmation_reference, orig_conf.confirmation_reference)
        self.assertEqual(conf_after.candidate_notes, orig_conf.candidate_notes)
        self.assertEqual(conf_after.submission_channel, orig_conf.submission_channel)
        self.assertEqual(conf_after.submission_timestamp, orig_conf.submission_timestamp)

        # 5. No SUBMISSION_CONFIRMATION_UPDATED event was appended
        events_after = self.db.get_application_events(app_id, self.user_a)
        self.assertEqual(len(events_after), len(events_before))
        for evt in events_after:
            self.assertNotEqual(evt.event_type, "SUBMISSION_CONFIRMATION_UPDATED")

        # 6. Event sequence numbers remain contiguous
        expected_seq = 1
        for evt in events_after:
            self.assertEqual(evt.sequence_no, expected_seq)
            expected_seq += 1

        # 7. Audit hash chain remains 100% valid
        valid, msg = self.db.verify_application_event_chain(app_id, self.user_a)
        self.assertTrue(valid, msg)

        # 8. Original approval record remains unchanged
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_consumed FROM application_approvals WHERE id = ?", (approval_id,))
            row = cursor.fetchone()
            if row:
                self.assertEqual(row["is_consumed"], 1)

    def test_failure_point_a_canonicalization_failure(self):
        """Point A: Simulate an exception while canonicalizing the event payload through canonical_json_bytes.
        Verifies that confirmation metadata update is rolled back and no partial event is persisted.
        """
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=101)
        orig_conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=101,
            confirmation_reference="INITIAL_REF_A",
            candidate_notes="Initial notes A",
            transition_status=True,
        )
        events_before = self.db.get_application_events(app.id, self.user_a)

        with patch("src.database.db_manager.canonical_json_bytes", side_effect=ValueError("Simulated canonicalization failure")):
            with self.assertRaises(ValueError) as ctx:
                self.db.correct_submission_confirmation(
                    confirmation_id=orig_conf.id,
                    user_id=self.user_a,
                    confirmation_reference="SHOULD_ROLL_BACK_A",
                    candidate_notes="Notes that must roll back A",
                    submission_channel=SubmissionChannel.EMAIL.value,
                )
            self.assertIn("Simulated canonicalization failure", str(ctx.exception))

        self._assert_rollback_invariants(app.id, orig_conf.id, orig_conf, events_before, approval_id=101)

    def test_failure_point_b_sequence_lookup_failure(self):
        """Point B: Inject a failure during event sequence/previous-hash lookup in _insert_application_event_internal().
        Verifies that confirmation update is rolled back and no partial event is appended.
        """
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=102)
        orig_conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=102,
            confirmation_reference="INITIAL_REF_B",
            candidate_notes="Initial notes B",
            transition_status=True,
        )
        events_before = self.db.get_application_events(app.id, self.user_a)

        class SequenceLookupFailingProxy:
            def __init__(self, real_conn):
                self._conn = real_conn
                self.lookup_intercepted = False

            def cursor(self):
                real_cursor = self._conn.cursor()
                proxy_self = self

                class CursorProxy:
                    def __init__(self, c):
                        self._c = c

                    def execute(self, sql, *params):
                        if "SELECT sequence_no, event_hash FROM application_events" in sql:
                            proxy_self.lookup_intercepted = True
                            raise sqlite3.OperationalError("Simulated sequence lookup query failure")
                        return self._c.execute(sql, *params)

                    def fetchone(self):
                        return self._c.fetchone()

                    def fetchall(self):
                        return self._c.fetchall()

                    def __getattr__(self, name):
                        return getattr(self._c, name)

                return CursorProxy(real_cursor)

            def commit(self):
                return self._conn.commit()

            def rollback(self):
                return self._conn.rollback()

            def close(self):
                return self._conn.close()

            def __getattr__(self, name):
                return getattr(self._conn, name)

        orig_get_conn = self.db.get_connection
        proxy_instances = []

        def fault_injecting_get_connection():
            conn = orig_get_conn()
            proxy = SequenceLookupFailingProxy(conn)
            proxy_instances.append(proxy)
            return proxy

        self.db.get_connection = fault_injecting_get_connection
        try:
            with self.assertRaises(sqlite3.OperationalError) as ctx:
                self.db.correct_submission_confirmation(
                    confirmation_id=orig_conf.id,
                    user_id=self.user_a,
                    confirmation_reference="SHOULD_ROLL_BACK_B",
                    candidate_notes="Notes that must roll back B",
                    submission_channel=SubmissionChannel.EMAIL.value,
                )
            self.assertIn("Simulated sequence lookup query failure", str(ctx.exception))
        finally:
            self.db.get_connection = orig_get_conn

        self.assertTrue(len(proxy_instances) > 0)
        self.assertTrue(proxy_instances[0].lookup_intercepted, "Sequence lookup query was not intercepted")
        self._assert_rollback_invariants(app.id, orig_conf.id, orig_conf, events_before, approval_id=102)

    def test_failure_point_c_event_hash_computation_failure(self):
        """Point C: Inject an exception from DatabaseManager.compute_event_hash() during correction event creation.
        Verifies that exception propagates, confirmation metadata is rolled back, and no event is persisted.
        """
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=103)
        orig_conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=103,
            confirmation_reference="INITIAL_REF_C",
            candidate_notes="Initial notes C",
            transition_status=True,
        )
        events_before = self.db.get_application_events(app.id, self.user_a)

        with patch.object(DatabaseManager, "compute_event_hash", side_effect=RuntimeError("Simulated event hash computation failure")):
            with self.assertRaises(RuntimeError) as ctx:
                self.db.correct_submission_confirmation(
                    confirmation_id=orig_conf.id,
                    user_id=self.user_a,
                    confirmation_reference="SHOULD_ROLL_BACK_C",
                    candidate_notes="Notes that must roll back C",
                    submission_channel=SubmissionChannel.EMAIL.value,
                )
            self.assertIn("Simulated event hash computation failure", str(ctx.exception))

        self._assert_rollback_invariants(app.id, orig_conf.id, orig_conf, events_before, approval_id=103)

    def test_failure_point_d_event_insertion_failure(self):
        """Point D: SQLite-trigger-based event insertion failure during SUBMISSION_CONFIRMATION_UPDATED insert.
        Verifies that database constraint/trigger failure rolls back the confirmation update.
        """
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=104)
        orig_conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=104,
            confirmation_reference="INITIAL_REF_D",
            candidate_notes="Initial notes D",
            transition_status=True,
        )
        events_before = self.db.get_application_events(app.id, self.user_a)

        # Install SQLite trigger
        with self.db.connection() as conn:
            conn.execute("""
                CREATE TRIGGER simulate_event_failure_trg
                BEFORE INSERT ON application_events
                WHEN NEW.event_type = 'SUBMISSION_CONFIRMATION_UPDATED'
                BEGIN
                    SELECT RAISE(FAIL, 'Simulated failure during event insertion');
                END;
            """)

        try:
            with self.assertRaises(sqlite3.IntegrityError) as ctx:
                self.db.correct_submission_confirmation(
                    confirmation_id=orig_conf.id,
                    user_id=self.user_a,
                    confirmation_reference="SHOULD_ROLL_BACK_D",
                    candidate_notes="Notes that must roll back D",
                    submission_channel=SubmissionChannel.EMAIL.value,
                )
            self.assertIn("Simulated failure during event insertion", str(ctx.exception))
        finally:
            with self.db.connection() as conn:
                conn.execute("DROP TRIGGER IF EXISTS simulate_event_failure_trg")

        self._assert_rollback_invariants(app.id, orig_conf.id, orig_conf, events_before, approval_id=104)

    # Retain exact legacy test method name as alias for backward compatibility
    test_failure_during_event_insertion_rolls_back_confirmation_update = test_failure_point_d_event_insertion_failure

    def test_failure_point_e_transaction_commit_failure(self):
        """Point E: Failure during transaction commit in DatabaseManager.transaction().
        Verifies that when conn.commit() fails after all updates and event inserts have executed,
        transaction() catches the exception, calls conn.rollback(), and neither update nor event persists.
        """
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=105)
        orig_conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=105,
            confirmation_reference="INITIAL_REF_E",
            candidate_notes="Initial notes E",
            transition_status=True,
        )
        events_before = self.db.get_application_events(app.id, self.user_a)

        class CommitFailingProxy:
            def __init__(self, real_conn):
                self._conn = real_conn
                self.commit_attempted = False

            def commit(self):
                self.commit_attempted = True
                raise sqlite3.OperationalError("Simulated commit failure: disk I/O error or lock conflict")

            def rollback(self):
                return self._conn.rollback()

            def close(self):
                return self._conn.close()

            def cursor(self):
                return self._conn.cursor()

            def __getattr__(self, name):
                return getattr(self._conn, name)

        orig_get_conn = self.db.get_connection
        proxy_instances = []

        def fault_injecting_get_connection():
            conn = orig_get_conn()
            proxy = CommitFailingProxy(conn)
            proxy_instances.append(proxy)
            return proxy

        self.db.get_connection = fault_injecting_get_connection
        try:
            with self.assertRaises(sqlite3.OperationalError) as ctx:
                self.db.correct_submission_confirmation(
                    confirmation_id=orig_conf.id,
                    user_id=self.user_a,
                    confirmation_reference="SHOULD_ROLL_BACK_E",
                    candidate_notes="Notes that must roll back E",
                    submission_channel=SubmissionChannel.EMAIL.value,
                )
            self.assertIn("Simulated commit failure", str(ctx.exception))
        finally:
            self.db.get_connection = orig_get_conn

        # Verify that commit was actually attempted by transaction context manager
        self.assertTrue(len(proxy_instances) > 0)
        self.assertTrue(proxy_instances[0].commit_attempted)

        self._assert_rollback_invariants(app.id, orig_conf.id, orig_conf, events_before, approval_id=105)

    def test_correction_audit_event_records_before_and_after_fields(self):
        """Verifies that SUBMISSION_CONFIRMATION_UPDATED records both updated_fields and previous_fields."""
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=106)
        orig_conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=106,
            confirmation_reference="ORIG_REF_106",
            candidate_notes="Original Notes 106",
            transition_status=True,
        )

        corrected = self.db.correct_submission_confirmation(
            confirmation_id=orig_conf.id,
            user_id=self.user_a,
            confirmation_reference="NEW_REF_106",
            candidate_notes="New Notes 106",
            submission_channel=SubmissionChannel.EMAIL.value,
        )

        self.assertEqual(corrected.confirmation_reference, "NEW_REF_106")
        self.assertEqual(corrected.candidate_notes, "New Notes 106")
        self.assertEqual(corrected.submission_channel, SubmissionChannel.EMAIL.value)

        events = self.db.get_application_events(app.id, self.user_a)
        corr_evt = events[-1]
        self.assertEqual(corr_evt.event_type, "SUBMISSION_CONFIRMATION_UPDATED")
        payload = json.loads(corr_evt.event_payload_json)

        self.assertEqual(payload["confirmation_id"], orig_conf.id)
        # Verify updated_fields contains new values
        self.assertEqual(payload["updated_fields"]["confirmation_reference"], "NEW_REF_106")
        self.assertEqual(payload["updated_fields"]["candidate_notes"], "New Notes 106")
        self.assertEqual(payload["updated_fields"]["submission_channel"], SubmissionChannel.EMAIL.value)

        # Verify previous_fields contains exact previous values
        self.assertEqual(payload["previous_fields"]["confirmation_reference"], "ORIG_REF_106")
        self.assertEqual(payload["previous_fields"]["candidate_notes"], "Original Notes 106")
        self.assertEqual(payload["previous_fields"]["submission_channel"], SubmissionChannel.COMPANY_PORTAL.value)

        # Verify audit hash chain
        valid, msg = self.db.verify_application_event_chain(app.id, self.user_a)
        self.assertTrue(valid, msg)


class TestTimestampSeparation(TestPhase713Base):
    """Verifies that candidate submission timestamps and audit event created_at timestamps are strictly independent."""

    def test_earlier_candidate_submission_timestamp_separated_from_audit_created_at(self):
        """When a candidate enters an earlier submission date (e.g. 2025-06-15),

        the confirmation record and applications.date_submitted retain that date,
        but the audit event created_at uses the server's current UTC time.
        """
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=301)

        candidate_sub_time = "2025-06-15 14:30:00"

        conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=301,
            submission_timestamp=candidate_sub_time,
            confirmation_reference="REF-2025",
            transition_status=True,
        )

        # 1. Submission confirmation retains candidate's historical submission time
        self.assertEqual(conf.submission_timestamp, candidate_sub_time)

        # 2. Application date_submitted retains candidate's historical submission time
        fresh_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(fresh_app.status, ApplicationStatus.SUBMITTED.value)
        self.assertEqual(fresh_app.date_submitted, candidate_sub_time)

        # 3. Audit event created_at must NOT be the candidate's earlier submission date!
        events = self.db.get_application_events(app.id, self.user_a)
        sub_evt = [e for e in events if e.event_type == "SUBMISSION_CONFIRMED"][0]

        self.assertNotEqual(sub_evt.created_at, candidate_sub_time)
        # Server UTC event created_at must be recent (year >= 2026)
        self.assertTrue(sub_evt.created_at.startswith("2026"))

        # 4. Event payload preserves candidate submission_timestamp for provenance
        self.assertIn(candidate_sub_time, sub_evt.event_payload_json)

        # 5. Independent hash chain verification succeeds with server created_at
        valid, msg = self.db.verify_application_event_chain(app.id, self.user_a)
        self.assertTrue(valid, msg)

    def test_tampering_audit_created_at_breaks_hash_verification(self):
        """Tampering with application_events.created_at breaks cryptographic verification."""
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=401)

        self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=401,
            transition_status=True,
        )

        events = self.db.get_application_events(app.id, self.user_a)
        sub_evt = [e for e in events if e.event_type == "SUBMISSION_CONFIRMED"][0]

        # Tamper created_at in the database directly
        with self.db.connection() as conn:
            conn.execute("DROP TRIGGER trg_prevent_application_events_update")
            conn.execute(
                "UPDATE application_events SET created_at = '2020-01-01 00:00:00' WHERE id = ?",
                (sub_evt.id,),
            )
            conn.commit()

        # Verification must detect the tamper
        valid, msg = self.db.verify_application_event_chain(app.id, self.user_a)
        self.assertFalse(valid)
        self.assertIn("Event tamper detected", msg)

    def test_correction_preserves_original_submission_timestamp(self):
        """Correcting a submission confirmation does NOT change the original submission_timestamp."""
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=501)

        original_sub_time = "2025-08-20 11:15:00"
        conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=501,
            submission_timestamp=original_sub_time,
            transition_status=True,
        )

        # Correct metadata
        corrected = self.db.correct_submission_confirmation(
            confirmation_id=conf.id,
            user_id=self.user_a,
            confirmation_reference="REF-NEW",
            candidate_notes="Updated candidate notes",
        )

        # Original submission timestamp is strictly preserved
        self.assertEqual(corrected.submission_timestamp, original_sub_time)

        # Correction event has its own server UTC created_at
        events = self.db.get_application_events(app.id, self.user_a)
        corr_evt = events[-1]
        self.assertEqual(corr_evt.event_type, "SUBMISSION_CONFIRMATION_UPDATED")
        self.assertTrue(corr_evt.created_at.startswith("2026"))

        # Chain verification remains completely intact
        valid, msg = self.db.verify_application_event_chain(app.id, self.user_a)
        self.assertTrue(valid, msg)


class TestAuditEventSemantics(TestPhase713Base):
    """Verifies distinct semantic event types for storage-only confirmations vs submitted transitions."""

    def test_storage_only_event_type_is_submission_confirmation_recorded(self):
        """When transition_status=False, the event type is strictly SUBMISSION_CONFIRMATION_RECORDED."""
        app = self._create_application(self.user_a, status=ApplicationStatus.DRAFT.value)

        self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.LINKEDIN.value,
            transition_status=False,
        )

        events = self.db.get_application_events(app.id, self.user_a)
        last_evt = events[-1]
        self.assertEqual(last_evt.event_type, "SUBMISSION_CONFIRMATION_RECORDED")
        self.assertEqual(last_evt.new_status, ApplicationStatus.DRAFT.value)

        # Application status is still DRAFT
        fresh_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(fresh_app.status, ApplicationStatus.DRAFT.value)

    def test_transition_status_event_type_is_submission_confirmed(self):
        """When transition_status=True, the event type is strictly SUBMISSION_CONFIRMED."""
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=601)

        self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=601,
            transition_status=True,
        )

        events = self.db.get_application_events(app.id, self.user_a)
        last_evt = events[-1]
        self.assertEqual(last_evt.event_type, "SUBMISSION_CONFIRMED")
        self.assertEqual(last_evt.new_status, ApplicationStatus.SUBMITTED.value)

        fresh_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(fresh_app.status, ApplicationStatus.SUBMITTED.value)


if __name__ == "__main__":
    unittest.main()

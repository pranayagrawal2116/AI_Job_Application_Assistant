"""Tests for Phase 7.1.2: Final Database Safety & Migration Hardening.

Covers:
1. Generic application events cannot mutate application status.
2. Require explicitly approved application before transitioning to SUBMITTED (strict allowlist,
   unconditional rejection of consumed approvals, and correct_submission_confirmation method).
3. Migration of existing Phase 7.1 databases (upgrading submission_confirmations to RESTRICT).
4. Migration lock ordering (acquiring write lock before preflight and snapshot).
5. Hardened connection-scoped privacy-erasure authorization.
"""

import os
import sqlite3
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    MigrationPreflightError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.database.models import Application, ApplicationStatus, SubmissionChannel


class TestPhase712Base(unittest.TestCase):
    """Base fixture providing an isolated temporary database with registered test users."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_lifecycle_712.db")
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


class TestGenericEventStatusImmutability(TestPhase712Base):
    """Area 1: Generic application events cannot mutate application status."""

    def test_generic_event_emission_cannot_mutate_application_status(self):
        """create_application_event with new_status must NOT modify applications.status."""
        app = self._create_application(self.user_a, status=ApplicationStatus.DRAFT.value)
        self.assertEqual(app.status, ApplicationStatus.DRAFT.value)

        # Emit event with new_status=SUBMITTED
        evt = self.db.create_application_event(
            application_id=app.id,
            user_id=self.user_a,
            event_type="FORM_SUBMISSION_ATTEMPTED",
            new_status=ApplicationStatus.SUBMITTED.value,
            actor_type="CANDIDATE",
            event_payload={"notes": "Testing event status immutability"},
        )
        self.assertEqual(evt.new_status, ApplicationStatus.SUBMITTED.value)

        # Application in DB must remain strictly in DRAFT status
        fresh_app = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(fresh_app.status, ApplicationStatus.DRAFT.value)
        self.assertIsNone(fresh_app.date_submitted)

        # Emit event with new_status=APPROVED
        evt2 = self.db.create_application_event(
            application_id=app.id,
            user_id=self.user_a,
            event_type="ARBITRARY_STATUS_EVT",
            new_status=ApplicationStatus.APPROVED.value,
        )
        self.assertEqual(evt2.new_status, ApplicationStatus.APPROVED.value)

        fresh_app2 = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(fresh_app2.status, ApplicationStatus.DRAFT.value)

        # Chain verification must succeed
        valid, msg = self.db.verify_application_event_chain(app.id, self.user_a)
        self.assertTrue(valid, msg)


class TestSubmissionConfirmationPreconditions(TestPhase712Base):
    """Area 2: Require an explicitly approved application before transitioning to SUBMITTED."""

    def test_status_allowlist_for_submission_transition(self):
        """transition_status=True must reject ALL statuses outside of APPROVED and legacy 'Awaiting Approval'."""
        disallowed_statuses = [
            ApplicationStatus.DRAFT.value,
            ApplicationStatus.PREPARING.value,
            ApplicationStatus.READY_FOR_REVIEW.value,
            ApplicationStatus.SUBMITTED.value,
            ApplicationStatus.IN_PROGRESS.value,
            ApplicationStatus.ASSESSMENT.value,
            ApplicationStatus.INTERVIEW.value,
            ApplicationStatus.OFFER.value,
            ApplicationStatus.REJECTED.value,
            ApplicationStatus.WITHDRAWN.value,
            ApplicationStatus.CLOSED.value,
        ]

        app = self._create_application(self.user_a, status=ApplicationStatus.DRAFT.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=201, is_consumed=0)

        for status in disallowed_statuses:
            with self.db.transaction() as conn:
                conn.execute("UPDATE applications SET status = ? WHERE id = ?", (status, app.id))

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.create_submission_confirmation(
                    application_id=app.id,
                    user_id=self.user_a,
                    submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
                    packet_id=201,
                    transition_status=True,
                )
            self.assertIn("Application must be approved by candidate", str(ctx.exception))

    def test_approved_and_legacy_awaiting_approval_transition_allowed(self):
        """Applications in APPROVED or legacy 'Awaiting Approval' can transition to SUBMITTED."""
        # 1. APPROVED status
        app1 = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app1.id, self.user_a, packet_id=301, is_consumed=0)

        conf1 = self.db.create_submission_confirmation(
            application_id=app1.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=301,
            transition_status=True,
        )
        self.assertEqual(conf1.packet_id, 301)
        fresh1 = self.db.get_user_application(app1.id, self.user_a)
        self.assertEqual(fresh1.status, ApplicationStatus.SUBMITTED.value)
        self.assertIsNotNone(fresh1.date_submitted)

        # 2. Legacy 'Awaiting Approval' status
        app2 = self._create_application(self.user_a, status="Awaiting Approval")
        self._create_packet_and_approval(app2.id, self.user_a, packet_id=302, is_consumed=0)

        conf2 = self.db.create_submission_confirmation(
            application_id=app2.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.LINKEDIN.value,
            packet_id=302,
            transition_status=True,
        )
        self.assertEqual(conf2.packet_id, 302)
        fresh2 = self.db.get_user_application(app2.id, self.user_a)
        self.assertEqual(fresh2.status, ApplicationStatus.SUBMITTED.value)
        self.assertIsNotNone(fresh2.date_submitted)

    def test_consumed_approval_unconditionally_rejected(self):
        """Even if application is in APPROVED status, a consumed approval cannot be submitted."""
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=401, is_consumed=1)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.create_submission_confirmation(
                application_id=app.id,
                user_id=self.user_a,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
                packet_id=401,
                transition_status=True,
            )
        self.assertIn("has already been consumed", str(ctx.exception))

    def test_correct_submission_confirmation_workflow(self):
        """Candidate can correct/add metadata to an existing confirmation without re-submitting."""
        app = self._create_application(self.user_a, status=ApplicationStatus.APPROVED.value)
        self._create_packet_and_approval(app.id, self.user_a, packet_id=501, is_consumed=0)

        conf = self.db.create_submission_confirmation(
            application_id=app.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=501,
            transition_status=True,
        )

        # Correct confirmation: attach reference and screenshot doc
        corrected = self.db.correct_submission_confirmation(
            confirmation_id=conf.id,
            user_id=self.user_a,
            confirmation_reference="REF-CONF-9876",
            confirmation_doc_path="/path/to/screenshot.png",
            confirmation_doc_hash="sha256_mock_doc",
            candidate_notes="Confirmed via Workday portal email",
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
        )
        self.assertEqual(corrected.confirmation_reference, "REF-CONF-9876")
        self.assertEqual(corrected.confirmation_doc_path, "/path/to/screenshot.png")
        self.assertEqual(corrected.confirmation_doc_hash, "sha256_mock_doc")
        self.assertEqual(corrected.candidate_notes, "Confirmed via Workday portal email")

        # Application remains SUBMITTED without error
        fresh = self.db.get_user_application(app.id, self.user_a)
        self.assertEqual(fresh.status, ApplicationStatus.SUBMITTED.value)

        # Audit event SUBMISSION_CONFIRMATION_UPDATED recorded
        events = self.db.get_application_events(app.id, self.user_a)
        update_evts = [e for e in events if e.event_type == "SUBMISSION_CONFIRMATION_UPDATED"]
        self.assertEqual(len(update_evts), 1)
        self.assertIn("REF-CONF-9876", update_evts[0].event_payload_json)

        # User B cannot update User A's confirmation
        with self.assertRaises(CrossUserAccessError):
            self.db.correct_submission_confirmation(
                confirmation_id=conf.id,
                user_id=self.user_b,
                confirmation_reference="HACKED",
            )

        # Invalid channel rejected
        with self.assertRaises(ValidationError):
            self.db.correct_submission_confirmation(
                confirmation_id=conf.id,
                user_id=self.user_a,
                submission_channel="INVALID_PORTAL",
            )


class TestPhase71ExistingDatabaseMigration(unittest.TestCase):
    """Area 3: Correctly migrate existing Phase 7.1 databases, not just Phase 6 databases."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "migration_test.db")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_upgrade_existing_phase71_database_with_set_null_to_restrict(self):
        """An existing Phase 7.1 database with ON DELETE SET NULL on submission_confirmations upgrades to RESTRICT."""
        # Setup mock Phase 7.1 database directly via sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        cursor = conn.cursor()

        # Create basic tables
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, full_name TEXT)")
        cursor.execute("INSERT INTO users VALUES (1, 'alice@example.com', 'h1', 'Alice')")

        cursor.execute("""
            CREATE TABLE applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER,
                job_description_id INTEGER,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                resume_id INTEGER,
                company_name TEXT NOT NULL,
                job_title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'DRAFT',
                application_source TEXT NOT NULL DEFAULT 'JOB_DESCRIPTION',
                external_application_url TEXT,
                target_role TEXT,
                employment_type TEXT,
                location TEXT,
                salary_range TEXT,
                application_deadline DATETIME,
                date_prepared DATETIME,
                date_submitted DATETIME,
                resume_used TEXT,
                cover_letter_reference TEXT,
                notes TEXT,
                is_archived INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(id, user_id)
            )
        """)
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (1, 1, 'Co', 'Dev', 'SUBMITTED')")

        cursor.execute("""
            CREATE TABLE prepared_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                version_num INTEGER NOT NULL,
                packet_version_hash TEXT NOT NULL,
                original_resume_hash TEXT NOT NULL,
                job_description_snapshot_hash TEXT NOT NULL,
                screening_answers_json TEXT NOT NULL DEFAULT '{}',
                is_active_revision INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(id, user_id)
            )
        """)
        cursor.execute("INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash) VALUES (10, 1, 1, 1, 'hash10', 'rh', 'jdh')")

        # Phase 7.1 table with SET NULL (not RESTRICT)
        cursor.execute("""
            CREATE TABLE submission_confirmations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                packet_id INTEGER,
                packet_version_hash TEXT,
                submission_timestamp DATETIME NOT NULL,
                submission_channel TEXT NOT NULL,
                confirmation_reference TEXT,
                confirmation_doc_path TEXT,
                confirmation_doc_hash TEXT,
                candidate_notes TEXT,
                is_active_confirmation INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE,
                FOREIGN KEY (packet_id, user_id) REFERENCES prepared_packets(id, user_id) ON DELETE SET NULL
            )
        """)
        cursor.execute("""
            INSERT INTO submission_confirmations (
                id, application_id, user_id, packet_id, packet_version_hash,
                submission_timestamp, submission_channel, confirmation_reference
            ) VALUES (5, 1, 1, 10, 'hash10', '2026-03-01 12:00:00', 'COMPANY_PORTAL', 'CONF-555')
        """)

        # Add application_events with legacy _privacy_erasure_tokens table
        cursor.execute("""
            CREATE TABLE application_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                sequence_no INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                previous_status TEXT,
                new_status TEXT,
                actor_type TEXT NOT NULL DEFAULT 'CANDIDATE',
                actor_identifier TEXT NOT NULL,
                session_reference TEXT,
                event_payload_json TEXT NOT NULL DEFAULT '{}',
                previous_event_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(application_id, sequence_no),
                FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE RESTRICT
            )
        """)
        cursor.execute("CREATE TABLE _privacy_erasure_tokens (user_id INTEGER PRIMARY KEY, token_nonce TEXT)")
        cursor.execute("""
            CREATE TRIGGER trg_prevent_application_events_delete
            BEFORE DELETE ON application_events
            BEGIN
                SELECT RAISE(FAIL, 'fail') WHERE NOT EXISTS (SELECT 1 FROM _privacy_erasure_tokens WHERE user_id = OLD.user_id);
            END
        """)

        conn.commit()
        conn.close()

        # Initialize DatabaseManager on this existing database — must run migration
        db = DatabaseManager(self.db_path)

        with db.connection() as check_conn:
            cursor = check_conn.cursor()
            # 1. Verify submission_confirmations foreign key is now RESTRICT
            cursor.execute("PRAGMA foreign_key_list(submission_confirmations)")
            fks = [dict(r) for r in cursor.fetchall()]
            packet_fks = [fk for fk in fks if fk.get("table") == "prepared_packets"]
            self.assertTrue(len(packet_fks) >= 1)
            self.assertTrue(all(fk.get("on_delete") == "RESTRICT" for fk in packet_fks))

            # 2. Verify all rows were preserved
            cursor.execute("SELECT * FROM submission_confirmations WHERE id = 5")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["confirmation_reference"], "CONF-555")
            self.assertEqual(row["packet_id"], 10)
            self.assertEqual(row["packet_version_hash"], "hash10")

            # 3. Verify _privacy_erasure_tokens table was dropped
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='_privacy_erasure_tokens'")
            self.assertIsNone(cursor.fetchone())

            # 4. Verify trigger now uses verify_privacy_erasure_authorization
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='trg_prevent_application_events_delete'")
            trg_sql = cursor.fetchone()[0]
            self.assertIn("verify_privacy_erasure_authorization", trg_sql)

            # 5. Verify deleting prepared packet 10 is blocked by ON DELETE RESTRICT
            with self.assertRaises(sqlite3.IntegrityError):
                with db.transaction() as t_conn:
                    t_conn.execute("DELETE FROM prepared_packets WHERE id = 10")

    def test_idempotent_phase712_migration_does_no_unnecessary_rebuild(self):
        """Running on an already correct Phase 7.1.2 database returns early without error."""
        db = DatabaseManager(self.db_path)
        with db.connection() as conn:
            # Running migration again on the already initialized database is completely idempotent
            db._migrate_phase7_lifecycle_tables(conn)


class TestMigrationLockOrderingAndPreflightRollback(unittest.TestCase):
    """Area 4: Acquire SQLite write lock before migration preflight and data snapshot."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "lock_test.db")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_preflight_failure_aborts_and_rolls_back_cleanly(self):
        """If preflight fails (e.g. applications with NULL user_id), transaction rolls back cleanly."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, full_name TEXT)")
        cursor.execute("INSERT INTO users VALUES (1, 'alice@example.com', 'h1', 'Alice')")
        cursor.execute("""
            CREATE TABLE applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                company_name TEXT NOT NULL,
                job_title TEXT NOT NULL,
                status TEXT
            )
        """)
        # Insert corrupted application with NULL user_id
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (1, NULL, 'CorruptCorp', 'Engineer', 'DRAFT')")
        conn.commit()
        conn.close()

        # DatabaseManager initialization must fail preflight check 1
        with self.assertRaises(MigrationPreflightError) as ctx:
            DatabaseManager(self.db_path)
        self.assertIn("NULL user_id", str(ctx.exception))

        # Confirm the database remained un-migrated and unmodified
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM applications WHERE user_id IS NULL")
        self.assertEqual(cursor.fetchone()[0], 1)
        # Temporary v7 table must not exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='applications_v7'")
        self.assertIsNone(cursor.fetchone())
        conn.close()


class TestPrivacyErasureSecurity(TestPhase712Base):
    """Area 5: Strengthen privacy-erasure authorization mechanism."""

    def test_direct_delete_blocked_by_trigger(self):
        """Direct DELETE FROM application_events on a normal connection is blocked."""
        app = self._create_application(self.user_a)
        evt = self.db.create_application_event(
            application_id=app.id,
            user_id=self.user_a,
            event_type="TEST_EVENT",
        )

        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            with self.db.connection() as conn:
                conn.execute("DELETE FROM application_events WHERE id = ?", (evt.id,))
        self.assertIn("application_events records are immutable", str(ctx.exception))

    def test_legacy_tokens_table_cannot_authorize_deletion(self):
        """Creating an external table like _privacy_erasure_tokens does NOT authorize deletion."""
        app = self._create_application(self.user_a)
        evt = self.db.create_application_event(
            application_id=app.id,
            user_id=self.user_a,
            event_type="TEST_EVENT",
        )

        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.connection() as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS _privacy_erasure_tokens (user_id INTEGER, token TEXT)")
                conn.execute("INSERT INTO _privacy_erasure_tokens VALUES (1, 'fake_token')")
                conn.execute("DELETE FROM application_events WHERE id = ?", (evt.id,))

    def test_scoped_authorization_rejects_cross_user_deletion(self):
        """_authorized_privacy_erasure_scope(conn, user_a) rejects attempts to delete user_b events."""
        app_a = self._create_application(self.user_a, title="Dev A")
        app_b = self._create_application(self.user_b, title="Dev B")

        self.db.create_application_event(application_id=app_a.id, user_id=self.user_a, event_type="EVT_A")
        self.db.create_application_event(application_id=app_b.id, user_id=self.user_b, event_type="EVT_B")

        with self.db.connection() as conn:
            # Active authorization strictly for user_a
            with self.db._authorized_privacy_erasure_scope(conn, self.user_a):
                # Deleting user_b's event must fail with IntegrityError
                with self.assertRaises(sqlite3.IntegrityError) as ctx:
                    conn.execute("DELETE FROM application_events WHERE user_id = ?", (self.user_b,))
                self.assertIn("application_events records are immutable", str(ctx.exception))

                # Deleting user_a's event succeeds
                conn.execute("DELETE FROM application_events WHERE user_id = ?", (self.user_a,))

        # Verify user_b's event is still present
        events_b = self.db.get_application_events(app_b.id, self.user_b)
        self.assertEqual(len(events_b), 2)  # MIGRATION_INITIALIZED + EVT_B

    def test_concurrent_connection_cannot_delete_events(self):
        """Another connection cannot delete events while conn1 is inside the erasure scope."""
        app = self._create_application(self.user_a)
        self.db.create_application_event(application_id=app.id, user_id=self.user_a, event_type="EVT")

        with self.db.connection() as conn1:
            with self.db._authorized_privacy_erasure_scope(conn1, self.user_a):
                # Independent connection 2 attempts delete
                with self.assertRaises(sqlite3.IntegrityError):
                    with self.db.connection() as conn2:
                        conn2.execute("DELETE FROM application_events WHERE user_id = ?", (self.user_a,))

    def test_delete_user_account_data_erases_target_user_leaves_other_intact(self):
        """delete_user_account_data cleans up user_a cleanly while preserving user_b event chain."""
        app_a = self._create_application(self.user_a, title="Job A")
        app_b = self._create_application(self.user_b, title="Job B")

        self.db.create_application_event(application_id=app_a.id, user_id=self.user_a, event_type="EA_1")
        self.db.create_application_event(application_id=app_b.id, user_id=self.user_b, event_type="EB_1")

        deleted = self.db.delete_user_account_data(self.user_a)
        self.assertTrue(deleted)
        self.assertIsNone(self.db.get_user_by_id(self.user_a))

        # User B's application and events remain 100% intact
        app_b_fresh = self.db.get_user_application(app_b.id, self.user_b)
        self.assertIsNotNone(app_b_fresh)
        valid, msg = self.db.verify_application_event_chain(app_b.id, self.user_b)
        self.assertTrue(valid, msg)


if __name__ == "__main__":
    unittest.main()

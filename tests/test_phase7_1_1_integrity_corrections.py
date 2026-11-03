"""Phase 7.1.1 Integrity Corrections & Security Hardening Tests.

Covers:
1. Actual Phase 6 approval schema compatibility & zero-fabrication migration.
2. Composite packet foreign key restriction (ON DELETE RESTRICT) & safe account erasure.
3. Strict approval-to-submission boundary & status protection against arbitrary mutation.
4. Multi-user global job insertion isolation (no auto-assignment to first user, no placeholder candidate).
5. Event timestamp hashing (v2), comprehensive tamper detection, deletion prevention trigger & privacy erasure.
6. Migration atomicity, transactional isolation, and clean rollback on simulated failures.
"""

from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    DatabaseMigrationError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.database.models import ApplicationStatus, Job, SubmissionChannel


class TestPhase711ApprovalMigration(unittest.TestCase):
    """Verifies that Phase 7 migration correctly queries the real Phase 6 application_approvals schema."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_migration_phase6.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_phase6_database(self) -> sqlite3.Connection:
        """Creates a legacy database matching the exact Phase 6.1.3 schema."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                full_name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                job_description_id INTEGER,
                resume_id INTEGER,
                company_name TEXT NOT NULL,
                job_title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Discovered',
                date_prepared DATETIME,
                date_submitted DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(id, user_id)
            )
        """)

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
                UNIQUE(id, user_id),
                UNIQUE(application_id, version_num),
                FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE application_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                packet_id INTEGER,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                packet_version_hash TEXT NOT NULL,
                ticket_nonce TEXT NOT NULL UNIQUE,
                key_id TEXT NOT NULL DEFAULT 'v1',
                approver_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                approved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                consumed_at DATETIME,
                is_consumed INTEGER DEFAULT 0 CHECK(is_consumed IN (0, 1)),
                FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE,
                FOREIGN KEY (packet_id, user_id) REFERENCES prepared_packets(id, user_id) ON DELETE CASCADE
            )
        """)

        conn.commit()
        return conn

    def test_actual_phase6_approval_schema_compatibility(self):
        """Verifies migration runs cleanly against realistic Phase 6 schema without no-such-column errors."""
        conn = self._create_phase6_database()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u@test.com', 'h', 's', 'User')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (1, 1, 'DeepMind', 'Researcher', 'Awaiting Approval')")
        cursor.execute(
            "INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, is_active_revision) VALUES (1, 1, 1, 1, 'hash_app1', 'rh', 'jdh', 1)"
        )
        cursor.execute(
            "INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, approved_at, is_consumed) VALUES (1, 1, 1, 1, 'hash_app1', 'nonce_1', 'Candidate', 'sess_1', CURRENT_TIMESTAMP, 0)"
        )
        conn.commit()
        conn.close()

        # Instantiating DatabaseManager runs migration
        db = DatabaseManager(db_path=self.db_path)
        app = db.get_user_application(1, 1)
        self.assertIsNotNone(app)
        self.assertEqual(app.status, ApplicationStatus.APPROVED.value)

    def test_unapproved_or_mismatched_applications_map_to_ready_for_review(self):
        """Verifies all unconfirmed/mismatched Awaiting Approval applications map conservatively to READY_FOR_REVIEW."""
        conn = self._create_phase6_database()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u1@test.com', 'h', 's', 'User 1')")
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (2, 'u2@test.com', 'h', 's', 'User 2')")

        # 1. Genuine approval -> APPROVED
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (1, 1, 'C1', 'R1', 'Awaiting Approval')")
        cursor.execute("INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, is_active_revision) VALUES (1, 1, 1, 1, 'hash_1', 'rh', 'jdh', 1)")
        cursor.execute("INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (1, 1, 1, 1, 'hash_1', 'n1', 'Cand', 's1', 0)")

        # 2. No approval -> READY_FOR_REVIEW
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (2, 1, 'C2', 'R2', 'Awaiting Approval')")
        cursor.execute("INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, is_active_revision) VALUES (2, 2, 1, 1, 'hash_2', 'rh', 'jdh', 1)")

        # 3. Approval for another application -> READY_FOR_REVIEW
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (3, 1, 'C3', 'R3', 'Awaiting Approval')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (30, 1, 'C30', 'R30', 'Discovered')")
        cursor.execute("INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, is_active_revision) VALUES (3, 3, 1, 1, 'hash_3', 'rh', 'jdh', 1)")
        cursor.execute("INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (3, 30, 3, 1, 'hash_3', 'n3', 'Cand', 's3', 0)")

        # 4. User mismatch (User 2 has App 4 with packet, but approval is registered under User 1 for User 1's App 40)
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (40, 1, 'C40', 'R40', 'Awaiting Approval')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (4, 2, 'C4', 'R4', 'Awaiting Approval')")
        cursor.execute("INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, is_active_revision) VALUES (40, 40, 1, 1, 'hash_4_shared', 'rh', 'jdh', 1)")
        cursor.execute("INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (4, 40, 40, 1, 'hash_4_shared', 'n4', 'Cand', 's4', 0)")
        cursor.execute("INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, is_active_revision) VALUES (4, 4, 2, 1, 'hash_4_shared', 'rh', 'jdh', 1)")

        # 5. Inactive packet revision -> READY_FOR_REVIEW
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (5, 1, 'C5', 'R5', 'Awaiting Approval')")
        cursor.execute("INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, is_active_revision) VALUES (5, 5, 1, 1, 'hash_5', 'rh', 'jdh', 0)")
        cursor.execute("INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (5, 5, 5, 1, 'hash_5', 'n5', 'Cand', 's5', 0)")

        # 6. Consumed approval -> READY_FOR_REVIEW
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (6, 1, 'C6', 'R6', 'Awaiting Approval')")
        cursor.execute("INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, is_active_revision) VALUES (6, 6, 1, 1, 'hash_6', 'rh', 'jdh', 1)")
        cursor.execute("INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (6, 6, 6, 1, 'hash_6', 'n6', 'Cand', 's6', 1)")

        # 7. Hash mismatch -> READY_FOR_REVIEW
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (7, 1, 'C7', 'R7', 'Awaiting Approval')")
        cursor.execute("INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, is_active_revision) VALUES (7, 7, 1, 1, 'hash_7_pkt', 'rh', 'jdh', 1)")
        cursor.execute("INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (7, 7, 7, 1, 'hash_7_diff', 'n7', 'Cand', 's7', 0)")

        conn.commit()
        conn.close()

        db = DatabaseManager(db_path=self.db_path)

        # Assertions
        self.assertEqual(db.get_user_application(1, 1).status, ApplicationStatus.APPROVED.value)
        self.assertEqual(db.get_user_application(2, 1).status, ApplicationStatus.READY_FOR_REVIEW.value)
        self.assertEqual(db.get_user_application(3, 1).status, ApplicationStatus.READY_FOR_REVIEW.value)
        self.assertEqual(db.get_user_application(40, 1).status, ApplicationStatus.APPROVED.value)
        self.assertEqual(db.get_user_application(4, 2).status, ApplicationStatus.READY_FOR_REVIEW.value)
        self.assertEqual(db.get_user_application(5, 1).status, ApplicationStatus.READY_FOR_REVIEW.value)
        self.assertEqual(db.get_user_application(6, 1).status, ApplicationStatus.READY_FOR_REVIEW.value)
        self.assertEqual(db.get_user_application(7, 1).status, ApplicationStatus.READY_FOR_REVIEW.value)


class TestPhase711CompositePacketFK(unittest.TestCase):
    """Verifies that composite (packet_id, user_id) on submission_confirmations enforces ON DELETE RESTRICT."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_packet_fk.db"
        self.db = DatabaseManager(db_path=self.db_path)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('a@t.com', 'h', 's', 'User A')")
            self.user_a = cursor.lastrowid
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('b@t.com', 'h', 's', 'User B')")
            self.user_b = cursor.lastrowid

        self.app_a = self.db.create_user_application(user_id=self.user_a, company_name="Corp A", job_title="Role A")
        self.app_b = self.db.create_user_application(user_id=self.user_b, company_name="Corp B", job_title="Role B")

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision
                ) VALUES (10, ?, ?, 1, 'hash_pkt_a', 'rh', 'jdh', '{}', 1)
                """,
                (self.app_a.id, self.user_a),
            )
            self.pkt_a_id = 10

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_submission_confirmation_packet_fk_ownership(self):
        """Submission confirmation references own user's packet, and cross-user packet is rejected."""
        # User A linking User A's packet succeeds
        conf = self.db.create_submission_confirmation(
            application_id=self.app_a.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.LINKEDIN.value,
            packet_id=self.pkt_a_id,
        )
        self.assertEqual(conf.packet_id, self.pkt_a_id)
        self.assertEqual(conf.packet_version_hash, "hash_pkt_a")

        # User B linking User A's packet is rejected
        with self.assertRaises(CrossUserAccessError):
            self.db.create_submission_confirmation(
                application_id=self.app_b.id,
                user_id=self.user_b,
                submission_channel=SubmissionChannel.EMAIL.value,
                packet_id=self.pkt_a_id,
            )

    def test_packet_deletion_restricted_by_foreign_key(self):
        """Deleting a prepared packet referenced by an active submission confirmation is blocked by ON DELETE RESTRICT."""
        self.db.create_submission_confirmation(
            application_id=self.app_a.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=self.pkt_a_id,
        )

        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as conn:
                conn.execute("DELETE FROM prepared_packets WHERE id = ? AND user_id = ?", (self.pkt_a_id, self.user_a))

        # Confirm prepared packet and submission confirmation remain 100% intact
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, packet_version_hash FROM prepared_packets WHERE id = ?", (self.pkt_a_id,))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["packet_version_hash"], "hash_pkt_a")

            cursor.execute("SELECT id, packet_id, packet_version_hash FROM submission_confirmations WHERE packet_id = ?", (self.pkt_a_id,))
            conf_row = cursor.fetchone()
            self.assertIsNotNone(conf_row)
            self.assertEqual(conf_row["packet_version_hash"], "hash_pkt_a")

    def test_safe_account_erasure_deletes_cleanly(self):
        """Explicit delete_user_account_data cleans up packets and confirmations in topological order."""
        self.db.create_submission_confirmation(
            application_id=self.app_a.id,
            user_id=self.user_a,
            submission_channel=SubmissionChannel.REFERRAL.value,
            packet_id=self.pkt_a_id,
        )

        deleted = self.db.delete_user_account_data(self.user_a)
        self.assertTrue(deleted)
        self.assertIsNone(self.db.get_user_by_id(self.user_a))
        self.assertIsNotNone(self.db.get_user_by_id(self.user_b))


class TestPhase711ApprovalToSubmissionBoundary(unittest.TestCase):
    """Enforces that applications cannot transition to SUBMITTED without explicit human approval."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_boundary.db"
        self.db = DatabaseManager(db_path=self.db_path)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('cand@test.com', 'h', 's', 'Candidate')")
            self.user_id = cursor.lastrowid

        self.app = self.db.create_user_application(
            user_id=self.user_id,
            company_name="Safety Corp",
            job_title="Security Engineer",
            status=ApplicationStatus.DRAFT.value,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_storage_only_confirmation_does_not_mutate_status(self):
        """Calling create_submission_confirmation (default transition_status=False) records record but leaves app in DRAFT."""
        conf = self.db.create_submission_confirmation(
            application_id=self.app.id,
            user_id=self.user_id,
            submission_channel=SubmissionChannel.LINKEDIN.value,
            confirmation_reference="REF-12345",
        )
        self.assertEqual(conf.confirmation_reference, "REF-12345")

        # Application status must remain unchanged in DRAFT
        app_fresh = self.db.get_user_application(self.app.id, self.user_id)
        self.assertEqual(app_fresh.status, ApplicationStatus.DRAFT.value)
        self.assertIsNone(app_fresh.date_submitted)

    def test_unrestricted_database_call_cannot_mark_unapproved_application_as_submitted(self):
        """Attempting transition_status=True on DRAFT, PREPARING, or READY_FOR_REVIEW fails closed with SecurityAuthorizationError."""
        for unapproved_status in (
            ApplicationStatus.DRAFT.value,
            ApplicationStatus.PREPARING.value,
            ApplicationStatus.READY_FOR_REVIEW.value,
        ):
            with self.db.transaction() as conn:
                conn.execute("UPDATE applications SET status = ? WHERE id = ?", (unapproved_status, self.app.id))

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.create_submission_confirmation(
                    application_id=self.app.id,
                    user_id=self.user_id,
                    submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
                    packet_id=1,
                    transition_status=True,
                )
            self.assertIn("Application must be approved by candidate", str(ctx.exception))

    def test_transition_requires_mandatory_packet_and_valid_unconsumed_approval(self):
        """Transitioning to SUBMITTED requires packet_id and a valid active unconsumed human approval."""
        # Set app to APPROVED
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'APPROVED' WHERE id = ?", (self.app.id,))

        # 1. Missing packet_id fails
        with self.assertRaises(ValidationError) as ctx:
            self.db.create_submission_confirmation(
                application_id=self.app.id,
                user_id=self.user_id,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
                packet_id=None,
                transition_status=True,
            )
        self.assertIn("packet_id is required", str(ctx.exception))

        # Create active packet
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision
                ) VALUES (20, ?, ?, 1, 'hash_safe_20', 'rh', 'jdh', '{}', 1)
                """,
                (self.app.id, self.user_id),
            )

        # 2. Packet exists, but no approval in application_approvals fails
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.create_submission_confirmation(
                application_id=self.app.id,
                user_id=self.user_id,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
                packet_id=20,
                transition_status=True,
            )
        self.assertIn("No valid human approval record found", str(ctx.exception))

        # 3. Insert consumed approval fails
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO application_approvals (
                    id, application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, approver_name, session_id, is_consumed
                ) VALUES (20, ?, 20, ?, 'hash_safe_20', 'nonce_c', 'Cand', 's1', 1)
                """,
                (self.app.id, self.user_id),
            )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.create_submission_confirmation(
                application_id=self.app.id,
                user_id=self.user_id,
                submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
                packet_id=20,
                transition_status=True,
            )
        self.assertIn("has already been consumed", str(ctx.exception))

    def test_valid_transition_to_submitted_consumes_approval_and_updates_status(self):
        """When an approved application has a valid unconsumed approval, submission transitions to SUBMITTED and consumes approval."""
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'APPROVED' WHERE id = ?", (self.app.id,))
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision
                ) VALUES (30, ?, ?, 1, 'hash_safe_30', 'rh', 'jdh', '{}', 1)
                """,
                (self.app.id, self.user_id),
            )
            cursor.execute(
                """
                INSERT INTO application_approvals (
                    id, application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, approver_name, session_id, is_consumed
                ) VALUES (30, ?, 30, ?, 'hash_safe_30', 'nonce_valid', 'Cand', 's1', 0)
                """,
                (self.app.id, self.user_id),
            )

        conf = self.db.create_submission_confirmation(
            application_id=self.app.id,
            user_id=self.user_id,
            submission_channel=SubmissionChannel.COMPANY_PORTAL.value,
            packet_id=30,
            confirmation_reference="CONF-30-OK",
            transition_status=True,
        )
        self.assertEqual(conf.confirmation_reference, "CONF-30-OK")

        # Verify application status became SUBMITTED
        app_fresh = self.db.get_user_application(self.app.id, self.user_id)
        self.assertEqual(app_fresh.status, ApplicationStatus.SUBMITTED.value)
        self.assertIsNotNone(app_fresh.date_submitted)

        # Verify approval is now marked consumed
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_consumed, consumed_at FROM application_approvals WHERE id = 30")
            row = cursor.fetchone()
            self.assertEqual(row["is_consumed"], 1)
            self.assertIsNotNone(row["consumed_at"])

        # Verify SUBMISSION_CONFIRMED event emitted
        events = self.db.get_application_events(self.app.id, self.user_id)
        last_evt = events[-1]
        self.assertEqual(last_evt.event_type, "SUBMISSION_CONFIRMED")
        self.assertEqual(last_evt.new_status, ApplicationStatus.SUBMITTED.value)


class TestPhase711GlobalJobAssignment(unittest.TestCase):
    """Verifies that inserting a global job does NOT create applications or placeholder candidates."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_global_job.db"
        self.db = DatabaseManager(db_path=self.db_path)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('user_a@test.com', 'h', 's', 'Candidate A')")
            self.user_a_id = cursor.lastrowid
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('user_b@test.com', 'h', 's', 'Candidate B')")
            self.user_b_id = cursor.lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_global_job_insertion_does_not_assign_to_user_a_or_user_b(self):
        """Inserting a global catalogue job creates 0 applications and no placeholder system users."""
        initial_users_count = len(self._get_all_users())
        self.assertEqual(initial_users_count, 2)

        job = Job(
            company_name="DeepMind",
            job_title="AGI Researcher",
            job_url="https://deepmind.google/careers/agi-researcher-2028",
            platform="Company Portal",
        )
        inserted_job = self.db.insert_job(job)
        self.assertIsNotNone(inserted_job.id)

        # 1. User A has zero applications
        apps_a = self.db.list_user_applications(self.user_a_id)
        self.assertEqual(len(apps_a), 0)

        # 2. User B has zero applications
        apps_b = self.db.list_user_applications(self.user_b_id)
        self.assertEqual(len(apps_b), 0)

        # 3. First registered user received no special treatment
        self.assertEqual(len(apps_a), len(apps_b))

        # 4. No placeholder user was created
        current_users = self._get_all_users()
        self.assertEqual(len(current_users), 2)
        self.assertNotIn("system@localhost", [u["email"] for u in current_users])

        # 5. Candidate can explicitly create a private application using their authenticated user_id
        candidate_app = self.db.create_user_application(
            user_id=self.user_b_id,
            job_id=inserted_job.id,
            company_name=inserted_job.company_name,
            job_title=inserted_job.job_title,
        )
        self.assertIsNotNone(candidate_app)
        self.assertEqual(candidate_app.user_id, self.user_b_id)
        self.assertEqual(len(self.db.list_user_applications(self.user_a_id)), 0)
        self.assertEqual(len(self.db.list_user_applications(self.user_b_id)), 1)

    def _get_all_users(self):
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users")
            return [dict(r) for r in cursor.fetchall()]


class TestPhase711EventTimestampHashingAndDeletionProtection(unittest.TestCase):
    """Verifies that UTC timestamps are bound in canonical v2 event hashes and deletion is strictly prevented."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_event_hardening.db"
        self.db = DatabaseManager(db_path=self.db_path)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('event_cand@test.com', 'h', 's', 'Event Candidate')")
            self.user_id = cursor.lastrowid

        self.app = self.db.create_user_application(
            user_id=self.user_id,
            company_name="Event Corp",
            job_title="Auditor",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_timestamp_bound_in_event_hash_v2(self):
        """New events bind the exact UTC created_at timestamp into their canonical hash."""
        evt = self.db.create_application_event(
            application_id=self.app.id,
            user_id=self.user_id,
            event_type="SECTION_REVIEWED",
            event_payload={"section": "experience"},
        )
        self.assertIsNotNone(evt.created_at)

        # Recomputing without created_at (v1) must NOT match the stored v2 hash
        hash_without_ts = DatabaseManager.compute_event_hash(
            actor_identifier=evt.actor_identifier,
            actor_type=evt.actor_type,
            application_id=evt.application_id,
            event_payload_json=evt.event_payload_json,
            event_type=evt.event_type,
            new_status=evt.new_status,
            previous_event_hash=evt.previous_event_hash,
            previous_status=evt.previous_status,
            sequence_no=evt.sequence_no,
            session_reference=evt.session_reference,
            user_id=evt.user_id,
            hash_version="v1",
        )
        self.assertNotEqual(hash_without_ts, evt.event_hash)

        # Recomputing with created_at (v2) matches exactly
        hash_with_ts = DatabaseManager.compute_event_hash(
            actor_identifier=evt.actor_identifier,
            actor_type=evt.actor_type,
            application_id=evt.application_id,
            event_payload_json=evt.event_payload_json,
            event_type=evt.event_type,
            new_status=evt.new_status,
            previous_event_hash=evt.previous_event_hash,
            previous_status=evt.previous_status,
            sequence_no=evt.sequence_no,
            session_reference=evt.session_reference,
            user_id=evt.user_id,
            created_at=evt.created_at,
            hash_version="v2",
        )
        self.assertEqual(hash_with_ts, evt.event_hash)

    def test_tamper_detection_on_timestamp_modification(self):
        """Tampering with stored created_at timestamp breaks chain verification."""
        evt = self.db.create_application_event(
            application_id=self.app.id,
            user_id=self.user_id,
            event_type="TIMESTAMP_TEST",
        )

        with self.db.connection() as conn:
            conn.execute("DROP TRIGGER trg_prevent_application_events_update")
            conn.execute(
                "UPDATE application_events SET created_at = '2020-01-01 00:00:00' WHERE id = ?",
                (evt.id,),
            )
            conn.commit()

        is_valid, msg = self.db.verify_application_event_chain(self.app.id, self.user_id)
        self.assertFalse(is_valid)
        self.assertIn("Event tamper detected", msg)

    def test_normal_database_operations_cannot_delete_events(self):
        """The SQLite trigger trg_prevent_application_events_delete blocks raw DELETE operations."""
        events = self.db.get_application_events(self.app.id, self.user_id)
        first_evt_id = events[0].id

        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            with self.db.transaction() as conn:
                conn.execute("DELETE FROM application_events WHERE id = ?", (first_evt_id,))
        self.assertIn("application_events records are immutable and cannot be deleted", str(ctx.exception))

    def test_authorized_privacy_erasure_deletes_events_cleanly(self):
        """Authorized account erasure works via _privacy_erasure_tokens and cleans up events cleanly."""
        deleted = self.db.delete_user_account_data(self.user_id)
        self.assertTrue(deleted)
        self.assertIsNone(self.db.get_user_by_id(self.user_id))

    def test_missing_final_event_checkpoint_limitation(self):
        """Documents and proves that chain verification alone verifies internal linkage (1..K),
        meaning truncation of the final event requires an external trusted sequence checkpoint.
        """
        # Append events 2 and 3
        evt2 = self.db.create_application_event(application_id=self.app.id, user_id=self.user_id, event_type="E2")
        self.assertEqual(evt2.sequence_no, 2)
        evt3 = self.db.create_application_event(application_id=self.app.id, user_id=self.user_id, event_type="E3")

        # Record external trusted checkpoint of the latest sequence number
        trusted_checkpoint_latest_seq = evt3.sequence_no
        self.assertEqual(trusted_checkpoint_latest_seq, 3)

        # Authorize deletion of event 3 via test token
        with self.db.transaction() as conn:
            conn.execute("INSERT OR REPLACE INTO _privacy_erasure_tokens (user_id, token_nonce) VALUES (?, 'nonce_t')", (self.user_id,))
            conn.execute("DELETE FROM application_events WHERE id = ?", (evt3.id,))
            conn.execute("DELETE FROM _privacy_erasure_tokens WHERE user_id = ?", (self.user_id,))

        # Without trusted checkpoint: sequence 1..2 is internally self-consistent
        valid, msg = self.db.verify_application_event_chain(self.app.id, self.user_id)
        self.assertTrue(valid, "1..2 remains internally valid without external checkpoint.")

        # With trusted checkpoint: detects that event 3 is missing!
        events = self.db.get_application_events(self.app.id, self.user_id)
        observed_max_seq = max(e.sequence_no for e in events) if events else 0
        self.assertLess(observed_max_seq, trusted_checkpoint_latest_seq, "External checkpoint successfully detects tail event deletion.")


class TestPhase711MigrationAtomicityAndRollback(unittest.TestCase):
    """Verifies that Phase 7 migration executes inside atomic transaction and rolls back cleanly on any failure."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_migration_atomicity.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_legacy_populated_database(self) -> None:
        if self.db_path.exists():
            self.db_path.unlink()
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, password_salt TEXT, full_name TEXT)")
        cursor.execute("INSERT INTO users VALUES (1, 'u@test.com', 'h', 's', 'Candidate')")

        cursor.execute("""
            CREATE TABLE applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                company_name TEXT NOT NULL,
                job_title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Discovered',
                date_prepared DATETIME,
                date_submitted DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(id, user_id)
            )
        """)
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (1, 1, 'Legacy Corp', 'Architect', 'Under Review')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (2, 1, 'Legacy AI', 'Engineer', 'Shortlisted')")
        conn.commit()
        conn.close()

    def test_migration_atomicity_and_rollback_on_populated_database(self):
        """When an exception occurs during table rebuild, the entire migration rolls back and legacy database is intact."""
        self._create_legacy_populated_database()

        class MockCursorProxy:
            def __init__(self, real_cursor, matcher, err):
                self._real = real_cursor
                self._matcher = matcher
                self._err = err

            def execute(self, sql, *args, **kwargs):
                if self._matcher in str(sql):
                    raise sqlite3.OperationalError(self._err)
                return self._real.execute(sql, *args, **kwargs)

            def executemany(self, sql, *args, **kwargs):
                if self._matcher in str(sql):
                    raise sqlite3.OperationalError(self._err)
                return self._real.executemany(sql, *args, **kwargs)

            def executescript(self, sql):
                return self._real.executescript(sql)

            def fetchone(self):
                return self._real.fetchone()

            def fetchall(self):
                return self._real.fetchall()

            def fetchmany(self, size=None):
                return self._real.fetchmany(size) if size else self._real.fetchmany()

            def __iter__(self):
                return iter(self._real)

            def __getattr__(self, name):
                return getattr(self._real, name)

        class MockConnProxy:
            def __init__(self, real_conn, matcher, err):
                self.__dict__["_real"] = real_conn
                self.__dict__["_matcher"] = matcher
                self.__dict__["_err"] = err

            def cursor(self):
                return MockCursorProxy(self._real.cursor(), self._matcher, self._err)

            def __getattr__(self, name):
                return getattr(self._real, name)

            def __setattr__(self, name, value):
                if name in ("_real", "_matcher", "_err"):
                    self.__dict__[name] = value
                else:
                    setattr(self._real, name, value)

        orig_get_connection = DatabaseManager.get_connection

        def failing_get_connection(dm_self):
            real_conn = orig_get_connection(dm_self)
            return MockConnProxy(real_conn, "INSERT INTO applications_v7", "Simulated disk error during row copy")

        with patch.object(DatabaseManager, "get_connection", failing_get_connection):
            with self.assertRaises(DatabaseMigrationError) as ctx:
                DatabaseManager(db_path=self.db_path)
            self.assertIn("Simulated disk error during row copy", str(ctx.exception))

        # Inspect database using raw sqlite3: verify original applications table remains intact
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, company_name, status FROM applications ORDER BY id ASC")
        rows = cursor.fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][1], "Legacy Corp")
        self.assertEqual(rows[0][2], "Under Review")
        self.assertEqual(rows[1][1], "Legacy AI")
        self.assertEqual(rows[1][2], "Shortlisted")

        # applications_v7 must NOT exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='applications_v7'")
        self.assertIsNone(cursor.fetchone())
        conn.close()

    def test_simulated_failures_across_migration_stages(self):
        """Tests that simulated failures across 4 stages roll back cleanly."""
        stages = [
            ("CREATE TABLE applications_v7", "Simulated failure creating applications_v7"),
            ("DROP TABLE applications", "Simulated failure dropping legacy applications"),
            ("CREATE TABLE IF NOT EXISTS application_events", "Simulated failure creating application_events"),
            ("PRAGMA foreign_key_check", "Simulated failure on foreign_key_check"),
        ]

        class MockCursorProxy:
            def __init__(self, real_cursor, matcher, err):
                self._real = real_cursor
                self._matcher = matcher
                self._err = err

            def execute(self, sql, *args, **kwargs):
                if self._matcher in str(sql):
                    raise sqlite3.OperationalError(self._err)
                return self._real.execute(sql, *args, **kwargs)

            def executemany(self, sql, *args, **kwargs):
                if self._matcher in str(sql):
                    raise sqlite3.OperationalError(self._err)
                return self._real.executemany(sql, *args, **kwargs)

            def executescript(self, sql):
                return self._real.executescript(sql)

            def fetchone(self):
                return self._real.fetchone()

            def fetchall(self):
                return self._real.fetchall()

            def fetchmany(self, size=None):
                return self._real.fetchmany(size) if size else self._real.fetchmany()

            def __iter__(self):
                return iter(self._real)

            def __getattr__(self, name):
                return getattr(self._real, name)

        class MockConnProxy:
            def __init__(self, real_conn, matcher, err):
                self.__dict__["_real"] = real_conn
                self.__dict__["_matcher"] = matcher
                self.__dict__["_err"] = err

            def cursor(self):
                return MockCursorProxy(self._real.cursor(), self._matcher, self._err)

            def __getattr__(self, name):
                return getattr(self._real, name)

            def __setattr__(self, name, value):
                if name in ("_real", "_matcher", "_err"):
                    self.__dict__[name] = value
                else:
                    setattr(self._real, name, value)

        orig_get_connection = DatabaseManager.get_connection

        for target_sql, err_msg in stages:
            self._create_legacy_populated_database()

            def make_failing_get_conn(tgt, msg):
                def failing_get_conn(dm_self):
                    real_conn = orig_get_connection(dm_self)
                    return MockConnProxy(real_conn, tgt, msg)
                return failing_get_conn

            with patch.object(DatabaseManager, "get_connection", make_failing_get_conn(target_sql, err_msg)):
                with self.assertRaises(DatabaseMigrationError) as ctx:
                    DatabaseManager(db_path=self.db_path)
                self.assertIn(err_msg, str(ctx.exception))

            # Verify database is intact
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM applications")
            self.assertEqual(cursor.fetchone()[0], 2)
            conn.close()


if __name__ == "__main__":
    unittest.main()

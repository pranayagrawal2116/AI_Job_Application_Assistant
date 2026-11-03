"""Phase 7.1 Schema Tests: Tables, Columns, Constraints, Composite Keys, Triggers and Indexes."""

from pathlib import Path
import sqlite3
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.models import ApplicationStatus, FollowUpType, SubmissionChannel


class TestPhase71Schema(unittest.TestCase):
    """Validates the Phase 7.1 database schema structure, constraints, and triggers."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_schema.db"
        self.db = DatabaseManager(db_path=self.db_path)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (email, password_hash, password_salt, full_name)
                VALUES ('user1@example.com', 'hash1', 'salt1', 'User One')
                """
            )
            self.user_id = cursor.lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_applications_table_columns_and_nullability(self):
        """Verifies all Phase 7 columns exist on applications with strict user_id NOT NULL."""
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(applications)")
            cols = {r["name"]: dict(r) for r in cursor.fetchall()}

        expected_columns = [
            "id", "job_id", "job_description_id", "user_id", "resume_id",
            "company_name", "job_title", "status", "application_source",
            "external_application_url", "target_role", "employment_type",
            "location", "salary_range", "application_deadline", "is_archived",
            "date_prepared", "date_submitted", "resume_used", "cover_letter_reference",
            "notes", "created_at", "updated_at"
        ]

        for col in expected_columns:
            self.assertIn(col, cols, f"Column '{col}' must exist on applications table.")

        # Verify user_id is NOT NULL
        self.assertEqual(cols["user_id"]["notnull"], 1, "applications.user_id must be NOT NULL.")

    def test_applications_foreign_key_delete_behaviors(self):
        """Verifies foreign key constraints on applications: RESTRICT on resumes/JDs, SET NULL on jobs, CASCADE on users."""
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_key_list(applications)")
            fks = [dict(r) for r in cursor.fetchall()]

        fk_map = {}
        for fk in fks:
            fk_map[(fk["table"], fk.get("from"))] = fk.get("on_delete")

        # user_id -> users(id) ON DELETE CASCADE
        self.assertEqual(fk_map.get(("users", "user_id")), "CASCADE")

        # job_id -> jobs(id) ON DELETE SET NULL
        self.assertEqual(fk_map.get(("jobs", "job_id")), "SET NULL")

        # job_descriptions -> ON DELETE RESTRICT
        jd_deletes = [fk.get("on_delete") for fk in fks if fk["table"] == "job_descriptions"]
        self.assertTrue(all(d == "RESTRICT" for d in jd_deletes), "job_descriptions FK must be ON DELETE RESTRICT")

        # resumes -> ON DELETE RESTRICT
        res_deletes = [fk.get("on_delete") for fk in fks if fk["table"] == "resumes"]
        self.assertTrue(all(d == "RESTRICT" for d in res_deletes), "resumes FK must be ON DELETE RESTRICT")

    def test_applications_status_check_constraint(self):
        """Validates that applications.status allows all 12 universal statuses and legacy aliases, but rejects invalid strings."""
        # Test 12 universal statuses
        for status in ApplicationStatus.universal_statuses():
            app = self.db.create_user_application(
                user_id=self.user_id,
                company_name=f"Comp_{status}",
                job_title="Role",
                status=status,
            )
            self.assertEqual(app.status, status)

        # Test legacy statuses
        legacy_statuses = ["Discovered", "Under Review", "Shortlisted", "Application Prepared", "Awaiting Approval", "Applied", "Interview", "Rejected", "Withdrawn"]
        for legacy in legacy_statuses:
            app = self.db.create_user_application(
                user_id=self.user_id,
                company_name=f"Comp_Leg_{legacy}",
                job_title="Role",
                status=legacy,
            )
            self.assertEqual(app.status, legacy)

        # Invalid status must fail SQLite CHECK constraint
        with self.assertRaises(Exception):
            with self.db.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO applications (user_id, company_name, job_title, status)
                    VALUES (?, 'Fail Corp', 'Tester', 'INVALID_STATUS_STRING')
                    """,
                    (self.user_id,),
                )

    def test_application_events_table_and_trigger(self):
        """Validates application_events columns, unique sequence constraint, and append-only update trigger."""
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(application_events)")
            cols = {r["name"]: dict(r) for r in cursor.fetchall()}

        for col in [
            "id", "application_id", "user_id", "sequence_no", "event_type",
            "previous_status", "new_status", "actor_type", "actor_identifier",
            "session_reference", "event_payload_json", "previous_event_hash",
            "event_hash", "created_at"
        ]:
            self.assertIn(col, cols)

        app = self.db.create_user_application(user_id=self.user_id, company_name="Acme", job_title="Engineer")

        # Verify initial event was created by create_user_application
        events = self.db.get_application_events(app.id, self.user_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].sequence_no, 1)

        # Attempt to UPDATE an application_events row -> Must fail due to trg_prevent_application_events_update
        with self.assertRaises(sqlite3.IntegrityError) as ctx:
            with self.db.transaction() as conn:
                conn.execute(
                    "UPDATE application_events SET event_type = 'TAMPERED' WHERE id = ?",
                    (events[0].id,),
                )
        self.assertIn("append-only and cannot be updated", str(ctx.exception))

        # Attempt to insert duplicate sequence_no for same application -> Must fail UNIQUE(application_id, sequence_no)
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO application_events (
                        application_id, user_id, sequence_no, event_type,
                        actor_identifier, previous_event_hash, event_hash
                    ) VALUES (?, ?, 1, 'DUP_EVENT', 'tester', 'H1', 'H2')
                    """,
                    (app.id, self.user_id),
                )

    def test_submission_confirmations_schema_and_partial_unique_index(self):
        """Validates submission_confirmations channels and active confirmation partial uniqueness."""
        app = self.db.create_user_application(user_id=self.user_id, company_name="Acme", job_title="Engineer")

        # Test valid submission channels
        for ch in SubmissionChannel.list():
            conf = self.db.create_submission_confirmation(
                application_id=app.id,
                user_id=self.user_id,
                submission_channel=ch,
                confirmation_reference=f"REF-{ch}",
            )
            self.assertEqual(conf.submission_channel, ch)
            self.assertEqual(conf.is_active_confirmation, 1)

        # Only one active confirmation per application
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM submission_confirmations WHERE application_id = ? AND is_active_confirmation = 1",
                (app.id,),
            )
            self.assertEqual(cursor.fetchone()[0], 1)

        # Direct insert of two active confirmations must violate idx_sub_conf_active_app
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO submission_confirmations (
                        application_id, user_id, submission_timestamp, submission_channel, is_active_confirmation
                    ) VALUES (?, ?, '2026-11-03 10:00:00', 'EMAIL', 1)
                    """,
                    (app.id, self.user_id),
                )

    def test_application_follow_ups_schema_and_types(self):
        """Validates application_follow_ups table columns, constraints, and valid types."""
        app = self.db.create_user_application(user_id=self.user_id, company_name="Acme", job_title="Engineer")

        for ftype in FollowUpType.list():
            fu = self.db.create_application_follow_up(
                application_id=app.id,
                user_id=self.user_id,
                follow_up_date="2026-12-01",
                follow_up_type=ftype,
                description=f"Follow up for {ftype}",
            )
            self.assertEqual(fu.follow_up_type, ftype)
            self.assertEqual(fu.is_completed, 0)

        # Invalid follow_up_type must fail CHECK constraint
        with self.assertRaises(Exception):
            with self.db.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO application_follow_ups (
                        application_id, user_id, follow_up_date, follow_up_type, description
                    ) VALUES (?, ?, '2026-12-01', 'INVALID_TYPE', 'Invalid')
                    """,
                    (app.id, self.user_id),
                )


if __name__ == "__main__":
    unittest.main()

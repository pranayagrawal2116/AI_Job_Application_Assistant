"""Phase 7.1 Migration Tests: Legacy Database Upgrades, Preflight Safeguards, Deterministic Status Mapping, and Idempotency."""

from pathlib import Path
import sqlite3
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import MigrationPreflightError
from src.database.models import ApplicationStatus


class TestPhase71Migrations(unittest.TestCase):
    """Tests the Phase 7.1 legacy database migration and preflight checks."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_migration.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_legacy_database(self) -> sqlite3.Connection:
        """Constructs a realistic legacy database matching pre-Phase 7 schema."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        cursor = conn.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                full_name TEXT NOT NULL,
                profession_industry TEXT,
                career_level TEXT,
                account_status TEXT NOT NULL DEFAULT 'active',
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Jobs table
        cursor.execute("""
            CREATE TABLE jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER,
                company_name TEXT NOT NULL,
                job_title TEXT NOT NULL,
                job_description TEXT,
                job_url TEXT,
                location TEXT,
                stipend TEXT,
                required_skills TEXT,
                eligibility_criteria TEXT,
                application_deadline DATETIME,
                match_score REAL DEFAULT 0.0,
                match_classification TEXT DEFAULT 'Low',
                is_eligible INTEGER DEFAULT 0,
                score_breakdown TEXT,
                platform TEXT,
                work_arrangement TEXT,
                publication_date DATETIME,
                internship_duration TEXT,
                listing_status TEXT DEFAULT 'ACTIVE',
                last_verified DATETIME,
                extraction_confidence REAL DEFAULT 1.0,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Job descriptions table
        cursor.execute("""
            CREATE TABLE job_descriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                company_name TEXT NOT NULL,
                job_title TEXT NOT NULL,
                raw_content TEXT NOT NULL,
                source_type TEXT NOT NULL DEFAULT 'pasted_text',
                source_url TEXT,
                original_filename TEXT,
                storage_filename TEXT,
                parser_version TEXT DEFAULT '1.0.0',
                extraction_confidence REAL DEFAULT 1.0,
                parsed_data TEXT,
                supersedes_job_description_id INTEGER,
                snapshot_hash TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(id, user_id)
            )
        """)

        # Resumes table
        cursor.execute("""
            CREATE TABLE resumes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                original_filename TEXT NOT NULL,
                storage_filename TEXT NOT NULL,
                file_format TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                parsed_data TEXT,
                is_primary INTEGER DEFAULT 0,
                label TEXT DEFAULT 'General',
                target_role TEXT,
                active_version INTEGER DEFAULT 1,
                is_active INTEGER DEFAULT 1,
                parsing_status TEXT DEFAULT 'COMPLETED',
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(id, user_id)
            )
        """)

        # Legacy applications table (nullable user_id, old statuses)
        cursor.execute("""
            CREATE TABLE applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
                job_description_id INTEGER,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                resume_id INTEGER,
                company_name TEXT NOT NULL,
                job_title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Discovered',
                date_prepared DATETIME,
                date_submitted DATETIME,
                resume_used TEXT,
                cover_letter_reference TEXT,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(id, user_id)
            )
        """)

        # Prepared packets table
        cursor.execute("""
            CREATE TABLE prepared_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                version_num INTEGER NOT NULL DEFAULT 1,
                packet_version_hash TEXT NOT NULL,
                original_resume_id INTEGER,
                original_resume_hash TEXT NOT NULL,
                tailored_resume_path TEXT,
                tailored_resume_hash TEXT,
                cover_letter_path TEXT,
                cover_letter_hash TEXT,
                job_description_snapshot_hash TEXT NOT NULL,
                screening_answers_json TEXT NOT NULL,
                form_payload_json TEXT,
                form_payload_hash TEXT,
                attachments_manifest_json TEXT,
                attachments_manifest_hash TEXT,
                canonical_snapshot_json TEXT,
                candidate_profile_version INTEGER,
                candidate_profile_hash TEXT,
                matching_result_id INTEGER,
                matching_engine_version TEXT,
                scoring_configuration_version TEXT,
                scoring_profile TEXT,
                original_resume_version_num INTEGER,
                job_description_id INTEGER,
                template_id TEXT,
                template_version TEXT,
                is_active_revision INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(id, user_id),
                UNIQUE(application_id, version_num),
                FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE,
                FOREIGN KEY (original_resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE RESTRICT
            )
        """)

        # Application approvals table (Actual Phase 6.1.3 schema)
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

    def test_legacy_status_migration_and_mapping(self):
        """Verifies deterministic legacy status mapping across all 9 legacy statuses including approval distinction."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()

        # Seed candidate user
        cursor.execute(
            "INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'cand@test.com', 'h', 's', 'Cand')"
        )

        # Seed 9 legacy status applications
        statuses = [
            ("Discovered", 1),
            ("Under Review", 2),
            ("Shortlisted", 3),
            ("Application Prepared", 4),
            ("Awaiting Approval", 5),  # With approved packet -> APPROVED
            ("Awaiting Approval", 6),  # Without approved packet -> READY_FOR_REVIEW
            ("Applied", 7),            # -> SUBMITTED (without fabricating submission confirmation)
            ("Interview", 8),          # -> INTERVIEW
            ("Rejected", 9),           # -> REJECTED
            ("Withdrawn", 10),         # -> WITHDRAWN
        ]

        for st, app_id in statuses:
            cursor.execute(
                """
                INSERT INTO applications (id, user_id, company_name, job_title, status)
                VALUES (?, 1, ?, 'Role', ?)
                """,
                (app_id, f"Company_{app_id}", st),
            )

        # Create approved packet for app #5
        cursor.execute(
            """
            INSERT INTO prepared_packets (
                id, application_id, user_id, version_num, packet_version_hash,
                original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision
            ) VALUES (101, 5, 1, 1, 'hash_5', 'res_h', 'jd_h', '{}', 1)
            """
        )
        cursor.execute(
            """
            INSERT INTO application_approvals (
                packet_id, application_id, user_id, packet_version_hash,
                ticket_nonce, key_id, approver_name, session_id, approved_at, is_consumed
            ) VALUES (101, 5, 1, 'hash_5', 'nonce_5', 'v1', 'Human Candidate', 'sess_1', CURRENT_TIMESTAMP, 0)
            """
        )

        conn.commit()
        conn.close()

        # Run Phase 7.1 migration by instantiating DatabaseManager
        db = DatabaseManager(db_path=self.db_path)

        # Verify mapping outcomes
        app1 = db.get_user_application(1, 1)
        self.assertEqual(app1.status, ApplicationStatus.DRAFT.value)

        app2 = db.get_user_application(2, 1)
        self.assertEqual(app2.status, ApplicationStatus.PREPARING.value)

        app3 = db.get_user_application(3, 1)
        self.assertEqual(app3.status, ApplicationStatus.PREPARING.value)

        app4 = db.get_user_application(4, 1)
        self.assertEqual(app4.status, ApplicationStatus.READY_FOR_REVIEW.value)

        # App 5 (had approved packet) -> APPROVED
        app5 = db.get_user_application(5, 1)
        self.assertEqual(app5.status, ApplicationStatus.APPROVED.value)

        # App 6 (no approved packet) -> READY_FOR_REVIEW
        app6 = db.get_user_application(6, 1)
        self.assertEqual(app6.status, ApplicationStatus.READY_FOR_REVIEW.value)

        # App 7 (Applied) -> SUBMITTED
        app7 = db.get_user_application(7, 1)
        self.assertEqual(app7.status, ApplicationStatus.SUBMITTED.value)
        # Ensure zero fabricated submission_confirmations
        confs = db.list_submission_confirmations(user_id=1, application_id=7)
        self.assertEqual(len(confs), 0, "Migration must never fabricate submission confirmations.")

        app8 = db.get_user_application(8, 1)
        self.assertEqual(app8.status, ApplicationStatus.INTERVIEW.value)

        app9 = db.get_user_application(9, 1)
        self.assertEqual(app9.status, ApplicationStatus.REJECTED.value)

        app10 = db.get_user_application(10, 1)
        self.assertEqual(app10.status, ApplicationStatus.WITHDRAWN.value)

        # Verify that all applications received an initial MIGRATION_INITIALIZED event with sequence_no = 1
        for _, app_id in statuses:
            events = db.get_application_events(app_id, 1)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].sequence_no, 1)
            self.assertEqual(events[0].event_type, "MIGRATION_INITIALIZED")
            self.assertEqual(events[0].previous_event_hash, "GENESIS")
            valid, msg = db.verify_application_event_chain(app_id, 1)
            self.assertTrue(valid, msg)

    def test_approval_migration_exhaustive_scenarios(self):
        """Verifies the 7 explicit approval migration scenarios under realistic Phase 6 schema."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()

        # Seed two users
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u1@test.com', 'h', 's', 'User 1')")
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (2, 'u2@test.com', 'h', 's', 'User 2')")

        # 7 applications in 'Awaiting Approval'
        for app_id in range(1, 8):
            cursor.execute(
                "INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (?, 1, 'Corp', 'Role', 'Awaiting Approval')",
                (app_id,),
            )
        # Application for User 2 (Scenario 4)
        cursor.execute(
            "INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (8, 2, 'Corp 2', 'Role', 'Awaiting Approval')"
        )

        # 1. Genuine approved packet and corresponding human approval record (App 1) -> APPROVED
        cursor.execute(
            "INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision) VALUES (1, 1, 1, 1, 'hash_1', 'rh', 'jdh', '{}', 1)"
        )
        cursor.execute(
            "INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (1, 1, 1, 1, 'hash_1', 'nonce_1', 'Cand', 's1', 0)"
        )

        # 2. Application awaiting approval without an approval record (App 2) -> READY_FOR_REVIEW
        cursor.execute(
            "INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision) VALUES (2, 2, 1, 1, 'hash_2', 'rh', 'jdh', '{}', 1)"
        )
        # (No approval inserted for App 2)

        # 3. An approval belonging to another application (App 3) -> READY_FOR_REVIEW
        cursor.execute(
            "INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (9, 1, 'Corp 9', 'Role', 'Discovered')"
        )
        cursor.execute(
            "INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision) VALUES (3, 3, 1, 1, 'hash_3', 'rh', 'jdh', '{}', 1)"
        )
        cursor.execute(
            "INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (3, 9, 3, 1, 'hash_3', 'nonce_3', 'Cand', 's3', 0)"
        )

        # 4. An approval belonging to another user (User 1 has approved App 10 with matching hash, but User 2's App 8 has no approval) -> READY_FOR_REVIEW
        cursor.execute(
            "INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (10, 1, 'Corp 10', 'Role', 'Awaiting Approval')"
        )
        cursor.execute(
            "INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision) VALUES (10, 10, 1, 1, 'hash_shared', 'rh', 'jdh', '{}', 1)"
        )
        cursor.execute(
            "INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (10, 10, 10, 1, 'hash_shared', 'nonce_10', 'Cand', 's10', 0)"
        )
        cursor.execute(
            "INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision) VALUES (4, 8, 2, 1, 'hash_shared', 'rh', 'jdh', '{}', 1)"
        )

        # 5. Inactive packet revision (App 5) -> READY_FOR_REVIEW
        cursor.execute(
            "INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision) VALUES (5, 5, 1, 1, 'hash_5', 'rh', 'jdh', '{}', 0)"
        )
        cursor.execute(
            "INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (5, 5, 5, 1, 'hash_5', 'nonce_5', 'Cand', 's5', 0)"
        )

        # 6. A consumed approval (App 6) -> READY_FOR_REVIEW
        cursor.execute(
            "INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision) VALUES (6, 6, 1, 1, 'hash_6', 'rh', 'jdh', '{}', 1)"
        )
        cursor.execute(
            "INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (6, 6, 6, 1, 'hash_6', 'nonce_6', 'Cand', 's6', 1)"
        )

        # 7. An approval with a mismatching packet version hash (App 7) -> READY_FOR_REVIEW
        cursor.execute(
            "INSERT INTO prepared_packets (id, application_id, user_id, version_num, packet_version_hash, original_resume_hash, job_description_snapshot_hash, screening_answers_json, is_active_revision) VALUES (7, 7, 1, 1, 'hash_7_pkt', 'rh', 'jdh', '{}', 1)"
        )
        cursor.execute(
            "INSERT INTO application_approvals (id, application_id, packet_id, user_id, packet_version_hash, ticket_nonce, approver_name, session_id, is_consumed) VALUES (7, 7, 7, 1, 'hash_7_mismatch', 'nonce_7', 'Cand', 's7', 0)"
        )

        conn.commit()
        conn.close()

        # Run migration successfully
        db = DatabaseManager(db_path=self.db_path)

        # Scenario 1: Genuine approved -> APPROVED
        self.assertEqual(db.get_user_application(1, 1).status, ApplicationStatus.APPROVED.value)

        # Scenario 2: No approval -> READY_FOR_REVIEW
        self.assertEqual(db.get_user_application(2, 1).status, ApplicationStatus.READY_FOR_REVIEW.value)

        # Scenario 3: Approval for another application -> READY_FOR_REVIEW
        self.assertEqual(db.get_user_application(3, 1).status, ApplicationStatus.READY_FOR_REVIEW.value)

        # Scenario 4: Approval packet user mismatch (pkt is user 1, app is user 2) -> READY_FOR_REVIEW
        self.assertEqual(db.get_user_application(8, 2).status, ApplicationStatus.READY_FOR_REVIEW.value)

        # Scenario 5: Inactive revision -> READY_FOR_REVIEW
        self.assertEqual(db.get_user_application(5, 1).status, ApplicationStatus.READY_FOR_REVIEW.value)

        # Scenario 6: Consumed approval -> READY_FOR_REVIEW
        self.assertEqual(db.get_user_application(6, 1).status, ApplicationStatus.READY_FOR_REVIEW.value)

        # Scenario 7: Hash mismatch -> READY_FOR_REVIEW
        self.assertEqual(db.get_user_application(7, 1).status, ApplicationStatus.READY_FOR_REVIEW.value)

    def test_unowned_application_is_quarantined_safely(self):
        """Unowned application with NULL user_id must be safely moved to legacy_quarantined_applications."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u@t.com', 'h', 's', 'U')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title) VALUES (1, NULL, 'Orphaned Co', 'Role')")
        conn.commit()
        conn.close()

        db = DatabaseManager(db_path=self.db_path)
        # Verify application 1 is not in active applications for user 1
        self.assertIsNone(db.get_user_application(1, 1))

        # Verify application 1 is safely quarantined
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id, company_name, quarantine_reason FROM legacy_quarantined_applications WHERE id = 1")
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 1)
        self.assertEqual(row[1], 'Orphaned Co')
        self.assertEqual(row[2], 'UNOWNED_LEGACY_APPLICATION_NULL_USER_ID')
        conn.close()

    def test_preflight_aborts_on_cross_user_jd_reference(self):
        """Migration must abort with MigrationPreflightError if application references JD owned by another user."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u1@t.com', 'h', 's', 'U1'), (2, 'u2@t.com', 'h', 's', 'U2')")
        # JD owned by User 2
        cursor.execute("INSERT INTO job_descriptions (id, user_id, company_name, job_title, raw_content, snapshot_hash) VALUES (10, 2, 'Co', 'Dev', 'Content', 'h10')")
        # Application owned by User 1 referencing User 2's JD
        cursor.execute("INSERT INTO applications (id, user_id, job_description_id, company_name, job_title) VALUES (1, 1, 10, 'Co', 'Dev')")
        conn.commit()
        conn.close()

        with self.assertRaises(MigrationPreflightError) as ctx:
            DatabaseManager(db_path=self.db_path)
        self.assertIn("reference job descriptions owned by another user", str(ctx.exception))

    def test_preflight_aborts_on_cross_user_resume_reference(self):
        """Migration must abort with MigrationPreflightError if application references resume owned by another user."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u1@t.com', 'h', 's', 'U1'), (2, 'u2@t.com', 'h', 's', 'U2')")
        # Resume owned by User 2
        cursor.execute("INSERT INTO resumes (id, user_id, original_filename, storage_filename, file_format, file_hash, file_size_bytes) VALUES (20, 2, 'f.pdf', 's.pdf', 'pdf', 'h20', 100)")
        # Application owned by User 1 referencing User 2's Resume
        cursor.execute("INSERT INTO applications (id, user_id, resume_id, company_name, job_title) VALUES (1, 1, 20, 'Co', 'Dev')")
        conn.commit()
        conn.close()

        with self.assertRaises(MigrationPreflightError) as ctx:
            DatabaseManager(db_path=self.db_path)
        self.assertIn("reference resumes owned by another user", str(ctx.exception))

    def test_migration_is_idempotent(self):
        """Repeated initialization of an already-migrated database executes cleanly with zero alterations."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u@t.com', 'h', 's', 'U')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title, status) VALUES (1, 1, 'Acme', 'Dev', 'Discovered')")
        conn.commit()
        conn.close()

        # Run migration first time
        db1 = DatabaseManager(db_path=self.db_path)
        app1 = db1.get_user_application(1, 1)
        self.assertEqual(app1.status, ApplicationStatus.DRAFT.value)

        # Run migration second time on same database
        db2 = DatabaseManager(db_path=self.db_path)
        app2 = db2.get_user_application(1, 1)
        self.assertEqual(app2.status, ApplicationStatus.DRAFT.value)

        # Events count must remain 1 (no duplicate backfilled events)
        events = db2.get_application_events(1, 1)
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()

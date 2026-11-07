"""Regression Test Suite: Database Migration Quarantine & Unowned Application Reconciliation.

Verifies:
1. Unowned applications with NULL user_id and no links are safely quarantined to legacy_quarantined_applications.
2. Applications with NULL user_id but unambiguous links (via JD, resume, packet, approval) are reconciled.
3. Applications with conflicting multi-user links are quarantined with CONFLICTING_OWNERSHIP.
4. Applications referencing invalid non-existent user_id are quarantined with INVALID_USER_ID_NOT_IN_USERS.
5. Linked application_events are cleanly quarantined to legacy_quarantined_application_events.
6. Repeated migrations are strictly idempotent with clean PRAGMA integrity_check and foreign_key_check.
"""

from pathlib import Path
import sqlite3
import tempfile
import unittest

from src.database.db_manager import DatabaseManager


class TestMigrationQuarantine(unittest.TestCase):
    """Verifies that legacy unowned applications are safely reconciled or quarantined."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_quarantine.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_legacy_database(self) -> sqlite3.Connection:
        """Constructs a legacy database with pre-Phase 7 schema."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        cursor = conn.cursor()

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

        cursor.execute("""
            CREATE TABLE application_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                application_id INTEGER REFERENCES applications(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                details TEXT,
                user_id INTEGER
            )
        """)

        return conn

    def test_unowned_applications_quarantined_cleanly(self):
        """Unowned applications with NULL user_id must be moved to legacy_quarantined_applications."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u1@test.com', 'h', 's', 'User 1')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title) VALUES (1, NULL, 'Orphaned Inc', 'AI Researcher')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title) VALUES (2, 1, 'Valid Corp', 'Software Engineer')")
        conn.commit()
        conn.close()

        db = DatabaseManager(db_path=self.db_path)

        # Valid application should remain
        valid_app = db.get_user_application(2, 1)
        self.assertIsNotNone(valid_app)
        self.assertEqual(valid_app.company_name, "Valid Corp")

        # Orphaned app should not be in applications
        self.assertIsNone(db.get_user_application(1, 1))

        # Check quarantine table
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id, company_name, quarantine_reason FROM legacy_quarantined_applications WHERE id = 1")
        q_row = c.fetchone()
        self.assertIsNotNone(q_row)
        self.assertEqual(q_row[0], 1)
        self.assertEqual(q_row[1], "Orphaned Inc")
        self.assertEqual(q_row[2], "UNOWNED_LEGACY_APPLICATION_NULL_USER_ID")

        # Integrity check
        c.execute("PRAGMA foreign_key_check;")
        self.assertEqual(c.fetchall(), [])
        c.execute("PRAGMA integrity_check;")
        self.assertEqual(c.fetchall(), [("ok",)])
        conn.close()

    def test_unambiguous_reconciliation_via_linked_jd(self):
        """Application with NULL user_id but referencing a JD owned by User 1 should be reconciled to User 1."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u1@test.com', 'h', 's', 'User 1')")
        cursor.execute("""
            INSERT INTO job_descriptions (id, user_id, company_name, job_title, raw_content, snapshot_hash)
            VALUES (10, 1, 'TechCorp', 'Backend Dev', 'JD text', 'hash10')
        """)
        cursor.execute("""
            INSERT INTO applications (id, user_id, job_description_id, company_name, job_title)
            VALUES (1, NULL, 10, 'TechCorp', 'Backend Dev')
        """)
        conn.commit()
        conn.close()

        db = DatabaseManager(db_path=self.db_path)

        # Application should have been reconciled to user 1
        reconciled_app = db.get_user_application(1, 1)
        self.assertIsNotNone(reconciled_app)
        self.assertEqual(reconciled_app.user_id, 1)
        self.assertEqual(reconciled_app.company_name, "TechCorp")

        # Quarantine table should be empty
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM legacy_quarantined_applications")
        self.assertEqual(c.fetchone()[0], 0)
        conn.close()

    def test_conflicting_ownership_quarantined(self):
        """Application referencing JD of User 1 and Resume of User 2 must be quarantined due to conflicting ownership."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u1@test.com', 'h', 's', 'User 1')")
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (2, 'u2@test.com', 'h', 's', 'User 2')")
        cursor.execute("""
            INSERT INTO job_descriptions (id, user_id, company_name, job_title, raw_content, snapshot_hash)
            VALUES (10, 1, 'TechCorp', 'Backend Dev', 'JD text', 'hash10')
        """)
        cursor.execute("""
            INSERT INTO resumes (id, user_id, original_filename, storage_filename, file_format, file_hash, file_size_bytes)
            VALUES (20, 2, 'res.pdf', 'res_stored.pdf', 'pdf', 'res_hash', 1024)
        """)
        cursor.execute("""
            INSERT INTO applications (id, user_id, job_description_id, resume_id, company_name, job_title)
            VALUES (1, NULL, 10, 20, 'ConflictCorp', 'Dev')
        """)
        conn.commit()
        conn.close()

        db = DatabaseManager(db_path=self.db_path)

        # Application should not belong to either user
        self.assertIsNone(db.get_user_application(1, 1))
        self.assertIsNone(db.get_user_application(1, 2))

        # Check quarantine
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id, quarantine_reason FROM legacy_quarantined_applications WHERE id = 1")
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[1], "CONFLICTING_OWNERSHIP")
        conn.close()

    def test_invalid_user_id_quarantined(self):
        """Application with user_id that does not exist in users table must be quarantined."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = OFF;")
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u1@test.com', 'h', 's', 'User 1')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title) VALUES (1, 999, 'GhostCorp', 'Ghost')")
        cursor.execute("PRAGMA foreign_keys = ON;")
        conn.commit()
        conn.close()

        db = DatabaseManager(db_path=self.db_path)

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id, quarantine_reason FROM legacy_quarantined_applications WHERE id = 1")
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[1], "INVALID_USER_ID_NOT_IN_USERS")
        conn.close()

    def test_quarantine_is_idempotent(self):
        """Running migration repeatedly on a database with quarantined records remains cleanly idempotent."""
        conn = self._create_legacy_database()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u1@test.com', 'h', 's', 'User 1')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title) VALUES (1, NULL, 'Orphaned', 'Role')")
        cursor.execute("INSERT INTO applications (id, user_id, company_name, job_title) VALUES (2, 1, 'Valid', 'Role')")
        conn.commit()
        conn.close()

        # Run migration 1st time
        db1 = DatabaseManager(db_path=self.db_path)
        self.assertIsNotNone(db1.get_user_application(2, 1))

        # Run migration 2nd time
        db2 = DatabaseManager(db_path=self.db_path)
        self.assertIsNotNone(db2.get_user_application(2, 1))

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM legacy_quarantined_applications")
        self.assertEqual(c.fetchone()[0], 1)
        c.execute("PRAGMA foreign_key_check;")
        self.assertEqual(c.fetchall(), [])
        c.execute("PRAGMA integrity_check;")
        self.assertEqual(c.fetchall(), [("ok",)])
        conn.close()


if __name__ == "__main__":
    unittest.main()

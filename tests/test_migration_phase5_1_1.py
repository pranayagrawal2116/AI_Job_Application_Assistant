"""Phase 5.1.1 Genuine SQLite Database Migration Regression Test Suite.

Verifies transactional table rebuild of match_results from realistic commit 7c21141
schema, ensuring:
1. Row preservation, ID stability, and data integrity.
2. Foreign key actions updated (jobs -> SET NULL, resumes/JDs -> RESTRICT).
3. Catalog job deletion preserves match evaluations without cascading deletion.
4. Direct resume/JD deletions blocked by RESTRICT, while application soft-archives.
5. Idempotent repeated migrations without corrupting or duplicating records.
6. Zero foreign key violations (PRAGMA foreign_key_check = 0).
7. Privacy-compliant account data deletion.
"""

from pathlib import Path
import sqlite3
import tempfile
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager


class TestMigrationPhase511(unittest.TestCase):
    """Rigorous migration tests using a simulated pre-migration SQLite database."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_migration_phase511.db"

        # Construct a realistic pre-migration database simulating commit 7c21141
        self._build_legacy_phase5_database(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _build_legacy_phase5_database(self, db_path: Path):
        """Constructs realistic SQLite schema as it existed in Phase 5 commit 7c21141."""
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                full_name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_active INTEGER DEFAULT 1
            )
        """)

        # Resumes table (pre-migration: lacked is_active)
        cursor.execute("""
            CREATE TABLE resumes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                storage_filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_format TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                parsed_data TEXT,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                active_version INTEGER DEFAULT 1,
                label TEXT DEFAULT 'General',
                target_role TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                parsing_status TEXT DEFAULT 'COMPLETED',
                UNIQUE(id, user_id)
            )
        """)

        # Resume versions table
        cursor.execute("""
            CREATE TABLE resume_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resume_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                version_number INTEGER NOT NULL,
                storage_filename TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                parsed_data TEXT,
                change_notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE CASCADE,
                UNIQUE (resume_id, version_number)
            )
        """)

        # Job descriptions table
        cursor.execute("""
            CREATE TABLE job_descriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                source_type TEXT NOT NULL,
                company_name TEXT NOT NULL,
                job_title TEXT NOT NULL,
                raw_content TEXT NOT NULL,
                parsed_data TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                source_url TEXT,
                original_filename TEXT,
                storage_filename TEXT,
                parser_version TEXT DEFAULT '1.0.0',
                extraction_confidence REAL DEFAULT 1.0,
                supersedes_job_description_id INTEGER REFERENCES job_descriptions(id) ON DELETE SET NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                snapshot_hash TEXT,
                UNIQUE(id, user_id)
            )
        """)

        # Catalog jobs table
        cursor.execute("""
            CREATE TABLE jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER,
                company_name TEXT NOT NULL,
                job_title TEXT NOT NULL,
                job_description TEXT,
                job_url TEXT NOT NULL UNIQUE,
                location TEXT,
                match_score REAL DEFAULT 0.0,
                match_classification TEXT,
                is_eligible INTEGER DEFAULT 1,
                score_breakdown TEXT,
                platform TEXT NOT NULL DEFAULT 'manual',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Candidate profiles table
        cursor.execute("""
            CREATE TABLE candidate_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                version INTEGER NOT NULL DEFAULT 1,
                profile_data TEXT NOT NULL,
                profile_hash TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, version)
            )
        """)

        # Applications table
        cursor.execute("""
            CREATE TABLE applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE CASCADE,
                status TEXT NOT NULL DEFAULT 'Discovered',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                resume_id INTEGER
            )
        """)

        # Historical match_results table with CASCADE deletion and missing candidate_profile_hash
        cursor.execute("""
            CREATE TABLE match_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                resume_id INTEGER,
                job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
                job_description_id INTEGER,
                match_score REAL NOT NULL,
                match_classification TEXT NOT NULL,
                eligibility_status TEXT NOT NULL CHECK(eligibility_status IN ('ELIGIBLE', 'INELIGIBLE', 'UNKNOWN')),
                score_breakdown TEXT NOT NULL,
                explanation TEXT NOT NULL,
                resume_version_num INTEGER DEFAULT 1,
                resume_file_hash TEXT,
                candidate_profile_version INTEGER DEFAULT 1,
                job_snapshot_hash TEXT,
                scoring_profile TEXT DEFAULT 'general_baseline',
                scoring_config_version TEXT DEFAULT '1.0.0',
                assessment_confidence REAL DEFAULT 1.0,
                engine_version TEXT DEFAULT '2.1.1',
                matching_skills TEXT,
                related_skills TEXT,
                partial_matches TEXT,
                missing_skills TEXT,
                education_analysis TEXT,
                experience_analysis TEXT,
                certification_analysis TEXT,
                eligibility_reasons TEXT,
                scoring_explanations TEXT,
                recommendations TEXT,
                details_json TEXT,
                evaluated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE CASCADE,
                FOREIGN KEY (job_description_id, user_id) REFERENCES job_descriptions(id, user_id) ON DELETE CASCADE
            )
        """)

        # Seed data
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (1, 'u1@test.com', 'h1', 's1', 'User One')")
        cursor.execute("INSERT INTO users (id, email, password_hash, password_salt, full_name) VALUES (2, 'u2@test.com', 'h2', 's2', 'User Two')")

        # Seed resumes for User 1
        cursor.execute("""
            INSERT INTO resumes (id, user_id, storage_filename, original_filename, file_format, file_hash, file_size_bytes, parsed_data)
            VALUES (101, 1, 'res101.pdf', 'resume_one.pdf', 'pdf', 'hash101', 2048, '{"skills":["Python"]}')
        """)
        cursor.execute("""
            INSERT INTO resume_versions (resume_id, user_id, version_number, storage_filename, file_hash, parsed_data)
            VALUES (101, 1, 1, 'res101.pdf', 'hash101', '{"skills":["Python"]}')
        """)

        # Seed job descriptions
        cursor.execute("""
            INSERT INTO job_descriptions (id, user_id, source_type, company_name, job_title, raw_content, parsed_data, content_hash)
            VALUES (201, 1, 'pasted', 'AI Labs', 'Senior AI Engineer', 'Text here', '{"mandatory_skills":["Python"]}', 'hash201')
        """)

        # Seed catalog job
        cursor.execute("""
            INSERT INTO jobs (id, job_title, company_name, job_url, job_description, platform)
            VALUES (301, 'Data Analyst', 'BigData Corp', 'https://example.com/job301', 'Catalog job description', 'manual')
        """)

        # Seed historical match_results record linking to catalog job 301, resume 101, and JD 201
        cursor.execute("""
            INSERT INTO match_results (
                id, user_id, resume_id, job_id, job_description_id, match_score, match_classification,
                eligibility_status, score_breakdown, explanation, details_json
            ) VALUES (
                501, 1, 101, 301, 201, 88.5, 'Excellent Match', 'ELIGIBLE',
                '{"skills": 30.0}', 'Detailed evaluation notes', '{"full": "data"}'
            )
        """)

        conn.commit()
        conn.close()

    def test_01_migration_executes_safely_and_updates_foreign_keys(self):
        """Initializes DatabaseManager, triggering migration, and verifies table structure."""
        db = DatabaseManager(db_path=self.db_path)

        with db.transaction() as conn:
            cursor = conn.cursor()

            # 1. Verify candidate_profile_hash column was added
            cursor.execute("PRAGMA table_info(match_results)")
            cols = {r[1]: r for r in cursor.fetchall()}
            self.assertIn("candidate_profile_hash", cols)

            # 2. Verify foreign keys
            cursor.execute("PRAGMA foreign_key_list(match_results)")
            fk_dict = {r[2]: r for r in cursor.fetchall()}

            # jobs foreign key must now be ON DELETE SET NULL
            self.assertIn("jobs", fk_dict)
            self.assertEqual(fk_dict["jobs"][6], "SET NULL")

            # resumes and job_descriptions must now be ON DELETE RESTRICT
            self.assertIn("resumes", fk_dict)
            self.assertEqual(fk_dict["resumes"][6], "RESTRICT")
            self.assertIn("job_descriptions", fk_dict)
            self.assertEqual(fk_dict["job_descriptions"][6], "RESTRICT")

            # 3. Verify PRAGMA foreign_key_check passes with zero violations
            cursor.execute("PRAGMA foreign_key_check(match_results)")
            violations = cursor.fetchall()
            self.assertEqual(len(violations), 0)

    def test_02_historical_match_record_data_preserved_intact(self):
        """Verifies row ID, scores, details_json, timestamps, and foreign key relations survive migration."""
        db = DatabaseManager(db_path=self.db_path)

        with db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM match_results WHERE id = 501")
            row = dict(cursor.fetchone())

            self.assertEqual(row["id"], 501)
            self.assertEqual(row["user_id"], 1)
            self.assertEqual(row["resume_id"], 101)
            self.assertEqual(row["job_id"], 301)
            self.assertEqual(row["job_description_id"], 201)
            self.assertEqual(row["match_score"], 88.5)
            self.assertEqual(row["match_classification"], "Excellent Match")
            self.assertEqual(row["eligibility_status"], "ELIGIBLE")
            self.assertEqual(row["details_json"], '{"full": "data"}')

    def test_03_catalog_job_deletion_sets_null_and_retains_match_history(self):
        """Deleting a catalog job must NOT delete historical match evaluations (sets job_id = NULL)."""
        db = DatabaseManager(db_path=self.db_path)

        with db.transaction() as conn:
            cursor = conn.cursor()
            # Delete catalog job 301
            cursor.execute("DELETE FROM jobs WHERE id = 301")

        with db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, job_id, resume_id, job_description_id FROM match_results WHERE id = 501")
            row = cursor.fetchone()

            # Record must STILL exist
            self.assertIsNotNone(row)
            self.assertEqual(row["id"], 501)
            # job_id must now be NULL due to ON DELETE SET NULL
            self.assertIsNone(row["job_id"])
            # resume_id and job_description_id remain intact
            self.assertEqual(row["resume_id"], 101)
            self.assertEqual(row["job_description_id"], 201)

    def test_04_direct_resume_deletion_blocked_by_restrict(self):
        """Direct SQL deletion of a resume referenced by historical match_results must be blocked by RESTRICT."""
        db = DatabaseManager(db_path=self.db_path)

        with self.assertRaises(sqlite3.IntegrityError):
            with db.transaction() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM resumes WHERE id = 101")

    def test_05_direct_job_description_deletion_blocked_by_restrict(self):
        """Direct SQL deletion of a job description referenced by historical match_results must be blocked by RESTRICT."""
        db = DatabaseManager(db_path=self.db_path)

        with self.assertRaises(sqlite3.IntegrityError):
            with db.transaction() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM job_descriptions WHERE id = 201")

    def test_06_application_resume_deletion_soft_archives_safely(self):
        """Application-level delete_user_resume archives the resume (is_active = 0) preserving foreign keys."""
        db = DatabaseManager(db_path=self.db_path)
        service = DashboardService(db_manager=db)

        # Application resume deletion
        success, msg = service.delete_user_resume(user_id=1, resume_id=101)
        self.assertTrue(success)

        with db.transaction() as conn:
            cursor = conn.cursor()
            # Resume row must still exist in table, marked inactive
            cursor.execute("SELECT id, is_active FROM resumes WHERE id = 101")
            res_row = cursor.fetchone()
            self.assertIsNotNone(res_row)
            self.assertEqual(res_row["is_active"], 0)

            # Match record must remain untouched
            cursor.execute("SELECT id, resume_id FROM match_results WHERE id = 501")
            match_row = cursor.fetchone()
            self.assertIsNotNone(match_row)
            self.assertEqual(match_row["resume_id"], 101)

    def test_07_application_job_description_deletion_soft_archives_safely(self):
        """Application-level delete_job_description archives the JD (is_active = 0) preserving match evaluations."""
        db = DatabaseManager(db_path=self.db_path)

        # Soft archive via db.delete_job_description
        deleted = db.delete_job_description(user_id=1, jd_id=201)
        self.assertTrue(deleted)

        with db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, is_active FROM job_descriptions WHERE id = 201")
            jd_row = cursor.fetchone()
            self.assertIsNotNone(jd_row)
            self.assertEqual(jd_row["is_active"], 0)

            # Match record must remain untouched
            cursor.execute("SELECT id, job_description_id FROM match_results WHERE id = 501")
            match_row = cursor.fetchone()
            self.assertIsNotNone(match_row)
            self.assertEqual(match_row["job_description_id"], 201)

    def test_08_migration_idempotent_on_repeated_runs(self):
        """Re-initializing DatabaseManager on an already-migrated database does not corrupt or alter rows."""
        DatabaseManager(db_path=self.db_path)
        DatabaseManager(db_path=self.db_path)
        db3 = DatabaseManager(db_path=self.db_path)

        with db3.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM match_results")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 1)

            cursor.execute("PRAGMA foreign_key_check(match_results)")
            violations = cursor.fetchall()
            self.assertEqual(len(violations), 0)

    def test_09_user_account_deletion_cleans_up_all_user_records(self):
        """Explicit user account deletion deletes match results and user data cleanly."""
        db = DatabaseManager(db_path=self.db_path)

        # Delete User 1
        db.delete_user_account_data(user_id=1)

        with db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM match_results WHERE user_id = 1")
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT COUNT(*) FROM resumes WHERE user_id = 1")
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT COUNT(*) FROM job_descriptions WHERE user_id = 1")
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT COUNT(*) FROM users WHERE id = 1")
            self.assertEqual(cursor.fetchone()[0], 0)

            # User 2 intact
            cursor.execute("SELECT COUNT(*) FROM users WHERE id = 2")
            self.assertEqual(cursor.fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()

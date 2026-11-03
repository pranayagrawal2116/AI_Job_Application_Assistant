"""Versioning and Deduplication Tests for Job Description Snapshots.

Verifies immutable snapshot creation, supersedes lineage tracking,
per-user deduplication, and cross-user duplicate independence.
"""

from pathlib import Path
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    DuplicateJobDescriptionError,
    JobDescriptionNotFoundError,
)
from src.security.auth import AuthManager


class TestJobDescriptionVersioning(unittest.TestCase):
    """Test suite for job description immutability and versioning."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_versioning.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)

        self.user_1 = self.auth.register(
            email="candidate1@example.com",
            password="StrongPassword123!",
            full_name="Candidate One",
        )
        self.user_2 = self.auth.register(
            email="candidate2@example.com",
            password="StrongPassword123!",
            full_name="Candidate Two",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_immutable_snapshot_update_creates_new_record(self):
        """Updating a job description creates a new snapshot without mutating the original."""
        original_jd = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="InnovateTech",
            job_title="Junior Data Analyst",
            raw_content="Raw job posting content for InnovateTech Data Analyst role.",
            parsed_data={"mandatory_skills": ["Python", "SQL"], "min_years_experience": 1.0},
        )
        self.assertTrue(original_jd.is_active)
        self.assertIsNone(original_jd.supersedes_job_description_id)

        # Candidate reviews and corrects requirements
        updated_data = {
            "mandatory_skills": ["Python", "SQL", "Tableau"],
            "min_years_experience": 2.0,
            "verification_status": "USER_CORRECTED",
        }
        revised_jd = self.db.update_job_description_snapshot(
            user_id=self.user_1.id,
            jd_id=original_jd.id,
            updated_parsed_data=updated_data,
            new_job_title="Data Analyst",
        )

        # Revised snapshot checks
        self.assertNotEqual(revised_jd.id, original_jd.id)
        self.assertEqual(revised_jd.supersedes_job_description_id, original_jd.id)
        self.assertTrue(revised_jd.is_active)
        self.assertEqual(revised_jd.job_title, "Data Analyst")

        # Original snapshot remains preserved and is marked inactive
        fetched_original = self.db.get_job_description(original_jd.id, user_id=self.user_1.id)
        self.assertIsNotNone(fetched_original)
        self.assertFalse(fetched_original.is_active)
        self.assertEqual(fetched_original.job_title, "Junior Data Analyst")

        # Lineage history traces back
        history = self.db.get_job_description_history(user_id=self.user_1.id, jd_id=revised_jd.id)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0].id, revised_jd.id)
        self.assertEqual(history[1].id, original_jd.id)

    def test_per_user_deduplication(self):
        """Saving exact duplicate content hash for the same user raises DuplicateJobDescriptionError."""
        jd_text = "Unique content text describing an engineering position at Robotics Co."

        jd_first = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Robotics Co",
            job_title="Robotics Engineer",
            raw_content=jd_text,
        )
        self.assertIsNotNone(jd_first)

        # Attempt to save exact duplicate for User 1
        with self.assertRaises(DuplicateJobDescriptionError) as ctx:
            self.db.save_job_description_snapshot(
                user_id=self.user_1.id,
                company_name="Robotics Co",
                job_title="Robotics Engineer",
                raw_content=jd_text,
            )
        self.assertEqual(ctx.exception.existing_id, jd_first.id)

    def test_cross_user_duplicate_independence(self):
        """Two distinct users can ingest identical job posting text without conflict."""
        shared_jd_text = "Shared public job description for Cloud Architect at Global Cloud Systems."

        # User 1 saves
        jd_u1 = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Global Cloud Systems",
            job_title="Cloud Architect",
            raw_content=shared_jd_text,
        )

        # User 2 saves identical content successfully
        jd_u2 = self.db.save_job_description_snapshot(
            user_id=self.user_2.id,
            company_name="Global Cloud Systems",
            job_title="Cloud Architect",
            raw_content=shared_jd_text,
        )

        self.assertEqual(jd_u1.id != jd_u2.id, True)
        self.assertEqual(jd_u1.user_id, self.user_1.id)
        self.assertEqual(jd_u2.user_id, self.user_2.id)
        self.assertEqual(jd_u1.content_hash, jd_u2.content_hash)

    def test_composite_foreign_key_cross_user_supersedes_rejected(self):
        """User 2 cannot create a revision claiming to supersede User 1's snapshot."""
        import sqlite3

        jd_u1 = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Alpha Corp",
            job_title="Software Engineer",
            raw_content="Alpha Corp job description content.",
        )

        # 1. Blocked at application service layer via CrossUserAccessError
        with self.assertRaises((JobDescriptionNotFoundError, CrossUserAccessError)):
            self.db.save_job_description_snapshot(
                user_id=self.user_2.id,
                company_name="Alpha Corp",
                job_title="Software Engineer",
                raw_content="Alpha Corp modified content.",
                supersedes_job_description_id=jd_u1.id,
            )

        # 2. Blocked at database schema level via composite foreign key constraint
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as conn:
                conn.cursor().execute(
                    """
                    INSERT INTO job_descriptions (
                        user_id, source_type, company_name, job_title, raw_content, content_hash,
                        supersedes_job_description_id
                    ) VALUES (?, 'pasted', 'Alpha Corp', 'Eng', 'Raw', 'hash123', ?)
                    """,
                    (self.user_2.id, jd_u1.id),
                )

    def test_snapshot_hash_differs_when_parsed_data_updates(self):
        """snapshot_hash changes when structured fields update even if raw_content remains identical."""
        raw_text = "Universal job posting text for Security Engineer at Cyber Defense Inc."
        
        snap_1 = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Cyber Defense Inc",
            job_title="Security Engineer",
            raw_content=raw_text,
            parsed_data={"min_years_experience": 3.0, "skills": ["SIEM"]},
        )
        self.assertIsNotNone(snap_1.snapshot_hash)
        self.assertIsNotNone(snap_1.content_hash)

        # Revision with updated parsed data and corrected title
        snap_2 = self.db.update_job_description_snapshot(
            user_id=self.user_1.id,
            jd_id=snap_1.id,
            updated_parsed_data={"min_years_experience": 5.0, "skills": ["SIEM", "Incident Response"]},
            new_job_title="Senior Security Engineer",
        )
        self.assertIsNotNone(snap_2.snapshot_hash)
        # raw_content hash is identical because raw text didn't change
        self.assertEqual(snap_1.content_hash, snap_2.content_hash)
        # snapshot_hash MUST be different
        self.assertNotEqual(snap_1.snapshot_hash, snap_2.snapshot_hash)

    def test_delete_unreferenced_job_description_hard_deleted(self):
        """Deleting an unreferenced job description completely removes it from database."""
        jd = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Temp Co",
            job_title="Intern",
            raw_content="Temporary intern job description.",
        )
        res = self.db.delete_job_description(jd_id=jd.id, user_id=self.user_1.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["action"], "deleted")
        self.assertTrue(res["deleted"])
        self.assertFalse(res["archived"])
        self.assertIsNone(self.db.get_job_description(jd.id, user_id=self.user_1.id))

    def test_delete_referenced_job_description_archived(self):
        """Deleting a job description linked to an application safely archives it (is_active=0)."""
        jd = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Enterprise Corp",
            job_title="Staff Engineer",
            raw_content="Enterprise staff engineer posting.",
        )
        # Create linked application
        app = self.db.create_user_application(
            user_id=self.user_1.id,
            job_description_id=jd.id,
            company_name="Enterprise Corp",
            job_title="Staff Engineer",
            status="Discovered",
        )

        res = self.db.delete_job_description(jd_id=jd.id, user_id=self.user_1.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["action"], "archived")
        self.assertTrue(res["archived"])
        self.assertFalse(res["deleted"])

        # Record still exists but is inactive
        archived_jd = self.db.get_job_description(jd.id, user_id=self.user_1.id)
        self.assertIsNotNone(archived_jd)
        self.assertFalse(archived_jd.is_active)

        # Application is preserved
        preserved_app = self.db.get_user_application(app.id, user_id=self.user_1.id)
        self.assertIsNotNone(preserved_app)
        self.assertEqual(preserved_app.job_description_id, jd.id)

    def test_shared_storage_file_deleted_only_when_zero_references_remain(self):
        """Physical storage file is preserved when other snapshots still reference storage_filename."""
        from src.security.file_security import FileSecurityValidator
        validator = FileSecurityValidator()

        # Create physical dummy file in user's job description directory
        user_jd_dir = validator.get_user_job_descriptions_dir(self.user_1.id)
        user_jd_dir.mkdir(parents=True, exist_ok=True)
        storage_file = user_jd_dir / "shared_doc_123.pdf"
        storage_file.write_bytes(b"%PDF-1.4 dummy content")
        self.assertTrue(storage_file.exists())

        # Snapshot 1 references this storage file
        snap_1 = self.db.save_job_description_snapshot(
            user_id=self.user_1.id,
            company_name="Doc Corp",
            job_title="Doc Specialist",
            raw_content="Doc Specialist raw text v1.",
            storage_filename="shared_doc_123.pdf",
        )
        # Snapshot 2 (revision) also references the same storage file
        snap_2 = self.db.update_job_description_snapshot(
            user_id=self.user_1.id,
            jd_id=snap_1.id,
            updated_parsed_data={"skills": ["Documentation"]},
            new_job_title="Senior Doc Specialist",
        )
        self.assertEqual(snap_2.storage_filename, "shared_doc_123.pdf")

        # Deleting snap_1 is prevented from hard delete because snap_2 supersedes it
        res_1 = self.db.delete_job_description(snap_1.id, user_id=self.user_1.id)
        self.assertEqual(res_1["action"], "archived")
        self.assertTrue(storage_file.exists())

        # Deleting snap_2 (unreferenced): snap_1 still has storage_filename in DB, so file must NOT be deleted
        res_2 = self.db.delete_job_description(snap_2.id, user_id=self.user_1.id)
        self.assertEqual(res_2["action"], "deleted")
        self.assertTrue(storage_file.exists())

        # Finally, if snap_1 is also hard-deleted directly, file is deleted
        with self.db.transaction() as conn:
            conn.cursor().execute("DELETE FROM job_descriptions WHERE id = ?", (snap_1.id,))
        # Now 0 references remain
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM job_descriptions WHERE user_id = ? AND storage_filename = ?", (self.user_1.id, "shared_doc_123.pdf"))
            cnt = cursor.fetchone()["cnt"]
        self.assertEqual(cnt, 0)
        validator.delete_stored_job_description_file(self.user_1.id, "shared_doc_123.pdf")
        self.assertFalse(storage_file.exists())


if __name__ == "__main__":
    unittest.main()


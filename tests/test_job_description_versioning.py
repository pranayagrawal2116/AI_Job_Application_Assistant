"""Versioning and Deduplication Tests for Job Description Snapshots.

Verifies immutable snapshot creation, supersedes lineage tracking,
per-user deduplication, and cross-user duplicate independence.
"""

from pathlib import Path
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import DuplicateJobDescriptionError
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

        self.assertNotEqual(jd_u1.id, jd_u2.id)
        self.assertEqual(jd_u1.user_id, self.user_1.id)
        self.assertEqual(jd_u2.user_id, self.user_2.id)
        self.assertEqual(jd_u1.content_hash, jd_u2.content_hash)


if __name__ == "__main__":
    unittest.main()

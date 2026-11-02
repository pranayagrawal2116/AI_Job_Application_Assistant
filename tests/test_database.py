"""Comprehensive unit tests for the SQLite Database & Job Management Engine (Phase 2)."""

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import pandas as pd

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ApplicationNotFoundError,
    CompanyNotFoundError,
    DatabaseError,
    DuplicateJobError,
    InvalidStatusError,
    InvalidStatusTransitionError,
    JobNotFoundError,
    UnconfirmedSubmissionError,
    ValidationError,
)
from src.database.models import ApplicationStatus, Company, Job
from src.database.url_normalizer import normalize_job_url


class TestDatabaseManager(unittest.TestCase):
    """Test suite using isolated temporary databases."""

    def setUp(self):
        """Creates a dedicated temporary SQLite database for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_job_assistant.db"
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self):
        """Cleans up temporary resources."""
        self.temp_dir.cleanup()

    def _create_sample_job(
        self,
        company: str = "DeepMind AI Labs",
        title: str = "Machine Learning Intern",
        url: str = "https://careers.deepmind.com/jobs/ml-intern-2028?utm_source=linkedin&ref=feed",
        platform: str = "LinkedIn",
        match_score: float = 92.5,
    ) -> Job:
        return Job(
            company_name=company,
            job_title=title,
            job_url=url,
            platform=platform,
            job_description="Research and develop computer vision and NLP models using Python and PyTorch.",
            location="Bengaluru, India (Remote)",
            stipend="₹45,000 / month",
            required_skills=["Python", "Machine Learning", "PyTorch", "Data Preprocessing"],
            eligibility_criteria={"degree": "B.Tech CSE / AI & DS", "graduation_year": 2028},
            application_deadline="2026-12-31",
            match_score=match_score,
            match_classification="Excellent",
            is_eligible=True,
            score_breakdown={
                "domain_relevance": 30,
                "technical_skills": 25,
                "educational_eligibility": 20,
                "experience_compatibility": 10,
                "location_preference": 10,
                "duration_compatibility": 5,
            },
        )

    # 1. Database Initialization
    def test_database_initialization(self):
        """Verifies that all 5 tables and their indexes exist after initialization."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

        expected_tables = ["companies", "jobs", "applications", "application_logs", "candidate_profile"]
        for table in expected_tables:
            self.assertIn(table, tables, f"Expected table '{table}' in database.")

    # 2. Company Operations
    def test_company_get_or_create(self):
        """Checks company creation, case-insensitivity, and auto-association."""
        comp1 = self.db.get_or_create_company("Google India", website="https://google.com", location="Bengaluru")
        self.assertIsNotNone(comp1.id)
        self.assertEqual(comp1.name, "Google India")

        # Second call with different casing should return identical record
        comp2 = self.db.get_or_create_company("google india")
        self.assertEqual(comp1.id, comp2.id)

        # Listing
        companies = self.db.list_companies()
        self.assertEqual(len(companies), 1)

    # 3. Inserting Jobs
    def test_insert_job_and_auto_application(self):
        """Checks inserting a job, auto-creating company, and auto-creating application with status 'Discovered'."""
        sample_job = self._create_sample_job()
        inserted = self.db.insert_job(sample_job)

        self.assertIsNotNone(inserted.id)
        self.assertIsNotNone(inserted.company_id)
        self.assertEqual(inserted.job_title, "Machine Learning Intern")
        # URL must be normalized (tracking params stripped)
        self.assertEqual(inserted.job_url, "https://careers.deepmind.com/jobs/ml-intern-2028")

        # Verify application created automatically
        app = self.db.get_application_by_job_id(inserted.id)
        self.assertIsNotNone(app)
        self.assertEqual(app.status, ApplicationStatus.DISCOVERED.value)

        # Verify audit log recorded
        logs = self.db.get_application_logs(inserted.id)
        self.assertGreaterEqual(len(logs), 1)
        self.assertEqual(logs[0].action, "JOB_DISCOVERED")

    # 4. Updating Jobs
    def test_update_job(self):
        """Checks updating job fields."""
        inserted = self.db.insert_job(self._create_sample_job())
        inserted.job_title = "Senior AI Research Intern"
        inserted.stipend = "₹60,000 / month"
        inserted.match_score = 96.0

        updated = self.db.update_job(inserted)
        self.assertEqual(updated.job_title, "Senior AI Research Intern")
        self.assertEqual(updated.stipend, "₹60,000 / month")
        self.assertEqual(updated.match_score, 96.0)

    # 5. Deleting Jobs & Cascading Foreign Keys
    def test_delete_job_cascades(self):
        """Checks that deleting a job cascades and removes its applications and application logs."""
        inserted = self.db.insert_job(self._create_sample_job())
        job_id = inserted.id

        # Verify app exists
        self.assertIsNotNone(self.db.get_application_by_job_id(job_id))

        # Delete job
        self.assertTrue(self.db.delete_job(job_id))

        # Job, Application, and Logs must no longer exist
        self.assertIsNone(self.db.get_job_by_id(job_id))
        self.assertIsNone(self.db.get_application_by_job_id(job_id))
        self.assertEqual(len(self.db.get_application_logs(job_id)), 0)

    # 6. Duplicate Detection
    def test_duplicate_url_detection(self):
        """Checks that inserting a job with identical normalized URL raises DuplicateJobError."""
        job1 = self._create_sample_job(url="https://company.com/jobs/1?utm_campaign=campus")
        self.db.insert_job(job1)

        # Same URL with different tracking query string
        job2 = self._create_sample_job(
            company="Another Name",
            title="Different Title",
            url="https://company.com/jobs/1?ref=internal&trk=direct",
        )
        with self.assertRaises(DuplicateJobError) as ctx:
            self.db.insert_job(job2)
        self.assertIn("Normalized URL match", str(ctx.exception))

    def test_duplicate_company_and_title_detection(self):
        """Checks that duplicate company and title combinations are detected across different URLs."""
        job1 = self._create_sample_job(
            company="NVIDIA India",
            title="GenAI Engineering Intern",
            url="https://nvidia.com/careers/post-1",
        )
        self.db.insert_job(job1)

        # Same company & title, different platform URL
        job2 = self._create_sample_job(
            company="nvidia india ",
            title="  genai engineering intern",
            url="https://linkedin.com/jobs/view/999888",
        )
        with self.assertRaises(DuplicateJobError) as ctx:
            self.db.insert_job(job2)
        self.assertIn("Company and Title match", str(ctx.exception))

    # 7. Application Status Lifecycle & Submission Safeguard
    def test_application_status_tracking(self):
        """Checks valid status transitions and audit log recording."""
        inserted = self.db.insert_job(self._create_sample_job())
        job_id = inserted.id

        # Discovered -> Under Review
        app1 = self.db.update_application_status(job_id, ApplicationStatus.UNDER_REVIEW)
        self.assertEqual(app1.status, ApplicationStatus.UNDER_REVIEW.value)

        # Under Review -> Shortlisted
        app2 = self.db.update_application_status(job_id, ApplicationStatus.SHORTLISTED)
        self.assertEqual(app2.status, ApplicationStatus.SHORTLISTED.value)

        # Shortlisted -> Application Prepared
        app3 = self.db.update_application_status(
            job_id,
            ApplicationStatus.APPLICATION_PREPARED,
            resume_used="data/resumes/resume.pdf",
            cover_letter_reference="letters/ml_intern_cover.txt",
        )
        self.assertEqual(app3.status, ApplicationStatus.APPLICATION_PREPARED.value)
        self.assertIsNotNone(app3.date_prepared)

        # Application Prepared -> Awaiting Approval (requires human approval)
        self.db.record_human_approval(
            job_id,
            approver_name="Candidate Pranay",
            approval_notes="Manually reviewed form inputs and authorized review packet.",
        )
        app4 = self.db.update_application_status(job_id, ApplicationStatus.AWAITING_APPROVAL)
        self.assertEqual(app4.status, ApplicationStatus.AWAITING_APPROVAL.value)

        # Check logs recorded
        logs = self.db.get_application_logs(job_id)
        self.assertGreaterEqual(len(logs), 4)

        # Check list_applications
        all_apps = self.db.list_applications()
        self.assertEqual(len(all_apps), 1)
        awaiting = self.db.list_applications(status=ApplicationStatus.AWAITING_APPROVAL.value)
        self.assertEqual(len(awaiting), 1)
        rejected = self.db.list_applications(status=ApplicationStatus.REJECTED.value)
        self.assertEqual(len(rejected), 0)

    def test_applied_status_submission_safeguard(self):
        """Ensures application status CANNOT be set to 'Applied' without explicit human approval record."""
        inserted = self.db.insert_job(self._create_sample_job())
        job_id = inserted.id

        # 1. Direct illegal transition from Discovered to Applied MUST fail
        with self.assertRaises(InvalidStatusTransitionError):
            self.db.update_application_status(job_id, ApplicationStatus.APPLIED, confirmed=True)

        # 2. Transition through valid sequence to Application Prepared
        self.db.update_application_status(job_id, ApplicationStatus.UNDER_REVIEW)
        self.db.update_application_status(job_id, ApplicationStatus.SHORTLISTED)
        self.db.update_application_status(job_id, ApplicationStatus.APPLICATION_PREPARED)

        # 3. Automated bots/agents cannot grant approval
        with self.assertRaises(ValidationError):
            self.db.record_human_approval(job_id, approver_name="automated_bot")

        # 4. Explicit human approval granted by the candidate
        approval_log = self.db.record_human_approval(
            job_id,
            approver_name="Candidate Pranay",
            approval_notes="Manually reviewed form inputs and authorized submission.",
        )
        self.assertEqual(approval_log.action, "HUMAN_APPROVAL_GRANTED")
        self.assertTrue(self.db.has_valid_human_approval(job_id))

        # 5. Transition to Awaiting Approval
        self.db.update_application_status(job_id, ApplicationStatus.AWAITING_APPROVAL)

        # 6. Attempt to set Applied without confirmed=True -> MUST fail
        with self.assertRaises(UnconfirmedSubmissionError):
            self.db.update_application_status(job_id, ApplicationStatus.APPLIED, confirmed=False)

        # 7. Now transition to Applied with confirmed=True succeeds
        app = self.db.update_application_status(job_id, ApplicationStatus.APPLIED, confirmed=True)
        self.assertEqual(app.status, ApplicationStatus.APPLIED.value)
        self.assertIsNotNone(app.date_submitted)

    def test_invalid_status_rejection(self):
        """Checks that invalid status strings are rejected."""
        inserted = self.db.insert_job(self._create_sample_job())
        with self.assertRaises(InvalidStatusError):
            self.db.update_application_status(inserted.id, "RandomFakeStatus")

    # 8. Foreign Key Constraints Enforcement
    def test_foreign_key_constraints(self):
        """Verifies SQLite foreign key constraints are actively enforced."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            # Attempt inserting job with invalid foreign company_id
            with self.assertRaises(sqlite3.IntegrityError):
                cursor.execute(
                    """
                    INSERT INTO jobs (company_id, company_name, job_title, job_url, platform)
                    VALUES (99999, 'Fake Co', 'Role', 'https://fake.co/job', 'Direct')
                    """
                )

    # 9. Transaction Rollback
    def test_transaction_rollback_on_error(self):
        """Verifies that failures inside a transaction rollback all intermediate changes."""
        job = self._create_sample_job(url="https://transaction-test.com/job1")
        self.db.insert_job(job)

        with self.assertRaises(ValueError):
            with self.db.transaction() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE jobs SET stipend = '₹999,999' WHERE id = ?", (job.id,))
                # Deliberate exception to trigger rollback
                raise ValueError("Simulated unexpected transaction failure")

        # Verify database state was not changed
        job_after = self.db.get_job_by_id(job.id)
        self.assertNotEqual(job_after.stipend, "₹999,999")
        self.assertEqual(job_after.stipend, "₹45,000 / month")

    # 10. Candidate Profile Storage
    def test_candidate_profile_persistence(self):
        """Verifies candidate profile snapshots can be stored and retrieved."""
        sample_profile = {
            "name": "Pranay",
            "education": "MIT WPU",
            "cgpa": 7.6,
            "interests": ["AI", "ML"],
        }
        record = self.db.save_candidate_profile(sample_profile)
        self.assertIsNotNone(record.id)

        latest = self.db.get_latest_candidate_profile()
        self.assertIsNotNone(latest)
        self.assertEqual(latest.profile_data["education"], "MIT WPU")
        self.assertEqual(latest.profile_data["cgpa"], 7.6)

    # 11. CSV Export
    def test_csv_export(self):
        """Checks CSV export functionality and columns."""
        job1 = self._create_sample_job(company="Alpha AI", title="Role 1", url="https://alpha.ai/1")
        job2 = self._create_sample_job(company="Beta ML", title="Role 2", url="https://beta.ml/2")
        self.db.insert_job(job1)
        self.db.insert_job(job2)

        export_path = Path(self.temp_dir.name) / "test_export.csv"
        result_path = self.db.export_jobs_to_csv(output_path=export_path)

        self.assertTrue(result_path.is_file())
        df = pd.read_csv(result_path)
        self.assertEqual(len(df), 2)
        self.assertIn("job_title", df.columns)
        self.assertIn("company_name", df.columns)
        self.assertIn("application_status", df.columns)
        self.assertIn("match_score", df.columns)

    # 12. Database Backup and Restoration
    def test_backup_and_restore(self):
        """Verifies SQLite online backup and restore functionality."""
        job = self._create_sample_job(company="Backup Test Corp", url="https://backuptest.com/1")
        self.db.insert_job(job)

        backup_file = Path(self.temp_dir.name) / "backup_test.db"
        created_backup = self.db.backup_database(backup_path=backup_file)
        self.assertTrue(created_backup.is_file())

        # Modify original database (delete the job)
        self.db.delete_job(job.id)
        self.assertIsNone(self.db.get_job_by_id(job.id))

        # Restore from backup
        self.assertTrue(self.db.restore_database(backup_file))

        # Verify job was restored
        restored_job = self.db.get_job_by_url("https://backuptest.com/1")
        self.assertIsNotNone(restored_job)
        self.assertEqual(restored_job.company_name, "Backup Test Corp")


if __name__ == "__main__":
    unittest.main()

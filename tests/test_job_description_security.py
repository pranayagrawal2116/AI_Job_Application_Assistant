"""Security and Isolation Tests for Multi-User Job Descriptions.

Verifies cross-user isolation, sandbox containment, path traversal prevention,
and file upload size limits.
"""

from pathlib import Path
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    FileTooLargeError,
    ValidationError,
)
from src.security.auth import AuthManager
from src.security.file_security import FileSecurityValidator


class TestJobDescriptionSecurity(unittest.TestCase):
    """Test suite for job description security boundaries."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_security.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)

        self.user_a = self.auth.register(
            email="user_a@example.com",
            password="StrongPassword123!",
            full_name="User Alpha",
        )
        self.user_b = self.auth.register(
            email="user_b@example.com",
            password="StrongPassword123!",
            full_name="User Beta",
        )

        self.jd_a = self.db.save_job_description_snapshot(
            user_id=self.user_a.id,
            company_name="Alpha Corp",
            job_title="Security Engineer",
            raw_content="Alpha Corp job requirements and confidential details.",
            source_type="pasted",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cross_user_read_isolation(self):
        """User B cannot view or retrieve User A's job description."""
        # User A can access
        retrieved = self.db.get_job_description(self.jd_a.id, user_id=self.user_a.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, self.jd_a.id)

        # User B gets CrossUserAccessError
        with self.assertRaises(CrossUserAccessError):
            self.db.get_job_description(self.jd_a.id, user_id=self.user_b.id)

    def test_cross_user_update_isolation(self):
        """User B cannot create a revision or update User A's job description."""
        with self.assertRaises(CrossUserAccessError):
            self.db.update_job_description_snapshot(
                user_id=self.user_b.id,
                jd_id=self.jd_a.id,
                updated_parsed_data={"job_title": "Hijacked Title"},
            )

    def test_cross_user_delete_isolation(self):
        """User B cannot delete User A's job description."""
        with self.assertRaises(CrossUserAccessError):
            self.db.delete_job_description(self.jd_a.id, user_id=self.user_b.id)

        # Verify job description still exists for User A
        self.assertIsNotNone(self.db.get_job_description(self.jd_a.id, user_id=self.user_a.id))

    def test_user_list_isolation(self):
        """List job descriptions returns only records owned by the calling user."""
        self.db.save_job_description_snapshot(
            user_id=self.user_b.id,
            company_name="Beta Corp",
            job_title="Data Scientist",
            raw_content="Beta Corp description text for user B.",
            source_type="pasted",
        )

        list_a = self.db.list_job_descriptions(user_id=self.user_a.id)
        list_b = self.db.list_job_descriptions(user_id=self.user_b.id)

        self.assertEqual(len(list_a), 1)
        self.assertEqual(list_a[0].company_name, "Alpha Corp")

        self.assertEqual(len(list_b), 1)
        self.assertEqual(list_b[0].company_name, "Beta Corp")

    def test_file_sandbox_path_traversal_defense(self):
        """Path traversal characters in storage filenames are rejected."""
        validator = FileSecurityValidator()
        malicious_names = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "/absolute/path/file.pdf",
            "normal_file.pdf/../../escape.pdf",
        ]

        for bad_name in malicious_names:
            with self.assertRaises(ValidationError):
                validator.get_stored_job_description_path(user_id=self.user_a.id, storage_filename=bad_name)

    def test_upload_file_size_limit_enforced(self):
        """File uploads exceeding 10 MB are rejected."""
        oversized_bytes = b"%PDF-" + b"0" * (10 * 1024 * 1024 + 100)
        with self.assertRaises(FileTooLargeError):
            self.db.upload_user_job_description(
                user_id=self.user_a.id,
                file_bytes=oversized_bytes,
                original_filename="large_document.pdf",
            )


if __name__ == "__main__":
    unittest.main()

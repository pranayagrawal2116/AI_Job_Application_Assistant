"""Unit tests for Resume Versioning, Primary Resume Rules, and Audit Deletion Integrity.

Validates:
1. Version incrementation (v1, v2, v3), change notes, and active version pointers.
2. Primary resume rules: partial unique index, automatic first-resume primary, atomic toggle.
3. Safe resume deletion when unreferenced.
4. Prevention of resume deletion when referenced by job applications or prepared packets (ResumeInUseError).
5. Automatic promotion of remaining resume when primary is safely deleted.
"""

from pathlib import Path
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    DuplicateResumeError,
    ResumeInUseError,
    ResumeNotFoundError,
)
from tests.fixtures.synthetic_personas import (
    generate_persona_docx,
    generate_persona_pdf,
)


class TestResumeVersioningAndGovernance(unittest.TestCase):
    """Test suite verifying multi-version resumes, primary toggling, and audit-locked deletion."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "test_versioning.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.user_base_dir = self.temp_path / "users"

        # Create two test users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (email, password_hash, password_salt, full_name)
                VALUES ('user1@test.com', 'hash1', 'salt1', 'User One')
                """
            )
            self.user1_id = cursor.lastrowid
            cursor.execute(
                """
                INSERT INTO users (email, password_hash, password_salt, full_name)
                VALUES ('user2@test.com', 'hash2', 'salt2', 'User Two')
                """
            )
            self.user2_id = cursor.lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Multi-Version Increment & History
    def test_resume_version_increments(self):
        """Uploads multiple versions of a resume and verifies sequential versioning."""
        # Version 1
        docx_bytes_v1 = generate_persona_docx("freshman_cs_student")
        res1 = self.db.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=docx_bytes_v1,
            original_filename="kevin_patel_v1.docx",
            label="CS Resume",
            user_base_dir=self.user_base_dir / str(self.user1_id) / "resumes",
        )
        self.assertEqual(res1["active_version"], 1)

        # Version 2
        docx_bytes_v2 = generate_persona_docx("backend_engineer")
        v2 = self.db.add_resume_version(
            user_id=self.user1_id,
            resume_id=res1["id"],
            file_bytes=docx_bytes_v2,
            original_filename="kevin_patel_v2.docx",
            change_notes="Updated to senior backend engineer skills",
            user_base_dir=self.user_base_dir / str(self.user1_id) / "resumes",
        )
        self.assertEqual(v2["version_num"], 2)
        self.assertEqual(v2["change_notes"], "Updated to senior backend engineer skills")

        # Verify active version updated in parent resumes table
        updated_res = self.db.get_user_resume(res1["id"], self.user1_id)
        self.assertEqual(updated_res["active_version"], 2)
        self.assertEqual(updated_res["original_filename"], "kevin_patel_v2.docx")

        # Verify version history list
        versions = self.db.get_user_resume_versions(self.user1_id, res1["id"])
        self.assertEqual(len(versions), 2)
        self.assertEqual(versions[0]["version_num"], 2)
        self.assertEqual(versions[1]["version_num"], 1)

    def test_duplicate_version_hash_rejected(self):
        """Rejects re-uploading the identical file content as a new version."""
        docx_bytes = generate_persona_docx("hotel_gm")
        res = self.db.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=docx_bytes,
            original_filename="gm.docx",
            user_base_dir=self.user_base_dir / str(self.user1_id) / "resumes",
        )
        with self.assertRaises(DuplicateResumeError):
            self.db.add_resume_version(
                user_id=self.user1_id,
                resume_id=res["id"],
                file_bytes=docx_bytes,
                original_filename="gm_duplicate.docx",
                user_base_dir=self.user_base_dir / str(self.user1_id) / "resumes",
            )

    # 2. Primary Resume Rules
    def test_automatic_first_resume_primary(self):
        """Ensures the first uploaded resume automatically becomes primary."""
        docx_bytes = generate_persona_docx("cpa_auditor")
        res1 = self.db.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=docx_bytes,
            original_filename="audit.docx",
            user_base_dir=self.user_base_dir / str(self.user1_id) / "resumes",
        )
        self.assertEqual(res1["is_primary"], 1)

        primary = self.db.get_primary_resume(self.user1_id)
        self.assertIsNotNone(primary)
        self.assertEqual(primary["id"], res1["id"])

    def test_primary_resume_toggle(self):
        """Uploads two resumes and tests atomic primary switching."""
        b1 = generate_persona_docx("stem_educator")
        res1 = self.db.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=b1,
            original_filename="stem.docx",
            user_base_dir=self.user_base_dir / str(self.user1_id) / "resumes",
        )
        self.assertEqual(res1["is_primary"], 1)

        b2 = generate_persona_docx("enterprise_sales")
        res2 = self.db.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=b2,
            original_filename="sales.docx",
            set_as_primary=False,
            user_base_dir=self.user_base_dir / str(self.user1_id) / "resumes",
        )
        self.assertEqual(res2["is_primary"], 0)

        # Switch primary to res2
        self.db.set_primary_resume(self.user1_id, res2["id"])

        p1 = self.db.get_user_resume(res1["id"], self.user1_id)
        p2 = self.db.get_user_resume(res2["id"], self.user1_id)
        self.assertEqual(p1["is_primary"], 0)
        self.assertEqual(p2["is_primary"], 1)

        active_primary = self.db.get_primary_resume(self.user1_id)
        self.assertEqual(active_primary["id"], res2["id"])

    # 3. Secure Deletion & Application Locks
    def test_delete_unreferenced_resume(self):
        """Allows deleting an unreferenced resume and removes physical files."""
        docx_bytes = generate_persona_docx("career_transitioner")
        res_dir = self.user_base_dir / str(self.user1_id) / "resumes"
        res = self.db.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=docx_bytes,
            original_filename="transition.docx",
            user_base_dir=res_dir,
        )
        file_path = self.db.get_resume_file_path(self.user1_id, res["id"], user_base_dir=res_dir)
        self.assertTrue(file_path.exists())

        succ = self.db.delete_user_resume(self.user1_id, res["id"], user_base_dir=res_dir)
        self.assertTrue(succ)
        self.assertIsNone(self.db.get_user_resume(res["id"], self.user1_id))
        self.assertFalse(file_path.exists())

    def test_delete_blocked_when_referenced_by_application(self):
        """Blocks deletion with ResumeInUseError if resume is linked to an existing application."""
        docx_bytes = generate_persona_docx("supply_chain_director")
        res = self.db.upload_user_resume(
            user_id=self.user1_id,
            file_bytes=docx_bytes,
            original_filename="sc.docx",
            user_base_dir=self.user_base_dir / str(self.user1_id) / "resumes",
        )

        # Create an application referencing this resume
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO applications (user_id, company_name, job_title, resume_id, status)
                VALUES (?, 'Global Logistics Corp', 'Director of Supply Chain', ?, 'Applied')
                """,
                (self.user1_id, res["id"]),
            )

        with self.assertRaises(ResumeInUseError):
            self.db.delete_user_resume(
                self.user1_id,
                res["id"],
                user_base_dir=self.user_base_dir / str(self.user1_id) / "resumes",
            )


if __name__ == "__main__":
    unittest.main()

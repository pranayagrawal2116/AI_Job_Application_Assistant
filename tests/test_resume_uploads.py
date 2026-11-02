"""Unit tests for Multi-User Resume Uploads, Isolation, and Duplicate Detection.

Validates:
1. Multi-user isolation: User A cannot read, modify, or download User B's resumes (CrossUserAccessError).
2. Per-user duplicate prevention: Re-uploading an identical file raises DuplicateResumeError.
3. Cross-user identical uploads: Two distinct users can upload identical template files without collision.
4. Download path retrieval and user directory containment.
5. Full upload lifecycle across PDF and DOCX document formats.
"""

from pathlib import Path
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    DuplicateResumeError,
)
from dashboard.services.dashboard_service import DashboardService
from tests.fixtures.synthetic_personas import (
    generate_persona_docx,
    generate_persona_pdf,
)


class TestResumeUploadsAndIsolation(unittest.TestCase):
    """Test suite verifying multi-user resume uploads, duplicate checks, and isolation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "test_uploads.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.user_base_dir = self.temp_path / "users"

        # Create two separate users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (email, password_hash, password_salt, full_name)
                VALUES ('userA@company.com', 'hashA', 'saltA', 'Alice Smith')
                """
            )
            self.userA_id = cursor.lastrowid

            cursor.execute(
                """
                INSERT INTO users (email, password_hash, password_salt, full_name)
                VALUES ('userB@company.com', 'hashB', 'saltB', 'Bob Jones')
                """
            )
            self.userB_id = cursor.lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Multi-User Isolation & Access Control
    def test_cross_user_isolation(self):
        """Ensures User B cannot read or access User A's resume."""
        docx_bytes = generate_persona_docx("backend_engineer")
        resA = self.db.upload_user_resume(
            user_id=self.userA_id,
            file_bytes=docx_bytes,
            original_filename="alice_backend.docx",
            label="Backend Lead",
            user_base_dir=self.user_base_dir / str(self.userA_id) / "resumes",
        )

        # Alice can fetch her resume
        self.assertIsNotNone(self.db.get_user_resume(resA["id"], self.userA_id))

        # Bob attempting to fetch Alice's resume raises CrossUserAccessError
        with self.assertRaises(CrossUserAccessError):
            self.db.get_user_resume(resA["id"], self.userB_id)

        # Bob's resume list does not include Alice's resume
        bob_resumes = self.db.list_user_resumes(self.userB_id)
        self.assertEqual(len(bob_resumes), 0)

        # Bob attempting to get file path for Alice's resume raises CrossUserAccessError
        with self.assertRaises(CrossUserAccessError):
            self.db.get_resume_file_path(
                user_id=self.userB_id,
                resume_id=resA["id"],
                user_base_dir=self.user_base_dir / str(self.userB_id) / "resumes",
            )

    # 2. Per-User Duplicate Prevention
    def test_duplicate_upload_prevention_same_user(self):
        """Prevents a user from uploading the exact same resume file twice."""
        docx_bytes = generate_persona_docx("attorney")
        self.db.upload_user_resume(
            user_id=self.userA_id,
            file_bytes=docx_bytes,
            original_filename="m_vance.docx",
            user_base_dir=self.user_base_dir / str(self.userA_id) / "resumes",
        )

        # Attempting identical upload for Alice raises DuplicateResumeError
        with self.assertRaises(DuplicateResumeError):
            self.db.upload_user_resume(
                user_id=self.userA_id,
                file_bytes=docx_bytes,
                original_filename="m_vance_copy.docx",
                user_base_dir=self.user_base_dir / str(self.userA_id) / "resumes",
            )

    def test_duplicate_allowed_across_different_users(self):
        """Allows two distinct users to upload identical files without conflict."""
        docx_bytes = generate_persona_docx("stem_educator")

        resA = self.db.upload_user_resume(
            user_id=self.userA_id,
            file_bytes=docx_bytes,
            original_filename="template.docx",
            user_base_dir=self.user_base_dir / str(self.userA_id) / "resumes",
        )
        resB = self.db.upload_user_resume(
            user_id=self.userB_id,
            file_bytes=docx_bytes,
            original_filename="template.docx",
            user_base_dir=self.user_base_dir / str(self.userB_id) / "resumes",
        )

        self.assertNotEqual(resA["id"], resB["id"])
        self.assertEqual(resA["user_id"], self.userA_id)
        self.assertEqual(resB["user_id"], self.userB_id)

    # 3. Download Path Retrieval & User Sandbox Containment
    def test_download_path_containment(self):
        """Ensures get_resume_file_path returns path strictly contained in user's directory."""
        pdf_bytes = generate_persona_pdf("cardiologist")
        user_dir = self.user_base_dir / str(self.userA_id) / "resumes"
        res = self.db.upload_user_resume(
            user_id=self.userA_id,
            file_bytes=pdf_bytes,
            original_filename="sarah.pdf",
            user_base_dir=user_dir,
        )

        path = self.db.get_resume_file_path(self.userA_id, res["id"], user_base_dir=user_dir)
        self.assertTrue(path.exists())
        self.assertTrue(path.resolve().is_relative_to(user_dir.resolve()))

    # 4. Upload Lifecycle (PDF and DOCX)
    def test_upload_lifecycle_pdf_and_docx(self):
        """Verifies full lifecycle of uploading both PDF and DOCX documents with metadata."""
        # PDF upload
        pdf_bytes = generate_persona_pdf("cfa_investment_banker")
        u_dir = self.user_base_dir / str(self.userA_id) / "resumes"
        res_pdf = self.db.upload_user_resume(
            user_id=self.userA_id,
            file_bytes=pdf_bytes,
            original_filename="priya.pdf",
            label="Investment Banking",
            target_role="VP Investment Banking",
            user_base_dir=u_dir,
        )
        self.assertEqual(res_pdf["file_format"], "pdf")
        self.assertEqual(res_pdf["label"], "Investment Banking")
        self.assertEqual(res_pdf["target_role"], "VP Investment Banking")
        self.assertEqual(res_pdf["parsing_status"], "COMPLETED")
        self.assertIsNotNone(res_pdf["parsed_data"])

        # DOCX upload
        docx_bytes = generate_persona_docx("creative_director")
        res_docx = self.db.upload_user_resume(
            user_id=self.userA_id,
            file_bytes=docx_bytes,
            original_filename="elena.docx",
            label="Creative Portfolio",
            target_role="Design Director",
            set_as_primary=False,
            user_base_dir=u_dir,
        )
        self.assertEqual(res_docx["file_format"], "docx")
        self.assertEqual(res_docx["label"], "Creative Portfolio")
        self.assertEqual(res_docx["is_primary"], 0)

        # Check total user resumes
        resumes = self.db.list_user_resumes(self.userA_id)
        self.assertEqual(len(resumes), 2)

    # 5. Comprehensive Bidirectional Isolation Regression Tests
    def test_bidirectional_multi_user_isolation(self):
        """Proves Candidate A and B cannot list, access, download, toggle primary, or delete each other's resumes."""
        pdf_a = generate_persona_pdf("cardiologist")
        u_dir_a = self.user_base_dir / str(self.userA_id) / "resumes"
        res_a = self.db.upload_user_resume(
            user_id=self.userA_id,
            file_bytes=pdf_a,
            original_filename="alice_resume.pdf",
            user_base_dir=u_dir_a,
        )

        docx_b = generate_persona_docx("mechanical_engineer")
        u_dir_b = self.user_base_dir / str(self.userB_id) / "resumes"
        res_b = self.db.upload_user_resume(
            user_id=self.userB_id,
            file_bytes=docx_b,
            original_filename="bob_resume.docx",
            user_base_dir=u_dir_b,
        )

        # 1. Listing Isolation: User A only sees A; User B only sees B
        list_a = self.db.list_user_resumes(self.userA_id)
        list_b = self.db.list_user_resumes(self.userB_id)
        self.assertTrue(all(r["user_id"] == self.userA_id for r in list_a))
        self.assertTrue(all(r["user_id"] == self.userB_id for r in list_b))
        self.assertNotIn(res_b["id"], [r["id"] for r in list_a])
        self.assertNotIn(res_a["id"], [r["id"] for r in list_b])

        # 2. Cross-user Path Resolution / Download: raises CrossUserAccessError
        with self.assertRaises(CrossUserAccessError):
            self.db.get_resume_file_path(self.userA_id, res_b["id"], user_base_dir=u_dir_a)
        with self.assertRaises(CrossUserAccessError):
            self.db.get_resume_file_path(self.userB_id, res_a["id"], user_base_dir=u_dir_b)

        # 3. Cross-user Primary Toggle: raises CrossUserAccessError
        with self.assertRaises(CrossUserAccessError):
            self.db.set_primary_resume(self.userA_id, res_b["id"])
        with self.assertRaises(CrossUserAccessError):
            self.db.set_primary_resume(self.userB_id, res_a["id"])

        # 4. Cross-user Version Creation: raises CrossUserAccessError
        new_pdf = generate_persona_pdf("biotech_scientist")
        with self.assertRaises(CrossUserAccessError):
            self.db.add_resume_version(
                user_id=self.userA_id,
                resume_id=res_b["id"],
                file_bytes=new_pdf,
                original_filename="malicious_v2.pdf",
                user_base_dir=u_dir_a,
            )
        with self.assertRaises(CrossUserAccessError):
            self.db.add_resume_version(
                user_id=self.userB_id,
                resume_id=res_a["id"],
                file_bytes=new_pdf,
                original_filename="malicious_v2.pdf",
                user_base_dir=u_dir_b,
            )

        # 5. Cross-user Deletion: raises CrossUserAccessError
        with self.assertRaises(CrossUserAccessError):
            self.db.delete_user_resume(self.userA_id, res_b["id"])
        with self.assertRaises(CrossUserAccessError):
            self.db.delete_user_resume(self.userB_id, res_a["id"])

        # Confirm neither record was modified or deleted
        self.assertIsNotNone(self.db.get_user_resume(res_a["id"], self.userA_id))
        self.assertIsNotNone(self.db.get_user_resume(res_b["id"], self.userB_id))

    # 6. DashboardService Multi-User Access Safeguards
    def test_dashboard_service_multi_user_isolation(self):
        """Verifies DashboardService enforces multi-user boundaries across service methods."""
        service = DashboardService(db_manager=self.db)

        pdf_a = generate_persona_pdf("cfa_investment_banker")
        u_dir_a = self.temp_path / "data" / "users" / str(self.userA_id) / "resumes"
        res_a = self.db.upload_user_resume(
            user_id=self.userA_id,
            file_bytes=pdf_a,
            original_filename="alice_banking.pdf",
            user_base_dir=u_dir_a,
        )

        docx_b = generate_persona_docx("supply_chain_director")
        u_dir_b = self.temp_path / "data" / "users" / str(self.userB_id) / "resumes"
        res_b = self.db.upload_user_resume(
            user_id=self.userB_id,
            file_bytes=docx_b,
            original_filename="bob_supply.docx",
            user_base_dir=u_dir_b,
        )

        # Service-level primary toggle rejection
        succ_a_set_b, msg_a_set_b = service.set_primary_resume(self.userA_id, res_b["id"])
        self.assertFalse(succ_a_set_b)
        self.assertIn("Cross-user security violation", msg_a_set_b)

        succ_b_set_a, msg_b_set_a = service.set_primary_resume(self.userB_id, res_a["id"])
        self.assertFalse(succ_b_set_a)
        self.assertIn("Cross-user security violation", msg_b_set_a)

        # Service-level delete rejection
        succ_a_del_b, msg_a_del_b = service.delete_user_resume(self.userA_id, res_b["id"])
        self.assertFalse(succ_a_del_b)
        self.assertIn("Cross-user security violation", msg_a_del_b)

        succ_b_del_a, msg_b_del_a = service.delete_user_resume(self.userB_id, res_a["id"])
        self.assertFalse(succ_b_del_a)
        self.assertIn("Cross-user security violation", msg_b_del_a)

        # Service-level download data rejection
        data_a_on_b, name_a_on_b, _ = service.get_resume_download_data(self.userA_id, res_b["id"])
        self.assertIsNone(data_a_on_b)
        self.assertIsNone(name_a_on_b)

        data_b_on_a, name_b_on_a, _ = service.get_resume_download_data(self.userB_id, res_a["id"])
        self.assertIsNone(data_b_on_a)
        self.assertIsNone(name_b_on_a)

    # 7. Directory Containment & Legacy Path Isolation
    def test_legacy_path_containment_and_isolation(self):
        """Verifies directory traversal prevention and isolated storage path resolution."""
        from src.security.file_security import FileSecurityValidator
        from src.database.exceptions import FileSecurityError

        pdf_a = generate_persona_pdf("cpa_auditor")
        u_dir_a = self.user_base_dir / str(self.userA_id) / "resumes"
        res_a = self.db.upload_user_resume(
            user_id=self.userA_id,
            file_bytes=pdf_a,
            original_filename="alice_cpa.pdf",
            user_base_dir=u_dir_a,
        )

        # Legitimate path resolution is contained
        legit_path = self.db.get_resume_file_path(self.userA_id, res_a["id"], user_base_dir=u_dir_a)
        self.assertTrue(legit_path.exists())
        self.assertTrue(legit_path.resolve().is_relative_to(u_dir_a.resolve()))

        # Direct containment check: path traversal in filename or path escapes directory
        with self.assertRaises(FileSecurityError):
            traversal_path = u_dir_a / ".." / "secret.txt"
            FileSecurityValidator.validate_path_containment(traversal_path, u_dir_a)

        # Service-level available resumes returns strictly user A files
        service = DashboardService(db_manager=self.db)
        a_resumes = service.get_available_resumes(user_id=self.userA_id, user_base_dir=u_dir_a)
        self.assertEqual(len(a_resumes), 1)
        self.assertEqual(a_resumes[0].name, legit_path.name)

        b_resumes = service.get_available_resumes(user_id=self.userB_id, user_base_dir=self.user_base_dir / str(self.userB_id) / "resumes")
        self.assertEqual(len(b_resumes), 0)


if __name__ == "__main__":
    unittest.main()

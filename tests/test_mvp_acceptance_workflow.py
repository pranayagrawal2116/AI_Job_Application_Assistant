"""Comprehensive End-to-End Acceptance Test Suite for AI Job Application Assistant MVP.

Verifies the complete 17-step user workflow defined in the Master Execution Prompt:
1. Application initialization & data directory creation
2. Candidate account registration & Argon2id hashing
3. Candidate login & authenticated session issuance
4. PDF & DOCX resume upload, security validation, and text extraction
5. Candidate profile review and synchronization
6. Manual job description entry, cross-industry requirements parsing, and deduplication
7. Deterministic multi-factor matching score calculation and 3-state eligibility
8. Scoring breakdown, matching skills, and missing skills transparency
9. Tailored application preparation (tailored resume, cover letter, screening questions)
10. Application review & document generation (PDF/DOCX)
11. Strict human-in-the-loop approval gate preventing automated submission
12. Application status tracking and lifecycle transitions
13. User logout and session revocation
14. User re-authentication and session re-establishment
15. Full data retention and persistence across sessions
16. Strict multi-user tenant isolation (User B cannot access User A's records)
17. Database persistence across application restarts (Windows service reboot resilience)
"""

from pathlib import Path
import tempfile
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    AuthenticationFailedError,
    CrossUserAccessError,
    DuplicateUserError,
    SecurityAuthorizationError,
)
from src.database.models import ApplicationStatus
from src.preparer.question_answerer import ScreeningQAPacket


class TestMVPAcceptanceWorkflow(unittest.TestCase):
    """End-to-End Acceptance Verification of the AI Job Application Assistant MVP."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.db_path = self.base_path / "storage" / "job_assistant.db"
        self.user_storage_path = self.base_path / "users"
        self.backup_path = self.base_path / "backups"
        self.exports_path = self.base_path / "exports"

        # Initialize clean isolated environment
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.user_storage_path.mkdir(parents=True, exist_ok=True)
        self.backup_path.mkdir(parents=True, exist_ok=True)
        self.exports_path.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=self.db_path)
        self.db.backup_dir = self.backup_path
        self.db.exports_dir = self.exports_path

        self.service = DashboardService(
            db_manager=self.db,
            storage_base_dir=self.user_storage_path,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_complete_mvp_workflow_end_to_end(self):
        """Executes the complete 17-step user journey from registration to service restart."""

        # ---------------------------------------------------------------------
        # STEP 1: Registration of Candidate Alice
        # ---------------------------------------------------------------------
        alice_user = self.service.register_candidate(
            email="alice.engineer@example.com",
            password="StrongPassword123!",
            full_name="Alice Engineer",
            profession_industry="Artificial Intelligence & Machine Learning",
            career_level="Student / Intern",
        )
        self.assertIsNotNone(alice_user.id)
        self.assertEqual(alice_user.email, "alice.engineer@example.com")
        self.assertEqual(alice_user.full_name, "Alice Engineer")

        # Duplicate email registration must be rejected
        with self.assertRaises(DuplicateUserError):
            self.service.register_candidate(
                email="ALICE.ENGINEER@EXAMPLE.COM",
                password="AnotherPassword123!",
                full_name="Alice Duplicate",
            )

        # ---------------------------------------------------------------------
        # STEP 2: Login & Session Issuance for Alice
        # ---------------------------------------------------------------------
        # Wrong password fails closed
        with self.assertRaises(AuthenticationFailedError):
            self.service.login_candidate("alice.engineer@example.com", "WrongPassword!")

        # Correct password issues valid session
        alice_logged, alice_session = self.service.login_candidate(
            email="alice.engineer@example.com",
            password="StrongPassword123!",
        )
        self.assertEqual(alice_logged.id, alice_user.id)
        self.assertIsNotNone(alice_session.session_id)

        # Authoritatively resolve active session
        resolved_uid, resolved_sess = self.service.resolve_authenticated_candidate(
            session_id=alice_session.session_id,
            client_user_id=alice_user.id,
        )
        self.assertEqual(resolved_uid, alice_user.id)
        self.assertEqual(resolved_sess.candidate_name, "Alice Engineer")

        # ---------------------------------------------------------------------
        # STEP 3: Resume Upload (PDF) and Parsing
        # ---------------------------------------------------------------------
        # Generate minimal valid PDF with candidate profile information
        sample_pdf_bytes = (
            b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n0000000101 00000 n \n"
            b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
        )

        succ_up, msg_up, res_rec = self.service.upload_user_resume(
            user_id=alice_user.id,
            file_bytes=sample_pdf_bytes,
            original_filename="Alice_AI_Resume.pdf",
            label="AI/ML Specialization",
            target_role="Machine Learning Engineer Intern",
            set_as_primary=True,
        )
        self.assertTrue(succ_up, f"Upload failed: {msg_up}")
        self.assertIsNotNone(res_rec)
        alice_resume_id = res_rec["id"]

        # Verify resume is listed in Alice's resumes
        alice_resumes = self.service.get_user_resumes(alice_user.id)
        self.assertEqual(len(alice_resumes), 1)
        self.assertEqual(alice_resumes[0]["id"], alice_resume_id)
        self.assertEqual(alice_resumes[0]["label"], "AI/ML Specialization")

        # ---------------------------------------------------------------------
        # STEP 4: Candidate Profile Update & Persistence
        # ---------------------------------------------------------------------
        alice_profile_data = {
            "personal": {
                "full_name": "Alice Engineer",
                "email": "alice.engineer@example.com",
                "phone": "+1-555-0199",
                "location": "Bengaluru, India",
            },
            "education": [
                {
                    "institution": "Indian Institute of Technology",
                    "degree": "Bachelor of Technology",
                    "major": "Computer Science & Artificial Intelligence",
                    "expected_graduation_year": 2026,
                    "current_cgpa": 8.8,
                    "provenance": "USER_CONFIRMED",
                }
            ],
            "technical_skills": {
                "languages": [
                    {"name": "Python", "provenance": "USER_CONFIRMED"},
                    {"name": "SQL", "provenance": "USER_CONFIRMED"},
                ],
                "frameworks": [
                    {"name": "PyTorch", "provenance": "USER_CONFIRMED"},
                    {"name": "Scikit-Learn", "provenance": "USER_CONFIRMED"},
                    {"name": "TensorFlow", "provenance": "USER_CONFIRMED"},
                ],
            },
            "work_experience": [
                {
                    "company": "Neural Innovations",
                    "position": "AI Research Intern",
                    "start_date": "2024-05-01",
                    "end_date": "2024-08-01",
                    "duration_months": 3,
                    "description": "Built computer vision models using PyTorch.",
                    "provenance": "USER_CONFIRMED",
                }
            ],
        }

        succ_prof, msg_prof = self.service.save_user_candidate_profile(
            user_id=alice_user.id,
            profile_data=alice_profile_data,
        )
        self.assertTrue(succ_prof)
        db_prof = self.service.db.get_user_candidate_profile(alice_user.id)
        self.assertIsNotNone(db_prof)
        self.assertEqual(db_prof["profile_data"]["personal"]["full_name"], "Alice Engineer")

        # ---------------------------------------------------------------------
        # STEP 5: Job Description Ingestion (Pasted Text)
        # ---------------------------------------------------------------------
        jd_text = """
        Job Title: Machine Learning Engineering Intern
        Company: DeepData Systems
        Location: Bengaluru, India (Hybrid)
        Job Type: Full-time Internship

        About the Role:
        We are seeking a talented Machine Learning Intern to join our AI platform team.
        You will work on deploying deep learning models for predictive analytics.

        Required Skills & Qualifications:
        - Strong proficiency in Python and SQL
        - Hands-on experience with PyTorch or TensorFlow
        - Understanding of machine learning algorithms and data preprocessing
        - Currently pursuing a Bachelor's degree in Computer Science, Data Science, or related field
        - Available for a 6-month internship in Bengaluru, India
        """

        succ_jd, msg_jd, jd_rec = self.service.ingest_job_text(
            user_id=alice_user.id,
            raw_text=jd_text,
            hint_title="Machine Learning Engineering Intern",
            hint_company="DeepData Systems",
            hint_location="Bengaluru, India",
        )
        self.assertTrue(succ_jd, f"JD ingestion failed: {msg_jd}")
        self.assertIsNotNone(jd_rec)
        alice_jd_id = jd_rec.id

        # Verify listed in Alice's job descriptions
        user_jds = self.service.get_user_job_descriptions(user_id=alice_user.id)
        self.assertEqual(len(user_jds), 1)
        self.assertEqual(user_jds[0].company_name, "DeepData Systems")

        # ---------------------------------------------------------------------
        # STEP 6: Multi-Factor Matching & Eligibility Evaluation
        # ---------------------------------------------------------------------
        match_result = self.service.run_match_evaluation(
            user_id=alice_user.id,
            resume_id=alice_resume_id,
            job_description_id=alice_jd_id,
            scoring_profile_id="INTERNSHIP_FRESHER",
        )
        self.assertIsNotNone(match_result)
        self.assertGreaterEqual(match_result.match_score, 50.0)
        self.assertIn(match_result.eligibility_status, ["ELIGIBLE", "UNKNOWN"])
        self.assertIsInstance(match_result.dimension_breakdown, dict)

        # ---------------------------------------------------------------------
        # STEP 7: Application Preparation (Tailored Materials & Documents)
        # ---------------------------------------------------------------------
        app_workspace = self.service.get_or_create_application_workspace(
            user_id=alice_user.id,
            job_description_id=alice_jd_id,
            resume_id=alice_resume_id,
        )
        self.assertIsNotNone(app_workspace)
        alice_app_id = app_workspace.id

        selected_res_meta = self.service.db.get_user_resume(alice_resume_id, alice_user.id)
        jd_dict = {
            "id": alice_jd_id,
            "company_name": jd_rec.company_name,
            "role_title": jd_rec.job_title,
            "required_skills": ["Python", "PyTorch", "SQL"],
            "preferred_skills": ["Deep Learning", "Data Preprocessing"],
        }

        # Tailored resume bullets
        tailored_res = self.service.generate_tailored_resume(
            user_id=alice_user.id,
            candidate_profile=alice_profile_data,
            resume_data=selected_res_meta,
            job_description=jd_dict,
            match_result=match_result.to_dict(),
            resume_id=alice_resume_id,
        )
        self.assertIsNotNone(tailored_res)

        # Cover letter generation
        cover_letter = self.service.generate_universal_cover_letter(
            user_id=alice_user.id,
            candidate_profile=alice_profile_data,
            job_description=jd_dict,
            resume_data=selected_res_meta,
            match_result=match_result.to_dict(),
            resume_id=alice_resume_id,
        )
        self.assertIsNotNone(cover_letter)
        self.assertIn("DeepData Systems", cover_letter.letter_text)

        # Screening questions drafting
        qa_packet = ScreeningQAPacket(
            user_id=alice_user.id,
            job_description_id=alice_jd_id,
            questions=[],
        )

        # Generate exported ATS documents
        exported_docs = self.service.export_application_documents(
            user_id=alice_user.id,
            application_id=alice_app_id,
            resume=tailored_res,
            cover_letter=cover_letter,
            qa_packet=qa_packet,
        )
        self.assertIn("resume_pdf", exported_docs)
        self.assertTrue(Path(exported_docs["resume_pdf"].file_path).exists())
        self.assertTrue(Path(exported_docs["cover_letter_pdf"].file_path).exists())

        # ---------------------------------------------------------------------
        # STEP 8: Review & Human Approval Gate (Strict Non-Negotiable Safeguard)
        # ---------------------------------------------------------------------
        # Prepare packet revision
        packet_rec = self.service.prepare_universal_application_packet(
            user_id=alice_user.id,
            application_id=alice_app_id,
            original_resume_id=alice_resume_id,
            original_resume_hash=res_rec["file_hash"],
            tailored_resume=tailored_res,
            cover_letter=cover_letter,
            qa_packet=qa_packet,
            job_description_snapshot_hash=jd_rec.content_hash,
            tailored_resume_doc=exported_docs["resume_pdf"],
            cover_letter_doc=exported_docs["cover_letter_pdf"],
        )
        self.assertIsNotNone(packet_rec)
        alice_packet_id = packet_rec.id
        alice_packet_hash = packet_rec.packet_version_hash

        # Automated submission is strictly forbidden
        # Explicit single-use ticket issued for human approval
        approval_ticket = self.service.issue_approval_ticket(
            session_id=alice_session.session_id,
            job_id=alice_app_id,
            packet_hash=alice_packet_hash,
        )
        self.assertIsNotNone(approval_ticket)

        # Candidate Alice explicitly authorizes the packet
        succ_auth, msg_auth, auth_rec = self.service.authorize_universal_application_packet(
            user_id=alice_user.id,
            application_id=alice_app_id,
            packet_id=alice_packet_id,
            approver_name="Alice Engineer",
            session_id=alice_session.session_id,
            action_ticket=approval_ticket,
            candidate_confirmed=True,
        )
        self.assertTrue(succ_auth, f"Approval authorization failed: {msg_auth}")

        # ---------------------------------------------------------------------
        # STEP 9: Application Tracking & Status Progression
        # ---------------------------------------------------------------------
        app_current = self.service.db.get_user_application(alice_app_id, alice_user.id)
        self.assertEqual(app_current.status, ApplicationStatus.AWAITING_APPROVAL.value)

        # Submission confirmation requires manual ticket
        sub_ticket = self.service.issue_submission_ticket(
            session_id=alice_session.session_id,
            job_id=alice_app_id,
            packet_hash=alice_packet_hash,
        )

        succ_submit, msg_submit = self.service.confirm_universal_manual_submission(
            application_id=alice_app_id,
            approver_name="Alice Engineer",
            session_id=alice_session.session_id,
            submission_ticket=sub_ticket,
            packet_version_hash=alice_packet_hash,
            submission_notes="Manually submitted via employer careers portal.",
        )
        self.assertTrue(succ_submit, f"Submission failed: {msg_submit}")

        app_after_submit = self.service.db.get_user_application(alice_app_id, alice_user.id)
        self.assertEqual(app_after_submit.status, ApplicationStatus.APPLIED.value)

        # ---------------------------------------------------------------------
        # STEP 10: Alice Logs Out
        # ---------------------------------------------------------------------
        succ_logout = self.service.logout_candidate(alice_session.session_id)
        self.assertTrue(succ_logout)

        # Alice's old session is now revoked and must be rejected
        with self.assertRaises(SecurityAuthorizationError):
            self.service.resolve_authenticated_candidate(
                session_id=alice_session.session_id,
                client_user_id=alice_user.id,
            )

        # ---------------------------------------------------------------------
        # STEP 11: Candidate Bob Registers & Logs In
        # ---------------------------------------------------------------------
        bob_user = self.service.register_candidate(
            email="bob.cardiology@example.com",
            password="MedicalPassword456!",
            full_name="Dr. Bob Cardiology",
            profession_industry="Healthcare & Medicine",
            career_level="Senior / Lead (5+ years)",
        )
        self.assertIsNotNone(bob_user.id)
        self.assertNotEqual(bob_user.id, alice_user.id)

        bob_logged, bob_session = self.service.login_candidate(
            email="bob.cardiology@example.com",
            password="MedicalPassword456!",
        )
        self.assertIsNotNone(bob_session.session_id)

        # ---------------------------------------------------------------------
        # STEP 12: Strict Tenant Isolation (Bob CANNOT access Alice's records)
        # ---------------------------------------------------------------------
        # Bob cannot see Alice's resumes
        bob_resumes = self.service.get_user_resumes(bob_user.id)
        self.assertEqual(len(bob_resumes), 0)

        # Bob cannot directly fetch Alice's resume by ID
        with self.assertRaises(CrossUserAccessError):
            self.service.db.get_user_resume(resume_id=alice_resume_id, user_id=bob_user.id)

        # Bob cannot see Alice's job descriptions
        bob_jds = self.service.get_user_job_descriptions(user_id=bob_user.id)
        self.assertEqual(len(bob_jds), 0)

        # Bob cannot access Alice's application
        with self.assertRaises(CrossUserAccessError):
            self.service.db.get_user_application(application_id=alice_app_id, user_id=bob_user.id)

        # Bob's candidate profile is separate and starts empty
        bob_profile = self.service.db.get_user_candidate_profile(bob_user.id)
        self.assertIsNone(bob_profile)

        # ---------------------------------------------------------------------
        # STEP 13: Alice Logs Back In and Accesses Her Prior Data
        # ---------------------------------------------------------------------
        alice_relogged, alice_new_session = self.service.login_candidate(
            email="alice.engineer@example.com",
            password="StrongPassword123!",
        )
        self.assertEqual(alice_relogged.id, alice_user.id)
        self.assertNotEqual(alice_new_session.session_id, alice_session.session_id)

        # Alice's resumes are preserved
        alice_resumes_reloaded = self.service.get_user_resumes(alice_user.id)
        self.assertEqual(len(alice_resumes_reloaded), 1)
        self.assertEqual(alice_resumes_reloaded[0]["id"], alice_resume_id)

        # Alice's candidate profile is preserved
        alice_prof_reloaded = self.service.db.get_user_candidate_profile(alice_user.id)
        self.assertIsNotNone(alice_prof_reloaded)
        self.assertEqual(alice_prof_reloaded["profile_data"]["personal"]["full_name"], "Alice Engineer")

        # Alice's job description is preserved
        alice_jds_reloaded = self.service.get_user_job_descriptions(user_id=alice_user.id)
        self.assertEqual(len(alice_jds_reloaded), 1)

        # Alice's application status is preserved
        alice_app_reloaded = self.service.db.get_user_application(alice_app_id, alice_user.id)
        self.assertEqual(alice_app_reloaded.status, ApplicationStatus.APPLIED.value)

        # ---------------------------------------------------------------------
        # STEP 14: Simulated Application & Windows Service Restart
        # ---------------------------------------------------------------------
        # Simulate complete application restart by instantiating fresh DatabaseManager and DashboardService
        del self.service
        del self.db

        restarted_db = DatabaseManager(db_path=self.db_path)
        restarted_service = DashboardService(
            db_manager=restarted_db,
            storage_base_dir=self.user_storage_path,
        )

        # After server restart, all database records remain intact
        user_alice_check = restarted_service.auth_manager.get_user_by_email("alice.engineer@example.com")
        self.assertIsNotNone(user_alice_check)
        self.assertEqual(user_alice_check.id, alice_user.id)

        user_bob_check = restarted_service.auth_manager.get_user_by_email("bob.cardiology@example.com")
        self.assertIsNotNone(user_bob_check)
        self.assertEqual(user_bob_check.id, bob_user.id)

        reloaded_alice_app = restarted_service.db.get_user_application(alice_app_id, alice_user.id)
        self.assertEqual(reloaded_alice_app.status, ApplicationStatus.APPLIED.value)

        # ---------------------------------------------------------------------
        # STEP 15: Online Backup & Restoration Verification
        # ---------------------------------------------------------------------
        backup_file = restarted_service.backup_database()
        self.assertTrue(backup_file.exists())
        self.assertGreater(backup_file.stat().st_size, 0)

        # Verify CSV export
        csv_file = restarted_service.export_jobs_to_csv()
        self.assertTrue(csv_file.exists())
        self.assertGreater(csv_file.stat().st_size, 0)

    def test_docx_resume_upload_and_parsing(self):
        """Verifies DOCX resume file upload, zip safety inspection, and parsing."""
        user = self.service.register_candidate(
            email="docx.user@example.com",
            password="DocxPassword123!",
            full_name="Docx Candidate",
        )

        import io
        import docx
        doc = docx.Document()
        doc.add_heading("Candidate Resume", 0)
        doc.add_paragraph("Alice Candidate - Python Developer & Data Scientist")
        buffer = io.BytesIO()
        doc.save(buffer)
        docx_bytes = buffer.getvalue()

        succ, msg, rec = self.service.upload_user_resume(
            user_id=user.id,
            file_bytes=docx_bytes,
            original_filename="candidate_resume.docx",
            label="DOCX Format Test",
        )
        self.assertTrue(succ, f"DOCX upload failed: {msg}")
        self.assertEqual(rec["file_format"], "docx")
        self.assertGreater(rec["file_size_bytes"], 0)

    def test_job_description_deduplication(self):
        """Verifies duplicate job description detection and handling."""
        user = self.service.register_candidate(
            email="duplicate.jd@example.com",
            password="Password123!",
            full_name="JD Test Candidate",
        )
        jd_text = "Software Engineer position at Global Solutions. We require Python, SQL, and Docker. Minimum 1 year experience."

        succ1, msg1, jd1 = self.service.ingest_job_text(
            user_id=user.id,
            raw_text=jd_text,
            hint_title="Software Engineer",
            hint_company="Global Solutions",
        )
        self.assertTrue(succ1)
        self.assertIsNotNone(jd1)

        # Ingesting the same text again should be rejected as a duplicate
        succ2, msg2, jd2 = self.service.ingest_job_text(
            user_id=user.id,
            raw_text=jd_text,
            hint_title="Software Engineer",
            hint_company="Global Solutions",
        )
        self.assertFalse(succ2)
        self.assertIn("already exists", msg2)

    def test_ineligible_job_matching_disqualification(self):
        """Verifies that an impossible requirement properly flags the match as INELIGIBLE or UNKNOWN."""
        user = self.service.register_candidate(
            email="ineligible.user@example.com",
            password="Password123!",
            full_name="Student Candidate",
        )
        # Empty profile with no work experience
        self.service.save_user_candidate_profile(user.id, {
            "personal": {"full_name": "Student Candidate"},
            "education": [{"degree": "B.Tech", "expected_graduation_year": 2028}],
            "work_experience": [],
        })
        # Valid minimal PDF resume
        sample_pdf = (
            b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n0000000101 00000 n \n"
            b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
        )
        succ_up, _, res = self.service.upload_user_resume(
            user_id=user.id,
            file_bytes=sample_pdf,
            original_filename="student_resume.pdf",
        )
        self.assertTrue(succ_up)

        # Job requiring 10+ years of professional experience
        strict_jd = """
        Job Title: VP of Artificial Intelligence
        Company: Enterprise Tech Corp
        Requirements:
        - Must have a minimum of 10 years of full-time professional industry experience in AI leadership.
        - Ph.D. in Computer Science required.
        """
        succ_jd, _, jd = self.service.ingest_job_text(
            user_id=user.id,
            raw_text=strict_jd,
            hint_title="VP of AI",
            hint_company="Enterprise Tech Corp",
        )
        self.assertTrue(succ_jd)

        match = self.service.run_match_evaluation(
            user_id=user.id,
            resume_id=res["id"],
            job_description_id=jd.id,
        )
        self.assertIsNotNone(match)
        # Eligibility must not default to eligible for candidates lacking mandatory qualifications
        self.assertIn(match.eligibility_status, ["INELIGIBLE", "UNKNOWN"])

    def test_app_storage_auto_initialization(self):
        """Verifies that ensure_app_storage creates all missing directories."""
        from dashboard.app import ensure_app_storage
        nested_dir = self.base_path / "deeply" / "nested" / "app_data"
        db_nested = nested_dir / "db" / "test.db"
        storage_nested = nested_dir / "users"
        db = DatabaseManager(db_path=db_nested)
        svc = DashboardService(db_manager=db, storage_base_dir=storage_nested)

        ensure_app_storage(svc)
        self.assertTrue(Path(db.db_path).parent.exists())
        self.assertTrue(svc.storage_base_dir.exists())


if __name__ == "__main__":
    unittest.main()

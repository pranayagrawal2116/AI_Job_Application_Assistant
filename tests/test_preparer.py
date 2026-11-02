"""Unit tests for Phase 7 Application Preparation Engine:
Resume parsing (PDF & DOCX), Profile Updating, Job Alignment, Cover Letter Drafting,
Question Answering, Form Pre-filling, and Strict Human Approval Gate.
"""

from pathlib import Path
import tempfile
import unittest

from docx import Document

from src.database.db_manager import DatabaseManager
from src.database.models import ApplicationStatus, Job
from src.preparer.approval_gate import HumanApprovalGate
from src.preparer.cover_letter_generator import CoverLetterGenerator
from src.preparer.form_prefiller import FormPrefiller
from src.preparer.profile_updater import ProfileUpdater
from src.preparer.question_answerer import QuestionAnswerer
from src.preparer.resume_matcher import ResumeJobMatcher
from src.preparer.resume_parser import ResumeParser


class TestApplicationPreparationEngine(unittest.TestCase):
    """Test suite for Phase 7 Application Preparation deliverables."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_prep.db"
        cls.db = DatabaseManager(db_path=cls.db_path)
        cls.profile_path = Path(cls.temp_dir.name) / "test_candidate_profile.json"

        # Check for sample PDF resume
        cls.sample_pdf = Path("data/resumes/Pranay_Agrawal_Resume(2).pdf").resolve()
        if not cls.sample_pdf.exists():
            cls.sample_pdf = Path("data/resumes/Pranay_Agrawal_Resume.pdf").resolve()

        # Create a synthetic DOCX resume for testing DOCX parsing
        cls.docx_path = Path(cls.temp_dir.name) / "test_candidate_resume.docx"
        doc = Document()
        doc.add_heading("PRANAY ANUP AGRAWAL", 0)
        doc.add_paragraph("☎ 95100 29575 | ✉ pranayagrawal2116@gmail.com | Kothrud, Pune, Maharashtra")
        doc.add_heading("EDUCATION", level=1)
        doc.add_paragraph("MIT World Peace University\nB.Tech – Computer Science & Engineering\nArtificial Intelligence & Data Science\nExpected Graduation: 2028 | CGPA: 7.6")
        doc.add_heading("TECHNICAL SKILLS", level=1)
        doc.add_paragraph("Python, JavaScript, C/C++, Flutter & Dart, Android application development, REST API integration, SQLite & MySQL, Git & GitHub")
        doc.add_heading("WORK EXPERIENCE", level=1)
        doc.add_paragraph("Sarita Infotech Pvt. Ltd. | 3 months\nProject Manager | Mobile App Development\nDeveloped and managed a mobile application, coordinating implementation and feature delivery.")
        doc.add_heading("SELECTED PROJECTS", level=1)
        doc.add_paragraph("Medical Chatbot\nBuilt a Python-based medical chatbot project focused on conversational access to health-related information.")
        doc.add_paragraph("Sarita ABDM – Milestone 2 Integration\nWorked on healthcare interoperability workflows involving ABDM consent management.")
        doc.add_heading("CORE STRENGTHS", level=1)
        doc.add_paragraph("Project coordination, Problem solving, Analytical thinking, Team collaboration")
        doc.save(str(cls.docx_path))

        # Register sample test job once
        cls.test_job = cls.db.add_job(
            Job(
                company_name="NeuralEdge Dynamics",
                job_title="AI Research Intern",
                job_url="https://neuraledge.ai/careers/intern-1",
                platform="LinkedIn",
                location="Pune / Remote",
                required_skills=["Python", "Machine Learning", "NLP", "REST APIs", "PyTorch"],
                job_description="Looking for an AI Research Intern to build NLP pipelines, chatbots, and evaluate machine learning models with Python.",
                match_score=94.0,
                match_classification="Excellent",
                is_eligible=True,
            )
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        self.parser = ResumeParser()
        self.updater = ProfileUpdater(db_manager=self.db, profile_path=self.profile_path)
        self.profile = self.updater.sync_from_resume(self.sample_pdf)
        self.matcher = ResumeJobMatcher(candidate_profile=self.profile)
        self.letter_gen = CoverLetterGenerator(
            candidate_profile=self.profile,
            output_dir=Path(self.temp_dir.name) / "cover_letters",
        )
        self.answerer = QuestionAnswerer(candidate_profile=self.profile)
        self.prefiller = FormPrefiller(candidate_profile=self.profile)
        self.gate = HumanApprovalGate(db_manager=self.db)

    # 1. PDF Resume Parsing Tests
    def test_pdf_resume_parsing(self):
        if not self.sample_pdf.exists():
            self.skipTest("Sample PDF not found.")
        parsed = self.parser.parse_file(self.sample_pdf)
        self.assertIn("Pranay", parsed.full_name)
        self.assertEqual(parsed.email, "pranayagrawal2116@gmail.com")
        self.assertEqual(parsed.phone, "95100 29575")
        self.assertIn("Pune", parsed.location)

        # Education
        self.assertTrue(len(parsed.education) >= 1)
        edu = parsed.education[0]
        self.assertIn("MIT World Peace University", edu.institution)
        self.assertEqual(edu.expected_graduation_year, 2028)
        self.assertEqual(edu.cgpa, 7.6)

        # Experience
        self.assertTrue(len(parsed.work_experience) >= 1)
        exp = parsed.work_experience[0]
        self.assertEqual(exp.employer, "Sarita Infotech Pvt. Ltd.")
        self.assertEqual(exp.job_title, "Project Manager | Mobile App Development")
        self.assertIn("3 months", exp.duration)

        # Skills & Projects
        self.assertIn("Python", parsed.technical_skills)
        self.assertIn("JavaScript", parsed.technical_skills)
        self.assertIn("C/C++", parsed.technical_skills)
        self.assertTrue(any("Medical Chatbot" in p.title for p in parsed.projects))
        self.assertTrue(any("Sarita ABDM" in p.title for p in parsed.projects))

    # 2. DOCX Resume Parsing Tests
    def test_docx_resume_parsing(self):
        parsed = self.parser.parse_file(self.docx_path)
        self.assertIn("Pranay", parsed.full_name)
        self.assertEqual(parsed.file_format, "DOCX")
        self.assertEqual(parsed.email, "pranayagrawal2116@gmail.com")
        self.assertEqual(parsed.education[0].cgpa, 7.6)
        self.assertEqual(parsed.work_experience[0].employer, "Sarita Infotech Pvt. Ltd.")
        self.assertIn("Python", parsed.technical_skills)
        self.assertTrue(any("Medical Chatbot" in p.title for p in parsed.projects))

    # 3. Missing Fields & Non-Existent File Handling
    def test_missing_fields_and_errors(self):
        with self.assertRaises(FileNotFoundError):
            self.parser.parse_file("non_existent_file.pdf")

        with self.assertRaises(ValueError):
            # Create dummy unsupported file
            bad_file = Path(self.temp_dir.name) / "test.xyz"
            bad_file.write_text("dummy")
            self.parser.parse_file(bad_file)

    # 4. Profile Updater & Immutable Snapshot
    def test_profile_updater_persistence(self):
        self.assertTrue(self.profile_path.exists())
        self.assertEqual(self.profile["personal"]["full_name"], "Pranay Anup Agrawal")
        self.assertEqual(self.profile["work_experience"][0]["employer"], "Sarita Infotech Pvt. Ltd.")
        self.assertEqual(self.profile["work_experience"][0]["duration_months"], 3)
        self.assertIn("Python", self.profile["technical_skills"]["programming_languages"])

        # Check SQLite candidate_profile snapshot
        snapshot = self.db.get_latest_candidate_profile()
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.profile_data["personal"]["email"], "pranayagrawal2116@gmail.com")

    # 5. Resume-Job Matching & Alignment
    def test_resume_job_alignment(self):
        alignment = self.matcher.align_job(self.test_job)
        self.assertEqual(alignment.company_name, "NeuralEdge Dynamics")
        self.assertIn("Python", alignment.matching_skills)
        self.assertTrue(any("rest api" in s.lower() for s in alignment.matching_skills))
        self.assertIn("PyTorch", alignment.missing_requirements)
        self.assertTrue(any("Medical Chatbot" in p["title"] for p in alignment.relevant_projects))
        self.assertTrue(len(alignment.relevant_experience) >= 1)
        self.assertIn("Candidate is a", alignment.alignment_summary)

    # 6. Cover Letter Generator
    def test_cover_letter_generator(self):
        result = self.letter_gen.generate_cover_letter(self.test_job)
        self.assertIn("letter_text", result)
        self.assertIn("file_path", result)
        self.assertTrue(Path(result["file_path"]).exists())

        letter = result["letter_text"]
        self.assertIn("NeuralEdge Dynamics", letter)
        self.assertIn("AI Research Intern", letter)
        self.assertIn("MIT World Peace University", letter)
        self.assertIn("Medical Chatbot", letter)
        self.assertIn("Sarita Infotech Pvt. Ltd.", letter)
        self.assertIn("Pranay Anup Agrawal", letter)

    # 7. Screening Question Answer Generator
    def test_question_answerer(self):
        answers = self.answerer.generate_standard_answers(self.test_job)
        self.assertEqual(len(answers), 7)
        self.assertIn("tell_about_yourself", answers)
        self.assertIn("MIT World Peace University", answers["tell_about_yourself"]["answer"])
        self.assertIn("Sarita Infotech Pvt. Ltd.", answers["describe_relevant_experience"]["answer"])
        self.assertIn("Medical Chatbot", answers["explain_project"]["answer"])
        self.assertIn("Python, Dart, JavaScript, and C/C++", answers["technical_skills"]["answer"])
        self.assertEqual(answers["availability"]["status"], "READY")

        # Test custom question requiring candidate input
        custom_salary = self.answerer.answer_custom_question("What is your expected monthly salary?")
        self.assertEqual(custom_salary["status"], "NEEDS_CANDIDATE_INPUT")
        self.assertIn("NEEDS CANDIDATE INPUT", custom_salary["answer"])

    # 8. Form Pre-filler & Safety Safeguards
    def test_form_prefiller(self):
        plan = self.prefiller.build_form_payload(
            job=self.test_job,
            cover_letter_text="Sample cover letter",
            resume_file_path=str(self.sample_pdf),
        )
        self.assertTrue(len(plan.fields_to_fill) > 5)
        field_names = [f.field_name for f in plan.fields_to_fill]
        self.assertIn("Full Name", field_names)
        self.assertIn("Email Address", field_names)
        self.assertIn("Resume File Attachment", field_names)
        self.assertTrue(plan.resume_attachment_ready)

        # Verify anti-automation detector
        self.assertTrue(self.prefiller.detect_anti_automation("Please complete this Cloudflare Turnstile challenge"))
        self.assertFalse(self.prefiller.detect_anti_automation("Welcome to the job application portal"))

    # 9. Strict Human Approval Gate
    def test_human_approval_gate(self):
        answers = self.answerer.generate_standard_answers(self.test_job)
        packet = self.gate.build_review_packet(
            job=self.test_job,
            cover_letter_text="Sample Letter",
            resume_path=str(self.sample_pdf),
            resume_hash="abc123hash",
            answers=answers,
        )

        # 1. Unconfirmed candidate checkbox -> must fail
        succ_no_check, msg1 = self.gate.authorize_application(packet, "Pranay Agrawal", candidate_confirmed=False)
        self.assertFalse(succ_no_check)
        self.assertIn("explicitly check", msg1)

        # 2. Empty approver name -> must fail
        succ_empty, msg2 = self.gate.authorize_application(packet, "  ", candidate_confirmed=True)
        self.assertFalse(succ_empty)
        self.assertIn("Human approver name is mandatory", msg2)

        # 3. Automated bot name -> must fail
        succ_bot, msg3 = self.gate.authorize_application(packet, "automated_agent_bot", candidate_confirmed=True)
        self.assertFalse(succ_bot)
        self.assertIn("automated authorization", msg3)

        # 4. Valid human authorization -> must succeed
        succ_ok, msg4 = self.gate.authorize_application(packet, "Pranay Agrawal", candidate_confirmed=True)
        self.assertTrue(succ_ok)
        self.assertTrue(packet.is_approved)
        self.assertEqual(packet.approver_name, "Pranay Agrawal")

        # Verify application status transitioned in DB
        app = self.db.get_application_by_job_id(self.test_job.id)
        self.assertEqual(app.status, ApplicationStatus.AWAITING_APPROVAL.value)

        # 5. Confirm manual submission
        succ_sub, msg5 = self.gate.record_manual_submission(self.test_job.id, approver_name="Pranay Agrawal")
        self.assertTrue(succ_sub)
        app_sub = self.db.get_application_by_job_id(self.test_job.id)
        self.assertEqual(app_sub.status, ApplicationStatus.APPLIED.value)


if __name__ == "__main__":
    unittest.main()

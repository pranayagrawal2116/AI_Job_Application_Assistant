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
from src.security.session_manager import SessionManager


class TestApplicationPreparationEngine(unittest.TestCase):
    """Test suite for Phase 7 Application Preparation deliverables."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_prep.db"
        cls.db = DatabaseManager(db_path=cls.db_path)
        cls.profile_path = Path(cls.temp_dir.name) / "test_candidate_profile.json"

        # Check for sample PDF resume; synthesize if absent (e.g. clean CI environment)
        cls.sample_pdf = Path("data/resumes/Pranay_Agrawal_Resume(2).pdf").resolve()
        if not cls.sample_pdf.exists():
            cls.sample_pdf = Path("data/resumes/Pranay_Agrawal_Resume.pdf").resolve()
        if not cls.sample_pdf.exists():
            cls.sample_pdf = Path(cls.temp_dir.name) / "Pranay_Agrawal_Resume.pdf"
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter
            c = canvas.Canvas(str(cls.sample_pdf), pagesize=letter)
            y = 750
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, y, "PRANAY ANUP AGRAWAL")
            y -= 20
            c.setFont("Helvetica", 10)
            c.drawString(50, y, "95100 29575 | pranayagrawal2116@gmail.com | Kothrud, Pune, Maharashtra")
            y -= 25
            c.setFont("Helvetica-Bold", 12)
            c.drawString(50, y, "EDUCATION")
            y -= 15
            c.setFont("Helvetica", 10)
            c.drawString(50, y, "MIT World Peace University")
            c.drawString(50, y - 15, "B.Tech - Computer Science & Engineering (Artificial Intelligence & Data Science)")
            c.drawString(50, y - 30, "Expected Graduation: 2028 | CGPA: 7.6")
            y -= 55
            c.setFont("Helvetica-Bold", 12)
            c.drawString(50, y, "TECHNICAL SKILLS")
            y -= 15
            c.setFont("Helvetica", 10)
            c.drawString(50, y, "Python, JavaScript, C/C++, Flutter & Dart, Android application development, REST API integration, SQLite & MySQL, Git & GitHub")
            y -= 25
            c.setFont("Helvetica-Bold", 12)
            c.drawString(50, y, "WORK EXPERIENCE")
            y -= 15
            c.setFont("Helvetica", 10)
            c.drawString(50, y, "Sarita Infotech Pvt. Ltd. | 3 months")
            c.drawString(50, y - 15, "Project Manager | Mobile App Development")
            y -= 40
            c.setFont("Helvetica-Bold", 12)
            c.drawString(50, y, "SELECTED PROJECTS")
            y -= 15
            c.setFont("Helvetica", 10)
            c.drawString(50, y, "Medical Chatbot")
            c.drawString(50, y - 15, "Sarita ABDM - Milestone 2 Integration")
            c.save()

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
        with cls.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('prep_tester@test.com', 'h', 's', 'Prep Tester')"
            )
            cls.user_id = cursor.lastrowid

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
            ),
            user_id=cls.user_id,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        self.parser = ResumeParser()
        self.updater = ProfileUpdater(db_manager=self.db, profile_path=self.profile_path)
        resume_to_sync = self.sample_pdf if self.sample_pdf.exists() else self.docx_path
        self.profile = self.updater.sync_from_resume(resume_to_sync)
        self.matcher = ResumeJobMatcher(candidate_profile=self.profile)
        self.letter_gen = CoverLetterGenerator(
            candidate_profile=self.profile,
            output_dir=Path(self.temp_dir.name) / "cover_letters",
        )
        self.answerer = QuestionAnswerer(candidate_profile=self.profile)
        self.prefiller = FormPrefiller(candidate_profile=self.profile)
        SessionManager.reset_instance()
        self.session_mgr = SessionManager()
        self.db._session_manager = self.session_mgr
        self.session = self.session_mgr.authenticate_candidate(
            candidate_id="candidate_pranay",
            candidate_name="Pranay Agrawal",
        )
        self.gate = HumanApprovalGate(db_manager=self.db, session_manager=self.session_mgr)

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

        # Zero-fabrication verifications
        self.assertEqual(parsed.github_url, "")
        self.assertEqual(parsed.linkedin_url, "")
        medical_bot = next(p for p in parsed.projects if "Medical Chatbot" in p.title)
        self.assertEqual(medical_bot.technologies, ["Python"])
        self.assertNotIn("NLP", medical_bot.technologies)
        self.assertNotIn("Machine Learning", medical_bot.technologies)
        self.assertNotIn("Pandas", parsed.technical_skills)
        self.assertNotIn("NumPy", parsed.technical_skills)
        self.assertNotIn("Scikit-learn", parsed.technical_skills)

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
        
        # Unpopulated candidate inputs mark availability as NEEDS_CANDIDATE_INPUT
        self.assertEqual(answers["availability"]["status"], "NEEDS_CANDIDATE_INPUT")
        self.assertIn("NEEDS CANDIDATE INPUT", answers["availability"]["answer"])

        # When candidate inputs are populated, availability transitions to READY
        profile_with_inputs = dict(self.profile)
        profile_with_inputs["candidate_inputs"] = {
            "internship_availability": "Immediate",
            "weekly_working_hours": "40 hours / week (Full-time)",
        }
        answerer_with_inputs = QuestionAnswerer(candidate_profile=profile_with_inputs)
        answers_ready = answerer_with_inputs.generate_standard_answers(self.test_job)
        self.assertEqual(answers_ready["availability"]["status"], "READY")
        self.assertIn("Immediate", answers_ready["availability"]["answer"])
        self.assertIn("40 hours / week", answers_ready["availability"]["answer"])

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

        # Transition job to Application Prepared first
        app = self.db.get_application_by_job_id(self.test_job.id)
        if app.status == ApplicationStatus.DISCOVERED.value:
            self.db.update_application_status(self.test_job.id, ApplicationStatus.UNDER_REVIEW)
            self.db.update_application_status(self.test_job.id, ApplicationStatus.SHORTLISTED)
            self.db.update_application_status(self.test_job.id, ApplicationStatus.APPLICATION_PREPARED)

        action_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="HUMAN_APPROVAL",
            application_id=self.test_job.id,
            packet_hash=packet.packet_version_hash,
        )

        # 1. Unconfirmed candidate checkbox -> must fail
        succ_no_check, msg1 = self.gate.authorize_application(
            packet, "Pranay Agrawal", candidate_confirmed=False, session_id=self.session.session_id, action_ticket=action_ticket
        )
        self.assertFalse(succ_no_check)
        self.assertIn("explicitly check", msg1)

        # 2. Empty approver name -> must fail
        succ_empty, msg2 = self.gate.authorize_application(
            packet, "  ", candidate_confirmed=True, session_id=self.session.session_id, action_ticket=action_ticket
        )
        self.assertFalse(succ_empty)
        self.assertIn("Human approver name is mandatory", msg2)

        # 3. Automated bot name -> must fail
        succ_bot, msg3 = self.gate.authorize_application(
            packet, "automated_agent_bot", candidate_confirmed=True, session_id=self.session.session_id, action_ticket=action_ticket
        )
        self.assertFalse(succ_bot)
        self.assertIn("automated authorization", msg3)

        # 4. Typed candidate name alone without ticket/session -> must fail
        succ_name_only, msg_tok = self.gate.authorize_application(
            packet, "Pranay Agrawal", candidate_confirmed=True, session_id="", action_ticket=""
        )
        self.assertFalse(succ_name_only)
        self.assertIn("Missing or invalid", msg_tok)

        # 5. Invalid/forged action_ticket -> must fail
        succ_bad_tok, msg_bad = self.gate.authorize_application(
            packet, "Pranay Agrawal", candidate_confirmed=True, session_id=self.session.session_id, action_ticket="TKT-badnonce.123.badsig"
        )
        self.assertFalse(succ_bad_tok)
        self.assertIn("Unrecognized or unissued", msg_bad)

        # 6. Valid human authorization with authenticated session and ticket -> must succeed
        succ_ok, msg4 = self.gate.authorize_application(
            packet, "Pranay Agrawal", candidate_confirmed=True, session_id=self.session.session_id, action_ticket=action_ticket
        )
        self.assertTrue(succ_ok)
        self.assertTrue(packet.is_approved)
        self.assertEqual(packet.approver_name, "Pranay Agrawal")

        # Verify application status transitioned in DB
        app = self.db.get_application_by_job_id(self.test_job.id)
        self.assertEqual(app.status, ApplicationStatus.AWAITING_APPROVAL.value)

        # Issue submission ticket
        sub_ticket = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=self.test_job.id,
            packet_hash=packet.packet_version_hash,
        )

        # 7. Confirm manual submission without submission ticket -> must fail
        succ_no_sub_tok, msg_sub_fail = self.gate.record_manual_submission(
            self.test_job.id, approver_name="Pranay Agrawal", session_id=self.session.session_id, submission_ticket="", packet_version_hash=packet.packet_version_hash
        )
        self.assertFalse(succ_no_sub_tok)
        self.assertIn("Missing action ticket", msg_sub_fail)

        # 8. Confirm manual submission on unapproved job -> must fail
        sub_ticket_fake = self.session_mgr.issue_action_ticket(
            session_id=self.session.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=99999,
            packet_hash=packet.packet_version_hash,
        )
        succ_unapproved, msg_unapp = self.gate.record_manual_submission(
            99999, approver_name="Pranay Agrawal", session_id=self.session.session_id, submission_ticket=sub_ticket_fake, packet_version_hash=packet.packet_version_hash
        )
        self.assertFalse(succ_unapproved)
        self.assertIn("does not have an active, unconsumed human approval record", msg_unapp)

        # 9. Valid manual submission confirmation with submission ticket -> must succeed
        succ_sub, msg5 = self.gate.record_manual_submission(
            self.test_job.id, approver_name="Pranay Agrawal", session_id=self.session.session_id, submission_ticket=sub_ticket, packet_version_hash=packet.packet_version_hash
        )
        self.assertTrue(succ_sub)
        app_sub = self.db.get_application_by_job_id(self.test_job.id)
        self.assertEqual(app_sub.status, ApplicationStatus.APPLIED.value)

    # 10. Candidate Input Requirements Verification
    def test_candidate_input_requirements(self):
        # Empty candidate inputs profile
        empty_profile = dict(self.profile)
        empty_profile["candidate_inputs"] = {}
        qa_empty = QuestionAnswerer(candidate_profile=empty_profile)

        unanswered_queries = [
            "What is your expected stipend?",
            "How many hours per week can you dedicate?",
            "What is your preferred internship duration?",
            "When can you join?",
            "Are you willing to relocate?",
            "What is your preferred work mode?",
            "What is your notice period?",
        ]
        for query in unanswered_queries:
            resp = qa_empty.answer_custom_question(query)
            self.assertEqual(resp["status"], "NEEDS_CANDIDATE_INPUT")
            self.assertIn("NEEDS CANDIDATE INPUT", resp["answer"])

        # Populated candidate inputs profile
        populated_profile = dict(self.profile)
        populated_profile["candidate_inputs"] = {
            "expected_stipend": "₹20,000 / month",
            "weekly_working_hours": "30-40 hours / week",
            "internship_duration_preference": "6 months",
            "joining_date": "Within 2 weeks",
            "relocation_willingness": "Yes, Pune or Bengaluru",
            "work_mode_preference": "Remote preferred, open to Hybrid",
            "notice_period": "Immediate",
        }
        qa_populated = QuestionAnswerer(candidate_profile=populated_profile)

        stipend_resp = qa_populated.answer_custom_question("What is your expected stipend?")
        self.assertEqual(stipend_resp["status"], "READY")
        self.assertIn("₹20,000 / month", stipend_resp["answer"])

        hours_resp = qa_populated.answer_custom_question("How many hours per week can you dedicate?")
        self.assertEqual(hours_resp["status"], "READY")
        self.assertIn("30-40 hours / week", hours_resp["answer"])

        duration_resp = qa_populated.answer_custom_question("What is your preferred internship duration?")
        self.assertEqual(duration_resp["status"], "READY")
        self.assertIn("6 months", duration_resp["answer"])

        joining_resp = qa_populated.answer_custom_question("When can you join?")
        self.assertEqual(joining_resp["status"], "READY")
        self.assertIn("Within 2 weeks", joining_resp["answer"])

        reloc_resp = qa_populated.answer_custom_question("Are you willing to relocate?")
        self.assertEqual(reloc_resp["status"], "READY")
        self.assertIn("Yes, Pune or Bengaluru", reloc_resp["answer"])

        mode_resp = qa_populated.answer_custom_question("What is your preferred work mode?")
        self.assertEqual(mode_resp["status"], "READY")
        self.assertIn("Remote preferred, open to Hybrid", mode_resp["answer"])

        notice_resp = qa_populated.answer_custom_question("What is your notice period?")
        self.assertEqual(notice_resp["status"], "READY")
        self.assertIn("Immediate", notice_resp["answer"])

    # 11. Zero-Fabrication Cover Letter Validation
    def test_zero_fabrication_cover_letter(self):
        # Generate with empty candidate profile URLs
        gen = CoverLetterGenerator(candidate_profile=self.profile)
        res = gen.generate_cover_letter(self.test_job)
        letter = res["letter_text"]

        # Must not contain placeholder dummy URLs
        self.assertNotIn("https://github.com |", letter)
        self.assertNotIn("https://linkedin.com", letter)
        self.assertNotIn("GitHub: https://github.com", letter)

        # Must not fabricate NLP/ML on Medical Chatbot
        self.assertNotIn("natural language processing", letter.lower())
        self.assertNotIn("machine learning models", letter.lower())

        # Must avoid generic flattery
        self.assertNotIn("represents exactly the dynamic environment", letter)

        # Must contain factual resume content
        self.assertIn("Medical Chatbot", letter)
        self.assertIn("conversational access to health-related information", letter)
        self.assertIn("Sarita Infotech Pvt. Ltd.", letter)
        self.assertIn("Project Manager | Mobile App Development", letter)


if __name__ == "__main__":
    unittest.main()

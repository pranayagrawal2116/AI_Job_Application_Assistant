"""Unit tests for Universal Document Generation & Export Engine (Architecture v2.1.1 - Phase 6).
Verifies PDF and DOCX generation across all templates and structural validation.
"""

from pathlib import Path
import tempfile
import unittest

from src.preparer.cover_letter_generator import (
    CoverLetter,
    CoverLetterGenerator,
    LetterTone,
)
from src.preparer.document_generator import (
    DocumentTemplate,
    UniversalDocumentGenerator,
)
from src.preparer.question_answerer import (
    QuestionAnswerer,
    ScreeningQAPacket,
)
from src.preparer.tailored_resume_generator import (
    UniversalTailoredResumeGenerator,
)


class TestUniversalDocumentGeneration(unittest.TestCase):
    """Test suite for Universal Document Generator."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)
        self.generator = UniversalDocumentGenerator()

        # Build candidate resume
        resume_gen = UniversalTailoredResumeGenerator()
        profile = {
            "personal": {
                "full_name": "Alexander Sterling",
                "email": "alex.sterling@example.com",
                "phone": "+1 415-555-0182",
                "location": "San Francisco, CA",
                "headline": "Lead Systems Architect",
            },
            "education": [{"institution": "Stanford University", "degree": "MS Computer Science", "graduation_year": 2018}],
            "work_experience": [
                {
                    "employer": "CloudScale Systems",
                    "job_title": "Principal Architect",
                    "duration": "5 years",
                    "responsibilities": [
                        "Architected distributed event streaming engine processing 2M events/sec.",
                        "Mentored team of 12 senior engineers across multi-region deployments.",
                    ],
                }
            ],
            "skills": ["Distributed Systems", "Go", "Kubernetes", "AWS", "Kafka"],
            "certifications": [{"name": "AWS Certified Solutions Architect - Professional"}],
        }
        jd = {
            "company_name": "Apex Cloud Tech",
            "role_title": "Staff Infrastructure Engineer",
            "required_skills": ["Distributed Systems", "Kubernetes", "Go"],
        }
        self.tailored_resume = resume_gen.generate(user_id=42, candidate_profile=profile, job_description=jd)

        # Build cover letter
        cl_gen = CoverLetterGenerator()
        self.cover_letter: CoverLetter = cl_gen.generate_universal_cover_letter(
            user_id=42,
            candidate_profile=profile,
            job_description=jd,
            tone=LetterTone.EXECUTIVE_FORMAL,
        )

        # Build QA packet
        qa_assistant = QuestionAnswerer()
        questions = [
            "What is your experience with Kubernetes?",
            "What is your target compensation?",
        ]
        answered_qs = qa_assistant.batch_answer_questions(
            questions=questions,
            user_id=42,
            candidate_profile=profile,
        )
        self.qa_packet = ScreeningQAPacket(user_id=42, job_description_id=1, questions=answered_qs)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_resume_pdf_and_docx_generation(self):
        """Verifies both PDF and DOCX tailored resumes are generated and valid."""
        pdf_doc = self.generator.generate_resume_pdf(self.tailored_resume, self.output_dir, DocumentTemplate.MODERN)
        self.assertEqual(pdf_doc.document_type, "resume")
        self.assertEqual(pdf_doc.file_format, "pdf")
        self.assertTrue(Path(pdf_doc.file_path).exists())
        self.assertTrue(pdf_doc.file_size_bytes > 500)
        self.assertTrue(len(pdf_doc.file_hash) == 64)

        docx_doc = self.generator.generate_resume_docx(self.tailored_resume, self.output_dir, DocumentTemplate.MODERN)
        self.assertEqual(docx_doc.document_type, "resume")
        self.assertEqual(docx_doc.file_format, "docx")
        self.assertTrue(Path(docx_doc.file_path).exists())
        self.assertTrue(docx_doc.file_size_bytes > 500)

    def test_cover_letter_pdf_and_docx_generation(self):
        """Verifies both PDF and DOCX cover letters are generated and valid."""
        pdf_cl = self.generator.generate_cover_letter_pdf(self.cover_letter, self.output_dir, DocumentTemplate.EXECUTIVE)
        self.assertEqual(pdf_cl.document_type, "cover_letter")
        self.assertEqual(pdf_cl.file_format, "pdf")
        self.assertTrue(Path(pdf_cl.file_path).exists())

        docx_cl = self.generator.generate_cover_letter_docx(self.cover_letter, self.output_dir, DocumentTemplate.EXECUTIVE)
        self.assertEqual(docx_cl.document_type, "cover_letter")
        self.assertEqual(docx_cl.file_format, "docx")
        self.assertTrue(Path(docx_cl.file_path).exists())

    def test_screening_qa_pdf_and_docx_generation(self):
        """Verifies screening QA documents are generated and valid."""
        pdf_qa = self.generator.generate_screening_qa_pdf(self.qa_packet, self.output_dir)
        self.assertEqual(pdf_qa.document_type, "screening_qa")
        self.assertEqual(pdf_qa.file_format, "pdf")

        docx_qa = self.generator.generate_screening_qa_docx(self.qa_packet, self.output_dir)
        self.assertEqual(docx_qa.document_type, "screening_qa")
        self.assertEqual(docx_qa.file_format, "docx")

    def test_application_packet_consolidation(self):
        """Verifies consolidated application packet combines resume, letter, and QA into one file."""
        pdf_pkt = self.generator.generate_application_packet_pdf(
            self.tailored_resume, self.cover_letter, self.qa_packet, self.output_dir, DocumentTemplate.MODERN
        )
        self.assertEqual(pdf_pkt.document_type, "application_packet")
        self.assertEqual(pdf_pkt.file_format, "pdf")

        docx_pkt = self.generator.generate_application_packet_docx(
            self.tailored_resume, self.cover_letter, self.qa_packet, self.output_dir, DocumentTemplate.MODERN
        )
        self.assertEqual(docx_pkt.document_type, "application_packet")
        self.assertEqual(docx_pkt.file_format, "docx")

    def test_all_templates_render_successfully(self):
        """Verifies that all 7 templates can generate without layout or font errors."""
        for template in DocumentTemplate:
            doc = self.generator.generate_resume_pdf(self.tailored_resume, self.output_dir, template)
            self.assertTrue(Path(doc.file_path).exists())
            self.assertEqual(doc.template, template.value)

    def test_pdf_validation_catches_invalid_files(self):
        """Verifies that validate_pdf_document raises ValueError on invalid or non-PDF files."""
        fake_pdf = self.output_dir / "fake.pdf"
        fake_pdf.write_bytes(b"This is not a PDF file.")
        with self.assertRaises(ValueError):
            self.generator.validate_pdf_document(fake_pdf)


if __name__ == "__main__":
    unittest.main()

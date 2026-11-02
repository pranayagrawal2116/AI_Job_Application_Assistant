"""Unit tests for Universal Resume Parser across 15 synthetic personas and diverse industries.

Validates:
- Cross-industry entity extraction (medical, legal, finance, engineering, sales, education, etc.)
- Strict zero-hallucination policy (unmentioned fields remain empty/unverified)
- Accurate field-level provenance tracking and confidence scoring
- Robust handling of edge cases (unusual degree names, missing sections, international phone formats)
"""

import io
from pathlib import Path
import tempfile
import unittest

from src.database.exceptions import InvalidFileFormatError
from src.preparer.resume_parser import (
    ParsedResume,
    ResumeParser,
    VerificationStatus,
    format_title_preserve_acronyms,
)
from tests.fixtures.synthetic_personas import (
    PERSONA_DEFINITIONS,
    generate_persona_docx,
    generate_persona_pdf,
)


class TestUniversalResumeParser(unittest.TestCase):
    """Test suite verifying universal resume parsing across all 15 synthetic personas."""

    def setUp(self):
        self.parser = ResumeParser()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. PERSONA EXTRACTION TESTS (DOCX & PDF)
    # -------------------------------------------------------------------------

    def test_parse_backend_engineer_docx(self):
        """Tests parsing a senior software/distributed systems engineer resume."""
        docx_bytes = generate_persona_docx("backend_engineer")
        fpath = self.temp_path / "alex_mercer.docx"
        fpath.write_bytes(docx_bytes)

        parsed = self.parser.parse_file(fpath)
        self.assertEqual(parsed.full_name, "Alex Mercer")
        self.assertEqual(parsed.email, "alex.mercer@cloudinfra.io")
        self.assertIn("Seattle", parsed.location)
        self.assertTrue(len(parsed.education) >= 1)
        self.assertIn("Washington", parsed.education[0].institution)
        self.assertTrue(any("Go" in s for s in parsed.technical_skills))
        self.assertTrue(any("Kubernetes" in s for s in parsed.technical_skills))
        self.assertEqual(parsed.file_format, "DOCX")

    def test_parse_cardiologist_pdf(self):
        """Tests parsing a certified medical doctor / cardiologist resume in PDF."""
        pdf_bytes = generate_persona_pdf("cardiologist")
        fpath = self.temp_path / "dr_sarah_jenkins.pdf"
        fpath.write_bytes(pdf_bytes)

        parsed = self.parser.parse_file(fpath)
        self.assertIn("Sarah Jenkins", parsed.full_name)
        self.assertEqual(parsed.email, "dr.jenkins@bostonheartclinic.org")
        self.assertIn("Boston", parsed.location)
        self.assertTrue(len(parsed.education) >= 1)
        self.assertIn("Harvard", parsed.education[0].institution)
        self.assertTrue(any("Catheterization" in s or "Echocardiography" in s for s in parsed.technical_skills))
        self.assertEqual(parsed.file_format, "PDF")

    def test_parse_attorney_docx(self):
        """Tests parsing a corporate/M&A attorney resume."""
        docx_bytes = generate_persona_docx("attorney")
        fpath = self.temp_path / "michael_vance.docx"
        fpath.write_bytes(docx_bytes)

        parsed = self.parser.parse_file(fpath)
        self.assertEqual(parsed.full_name, "Michael Vance")
        self.assertEqual(parsed.email, "mvance@vancecorporate.com")
        self.assertIn("New York", parsed.location)
        self.assertTrue(any("Columbia" in e.institution for e in parsed.education))
        self.assertTrue(any("Mergers" in s or "Acquisitions" in s for s in parsed.technical_skills))

    def test_parse_cfa_investment_banker_pdf(self):
        """Tests parsing a CFA charterholder / investment banker resume."""
        pdf_bytes = generate_persona_pdf("cfa_investment_banker")
        fpath = self.temp_path / "priya_sharma.pdf"
        fpath.write_bytes(pdf_bytes)

        parsed = self.parser.parse_file(fpath)
        self.assertIn("Priya Sharma", parsed.full_name)
        self.assertEqual(parsed.email, "priya.sharma@mumbaicapital.in")
        self.assertIn("Mumbai", parsed.location)
        self.assertTrue(any("Ahmedabad" in e.institution for e in parsed.education))
        self.assertTrue(any("Valuation" in s or "Modeling" in s for s in parsed.technical_skills))

    def test_parse_all_15_personas_coverage(self):
        """Ensures all 15 diverse personas extract valid name, email, and education without errors."""
        for p_id, p_def in PERSONA_DEFINITIONS.items():
            docx_bytes = generate_persona_docx(p_id)
            fpath = self.temp_path / f"{p_id}.docx"
            fpath.write_bytes(docx_bytes)

            parsed = self.parser.parse_file(fpath)
            self.assertTrue(len(parsed.full_name) > 0, f"Failed name extraction for {p_id}")
            self.assertEqual(parsed.email, p_def["email"], f"Failed email extraction for {p_id}")
            self.assertTrue(len(parsed.education) >= 1, f"Failed education extraction for {p_id}")
            self.assertIn(p_def["education"][0]["institution"], parsed.education[0].institution)

    # -------------------------------------------------------------------------
    # 2. ZERO-HALLUCINATION POLICY VERIFICATION
    # -------------------------------------------------------------------------

    def test_zero_hallucination_on_missing_fields(self):
        """Guarantees that unmentioned fields remain empty and are never fabricated."""
        # Create minimal resume with only name and email
        docx_bytes = io.BytesIO()
        from docx import Document
        doc = Document()
        doc.add_heading("Taylor Reed", 0)
        doc.add_paragraph("taylor.reed@example.com")
        doc.save(docx_bytes)

        fpath = self.temp_path / "minimal.docx"
        fpath.write_bytes(docx_bytes.getvalue())

        parsed = self.parser.parse_file(fpath)
        self.assertEqual(parsed.full_name, "Taylor Reed")
        self.assertEqual(parsed.email, "taylor.reed@example.com")
        # Ensure non-existent fields are empty, NOT populated with developer defaults
        self.assertEqual(parsed.phone, "")
        self.assertEqual(parsed.location, "")
        self.assertEqual(parsed.github_url, "")
        self.assertEqual(parsed.linkedin_url, "")
        self.assertEqual(parsed.education, [])
        self.assertEqual(parsed.work_experience, [])
        self.assertEqual(parsed.projects, [])

    # -------------------------------------------------------------------------
    # 3. FIELD PROVENANCE AND CONFIDENCE SCORING
    # -------------------------------------------------------------------------

    def test_field_provenance_tracking(self):
        """Verifies that extracted fields contain structured provenance and confidence tags."""
        docx_bytes = generate_persona_docx("cpa_auditor")
        fpath = self.temp_path / "robert_chen.docx"
        fpath.write_bytes(docx_bytes)

        parsed = self.parser.parse_file(fpath)
        prov = parsed.field_provenance

        self.assertIn("full_name", prov)
        self.assertEqual(prov["full_name"]["verification_status"], VerificationStatus.EXTRACTED_UNVERIFIED)
        self.assertGreaterEqual(prov["full_name"]["confidence"], 0.9)

        self.assertIn("email", prov)
        self.assertEqual(prov["email"]["verification_status"], VerificationStatus.EXTRACTED_UNVERIFIED)
        self.assertEqual(prov["email"]["confidence"], 1.0)

        self.assertIn("technical_skills", prov)
        self.assertEqual(prov["technical_skills"]["verification_status"], VerificationStatus.EXTRACTED_UNVERIFIED)

    # -------------------------------------------------------------------------
    # 4. EDGE CASES & UTILITIES
    # -------------------------------------------------------------------------

    def test_format_title_preserve_acronyms(self):
        """Verifies that acronyms (MIT, IIT, AI, ML, ABDM, CPA, CFA) are preserved in uppercase."""
        self.assertEqual(format_title_preserve_acronyms("MIT WORLD PEACE UNIVERSITY"), "MIT World Peace University")
        self.assertEqual(format_title_preserve_acronyms("INDIAN INSTITUTE OF TECHNOLOGY"), "Indian Institute Of Technology")
        self.assertEqual(format_title_preserve_acronyms("SARITA ABDM INTEGRATION"), "Sarita ABDM Integration")
        self.assertEqual(format_title_preserve_acronyms("CPA SENIOR AUDITOR"), "CPA Senior Auditor")
        self.assertEqual(format_title_preserve_acronyms("Already Mixed Case"), "Already Mixed Case")

    def test_unsupported_file_extension(self):
        """Verifies rejection of unsupported file extensions."""
        txt_path = self.temp_path / "resume.txt"
        txt_path.write_text("Name: John Doe")
        with self.assertRaises(InvalidFileFormatError):
            self.parser.parse_file(txt_path)


if __name__ == "__main__":
    unittest.main()

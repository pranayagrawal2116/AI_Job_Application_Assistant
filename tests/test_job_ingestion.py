"""Integration tests for Job Description Ingestion (Pasted text, PDF, and DOCX).

Verifies multi-user document ingestion, validation, and storage isolation.
"""

import io
from pathlib import Path
import tempfile
import unittest

from docx import Document
from pypdf import PdfWriter

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CorruptedFileError,
    InvalidFileFormatError,
)
from src.preparer.job_parser import JobParser
from src.security.auth import AuthManager


class TestJobIngestion(unittest.TestCase):
    """Test suite for job description ingestion mechanisms."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_ingestion.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)
        self.user = self.auth.register(
            email="ingest@example.com",
            password="StrongPassword123!",
            full_name="Ingest User",
        )
        self.parser = JobParser()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_sample_pdf(self, content_lines: list[str]) -> bytes:
        """Helper generating valid PDF bytes with PyPDF."""
        # Using reportlab or basic pdf writer structure
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        buf = io.BytesIO()
        writer.write(buf)
        # Note: PdfWriter empty page has PDF header and valid structure
        return buf.getvalue()

    def _create_sample_docx(self, paragraphs: list[str]) -> bytes:
        """Helper generating valid DOCX bytes with python-docx."""
        doc = Document()
        for p in paragraphs:
            doc.add_paragraph(p)
        buf = io.BytesIO()
        doc.save(buf)
        return buf.getvalue()

    def test_ingest_pasted_text_preserves_bullets_and_unicode(self):
        """Pasted text with unicode symbols, bullets, and accents is fully preserved."""
        unicode_jd = """
        Company: Société Générale
        Position: Quantitative Risk Analyst
        Location: Paris, France (Hybrid)

        Responsibilities:
        • Développer des modèles stochastiques pour l'évaluation des risques.
        • Calculer la Value-at-Risk (VaR) et Expected Shortfall (ES).
        • Collaborer avec l'équipe de trading en utilisant Python et R.

        Requirements:
        • Diplôme d'ingénieur ou Master en Mathématiques Financières.
        • Minimum 3 ans d'expérience.
        • Maîtrise de Python, C++, et SQL.
        """
        jd = self.db.save_job_description_snapshot(
            user_id=self.user.id,
            company_name="Société Générale",
            job_title="Quantitative Risk Analyst",
            raw_content=unicode_jd,
            source_type="pasted",
        )
        self.assertEqual(jd.user_id, self.user.id)
        self.assertIn("Société Générale", jd.company_name)
        self.assertIn("• Développer des modèles stochastiques", jd.raw_content)
        self.assertIn("Value-at-Risk", jd.raw_content)

    def test_ingest_docx_document(self):
        """Valid DOCX file is validated, stored in user sandbox, and parsed."""
        docx_bytes = self._create_sample_docx([
            "Company: BioGen Innovations",
            "Job Title: Senior Bioinformatician",
            "Location: Boston, MA",
            "Responsibilities:",
            "- Analyze next-generation sequencing data using Python and Nextflow.",
            "- Maintain genomic databases with PostgreSQL.",
            "Requirements:",
            "- Master's Degree or PhD in Bioinformatics or Computational Biology.",
            "- At least 3+ years of experience.",
            "- Proficiency in Python, Linux, and Git.",
        ])

        user_jd_dir = Path(self.temp_dir.name) / "users" / str(self.user.id) / "job_descriptions"
        user_jd_dir.mkdir(parents=True, exist_ok=True)

        jd = self.db.upload_user_job_description(
            user_id=self.user.id,
            file_bytes=docx_bytes,
            original_filename="Senior_Bioinformatician_BioGen.docx",
            user_base_dir=user_jd_dir,
        )

        self.assertEqual(jd.user_id, self.user.id)
        self.assertEqual(jd.source_type, "upload")
        self.assertIn("BioGen", jd.company_name)
        self.assertIn("Bioinformatician", jd.job_title)
        self.assertTrue(jd.storage_filename.endswith(".docx"))

        # Verify physical file existence in isolated directory
        saved_file = user_jd_dir / jd.storage_filename
        self.assertTrue(saved_file.exists())
        self.assertGreater(saved_file.stat().st_size, 0)

    def test_ingest_invalid_format_rejected(self):
        """Executable or unsupported format is rejected with InvalidFileFormatError."""
        fake_exe = b"MZ\x90\x00\x03\x00\x00\x00malicious binary content"
        with self.assertRaises(InvalidFileFormatError):
            self.db.upload_user_job_description(
                user_id=self.user.id,
                file_bytes=fake_exe,
                original_filename="malicious_jd.exe",
            )

    def test_ingest_corrupted_docx_rejected(self):
        """Corrupted zip archive with .docx extension is rejected."""
        corrupted_bytes = b"PK\x03\x04corrupted_zip_payload_not_valid_openxml"
        with self.assertRaises(CorruptedFileError):
            self.db.upload_user_job_description(
                user_id=self.user.id,
                file_bytes=corrupted_bytes,
                original_filename="corrupted.docx",
            )


if __name__ == "__main__":
    unittest.main()

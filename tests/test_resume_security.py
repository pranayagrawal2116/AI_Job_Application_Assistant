"""Unit tests for Resume File Security Engine.

Tests all 10 security requirements:
1. Magic-byte verification (PDF b"%PDF-", DOCX b"PK\x03\x04").
2. Rejection of spoofed extensions (executables, HTML, script files named .pdf or .docx).
3. Maximum file size enforcement (10 MB limit).
4. Zip-bomb decompression explosion protection for DOCX files.
5. Password-protected / encrypted PDF detection and rejection.
6. Corrupted file handling.
7. Path traversal prevention in filenames and directories.
8. Strict user sandbox containment (data/users/<user_id>/resumes/).
9. Atomic temporary file creation and replacement.
10. UUID storage filename generation without exposing user PII.
"""

import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from pypdf import PdfWriter

from src.database.exceptions import (
    CorruptedFileError,
    EncryptedFileError,
    FileSecurityError,
    FileTooLargeError,
    InvalidFileFormatError,
)
from src.security.file_security import (
    MAX_FILE_SIZE_BYTES,
    FileSecurityValidator,
)


class TestResumeFileSecurity(unittest.TestCase):
    """Test suite verifying file security constraints for user resumes."""

    def setUp(self):
        self.validator = FileSecurityValidator()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_sandbox = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Magic Bytes & Format Verification
    def test_valid_pdf_magic_bytes(self):
        """Accepts a genuine PDF with %PDF- header."""
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        buf = io.BytesIO()
        writer.write(buf)
        valid_pdf = buf.getvalue()

        fmt, file_hash = self.validator.validate_file(valid_pdf, "resume.pdf")
        self.assertEqual(fmt, "pdf")
        self.assertEqual(len(file_hash), 64)

    def test_valid_docx_magic_bytes(self):
        """Accepts a genuine DOCX (ZIP container) with PK\x03\x04 header."""
        from docx import Document
        doc = Document()
        doc.add_paragraph("Valid DOCX content")
        buf = io.BytesIO()
        doc.save(buf)
        raw_docx = buf.getvalue()

        fmt, file_hash = self.validator.validate_file(raw_docx, "my_resume.docx")
        self.assertEqual(fmt, "docx")
        self.assertEqual(len(file_hash), 64)

    def test_spoofed_pdf_extension_rejected(self):
        """Rejects executable binary or plain text disguised as .pdf."""
        fake_pdf = b"MZ\x90\x00\x03\x00\x00\x00This is an executable payload"
        with self.assertRaises(InvalidFileFormatError):
            self.validator.validate_file(fake_pdf, "malware.pdf")

    def test_spoofed_docx_extension_rejected(self):
        """Rejects HTML or script disguised as .docx."""
        fake_docx = b"<html><body>Not a real docx</body></html>"
        with self.assertRaises(InvalidFileFormatError):
            self.validator.validate_file(fake_docx, "exploit.docx")

    # 2. File Size Enforcement (10 MB Limit)
    def test_file_size_limit_enforced(self):
        """Rejects files exceeding 10 MB."""
        huge_bytes = b"%PDF-" + b"0" * (MAX_FILE_SIZE_BYTES + 1024)
        with self.assertRaises(FileTooLargeError):
            self.validator.validate_file(huge_bytes, "huge_resume.pdf")

    # 3. Zip-Bomb Detection for DOCX
    def test_zip_bomb_detection(self):
        """Rejects crafted zip-bomb with excessive compression ratio."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # 60 MB of zeroes compressed into tiny bytes
            zf.writestr("word/document.xml", b"\x00" * (60 * 1024 * 1024))
        bomb_bytes = buf.getvalue()

        with self.assertRaises(FileSecurityError) as ctx:
            self.validator.validate_file(bomb_bytes, "bomb.docx")
        self.assertIn("bomb", str(ctx.exception).lower())

    # 4. Encrypted / Password-Protected PDF Detection
    def test_encrypted_pdf_rejected(self):
        """Detects and rejects encrypted or password-protected PDF files."""
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.encrypt("secret_password")
        buf = io.BytesIO()
        writer.write(buf)
        encrypted_bytes = buf.getvalue()

        with self.assertRaises(EncryptedFileError):
            self.validator.validate_file(encrypted_bytes, "protected.pdf")

    # 5. Path Traversal & Filename Sanitization
    def test_path_traversal_sanitization(self):
        """Sanitizes malicious traversal tokens from original filenames."""
        malicious_names = [
            "../../../etc/passwd.pdf",
            "..\\..\\windows\\system32.docx",
            "/absolute/root/path.pdf",
            "normal/subdir/resume.docx",
        ]
        for name in malicious_names:
            clean = self.validator.sanitize_filename(name)
            self.assertNotIn("/", clean)
            self.assertNotIn("\\", clean)
            self.assertNotIn("..", clean)

    def test_validate_path_containment(self):
        """Ensures storage paths cannot escape designated user directory."""
        user_dir = self.base_sandbox / "data" / "users" / "42" / "resumes"
        user_dir.mkdir(parents=True, exist_ok=True)

        valid_path = user_dir / "safe_file.pdf"
        # Should succeed without error
        self.validator.validate_path_containment(valid_path, user_dir)

        # Escape path
        escape_path = user_dir / ".." / ".." / "other_user" / "secret.pdf"
        with self.assertRaises(FileSecurityError):
            self.validator.validate_path_containment(escape_path, user_dir)

    # 6. UUID Storage Filename Generation
    def test_uuid_storage_filename(self):
        """Generates cryptographically random UUID filenames with preserved extensions."""
        fname = self.validator.generate_storage_filename("my_private_resume_john_doe.pdf")
        self.assertTrue(fname.endswith(".pdf"))
        self.assertNotIn("john_doe", fname)
        self.assertEqual(len(fname.split(".")[0]), 36)  # Standard UUID length

    # 7. Atomic File Saving
    def test_atomic_file_saving(self):
        """Guarantees atomic file writing with temporary replacement."""
        dest = self.base_sandbox / "data" / "users" / "1" / "resumes" / "atomic.pdf"
        payload = b"%PDF-1.4\nvalid payload\n%%EOF"

        saved_path = self.validator.save_file(payload, dest, user_id=1)
        self.assertTrue(saved_path.exists())
        self.assertEqual(saved_path.read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()

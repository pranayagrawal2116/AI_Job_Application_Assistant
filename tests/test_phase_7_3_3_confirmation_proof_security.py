"""Comprehensive Unit, Integration & Security Tests for Phase 7.3.3:
Secure Submission Confirmation Evidence Upload & Retrieval.

Covers all 6 categories:
A. Upload Validation (PDF, PNG, JPEG, size limits, format spoofing, decompression bombs, malformed/corrupted files)
B. Private Storage (sandbox containment, server-generated filenames, SHA-256 calculation, atomic write & rollback)
C. Ownership Isolation (cross-candidate isolation, expired/missing sessions, client_user_id override prevention)
D. Integrity Verification (hash matching, tampered bytes, missing files, symlink rejection, format validation)
E. Manual Submission Workflow Regression (no-proof submission, HMAC single-use tickets, non-approved rejection, timeline hash chain)
F. UI Integration (optional file uploader, verified download buttons, safe error handling, absence handling)
"""

import hashlib
import io
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from PIL import Image
from pypdf import PdfWriter

from dashboard.components.tracker_components import (
    render_manual_submission_section,
    render_submission_confirmation_details,
)
from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ApplicationNotFoundError,
    CorruptedFileError,
    CrossUserAccessError,
    EncryptedFileError,
    FileSecurityError,
    FileTooLargeError,
    InvalidFileFormatError,
    SecurityAuthorizationError,
    UnconfirmedSubmissionError,
    ValidationError,
)
from src.database.models import Application
from src.preparer.approval_gate import canonical_json_bytes, canonical_json_hash
from src.security.file_security import (
    MAX_FILE_SIZE_BYTES,
    FileSecurityValidator,
)
from src.security.session_manager import SessionManager


def _make_pdf(num_pages: int = 1) -> bytes:
    """Generates synthetic, structurally valid PDF bytes."""
    writer = PdfWriter()
    for _ in range(num_pages):
        writer.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _make_png(width: int = 100, height: int = 100, color: str = "blue") -> bytes:
    """Generates synthetic, structurally valid PNG image bytes."""
    img = Image.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_jpeg(width: int = 100, height: int = 100, color: str = "red") -> bytes:
    """Generates synthetic, structurally valid JPEG image bytes."""
    img = Image.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _make_decompression_bomb() -> bytes:
    """Generates a synthetic PNG decompression bomb (6000x6000 = 36M pixels)."""
    img = Image.new("RGB", (6000, 6000), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class BaseConfirmationProofTest(unittest.TestCase):
    """Base test fixture setting up an isolated SQLite database and private filesystem sandbox."""

    def setUp(self):
        self.temp_db_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_db_dir.name) / "test_proof.db"
        self.db = DatabaseManager(db_path=str(self.db_path))

        self.temp_storage_dir = tempfile.TemporaryDirectory()
        self.storage_base = Path(self.temp_storage_dir.name)

        self.service = DashboardService(
            db_manager=self.db,
            storage_base_dir=self.storage_base,
        )
        self.validator = FileSecurityValidator(base_storage_dir=self.storage_base)

        SessionManager._instance = None
        self.session_mgr = SessionManager.get_instance()

        # Seed two candidate users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (1, 'candidate_a@example.com', 'h1', 's1', 'Candidate A')"
            )
            cursor.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, full_name) "
                "VALUES (2, 'candidate_b@example.com', 'h2', 's2', 'Candidate B')"
            )

        self.user_a = 1
        self.user_b = 2

        # Create active sessions
        self.session_a = self.session_mgr.authenticate_candidate(
            candidate_id="cand_a",
            candidate_name="Candidate A",
            user_id=self.user_a,
        )
        self.session_b = self.session_mgr.authenticate_candidate(
            candidate_id="cand_b",
            candidate_name="Candidate B",
            user_id=self.user_b,
        )

        # Create an APPROVED application for Candidate A with active packet and human approval
        self.app_a = self._setup_approved_application(self.user_a, self.session_a.session_id)

    def tearDown(self):
        if hasattr(self, "session_mgr") and self.session_mgr:
            self.session_mgr.reset_instance()
        SessionManager._instance = None
        self.temp_db_dir.cleanup()
        self.temp_storage_dir.cleanup()

    def _setup_approved_application(
        self,
        user_id: int,
        session_id: str,
        packet_id: int = 1001,
        company: str = "Acme Corp",
        title: str = "Senior AI Engineer",
    ) -> Application:
        """Sets up a complete APPROVED application with active prepared packet and human approval."""
        app = self.service.create_candidate_application(
            session_id=session_id,
            company_name=company,
            job_title=title,
            status="DRAFT",
        )

        # Advance status to APPROVED in DB
        with self.db.transaction() as conn:
            conn.execute("UPDATE applications SET status = 'APPROVED' WHERE id = ?", (app.id,))

        snap_payload = {
            "application_id": app.id,
            "user_id": user_id,
            "version_num": 1,
            "company_name": company,
            "job_title": title,
        }
        snap_json = canonical_json_bytes(snap_payload).decode("utf-8")
        pkt_hash = canonical_json_hash(snap_payload)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    id, application_id, user_id, version_num, packet_version_hash,
                    original_resume_hash, job_description_snapshot_hash, screening_answers_json,
                    canonical_snapshot_json, is_active_revision
                ) VALUES (?, ?, ?, 1, ?, 'rh', 'jdh', '{}', ?, 1)
                """,
                (packet_id, app.id, user_id, pkt_hash, snap_json),
            )
            cursor.execute(
                """
                INSERT INTO application_approvals (
                    id, application_id, packet_id, user_id, packet_version_hash,
                    ticket_nonce, approver_name, session_id, is_consumed
                ) VALUES (?, ?, ?, ?, ?, ?, 'Human Auditor', ?, 0)
                """,
                (
                    packet_id,
                    app.id,
                    packet_id,
                    user_id,
                    pkt_hash,
                    f"nonce_{packet_id}",
                    session_id,
                ),
            )

        return self.db.get_user_application(app.id, user_id)


# =============================================================================
# CATEGORY A: UPLOAD VALIDATION TESTS
# =============================================================================

class TestUploadValidation(BaseConfirmationProofTest):
    """Tests Section 3: File Acceptance Policy & Strict Structural Validation."""

    def test_valid_pdf_acceptance(self):
        """Accepts a structurally valid PDF file."""
        pdf_bytes = _make_pdf(1)
        fmt, f_hash = self.validator.validate_confirmation_proof(pdf_bytes, "confirmation.pdf")
        self.assertEqual(fmt, "pdf")
        self.assertEqual(f_hash, hashlib.sha256(pdf_bytes).hexdigest())

    def test_valid_png_acceptance(self):
        """Accepts a structurally valid PNG image."""
        png_bytes = _make_png(200, 200, "green")
        fmt, f_hash = self.validator.validate_confirmation_proof(png_bytes, "screenshot.png")
        self.assertEqual(fmt, "png")
        self.assertEqual(f_hash, hashlib.sha256(png_bytes).hexdigest())

    def test_valid_jpeg_acceptance(self):
        """Accepts a structurally valid JPEG image."""
        jpeg_bytes = _make_jpeg(200, 200, "blue")
        fmt, f_hash = self.validator.validate_confirmation_proof(jpeg_bytes, "receipt.jpg")
        self.assertEqual(fmt, "jpeg")
        self.assertEqual(f_hash, hashlib.sha256(jpeg_bytes).hexdigest())

    def test_empty_file_rejection(self):
        """Rejects zero-byte files immediately with ValidationError."""
        with self.assertRaises(ValidationError) as ctx:
            self.validator.validate_confirmation_proof(b"", "empty.pdf")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_file_larger_than_10mb_rejection(self):
        """Rejects files exceeding the strict 10 MB limit with FileTooLargeError."""
        huge_bytes = b"%PDF-" + b"0" * (MAX_FILE_SIZE_BYTES + 1024)
        with self.assertRaises(FileTooLargeError) as ctx:
            self.validator.validate_confirmation_proof(huge_bytes, "huge.pdf")
        self.assertIn("exceeds maximum allowed limit of 10 MB", str(ctx.exception))

    def test_extension_mismatch_png_named_pdf(self):
        """Rejects genuine PNG bytes when filename extension claims .pdf."""
        png_bytes = _make_png()
        with self.assertRaises(InvalidFileFormatError) as ctx:
            self.validator.validate_confirmation_proof(png_bytes, "receipt.pdf")
        self.assertIn("invalid pdf header", str(ctx.exception).lower())

    def test_extension_mismatch_pdf_named_png(self):
        """Rejects genuine PDF bytes when filename extension claims .png."""
        pdf_bytes = _make_pdf()
        with self.assertRaises(InvalidFileFormatError) as ctx:
            self.validator.validate_confirmation_proof(pdf_bytes, "receipt.png")
        self.assertIn("invalid png header", str(ctx.exception).lower())

    def test_mime_spoofing_html_named_pdf(self):
        """Rejects HTML payload disguised with a .pdf extension."""
        html_bytes = b"<!DOCTYPE html><html><body>Receipt</body></html>"
        with self.assertRaises(InvalidFileFormatError):
            self.validator.validate_confirmation_proof(html_bytes, "receipt.pdf")

    def test_incorrect_magic_bytes_rejection(self):
        """Rejects arbitrary text or corrupted headers with InvalidFileFormatError."""
        fake_bytes = b"NOT_A_VALID_MAGIC_BYTE_SEQUENCE" * 10
        with self.assertRaises(InvalidFileFormatError):
            self.validator.validate_confirmation_proof(fake_bytes, "proof.jpg")

    def test_corrupted_pdf_rejection(self):
        """Rejects PDFs that start with %PDF- but contain corrupted body streams."""
        corrupted_pdf = b"%PDF-1.4\n" + b"\x00\xFF\xAA\x55" * 100 + b"trailer\n<<>>\n%%EOF"
        with self.assertRaises(CorruptedFileError):
            self.validator.validate_confirmation_proof(corrupted_pdf, "broken.pdf")

    def test_corrupted_png_rejection(self):
        """Rejects PNG files that start with magic bytes but contain corrupt chunks."""
        corrupted_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 80
        with self.assertRaises(CorruptedFileError):
            self.validator.validate_confirmation_proof(corrupted_png, "broken.png")

    def test_svg_rejection(self):
        """Rejects SVG XML vector images."""
        svg_bytes = b"<svg xmlns='http://www.w3.org/2000/svg'><circle r='50'/></svg>"
        with self.assertRaises(InvalidFileFormatError):
            self.validator.validate_confirmation_proof(svg_bytes, "vector.svg")

    def test_executable_rejection(self):
        """Rejects Windows PE / DOS executables starting with MZ."""
        exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
        with self.assertRaises(InvalidFileFormatError):
            self.validator.validate_confirmation_proof(exe_bytes, "malware.exe")

    def test_zip_and_docx_rejection(self):
        """Rejects ZIP and DOCX archives for confirmation evidence."""
        zip_bytes = b"PK\x03\x04" + b"\x00" * 50
        with self.assertRaises(InvalidFileFormatError):
            self.validator.validate_confirmation_proof(zip_bytes, "proof.docx")

    def test_image_decompression_bomb_rejection(self):
        """Rejects images exceeding safe pixel ceilings (decompression bombs)."""
        bomb_bytes = _make_decompression_bomb()
        with self.assertRaises(CorruptedFileError) as ctx:
            self.validator.validate_confirmation_proof(bomb_bytes, "bomb.png")
        self.assertIn("decompression bomb", str(ctx.exception).lower())

    def test_corrupted_jpeg_rejection(self):
        """Rejects JPEG files with valid SOI markers but corrupt image stream."""
        corrupted_jpeg = b"\xff\xd8\xff" + b"\x00" * 80
        with self.assertRaises(CorruptedFileError):
            self.validator.validate_confirmation_proof(corrupted_jpeg, "broken.jpg")

    def test_encrypted_pdf_rejection(self):
        """Detects and rejects password-protected or encrypted PDF files."""
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.encrypt("secret_pass")
        buf = io.BytesIO()
        writer.write(buf)
        encrypted_bytes = buf.getvalue()
        with self.assertRaises(EncryptedFileError):
            self.validator.validate_confirmation_proof(encrypted_bytes, "locked.pdf")


# =============================================================================
# CATEGORY B: PRIVATE STORAGE SECURITY TESTS
# =============================================================================

class TestPrivateStorageSecurity(BaseConfirmationProofTest):
    """Tests Section 4: Isolated Storage Architecture, Server Filenames & Atomic Writes."""

    def test_file_stored_inside_candidate_confirmations_directory(self):
        """Confirmation proof is stored strictly in data/users/<user_id>/confirmations/."""
        pdf_bytes = _make_pdf()
        filename, _fmt, size, _f_hash = self.validator.save_user_confirmation_file(
            user_id=self.user_a,
            application_id=self.app_a.id,
            file_bytes=pdf_bytes,
            original_filename="receipt.pdf",
        )
        expected_dir = self.storage_base / str(self.user_a) / "confirmations"
        saved_file = expected_dir / filename
        self.assertTrue(saved_file.exists())
        self.assertTrue(saved_file.is_file())
        self.assertEqual(size, len(pdf_bytes))

    def test_server_generated_unique_filename_format(self):
        """Generated filename follows proof_<app_id>_<timestamp>_<uuid>.<ext> without candidate PII."""
        png_bytes = _make_png()
        filename, _fmt, _size, _f_hash = self.validator.save_user_confirmation_file(
            user_id=self.user_a,
            application_id=self.app_a.id,
            file_bytes=png_bytes,
            original_filename="candidate_confidential_receipt.png",
        )
        self.assertTrue(filename.startswith(f"proof_{self.app_a.id}_"))
        self.assertTrue(filename.endswith(".png"))
        self.assertNotIn("candidate", filename)
        self.assertNotIn("confidential", filename)

    def test_original_filename_never_used_as_physical_path(self):
        """Physical file on disk never uses client-supplied filename."""
        client_name = "secret_payroll_voucher.pdf"
        filename, _, _, _ = self.validator.save_user_confirmation_file(
            user_id=self.user_a,
            application_id=self.app_a.id,
            file_bytes=_make_pdf(),
            original_filename=client_name,
        )
        self.assertNotEqual(filename, client_name)
        target_dir = self.storage_base / str(self.user_a) / "confirmations"
        self.assertFalse((target_dir / client_name).exists())

    def test_correct_sha256_calculated_server_side(self):
        """Server independently calculates SHA-256 from uploaded bytes."""
        jpeg_bytes = _make_jpeg()
        expected_hash = hashlib.sha256(jpeg_bytes).hexdigest()
        _, _, _, calc_hash = self.validator.save_user_confirmation_file(
            user_id=self.user_a,
            application_id=self.app_a.id,
            file_bytes=jpeg_bytes,
            original_filename="receipt.jpeg",
        )
        self.assertEqual(calc_hash, expected_hash)

    def test_path_traversal_in_filename_rejected(self):
        """Filename containing traversal attempts is rejected."""
        with self.assertRaises(ValidationError):
            self.validator.validate_confirmation_proof(_make_pdf(), "../../etc/passwd.pdf")

    def test_null_byte_in_filename_rejected(self):
        """Filename containing null byte is rejected."""
        with self.assertRaises(ValidationError):
            self.validator.validate_confirmation_proof(_make_pdf(), "test\x00receipt.pdf")

    def test_containment_violation_raises_security_error(self):
        """Attempting to save outside candidate sandbox triggers FileSecurityError."""
        outside_dir = self.storage_base / "unauthorized_shared"
        outside_dir.mkdir(parents=True, exist_ok=True)
        escaped_path = outside_dir / "escaped.pdf"
        user_dir = self.storage_base / str(self.user_a) / "confirmations"
        with self.assertRaises(FileSecurityError):
            self.validator.validate_path_containment(escaped_path, user_dir)

    def test_database_failure_cleans_up_newly_written_file(self):
        """If database insertion fails after file is written, the written file is cleaned up."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        pdf_bytes = _make_pdf()

        # Patch db.create_submission_confirmation to simulate a database crash
        with (
            patch.object(self.db, "create_submission_confirmation", side_effect=RuntimeError("Simulated DB Crash")),
            self.assertRaises(RuntimeError),
        ):
            self.service.record_candidate_manual_submission(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket,
                candidate_confirmed=True,
                submission_channel="COMPANY_PORTAL",
                proof_bytes=pdf_bytes,
                proof_filename="proof.pdf",
            )

        # Confirmations directory must have 0 files left
        user_dir = self.storage_base / str(self.user_a) / "confirmations"
        if user_dir.exists():
            files = list(user_dir.iterdir())
            self.assertEqual(len(files), 0)

    def test_attach_proof_database_failure_cleans_up_new_file(self):
        """When attaching proof fails at DB update, the newly created physical file is cleaned up."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
        )

        user_dir = self.storage_base / str(self.user_a) / "confirmations"
        initial_file_count = len(list(user_dir.iterdir())) if user_dir.exists() else 0

        with (
            patch.object(self.db, "attach_confirmation_proof", side_effect=RuntimeError("Simulated DB Crash")),
            self.assertRaises(RuntimeError),
        ):
            self.service.attach_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
                file_bytes=_make_pdf(),
                original_filename="receipt.pdf",
            )

        # File count must remain identical to before the failed upload
        current_file_count = len(list(user_dir.iterdir())) if user_dir.exists() else 0
        self.assertEqual(current_file_count, initial_file_count)

    def test_candidate_facing_metadata_contains_no_internal_server_paths(self):
        """Metadata returned by service contains zero internal filesystem paths."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
            proof_bytes=_make_pdf(),
            proof_filename="my_receipt.pdf",
        )

        conf_meta = self.service.get_candidate_submission_confirmation(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
        )
        self.assertIsNotNone(conf_meta)
        meta_str = str(conf_meta)
        self.assertNotIn(str(self.storage_base), meta_str)
        self.assertNotIn("confirmations/", meta_str)
        self.assertNotIn("data/users", meta_str)


# =============================================================================
# CATEGORY C: OWNERSHIP ISOLATION TESTS
# =============================================================================

class TestOwnershipIsolation(BaseConfirmationProofTest):
    """Tests Section 9: Multi-User Scoping, Session Enforcement & Cross-User IDOR Defense."""

    def setUp(self):
        super().setUp()
        # Candidate A submits with proof
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        self.conf_a = self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
            proof_bytes=_make_pdf(),
            proof_filename="proof_a.pdf",
        )

    def test_candidate_a_can_download_own_evidence(self):
        """Candidate A successfully downloads their own verified proof."""
        file_bytes, safe_name, mime = self.service.get_candidate_submission_confirmation_proof(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
        )
        self.assertTrue(len(file_bytes) > 0)
        self.assertEqual(mime, "application/pdf")
        self.assertEqual(safe_name, f"submission_proof_{self.app_a.id}.pdf")

    def test_candidate_b_cannot_download_candidate_a_evidence(self):
        """Candidate B cannot download Candidate A's evidence (CrossUserAccessError or ApplicationNotFoundError)."""
        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.get_candidate_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_b.session_id,
            )

    def test_candidate_b_cannot_attach_or_replace_candidate_a_evidence(self):
        """Candidate B cannot attach or overwrite Candidate A's confirmation evidence."""
        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.attach_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_b.session_id,
                file_bytes=_make_png(),
                original_filename="malicious_overwrite.png",
            )

    def test_candidate_b_cannot_view_candidate_a_confirmation_metadata(self):
        """Candidate B cannot view Candidate A's submission confirmation details."""
        with self.assertRaises((CrossUserAccessError, ApplicationNotFoundError)):
            self.service.get_candidate_submission_confirmation(
                application_id=self.app_a.id,
                session_id=self.session_b.session_id,
            )

    def test_expired_session_rejects_download(self):
        """Expired session is rejected with SecurityAuthorizationError on download."""
        self.session_a.expires_at = datetime.now(UTC).timestamp() - 100
        with self.assertRaises(SecurityAuthorizationError):
            self.service.get_candidate_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
            )

    def test_expired_session_rejects_upload(self):
        """Expired session is rejected with SecurityAuthorizationError on upload."""
        self.session_a.expires_at = datetime.now(UTC).timestamp() - 100
        with self.assertRaises(SecurityAuthorizationError):
            self.service.attach_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
                file_bytes=_make_pdf(),
                original_filename="receipt.pdf",
            )

    def test_missing_session_rejects_download(self):
        """Missing or forged session is rejected with SecurityAuthorizationError on download."""
        with self.assertRaises(SecurityAuthorizationError):
            self.service.get_candidate_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id="INVALID-SESSION-TOKEN",
            )

    def test_missing_session_rejects_upload(self):
        """Missing or forged session is rejected with SecurityAuthorizationError on upload."""
        with self.assertRaises(SecurityAuthorizationError):
            self.service.attach_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id="INVALID-SESSION-TOKEN",
                file_bytes=_make_pdf(),
                original_filename="receipt.pdf",
            )

    def test_client_supplied_user_id_cannot_override_session_identity(self):
        """Client-supplied user_id is ignored/rejected if conflicting with session."""
        with self.assertRaises(SecurityAuthorizationError):
            self.service.get_candidate_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_b.session_id,
                client_user_id=self.user_a,
            )


# =============================================================================
# CATEGORY D: INTEGRITY VERIFICATION TESTS
# =============================================================================

class TestIntegrityVerification(BaseConfirmationProofTest):
    """Tests Section 5 & 8: SHA-256 Integrity Verification, Path Defense & Tamper Detection."""

    def setUp(self):
        super().setUp()
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        self.pdf_bytes = _make_pdf()
        self.conf = self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
            proof_bytes=self.pdf_bytes,
            proof_filename="proof.pdf",
        )

    def test_intact_file_hash_permits_retrieval(self):
        """Unmodified document with matching SHA-256 retrieves cleanly."""
        file_bytes, _, _ = self.service.get_candidate_submission_confirmation_proof(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
        )
        self.assertEqual(file_bytes, self.pdf_bytes)

    def test_tampered_file_bytes_rejected_with_corrupted_file_error(self):
        """Modifying disk file bytes causes retrieval rejection via SHA-256 mismatch."""
        target_dir = self.storage_base / str(self.user_a)
        physical_file = target_dir / self.conf.confirmation_doc_path
        with open(physical_file, "wb") as f:
            f.write(b"%PDF-1.4 TAMPERED BYTES")

        with self.assertRaises(CorruptedFileError) as ctx:
            self.service.get_candidate_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
            )
        self.assertIn("hash mismatch", str(ctx.exception).lower())

    def test_missing_physical_file_causes_safe_failure(self):
        """Missing physical file on disk raises FileNotFoundError safely."""
        target_dir = self.storage_base / str(self.user_a)
        physical_file = target_dir / self.conf.confirmation_doc_path
        physical_file.unlink()

        with self.assertRaises(FileNotFoundError):
            self.service.get_candidate_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
            )

    def test_tampered_database_path_traversal_rejected(self):
        """Manipulating confirmation_doc_path in SQLite to traversal path is blocked."""
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE submission_confirmations SET confirmation_doc_path = '../../etc/passwd' WHERE id = ?",
                (self.conf.id,),
            )

        with self.assertRaises(SecurityAuthorizationError):
            self.service.get_candidate_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
            )

    def test_absolute_database_path_rejected(self):
        """Manipulating confirmation_doc_path in SQLite to an absolute path is blocked."""
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE submission_confirmations SET confirmation_doc_path = '/etc/shadow' WHERE id = ?",
                (self.conf.id,),
            )

        with self.assertRaises(SecurityAuthorizationError):
            self.service.get_candidate_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
            )

    def test_symlink_escape_rejected(self):
        """Symlinks pointing outside sandbox are detected and rejected."""
        target_dir = self.storage_base / str(self.user_a)
        physical_file = target_dir / self.conf.confirmation_doc_path
        physical_file.unlink()

        # Create symlink pointing to temporary outside file
        outside_file = self.temp_storage_dir.name + "/outside.txt"
        with open(outside_file, "w") as f:
            f.write("Secret data")

        try:
            os.symlink(outside_file, physical_file)
            with self.assertRaises(SecurityAuthorizationError):
                self.service.get_candidate_submission_confirmation_proof(
                    application_id=self.app_a.id,
                    session_id=self.session_a.session_id,
                )
        except OSError:
            # On platforms where symlink is restricted, pass
            pass

    def test_unsupported_stored_file_format_causes_retrieval_rejection(self):
        """If a stored file on disk was replaced with an executable, retrieval re-validation rejects it."""
        target_dir = self.storage_base / str(self.user_a)
        physical_file = target_dir / self.conf.confirmation_doc_path
        exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
        exe_hash = hashlib.sha256(exe_bytes).hexdigest()

        with open(physical_file, "wb") as f:
            f.write(exe_bytes)

        # Update DB hash to match so hash check passes but structural re-validation catches it
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE submission_confirmations SET confirmation_doc_hash = ? WHERE id = ?",
                (exe_hash, self.conf.id),
            )

        with self.assertRaises((InvalidFileFormatError, CorruptedFileError)):
            self.service.get_candidate_submission_confirmation_proof(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
            )


# =============================================================================
# CATEGORY E: MANUAL SUBMISSION WORKFLOW REGRESSION TESTS
# =============================================================================

class TestManualSubmissionWorkflowRegression(BaseConfirmationProofTest):
    """Tests Section 7: Manual Submission Safeguards & State Machine Invariants."""

    def test_existing_manual_submission_succeeds_without_uploaded_proof(self):
        """Candidate can confirm manual submission without any uploaded evidence."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        conf = self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
            confirmation_reference="REF-NO-PROOF",
            candidate_notes="Submitted without proof",
        )
        self.assertIsNone(conf.confirmation_doc_path)
        self.assertIsNone(conf.confirmation_doc_hash)

        # Application transitioned to SUBMITTED
        app = self.db.get_user_application(self.app_a.id, self.user_a)
        self.assertEqual(app.status, "SUBMITTED")

    def test_generic_transition_cannot_reach_approved_or_submitted(self):
        """Generic transitions forbid setting gate-protected targets APPROVED or SUBMITTED."""
        draft_app = self.db.create_user_application(
            user_id=self.user_a,
            company_name="Gate Target",
            job_title="Engineer",
            status="DRAFT",
        )
        for forbidden in ("APPROVED", "SUBMITTED"):
            with self.assertRaises(SecurityAuthorizationError):
                self.service.transition_application_status(
                    application_id=draft_app.id,
                    session_id=self.session_a.session_id,
                    new_status=forbidden,
                )

    def test_unconfirmed_submission_does_not_attach_evidence_or_consume_ticket(self):
        """candidate_confirmed=False blocks submission and does not create stored file."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        with self.assertRaises(UnconfirmedSubmissionError):
            self.service.record_candidate_manual_submission(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket,
                candidate_confirmed=False,
                submission_channel="COMPANY_PORTAL",
                proof_bytes=_make_pdf(),
                proof_filename="proof.pdf",
            )

        # Status remains APPROVED
        app = self.db.get_user_application(self.app_a.id, self.user_a)
        self.assertEqual(app.status, "APPROVED")

    def test_non_approved_application_cannot_confirm_submission_with_evidence(self):
        """DRAFT application cannot use manual submission workflow even with evidence."""
        draft_app = self.db.create_user_application(
            user_id=self.user_a,
            company_name="Draft Co",
            job_title="Developer",
            status="DRAFT",
        )
        with self.assertRaises(SecurityAuthorizationError):
            self.service.record_candidate_manual_submission(
                application_id=draft_app.id,
                session_id=self.session_a.session_id,
                submission_ticket="TKT-DUMMY",
                candidate_confirmed=True,
                submission_channel="COMPANY_PORTAL",
                proof_bytes=_make_pdf(),
            )

    def test_ticket_replay_attack_rejected(self):
        """A consumed submission ticket cannot be replayed with a new proof file."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        # First call succeeds
        self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
        )
        # Second call with same ticket is rejected
        with self.assertRaises(SecurityAuthorizationError):
            self.service.record_candidate_manual_submission(
                application_id=self.app_a.id,
                session_id=self.session_a.session_id,
                submission_ticket=ticket,
                candidate_confirmed=True,
                submission_channel="COMPANY_PORTAL",
                proof_bytes=_make_pdf(),
            )

    def test_proof_attachment_after_submission_does_not_mutate_status(self):
        """Attaching proof to an existing SUBMITTED confirmation preserves status."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
        )

        # Now attach proof post-submission
        self.service.attach_submission_confirmation_proof(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            file_bytes=_make_png(),
            original_filename="late_receipt.png",
        )

        app = self.db.get_user_application(self.app_a.id, self.user_a)
        self.assertEqual(app.status, "SUBMITTED")

    def test_timeline_hash_chain_remains_consistent_after_evidence_attachment(self):
        """Timeline cryptographic hash chain is valid after evidence attachment."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
            proof_bytes=_make_pdf(),
            proof_filename="proof.pdf",
        )

        timeline_res = self.service.get_application_timeline(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
        )
        self.assertTrue(timeline_res["chain_valid"])
        self.assertIn("verified", timeline_res["verification_message"].lower())

        # Verify event description does not contain server filesystem paths
        for ev in timeline_res["events"]:
            if ev.event_type == "SUBMISSION_CONFIRMATION_PROOF_ATTACHED":
                self.assertNotIn("confirmations/", ev.event_payload_json)
                self.assertNotIn(str(self.storage_base), ev.event_payload_json)


# =============================================================================
# CATEGORY F: UI INTEGRATION TESTS
# =============================================================================

class TestConfirmationProofUI(BaseConfirmationProofTest):
    """Tests Section 7 & 8: Streamlit UI Integration & Presentation Safeguards."""

    @patch("dashboard.components.tracker_components.st")
    def test_ui_optional_file_uploader_rendered_in_manual_submission(self, mock_st):
        """Optional file uploader is rendered inside manual submission section."""
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        mock_st.checkbox.return_value = False
        mock_st.selectbox.return_value = "COMPANY_PORTAL"
        mock_st.text_input.return_value = ""
        mock_st.text_area.return_value = ""
        mock_st.button.return_value = True

        render_manual_submission_section(self.service, self.session_a.session_id, self.app_a, self.user_a)

        mock_st.file_uploader.assert_called_with(
            "Upload Optional Submission Confirmation Evidence",
            type=["pdf", "png", "jpg", "jpeg"],
            help="Optional: Upload an employer confirmation email/PDF or receipt screenshot (PDF, PNG, JPEG up to 10 MB).",
            key=f"sub_proof_file_{self.user_a}_{self.app_a.id}",
        )

    @patch("dashboard.components.tracker_components.st")
    def test_ui_successful_submission_with_evidence(self, mock_st):
        """Submitting with an uploaded proof calls service and shows success message."""
        mock_st.container.return_value.__enter__.return_value = MagicMock()
        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        mock_st.checkbox.return_value = True
        mock_st.selectbox.return_value = "COMPANY_PORTAL"
        mock_st.text_input.return_value = "CONF-123"
        mock_st.text_area.return_value = "Notes"
        mock_st.button.return_value = True

        mock_file = MagicMock()
        mock_file.getvalue.return_value = _make_pdf()
        mock_file.name = "receipt.pdf"
        mock_st.file_uploader.return_value = mock_file

        render_manual_submission_section(self.service, self.session_a.session_id, self.app_a, self.user_a)

        mock_st.success.assert_called_with(
            "Manual submission successfully confirmed with evidence attached! Application status updated to SUBMITTED."
        )

    @patch("dashboard.components.tracker_components.st")
    def test_ui_render_submission_details_with_proof_renders_download_button(self, mock_st):
        """When an application has confirmation proof, download button is rendered."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
            proof_bytes=_make_pdf(),
            proof_filename="proof.pdf",
        )

        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()

        app = self.db.get_user_application(self.app_a.id, self.user_a)
        render_submission_confirmation_details(self.service, self.session_a.session_id, app, self.user_a)

        mock_st.download_button.assert_called()
        call_kwargs = mock_st.download_button.call_args[1]
        self.assertEqual(call_kwargs["file_name"], f"submission_proof_{self.app_a.id}.pdf")
        self.assertEqual(call_kwargs["mime"], "application/pdf")

    @patch("dashboard.components.tracker_components.st")
    def test_ui_render_submission_details_without_proof_shows_info_and_uploader(self, mock_st):
        """When an application has no confirmation proof, info notice and attach expander are shown."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
        )

        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()

        app = self.db.get_user_application(self.app_a.id, self.user_a)
        render_submission_confirmation_details(self.service, self.session_a.session_id, app, self.user_a)

        mock_st.info.assert_called_with("No confirmation evidence document attached.")
        mock_st.download_button.assert_not_called()

    @patch("dashboard.components.tracker_components.st")
    def test_ui_proof_attachment_failure_shows_error(self, mock_st):
        """When attaching proof fails, UI displays a safe error message."""
        ticket = self.service.issue_manual_submission_ticket(
            session_id=self.session_a.session_id,
            application_id=self.app_a.id,
            packet_hash=self.db.get_active_prepared_packet(self.app_a.id, self.user_a).packet_version_hash,
        )
        self.service.record_candidate_manual_submission(
            application_id=self.app_a.id,
            session_id=self.session_a.session_id,
            submission_ticket=ticket,
            candidate_confirmed=True,
            submission_channel="COMPANY_PORTAL",
        )

        mock_st.columns.return_value = [MagicMock(), MagicMock()]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.button.return_value = True

        mock_file = MagicMock()
        mock_file.getvalue.return_value = b"NOT_A_VALID_PDF_BYTES"
        mock_file.name = "broken.pdf"
        mock_st.file_uploader.return_value = mock_file

        app = self.db.get_user_application(self.app_a.id, self.user_a)
        render_submission_confirmation_details(self.service, self.session_a.session_id, app, self.user_a)

        mock_st.error.assert_called()


if __name__ == "__main__":
    unittest.main()

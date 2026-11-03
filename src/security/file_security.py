"""File Security and Isolated Storage Management for Candidate Resumes.

Enforces:
1. Strict magic-byte and structural validation for PDF and DOCX.
2. 10 MB file size limit and zip-bomb decompression limits.
3. Encrypted PDF rejection and corrupted document rejection.
4. Path traversal defense.
5. Isolated per-user storage: data/users/<user_id>/resumes/<uuid>.<ext>.
6. Atomic file writes and SHA-256 integrity verification.
"""

import hashlib
import io
import os
from pathlib import Path
import re
import secrets
from typing import Optional, Tuple
import uuid
import zipfile

from docx import Document
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from src.database.exceptions import (
    CorruptedFileError,
    EncryptedFileError,
    FileTooLargeError,
    InvalidFileFormatError,
    ValidationError,
)
from src.utils.logger import setup_logger

logger = setup_logger("FileSecurity")

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_UNCOMPRESSED_DOCX_BYTES = 50 * 1024 * 1024  # 50 MB zip decompression ceiling
DEFAULT_USER_STORAGE_BASE = Path(__file__).resolve().parent.parent.parent / "data" / "users"

PDF_MAGIC = b"%PDF-"
DOCX_MAGIC = b"PK\x03\x04"


class FileSecurityValidator:
    """Validates document security, structural integrity, and isolated filesystem persistence."""

    def __init__(self, base_storage_dir: Optional[Path] = None):
        self.base_storage_dir = Path(base_storage_dir) if base_storage_dir else DEFAULT_USER_STORAGE_BASE

    def get_user_resumes_dir(self, user_id: int) -> Path:
        """Returns the isolated private directory for a user's resumes."""
        if not user_id or int(user_id) <= 0:
            raise ValidationError(f"Invalid user_id: {user_id}")
        user_dir = (self.base_storage_dir / str(user_id) / "resumes").resolve()
        user_dir.mkdir(parents=True, exist_ok=True)
        return user_dir

    def get_user_job_descriptions_dir(self, user_id: int) -> Path:
        """Returns the isolated private directory for a user's uploaded job descriptions."""
        if not user_id or int(user_id) <= 0:
            raise ValidationError(f"Invalid user_id: {user_id}")
        user_dir = (self.base_storage_dir / str(user_id) / "job_descriptions").resolve()
        user_dir.mkdir(parents=True, exist_ok=True)
        return user_dir

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitizes original filename for display and metadata storage, stripping path traversal."""
        if not filename or not filename.strip():
            return "resume_document"
        clean = Path(filename).name
        # Remove null bytes and non-printable characters
        clean = clean.replace("\x00", "").strip()
        # Remove dangerous traversal patterns and slashes
        clean = re.sub(r"[/\\]+", "", clean)
        clean = re.sub(r"\.\.+", "", clean)
        return clean or "resume_document"

    @staticmethod
    def generate_storage_filename(original_filename: str) -> str:
        """Generates a cryptographically random UUID storage filename preserving original extension."""
        clean_ext = Path(original_filename).suffix.lstrip(".").lower()
        if clean_ext not in ("pdf", "docx"):
            clean_ext = "pdf"
        return f"{uuid.uuid4()}.{clean_ext}"

    @staticmethod
    def validate_path_containment(target_path: Path, base_dir: Path) -> None:
        """Asserts that target_path is strictly located inside base_dir, preventing path traversal."""
        resolved_target = Path(target_path).resolve()
        resolved_base = Path(base_dir).resolve()
        try:
            resolved_target.relative_to(resolved_base)
        except ValueError:
            from src.database.exceptions import FileSecurityError
            raise FileSecurityError(f"Path traversal detected: '{target_path}' escapes directory '{base_dir}'.")

    def save_file(self, file_bytes: bytes, dest_path: Path, user_id: Optional[int] = None) -> Path:
        """Atomically saves bytes to dest_path using a temporary write and fsync."""
        dest = Path(dest_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        temp_path = dest.parent / f"{dest.name}.tmp_{secrets.token_hex(4)}"

        try:
            with open(temp_path, "wb") as f:
                f.write(file_bytes)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, dest)
            return dest
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass

    def validate_file(self, file_bytes: bytes, original_filename: str) -> Tuple[str, str]:
        """Validates file size, format extension, magic bytes, and structural integrity.
        
        Returns:
            Tuple[detected_format: str ('pdf' | 'docx'), file_hash: str]
        """
        if not file_bytes:
            raise ValidationError("File content is empty (0 bytes).")

        # 1. Size Limit Check
        file_size = len(file_bytes)
        if file_size > MAX_FILE_SIZE_BYTES:
            raise FileTooLargeError(
                f"File size ({file_size / (1024*1024):.2f} MB) exceeds maximum allowed limit of 10 MB."
            )

        # 2. Path Traversal & Extension Check
        if "\x00" in original_filename or ".." in original_filename:
            raise ValidationError(f"Path traversal attempt detected in filename: '{original_filename}'")

        clean_ext = Path(original_filename).suffix.lower()
        if clean_ext not in (".pdf", ".docx"):
            raise InvalidFileFormatError(
                f"Unsupported file extension '{clean_ext}'. Only .pdf and .docx documents are accepted."
            )

        # 3. Magic-Bytes & Structural Inspection
        if file_bytes.startswith(PDF_MAGIC) or clean_ext == ".pdf":
            detected_format = self._validate_pdf_structure(file_bytes)
        elif file_bytes.startswith(DOCX_MAGIC) or clean_ext == ".docx":
            detected_format = self._validate_docx_structure(file_bytes)
        else:
            raise InvalidFileFormatError(
                "File signature mismatch. Document is neither a valid PDF nor a valid DOCX file."
            )

        file_hash = hashlib.sha256(file_bytes).hexdigest()
        return detected_format, file_hash

    def _validate_pdf_structure(self, file_bytes: bytes) -> str:
        """Deeply inspects PDF header and stream readability using pypdf."""
        if not file_bytes.startswith(PDF_MAGIC):
            raise InvalidFileFormatError("Invalid PDF header magic bytes.")

        stream = io.BytesIO(file_bytes)
        try:
            reader = PdfReader(stream)
            if reader.is_encrypted:
                # Try empty password; if locked, reject
                try:
                    decrypted = reader.decrypt("")
                    if decrypted == 0:
                        raise EncryptedFileError("PDF document is encrypted with a password and cannot be processed.")
                except Exception:
                    raise EncryptedFileError("PDF document is encrypted with a password and cannot be processed.")
            # Verify page readability
            _ = len(reader.pages)
        except (EncryptedFileError, InvalidFileFormatError):
            raise
        except PdfReadError as e:
            raise CorruptedFileError(f"Malformed or corrupted PDF document: {e}")
        except Exception as e:
            raise CorruptedFileError(f"Failed to read PDF structure: {e}")

        return "pdf"

    def _validate_docx_structure(self, file_bytes: bytes) -> str:
        """Validates DOCX PK ZIP archive, decompression ratios, and OpenXML structure."""
        if not file_bytes.startswith(DOCX_MAGIC):
            raise InvalidFileFormatError("Invalid DOCX zip header magic bytes.")

        stream = io.BytesIO(file_bytes)
        try:
            with zipfile.ZipFile(stream, "r") as zf:
                # Decompression Bomb Defense: calculate uncompressed volume
                total_uncompressed = 0
                for info in zf.infolist():
                    total_uncompressed += info.file_size
                    if total_uncompressed > MAX_UNCOMPRESSED_DOCX_BYTES:
                        raise CorruptedFileError(
                            "DOCX archive exceeds safe uncompressed expansion limit (possible decompression bomb)."
                        )

                namelist = zf.namelist()
                has_document = "word/document.xml" in namelist
                has_types = "[Content_Types].xml" in namelist
                if not (has_document or has_types):
                    raise CorruptedFileError("DOCX archive is missing critical OpenXML components (word/document.xml).")

            # Verify python-docx can parse the document
            stream.seek(0)
            doc = Document(stream)
            _ = len(doc.paragraphs)
        except (CorruptedFileError, InvalidFileFormatError):
            raise
        except zipfile.BadZipFile as e:
            raise CorruptedFileError(f"Malformed or invalid DOCX zip archive: {e}")
        except Exception as e:
            raise CorruptedFileError(f"Failed to read DOCX structure: {e}")

        return "docx"

    def save_user_resume_file(
        self,
        user_id: int,
        file_bytes: bytes,
        original_filename: str,
    ) -> Tuple[str, str, int, str]:
        """Atomically stores a validated resume file in private user directory using a UUID filename.
        
        Returns:
            Tuple[storage_filename: str, file_format: str, file_size_bytes: int, file_hash: str]
        """
        detected_format, file_hash = self.validate_file(file_bytes, original_filename)
        user_dir = self.get_user_resumes_dir(user_id)

        # Generate unguessable UUID storage filename
        unique_name = f"{uuid.uuid4().hex}.{detected_format}"
        final_path = user_dir / unique_name
        temp_path = user_dir / f"{unique_name}.tmp_{secrets.token_hex(4)}"

        try:
            # Atomic write
            with open(temp_path, "wb") as f:
                f.write(file_bytes)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_path, final_path)
            logger.info(
                "Securely persisted resume for User #%d: '%s' -> %s (%d bytes, SHA-256: %s)",
                user_id,
                self.sanitize_filename(original_filename),
                unique_name,
                len(file_bytes),
                file_hash[:12],
            )
            return unique_name, detected_format, len(file_bytes), file_hash
        except Exception as e:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            logger.error("Failed to write resume file atomically: %s", e)
            raise

    def get_stored_resume_path(self, user_id: int, storage_filename: str) -> Path:
        """Resolves and validates storage path within user's isolated directory, preventing path traversal."""
        if ".." in storage_filename or "/" in storage_filename or "\\" in storage_filename:
            raise ValidationError(f"Path traversal detected in storage filename: '{storage_filename}'")

        clean_name = Path(storage_filename).name
        user_dir = self.get_user_resumes_dir(user_id)
        target_path = (user_dir / clean_name).resolve()

        # Strict containment assertion
        if not str(target_path).startswith(str(user_dir)):
            raise ValidationError(f"Storage path escapes user sandbox: '{target_path}'")

        if not target_path.is_file():
            raise FileNotFoundError(f"Stored resume file not found on disk: {clean_name}")

        return target_path

    def delete_stored_resume_file(self, user_id: int, storage_filename: str) -> bool:
        """Securely deletes a physical resume file from user's storage."""
        try:
            path = self.get_stored_resume_path(user_id, storage_filename)
            path.unlink()
            logger.info("Deleted physical resume file for User #%d: %s", user_id, storage_filename)
            return True
        except FileNotFoundError:
            logger.warning("Resume file %s for User #%d was already missing from disk.", storage_filename, user_id)
            return False

    def save_user_job_description_file(
        self,
        user_id: int,
        file_bytes: bytes,
        original_filename: str,
        user_base_dir: Optional[Path] = None,
    ) -> Tuple[str, str, int, str]:
        """Atomically stores a validated job description file in private user directory using a UUID filename.

        Returns:
            Tuple[storage_filename: str, file_format: str, file_size_bytes: int, file_hash: str]
        """
        detected_format, file_hash = self.validate_file(file_bytes, original_filename)
        user_dir = user_base_dir or self.get_user_job_descriptions_dir(user_id)
        user_dir.mkdir(parents=True, exist_ok=True)

        unique_name = f"{uuid.uuid4().hex}.{detected_format}"
        final_path = user_dir / unique_name
        temp_path = user_dir / f"{unique_name}.tmp_{secrets.token_hex(4)}"

        try:
            with open(temp_path, "wb") as f:
                f.write(file_bytes)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_path, final_path)
            logger.info(
                "Securely persisted job description for User #%d: '%s' -> %s (%d bytes, SHA-256: %s)",
                user_id,
                self.sanitize_filename(original_filename),
                unique_name,
                len(file_bytes),
                file_hash[:12],
            )
            return unique_name, detected_format, len(file_bytes), file_hash
        except Exception as e:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            logger.error("Failed to write job description file atomically: %s", e)
            raise

    def get_stored_job_description_path(
        self,
        user_id: int,
        storage_filename: str,
        user_base_dir: Optional[Path] = None,
    ) -> Path:
        """Resolves and validates storage path within user's isolated job descriptions directory."""
        if ".." in storage_filename or "/" in storage_filename or "\\" in storage_filename:
            raise ValidationError(f"Path traversal detected in storage filename: '{storage_filename}'")

        clean_name = Path(storage_filename).name

        user_dir = user_base_dir or self.get_user_job_descriptions_dir(user_id)
        user_dir = user_dir.resolve()
        target_path = (user_dir / clean_name).resolve()

        if not str(target_path).startswith(str(user_dir)):
            raise ValidationError(f"Storage path escapes user sandbox: '{target_path}'")

        if not target_path.is_file():
            raise FileNotFoundError(f"Stored job description file not found on disk: {clean_name}")

        return target_path

    def delete_stored_job_description_file(
        self,
        user_id: int,
        storage_filename: str,
        user_base_dir: Optional[Path] = None,
    ) -> bool:
        """Securely deletes a physical job description file from user's storage."""
        try:
            path = self.get_stored_job_description_path(user_id, storage_filename, user_base_dir=user_base_dir)
            path.unlink()
            logger.info("Deleted physical job description file for User #%d: %s", user_id, storage_filename)
            return True
        except FileNotFoundError:
            logger.warning("Job description file %s for User #%d was already missing from disk.", storage_filename, user_id)
            return False

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
import re
import secrets
import uuid
import warnings
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from docx import Document
from PIL import Image
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from src.database.exceptions import (
    CorruptedFileError,
    EncryptedFileError,
    FileSecurityError,
    FileTooLargeError,
    InvalidFileFormatError,
    ValidationError,
)
from src.utils.logger import setup_logger

logger = setup_logger("FileSecurity")

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_UNCOMPRESSED_DOCX_BYTES = 50 * 1024 * 1024  # 50 MB zip decompression ceiling
MAX_CONFIRMATION_IMAGE_PIXELS = 25_000_000  # 25 megapixels safe decompression ceiling
DEFAULT_USER_STORAGE_BASE = Path(__file__).resolve().parent.parent.parent / "data" / "users"

PDF_MAGIC = b"%PDF-"
DOCX_MAGIC = b"PK\x03\x04"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
ALLOWED_CONFIRMATION_EXTENSIONS = (".pdf", ".png", ".jpg", ".jpeg")


class FileSecurityValidator:
    """Validates document security, structural integrity, and isolated filesystem persistence."""

    def __init__(self, base_storage_dir: Path | None = None):
        self.base_storage_dir = Path(base_storage_dir) if base_storage_dir else DEFAULT_USER_STORAGE_BASE

    def get_candidate_storage_root(self, user_id: int) -> Path:
        """Returns the isolated private root directory for a candidate (data/users/<user_id>/)."""
        if not user_id:
            raise ValidationError("user_id is mandatory.")
        try:
            uid = int(user_id)
            if uid <= 0:
                raise ValidationError(f"Invalid user_id: {user_id}")
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid user_id: {user_id}")

        base_dir = Path(self.base_storage_dir)
        raw_root = base_dir / str(uid)

        # Inspect candidate directory before following symlinks
        if os.path.lexists(raw_root) and (os.path.islink(raw_root) or raw_root.is_symlink()):
            raise FileSecurityError(
                f"Candidate root directory cannot be a symbolic link: '{raw_root}'"
            )

        raw_root.mkdir(parents=True, exist_ok=True)
        if os.path.islink(raw_root) or raw_root.is_symlink():
            raise FileSecurityError(
                f"Candidate root directory cannot be a symbolic link: '{raw_root}'"
            )

        resolved_base = base_dir.resolve()
        resolved_root = raw_root.resolve()

        try:
            rel = resolved_root.relative_to(resolved_base)
        except ValueError:
            raise FileSecurityError(
                f"Candidate root '{raw_root}' resolved outside base storage '{base_dir}'."
            )

        if rel.parts != (str(uid),):
            raise FileSecurityError(
                f"Candidate root '{raw_root}' resolved to unexpected path '{resolved_root}' (expected relative path '{uid}')."
            )

        return resolved_root

    def get_user_resumes_dir(self, user_id: int) -> Path:
        """Returns the isolated private directory for a user's resumes."""
        cand_root = self.get_candidate_storage_root(user_id)
        raw_dir = cand_root / "resumes"
        if os.path.lexists(raw_dir) and (os.path.islink(raw_dir) or raw_dir.is_symlink()):
            raise FileSecurityError(f"User resumes directory cannot be a symbolic link: '{raw_dir}'")
        raw_dir.mkdir(parents=True, exist_ok=True)
        if os.path.islink(raw_dir) or raw_dir.is_symlink():
            raise FileSecurityError(f"User resumes directory cannot be a symbolic link: '{raw_dir}'")
        resolved = raw_dir.resolve()
        resolved.relative_to(cand_root)
        return resolved

    def get_user_job_descriptions_dir(self, user_id: int) -> Path:
        """Returns the isolated private directory for a user's uploaded job descriptions."""
        cand_root = self.get_candidate_storage_root(user_id)
        raw_dir = cand_root / "job_descriptions"
        if os.path.lexists(raw_dir) and (os.path.islink(raw_dir) or raw_dir.is_symlink()):
            raise FileSecurityError(f"User job descriptions directory cannot be a symbolic link: '{raw_dir}'")
        raw_dir.mkdir(parents=True, exist_ok=True)
        if os.path.islink(raw_dir) or raw_dir.is_symlink():
            raise FileSecurityError(f"User job descriptions directory cannot be a symbolic link: '{raw_dir}'")
        resolved = raw_dir.resolve()
        resolved.relative_to(cand_root)
        return resolved

    def get_user_confirmations_dir(self, user_id: int) -> Path:
        """Returns the isolated private directory for a user's submission confirmations."""
        cand_root = self.get_candidate_storage_root(user_id)
        raw_dir = cand_root / "confirmations"
        if os.path.lexists(raw_dir) and (os.path.islink(raw_dir) or raw_dir.is_symlink()):
            raise FileSecurityError(f"User confirmations directory cannot be a symbolic link: '{raw_dir}'")
        raw_dir.mkdir(parents=True, exist_ok=True)
        if os.path.islink(raw_dir) or raw_dir.is_symlink():
            raise FileSecurityError(f"User confirmations directory cannot be a symbolic link: '{raw_dir}'")
        resolved = raw_dir.resolve()
        resolved.relative_to(cand_root)
        return resolved

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
    def generate_confirmation_storage_filename(application_id: int, detected_format: str) -> str:
        """Generates a secure server-generated filename for confirmation proof.

        Format: proof_<application_id>_<timestamp>_<uuid>.<ext>
        """
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        u = uuid.uuid4().hex[:16]
        clean_ext = "jpg" if detected_format == "jpeg" else detected_format
        return f"proof_{application_id}_{ts}_{u}.{clean_ext}"

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

    def save_file(self, file_bytes: bytes, dest_path: Path, user_id: int | None = None) -> Path:
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

    def validate_file(self, file_bytes: bytes, original_filename: str) -> tuple[str, str]:
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

    def _validate_image_structure(self, file_bytes: bytes, expected_format: str) -> None:
        """Deeply inspects image headers, pixel limits, and stream readability using Pillow."""
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            orig_max = Image.MAX_IMAGE_PIXELS
            Image.MAX_IMAGE_PIXELS = MAX_CONFIRMATION_IMAGE_PIXELS
            try:
                stream = io.BytesIO(file_bytes)
                img = Image.open(stream)
                if img.format != expected_format:
                    raise InvalidFileFormatError(
                        f"Image format mismatch: detected '{img.format}', expected '{expected_format}'."
                    )
                width, height = img.size
                if width <= 0 or height <= 0:
                    raise CorruptedFileError("Invalid image dimensions (zero or negative).")
                if width * height > MAX_CONFIRMATION_IMAGE_PIXELS:
                    raise CorruptedFileError(
                        f"Image dimensions ({width}x{height} = {width * height} pixels) exceed safe maximum ({MAX_CONFIRMATION_IMAGE_PIXELS} pixels)."
                    )
                img.verify()

                # Re-open stream and load pixel data to ensure valid chunks and no truncation
                stream.seek(0)
                img_decode = Image.open(stream)
                img_decode.load()
            except (Image.DecompressionBombError, Image.DecompressionBombWarning) as e:
                raise CorruptedFileError(f"Image exceeds safe decompression limits (possible decompression bomb): {e}")
            except (InvalidFileFormatError, CorruptedFileError):
                raise
            except (OSError, ValueError, RuntimeError) as e:
                raise CorruptedFileError(f"Malformed or corrupted image document: {e}")
            finally:
                Image.MAX_IMAGE_PIXELS = orig_max

    def validate_confirmation_proof(self, file_bytes: bytes, original_filename: str) -> tuple[str, str]:
        """Validates confirmation evidence size, extension, magic bytes, and structural integrity.

        Allowed formats: .pdf, .png, .jpg, .jpeg.
        Explicitly rejects: .docx, scripts, executables, HTML, SVG, ZIP, corrupted/malformed images.

        Returns:
            Tuple[detected_format: str ('pdf' | 'png' | 'jpeg'), file_hash: str]
        """
        if not file_bytes:
            raise ValidationError("File content is empty (0 bytes).")

        # 1. Size Limit Check (10 MB)
        file_size = len(file_bytes)
        if file_size > MAX_FILE_SIZE_BYTES:
            raise FileTooLargeError(
                f"File size ({file_size / (1024*1024):.2f} MB) exceeds maximum allowed limit of 10 MB."
            )

        # 2. Path Traversal & Filename Check
        if "\x00" in original_filename or ".." in original_filename:
            raise ValidationError(f"Path traversal attempt detected in filename: '{original_filename}'")

        clean_ext = Path(original_filename).suffix.lower()
        if clean_ext not in ALLOWED_CONFIRMATION_EXTENSIONS:
            raise InvalidFileFormatError(
                f"Unsupported file extension '{clean_ext}'. Only .pdf, .png, .jpg, and .jpeg files are accepted for confirmation evidence."
            )

        # 3. Check for obvious non-allowed magic bytes like ZIP / DOCX / EXE
        if file_bytes.startswith(DOCX_MAGIC):
            raise InvalidFileFormatError("ZIP/DOCX archive files are rejected for confirmation evidence.")
        if file_bytes.startswith(b"MZ"):
            raise InvalidFileFormatError("Executable files are rejected.")
        if file_bytes.strip().lower().startswith((b"<html", b"<!doctype html", b"<svg")):
            raise InvalidFileFormatError("HTML/SVG files are rejected for confirmation evidence.")

        # 4. Magic-Bytes & Structural Inspection
        if clean_ext == ".pdf":
            if not file_bytes.startswith(PDF_MAGIC):
                raise InvalidFileFormatError("Invalid PDF header magic bytes.")
            detected_format = self._validate_pdf_structure(file_bytes)
        elif clean_ext == ".png":
            if not file_bytes.startswith(PNG_MAGIC):
                raise InvalidFileFormatError("Invalid PNG header magic bytes.")
            self._validate_image_structure(file_bytes, expected_format="PNG")
            detected_format = "png"
        elif clean_ext in (".jpg", ".jpeg"):
            if not file_bytes.startswith(JPEG_MAGIC):
                raise InvalidFileFormatError("Invalid JPEG header magic bytes.")
            self._validate_image_structure(file_bytes, expected_format="JPEG")
            detected_format = "jpeg"
        else:
            raise InvalidFileFormatError(f"Unsupported file format '{clean_ext}'.")

        # 5. Check for extension and format mismatch
        if detected_format == "pdf" and file_bytes.startswith((PNG_MAGIC, JPEG_MAGIC)):
            raise InvalidFileFormatError("Extension and actual file format mismatch.")
        if detected_format in ("png", "jpeg") and file_bytes.startswith(PDF_MAGIC):
            raise InvalidFileFormatError("Extension and actual file format mismatch.")

        file_hash = hashlib.sha256(file_bytes).hexdigest()
        return detected_format, file_hash

    def save_user_confirmation_file(
        self,
        user_id: int,
        application_id: int,
        file_bytes: bytes,
        original_filename: str,
    ) -> tuple[str, str, int, str]:
        """Atomically stores a validated submission confirmation proof file in private user directory.

        Returns:
            Tuple[storage_filename: str, file_format: str, file_size_bytes: int, file_hash: str]
        """
        detected_format, file_hash = self.validate_confirmation_proof(file_bytes, original_filename)
        user_dir = self.get_user_confirmations_dir(user_id)

        storage_filename = self.generate_confirmation_storage_filename(application_id, detected_format)
        final_path = (user_dir / storage_filename).resolve()
        self.validate_path_containment(final_path, user_dir)
        temp_path = user_dir / f"{storage_filename}.tmp_{secrets.token_hex(4)}"

        try:
            with open(temp_path, "wb") as f:
                f.write(file_bytes)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_path, final_path)
            logger.info(
                "Securely persisted confirmation proof for User #%d, App #%d: '%s' -> %s (%d bytes, SHA-256: %s)",
                user_id,
                application_id,
                self.sanitize_filename(original_filename),
                storage_filename,
                len(file_bytes),
                file_hash[:12],
            )
            return storage_filename, detected_format, len(file_bytes), file_hash
        except Exception as e:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            logger.error("Failed to write confirmation proof file atomically: %s", e)
            raise

    def save_user_resume_file(
        self,
        user_id: int,
        file_bytes: bytes,
        original_filename: str,
    ) -> tuple[str, str, int, str]:
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
        user_base_dir: Path | None = None,
    ) -> tuple[str, str, int, str]:
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
        user_base_dir: Path | None = None,
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
        user_base_dir: Path | None = None,
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

    def resolve_and_verify_candidate_file(
        self,
        user_id: int,
        file_path: str | Path | None,
        expected_hash: str | None = None,
        expected_size: int | None = None,
        expected_format: str | None = None,
        is_mandatory: bool = True,
        resource_desc: str = "Candidate file",
    ) -> tuple[Path, bytes, str, int]:
        """Resolves, checks containment, and verifies cryptographic integrity of a candidate file.

        Enforces:
        1. Non-empty path requirement if is_mandatory is True.
        2. Immediate rejection of null bytes and '..' path traversal sequences.
        3. Strict containment within candidate's private storage root (data/users/<user_id>/).
        4. Rejection of symbolic links on all parent directory components and the final file.
        5. Regular readable file validation.
        6. Maximum file size check (10 MB) and exact byte-size match against expected_size.
        7. Recomputed SHA-256 digest validation against expected_hash (fail closed on mismatch or invalid hash).
        8. Magic-byte verification for expected document format (PDF, DOCX, PNG, JPEG).

        Returns:
            Tuple[resolved_path: Path, file_bytes: bytes, file_hash: str, file_size: int]
        """
        if not user_id:
            raise ValidationError("user_id is mandatory.")
        try:
            uid = int(user_id)
            if uid <= 0:
                raise ValidationError(f"Invalid user_id: {user_id}")
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid user_id: {user_id}")

        if not file_path or not str(file_path).strip():
            if is_mandatory:
                raise ValidationError(f"{resource_desc} path is missing or empty.")
            return Path(""), b"", "", 0

        path_str = str(file_path).strip()
        if "\x00" in path_str:
            raise FileSecurityError(f"Null byte detected in {resource_desc} path: '{file_path}'")
        if ".." in path_str or ".." in Path(path_str).parts:
            raise FileSecurityError(f"Path traversal detected in {resource_desc} path: '{file_path}'")

        candidate_root = self.get_candidate_storage_root(uid)
        raw_path = Path(path_str)

        # 1. Inspect original supplied path before resolution
        # Check absolute vs relative containment
        base_dir = Path(self.base_storage_dir)
        resolved_base = base_dir.resolve()

        if raw_path.is_absolute():
            # Check if relative to base_dir, resolved_base, or candidate_root
            rel_from_base = None
            try:
                rel_from_base = raw_path.relative_to(base_dir)
            except ValueError:
                try:
                    rel_from_base = raw_path.relative_to(resolved_base)
                except ValueError:
                    pass

            if rel_from_base is not None:
                if not rel_from_base.parts or rel_from_base.parts[0] != str(uid):
                    raise FileSecurityError(
                        f"Path containment violation: {resource_desc} '{file_path}' is outside candidate storage root '{candidate_root}'."
                    )
                rel = Path(*rel_from_base.parts[1:])
            else:
                try:
                    rel = raw_path.relative_to(candidate_root)
                except ValueError:
                    try:
                        rel = raw_path.relative_to(candidate_root.resolve())
                    except ValueError:
                        raise FileSecurityError(
                            f"Path containment violation: {resource_desc} '{file_path}' is outside candidate storage root '{candidate_root}'."
                        )
            effective_path = candidate_root.joinpath(*rel.parts)
        else:
            # Relative path
            parts = raw_path.parts
            if parts and parts[0] == str(uid):
                rel = Path(*parts[1:])
            else:
                rel = raw_path
            effective_path = candidate_root.joinpath(*rel.parts)

        # 2. Inspect every component from candidate_root down to target BEFORE resolving
        if ".." in rel.parts:
            raise FileSecurityError(f"Path traversal detected in {resource_desc} path: '{file_path}'")

        curr = candidate_root
        for part in rel.parts:
            curr = curr / part
            if os.path.lexists(curr) and (os.path.islink(curr) or curr.is_symlink()):
                raise FileSecurityError(
                    f"Symbolic link detected: {resource_desc} path component '{curr}' cannot be a symbolic link."
                )

        # 3. Resolve path only after original path components have been checked
        resolved_target = effective_path.resolve()
        try:
            resolved_target.relative_to(candidate_root)
        except ValueError:
            raise FileSecurityError(
                f"Path containment violation: {resource_desc} '{file_path}' resolves outside candidate storage root '{candidate_root}'."
            )

        if not resolved_target.exists():
            raise FileNotFoundError(f"{resource_desc} not found on disk at '{resolved_target}'.")

        if os.path.islink(resolved_target) or resolved_target.is_symlink() or not resolved_target.is_file():
            raise ValidationError(f"{resource_desc} path '{resolved_target}' is not a regular file.")

        # 4. Open and read actual bytes using O_NOFOLLOW
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(resolved_target, flags)
            with os.fdopen(fd, "rb") as f:
                file_bytes = f.read()
        except OSError as read_err:
            raise CorruptedFileError(f"Failed to read {resource_desc} file on disk: {read_err}")

        actual_size = len(file_bytes)
        if actual_size > MAX_FILE_SIZE_BYTES:
            raise FileTooLargeError(
                f"{resource_desc} size ({actual_size / (1024*1024):.2f} MB) exceeds maximum allowed limit of 10 MB."
            )

        if expected_size is not None:
            if not isinstance(expected_size, int) or expected_size < 0:
                raise ValidationError(f"Invalid expected size metadata for {resource_desc}: {expected_size}")
            if actual_size != expected_size:
                raise ValidationError(
                    f"{resource_desc} file size on disk ({actual_size} bytes) does not match manifest ({expected_size} bytes)."
                )

        actual_hash = hashlib.sha256(file_bytes).hexdigest()
        if expected_hash is not None:
            if not isinstance(expected_hash, str) or len(expected_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in expected_hash):
                raise ValidationError(f"Invalid expected SHA-256 metadata for {resource_desc}: '{expected_hash}'.")
            if actual_hash.lower() != expected_hash.lower():
                if "source resume" in resource_desc.lower():
                    raise ValidationError("Original source resume file hash has changed since packet creation.")
                raise ValidationError(
                    f"{resource_desc} SHA-256 hash on disk ({actual_hash}) does not match expected hash ({expected_hash})."
                )

        # Magic byte validation
        clean_ext = resolved_target.suffix.lstrip(".").lower()
        fmt = (expected_format or clean_ext).lower()
        if fmt == "pdf":
            if not file_bytes.startswith(PDF_MAGIC):
                raise InvalidFileFormatError(f"{resource_desc} is missing valid PDF header magic bytes.")
        elif fmt == "docx":
            if not file_bytes.startswith(DOCX_MAGIC):
                raise InvalidFileFormatError(f"{resource_desc} is missing valid DOCX header magic bytes.")
        elif fmt == "png":
            if not file_bytes.startswith(PNG_MAGIC):
                raise InvalidFileFormatError(f"{resource_desc} is missing valid PNG header magic bytes.")
        elif fmt in ("jpg", "jpeg"):
            if not file_bytes.startswith(JPEG_MAGIC):
                raise InvalidFileFormatError(f"{resource_desc} is missing valid JPEG header magic bytes.")

        return resolved_target, file_bytes, actual_hash, actual_size

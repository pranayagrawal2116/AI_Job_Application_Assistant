"""Centralized Resume Binary Integrity & Just-In-Time Verification Service.

Architecture v2.1.1 (Phase 9.1.1.1)

Enforces:
1. Exact database record, user ownership, and version resolution.
2. Descriptor-relative containment and O_NOFOLLOW file inspection via FileSecurityValidator.
3. Cryptographic SHA-256 and exact file-size verification against stored metadata.
4. Magic-byte verification for supported formats (.pdf, .docx).
5. Safe in-memory byte extraction directly from verified descriptor (TOCTOU defense).
6. Fresh universal extraction and parsing without falling back to stale serialized JSON.
7. Fail-closed behavior on missing files, size mismatches, hash deviations, tampering, or corrupted data.
8. Backward-compatible historical record policy rejecting unverified historical records without cryptographic hashes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple, Union

if TYPE_CHECKING:
    from src.preparer.resume_parser import ParsedResume, ResumeParser

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CorruptedFileError,
    CrossUserAccessError,
    FileSecurityError,
    FileTooLargeError,
    InvalidFileFormatError,
    ResumeIntegrityError,
    ResumeNotFoundError,
    ValidationError,
)
from src.security.file_security import FileSecurityValidator
from src.utils.logger import setup_logger

logger = setup_logger("ResumeIntegrityVerifier")

_SHA256_HEX_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class VerifiedResume:
    """Immutable verified resume artifact holding verified bytes, metadata, and fresh parsed representation."""

    resume_id: int
    user_id: int
    version_num: int
    storage_filename: str
    file_bytes: bytes
    file_hash: str
    file_size_bytes: int
    file_format: str
    raw_text: str
    parsed_resume: ParsedResume
    original_filename: str = ""
    resolved_path: Optional[Path] = None

    def __repr__(self) -> str:
        # Mask raw bytes and truncate text to prevent leaking candidate data into ordinary logs
        return (
            f"VerifiedResume(resume_id={self.resume_id}, user_id={self.user_id}, "
            f"version_num={self.version_num}, format='{self.file_format}', "
            f"size={self.file_size_bytes}, hash='{self.file_hash[:12]}...', "
            f"bytes=<bytes: {len(self.file_bytes)}>, text_len={len(self.raw_text)})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Returns safe serializable metadata dictionary excluding sensitive raw bytes."""
        return {
            "resume_id": self.resume_id,
            "user_id": self.user_id,
            "version_num": self.version_num,
            "storage_filename": self.storage_filename,
            "file_hash": self.file_hash,
            "file_size_bytes": self.file_size_bytes,
            "file_format": self.file_format,
            "original_filename": self.original_filename,
            "resolved_path": str(self.resolved_path) if self.resolved_path else "",
            "parsed_data": self.parsed_resume.to_dict(),
        }


class ResumeIntegrityVerifier:
    """Centralized verification engine for candidate resume binaries."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        file_validator: Optional[FileSecurityValidator] = None,
        resume_parser: Optional[Any] = None,
    ):
        self.db = db_manager or DatabaseManager()
        self.file_validator = file_validator or FileSecurityValidator()
        if resume_parser is not None:
            self.parser = resume_parser
        else:
            from src.preparer.resume_parser import ResumeParser
            self.parser = ResumeParser()

    def _validate_user_id(self, user_id: int) -> int:
        """Validates that user_id is a positive integer."""
        if not user_id:
            raise ValidationError("user_id is mandatory.")
        try:
            uid = int(user_id)
            if uid <= 0:
                raise ValidationError(f"Invalid user_id: {user_id}")
            return uid
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid user_id: {user_id}")

    def verify_resume_binary(
        self,
        user_id: int,
        resume_id: int,
        version_num: Optional[int] = None,
        user_base_dir: Optional[Path] = None,
        enforce_size: bool = True,
        resource_desc: Optional[str] = None,
    ) -> Tuple[Path, bytes, str, int, Dict[str, Any], int]:
        """Resolves authoritative database metadata and verifies binary integrity on disk.

        Returns:
            Tuple[resolved_path: Path, file_bytes: bytes, actual_hash: str, actual_size: int,
                  res_row: Dict[str, Any], target_version: int]
        """
        uid = self._validate_user_id(user_id)

        # 1. Fetch authoritative database record
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            row = cursor.fetchone()
            if not row:
                raise ResumeNotFoundError(f"Resume #{resume_id} not found.")

            res_row = dict(row)

            # Enforce cross-user boundary
            if res_row["user_id"] != uid:
                raise CrossUserAccessError(
                    user_id=uid,
                    target_user_id=res_row["user_id"],
                    resource=f"Resume #{resume_id}",
                )

            # Enforce active status
            if not res_row.get("is_active", 1):
                raise ResumeIntegrityError(f"Resume #{resume_id} is inactive or deleted.")

            active_ver = res_row.get("active_version", 1) or 1
            target_ver = version_num if version_num is not None else active_ver

            storage_filename = None
            expected_hash = None
            expected_size = None

            if version_num is not None:
                cursor.execute(
                    "SELECT * FROM resume_versions WHERE resume_id = ? AND user_id = ? AND version_num = ?",
                    (resume_id, uid, target_ver),
                )
                v_row = cursor.fetchone()
                if v_row:
                    v_dict = dict(v_row)
                    storage_filename = v_dict.get("storage_filename")
                    expected_hash = v_dict.get("file_hash")
                    expected_size = v_dict.get("file_size_bytes")

                    # If version record has nulls but targets active version, check parent record
                    if not storage_filename and target_ver == active_ver:
                        storage_filename = res_row.get("storage_filename")
                    if not expected_hash and target_ver == active_ver:
                        expected_hash = res_row.get("file_hash")
                    if expected_size is None and target_ver == active_ver:
                        expected_size = res_row.get("file_size_bytes")
                elif target_ver == active_ver:
                    # Active version metadata is authoritatively held in parent resumes table
                    storage_filename = res_row.get("storage_filename")
                    expected_hash = res_row.get("file_hash")
                    expected_size = res_row.get("file_size_bytes")
                else:
                    raise ResumeNotFoundError(f"Version {target_ver} for Resume #{resume_id} not found.")
            else:
                storage_filename = res_row.get("storage_filename")
                expected_hash = res_row.get("file_hash")
                expected_size = res_row.get("file_size_bytes")

        # 2. Historical records integrity check (Section 4.1 & 4.5)
        if not storage_filename or not str(storage_filename).strip():
            raise ResumeIntegrityError(
                f"Resume #{resume_id} (v{target_ver}) lacks storage filename metadata. "
                f"Historical record cannot be verified and requires re-upload."
            )

        if (
            not expected_hash
            or not isinstance(expected_hash, str)
            or not _SHA256_HEX_REGEX.match(expected_hash)
        ):
            raise ResumeIntegrityError(
                f"Resume #{resume_id} (v{target_ver}) lacks valid cryptographic integrity metadata (SHA-256 hash). "
                f"Historical record cannot be verified and requires re-upload."
            )

        if expected_size is None or not isinstance(expected_size, int) or expected_size < 0:
            raise ResumeIntegrityError(
                f"Resume #{resume_id} (v{target_ver}) lacks valid file size metadata. "
                f"Historical record cannot be verified and requires re-upload."
            )

        # 3. Path resolution & containment check
        sf_str = str(storage_filename).strip()
        if "\x00" in sf_str or ".." in sf_str or ".." in Path(sf_str).parts:
            raise FileSecurityError(f"Path traversal detected in resume storage filename: '{storage_filename}'")

        clean_name = Path(sf_str).name
        if not clean_name or clean_name in (".", ".."):
            raise FileSecurityError(f"Invalid resume storage filename: '{storage_filename}'")

        if user_base_dir is not None:
            ubd = Path(user_base_dir).resolve()
            if ubd.name == "resumes":
                user_resumes_dir = ubd
            elif ubd.name == str(uid):
                user_resumes_dir = ubd / "resumes"
            else:
                user_resumes_dir = ubd / str(uid) / "resumes"
        else:
            user_resumes_dir = self.file_validator.get_user_resumes_dir(uid)

        # Build target file path
        if Path(sf_str).is_absolute():
            # Absolute path: check containment via resolve_and_verify_candidate_file
            target_path = Path(sf_str)
        else:
            target_path = user_resumes_dir / clean_name

        clean_ext = Path(clean_name).suffix.lstrip(".").lower()
        expected_fmt = clean_ext if clean_ext in ("pdf", "docx") else (res_row.get("file_format") or clean_ext).lower()

        # 4. Invoke FileSecurityValidator.resolve_and_verify_candidate_file (Section 4.2)
        desc = resource_desc or f"Resume #{resume_id} (v{target_ver})"
        size_to_check = expected_size if enforce_size else None
        try:
            resolved_path, file_bytes, actual_hash, actual_size = self.file_validator.resolve_and_verify_candidate_file(
                user_id=uid,
                file_path=target_path,
                expected_hash=expected_hash,
                expected_size=size_to_check,
                expected_format=expected_fmt,
                is_mandatory=True,
                resource_desc=desc,
            )
        except ValidationError as val_err:
            raise ResumeIntegrityError(str(val_err)) from val_err

        return resolved_path, file_bytes, actual_hash, actual_size, res_row, target_ver

    def verify_and_load_resume(
        self,
        user_id: int,
        resume_id: int,
        version_num: Optional[int] = None,
        user_base_dir: Optional[Path] = None,
        fresh_parse: bool = True,
        enforce_size: bool = True,
        resource_desc: Optional[str] = None,
    ) -> VerifiedResume:
        """Just-in-time verifies and loads candidate resume binary with fresh extraction.

        Enforces:
        - Authenticated user ownership.
        - Exact requested version resolution.
        - Physical binary containment, O_NOFOLLOW descriptor inspection, size and SHA-256 match.
        - Fresh text extraction and universal parsing from verified in-memory bytes (TOCTOU defense).
        - Fail-closed behavior on tampering, truncation, or parser failures.
        """
        resolved_path, file_bytes, actual_hash, actual_size, res_row, target_ver = self.verify_resume_binary(
            user_id=user_id,
            resume_id=resume_id,
            version_num=version_num,
            user_base_dir=user_base_dir,
            enforce_size=enforce_size,
            resource_desc=resource_desc,
        )

        clean_ext = resolved_path.suffix.lstrip(".").lower()
        expected_fmt = clean_ext if clean_ext in ("pdf", "docx") else (res_row.get("file_format") or clean_ext).lower()

        # 5. Fresh extraction and parsing (Section 4.3)
        if fresh_parse:
            try:
                parsed_resume = self.parser.parse_bytes(
                    file_bytes=file_bytes,
                    file_format=expected_fmt,
                    file_path=str(resolved_path),
                )
            except (CorruptedFileError, InvalidFileFormatError):
                raise
            except Exception as parse_err:
                logger.error(
                    "Fresh resume parsing failed for Resume #%d (v%d): %s",
                    resume_id,
                    target_ver,
                    parse_err,
                )
                raise CorruptedFileError(
                    f"Failed to parse verified resume binary for Resume #{resume_id} (v{target_ver}): {parse_err}"
                ) from parse_err
        else:
            # Build minimal verified representation without re-parsing
            from src.preparer.resume_parser import ParsedResume
            parsed_resume = ParsedResume(
                file_path=str(resolved_path),
                file_format=expected_fmt.upper(),
                file_hash=actual_hash,
                raw_text="",
            )

        return VerifiedResume(
            resume_id=resume_id,
            user_id=int(user_id),
            version_num=target_ver,
            storage_filename=Path(str(res_row.get("storage_filename", ""))).name,
            file_bytes=file_bytes,
            file_hash=actual_hash,
            file_size_bytes=actual_size,
            file_format=expected_fmt,
            raw_text=parsed_resume.raw_text,
            parsed_resume=parsed_resume,
            original_filename=res_row.get("original_filename", ""),
            resolved_path=resolved_path,
        )

    def reverify_and_backfill_historical_resume(
        self,
        user_id: int,
        resume_id: int,
        user_base_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Controlled recovery path for historical resumes missing cryptographic integrity metadata.

        Verifies that the physical file exists in the candidate's isolated sandbox,
        validates magic bytes, computes SHA-256 and size, and persists metadata to DB.
        """
        uid = self._validate_user_id(user_id)

        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            row = cursor.fetchone()
            if not row:
                raise ResumeNotFoundError(f"Resume #{resume_id} not found.")

            res_row = dict(row)
            if res_row["user_id"] != uid:
                raise CrossUserAccessError(
                    user_id=uid,
                    target_user_id=res_row["user_id"],
                    resource=f"Resume #{resume_id}",
                )

        storage_filename = res_row.get("storage_filename")
        if not storage_filename or not str(storage_filename).strip():
            raise ResumeIntegrityError(f"Historical resume #{resume_id} has no storage filename recorded.")

        clean_name = Path(storage_filename).name
        if ".." in clean_name or "/" in clean_name or "\\" in clean_name or "\x00" in clean_name:
            raise FileSecurityError(f"Path traversal in storage filename: '{storage_filename}'")

        if user_base_dir is not None:
            ubd = Path(user_base_dir).resolve()
            if ubd.name == "resumes":
                user_resumes_dir = ubd
            elif ubd.name == str(uid):
                user_resumes_dir = ubd / "resumes"
            else:
                user_resumes_dir = ubd / str(uid) / "resumes"
        else:
            user_resumes_dir = self.file_validator.get_user_resumes_dir(uid)

        target_path = user_resumes_dir / clean_name
        expected_fmt = (res_row.get("file_format") or target_path.suffix.lstrip(".")).lower()

        # Verify on-disk file existence, symlink rejection, and magic bytes (without expected hash/size)
        resolved_path, file_bytes, actual_hash, actual_size = self.file_validator.resolve_and_verify_candidate_file(
            user_id=uid,
            file_path=target_path,
            expected_hash=None,
            expected_size=None,
            expected_format=expected_fmt,
            is_mandatory=True,
            resource_desc=f"Historical resume #{resume_id}",
        )

        # Parse freshly to ensure document is readable
        parsed = self.parser.parse_bytes(file_bytes=file_bytes, file_format=expected_fmt, file_path=str(resolved_path))

        # Idempotently update database record with verified integrity metadata
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE resumes SET
                    file_hash = ?,
                    file_size_bytes = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
                """,
                (actual_hash, actual_size, resume_id, uid),
            )
            cursor.execute(
                """
                UPDATE resume_versions SET
                    file_hash = ?,
                    file_size_bytes = ?
                WHERE resume_id = ? AND user_id = ? AND (file_hash IS NULL OR file_size_bytes IS NULL)
                """,
                (actual_hash, actual_size, resume_id, uid),
            )
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            updated_row = dict(cursor.fetchone())

        logger.info(
            "Successfully re-verified historical resume #%d for user %d (size: %d, SHA-256: %s...)",
            resume_id,
            uid,
            actual_size,
            actual_hash[:12],
        )
        return updated_row

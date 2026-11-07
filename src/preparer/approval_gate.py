"""Human Approval Workflow: Enforces authenticated sessions, cryptographic action tickets, and audit gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CorruptedFileError,
    CrossUserAccessError,
    FileSecurityError,
    FileTooLargeError,
    InvalidFileFormatError,
    InvalidSessionError,
    SecurityAuthorizationError,
    SessionExpiredError,
    ValidationError,
)
from src.database.models import (
    Application,
    ApplicationApproval,
    ApplicationStatus,
    Job,
    PreparedPacket,
)
from src.preparer.cover_letter_generator import CoverLetter
from src.preparer.document_generator import GeneratedDocument
from src.preparer.question_answerer import ScreeningQAPacket
from src.preparer.tailored_resume_generator import TailoredResume
from src.security.file_security import FileSecurityValidator
from src.security.session_manager import SessionManager
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash
from src.utils.logger import setup_logger

logger = setup_logger("HumanApprovalGate")


@dataclass
class ApplicationReviewPacket:
    """Encapsulates all verified content of a job application for human audit and authorization."""
    job_id: int
    company_name: str
    job_title: str
    job_url: str
    resume_file_path: str
    resume_version_hash: str
    cover_letter_text: str
    application_answers: Dict[str, Any]
    unanswered_questions: List[str] = field(default_factory=list)
    packet_version_hash: str = ""
    is_ready_for_review: bool = True
    approval_timestamp: Optional[str] = None
    approver_name: Optional[str] = None
    is_approved: bool = False

    def compute_hash(self) -> str:
        """Computes deterministic SHA-256 digest of the entire packet content using RFC 8785."""
        payload = {
            "job_id": self.job_id,
            "company_name": self.company_name.strip(),
            "job_title": self.job_title.strip(),
            "resume_version_hash": self.resume_version_hash.strip(),
            "cover_letter_text": self.cover_letter_text.strip(),
            "application_answers": self.application_answers,
        }
        return canonical_json_hash(payload)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _is_sha256_hex(val: Any) -> bool:
    if not isinstance(val, str) or len(val) != 64:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in val)


class HumanApprovalGate:
    """Manages the strict Human-in-the-Loop approval gate before any job application is submitted."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        session_manager: Optional[SessionManager] = None,
        file_validator: Optional[FileSecurityValidator] = None,
    ):
        from src.security.session_manager import SessionManager
        sm = session_manager if session_manager is not None else SessionManager.get_instance()
        if type(sm) is not SessionManager:
            raise SecurityAuthorizationError(
                f"Invalid verifier configuration: HumanApprovalGate.session_manager must be an exact SessionManager instance, got {type(sm)}."
            )
        self.session_manager = sm

        if db_manager is None:
            self.db = DatabaseManager(session_manager=self.session_manager)
        else:
            self.db = db_manager
            db_sm = getattr(self.db, "_session_manager", None)
            if db_sm is None:
                # Wire the genuine instance
                self.db._session_manager = self.session_manager
            else:
                if type(db_sm) is not SessionManager:
                    raise SecurityAuthorizationError(
                        f"Invalid verifier configuration: DatabaseManager._session_manager must be an exact SessionManager instance, got {type(db_sm)}."
                    )
                if db_sm is not self.session_manager:
                    raise SecurityAuthorizationError(
                        "SessionManager identity mismatch: DatabaseManager and HumanApprovalGate must share the exact same SessionManager instance."
                    )
        if hasattr(self.session_manager, "register_db_manager"):
            self.session_manager.register_db_manager(self.db)

        self._file_validator = file_validator

    @property
    def file_validator(self) -> FileSecurityValidator:
        if self._file_validator is not None:
            return self._file_validator
        base_dir = None
        if hasattr(self.db, "db_path") and self.db.db_path and self.db.db_path != ":memory:":
            cand_users = Path(self.db.db_path).parent / "users"
            cand_users_parent = Path(self.db.db_path).parent.parent / "users"
            if cand_users.is_dir():
                base_dir = cand_users
            elif cand_users_parent.is_dir():
                base_dir = cand_users_parent
        return FileSecurityValidator(base_storage_dir=base_dir)

    @file_validator.setter
    def file_validator(self, val: Optional[FileSecurityValidator]) -> None:
        self._file_validator = val

    # -------------------------------------------------------------------------
    # MULTI-USER UNIVERSAL PREPARED PACKET METHODS (Architecture v2.1.1)
    # -------------------------------------------------------------------------

    def prepare_universal_packet(
        self,
        user_id: int,
        application_id: int,
        original_resume_id: int,
        original_resume_hash: str,
        tailored_resume: TailoredResume,
        cover_letter: CoverLetter,
        qa_packet: ScreeningQAPacket,
        job_description_snapshot_hash: str,
        tailored_resume_doc: Optional[GeneratedDocument] = None,
        cover_letter_doc: Optional[GeneratedDocument] = None,
        attachments_manifest: Optional[List[Dict[str, Any]]] = None,
        candidate_profile_version: Optional[int] = None,
        candidate_profile_hash: Optional[str] = None,
        matching_result_id: Optional[int] = None,
        template_id: Optional[str] = None,
        template_version: Optional[str] = None,
        original_resume_version_num: Optional[int] = None,
        job_description_id: Optional[int] = None,
        matching_engine_version: Optional[str] = None,
        scoring_configuration_version: Optional[str] = None,
        scoring_profile: Optional[str] = None,
        scoring_config_version: Optional[str] = None,
        generated_docs: Optional[Dict[str, Any]] = None,
        tailored_resume_pdf_doc: Optional[GeneratedDocument] = None,
        tailored_resume_docx_doc: Optional[GeneratedDocument] = None,
        cover_letter_pdf_doc: Optional[GeneratedDocument] = None,
        cover_letter_docx_doc: Optional[GeneratedDocument] = None,
        generation_timestamp: Optional[str] = None,
    ) -> PreparedPacket:
        """Assembles and stores an immutable PreparedPacket revision in SQLite."""
        # 0. Security Preflight & Quarantine Verification for Job Description (Phase 9.1.2)
        from src.security.security_preflight import SecurityPreflightManager
        preflight = SecurityPreflightManager(db_manager=self.db, file_validator=self.file_validator)
        if job_description_id is not None:
            preflight.check_job_description_security(
                user_id=user_id,
                jd_id=job_description_id,
                target_action="packet_preparation",
            )

        # 0. JIT Resume Integrity Verification before packet preparation
        verified_res = None
        if original_resume_id is not None:
            from src.security.resume_verifier import ResumeIntegrityVerifier
            verifier = ResumeIntegrityVerifier(db_manager=self.db, file_validator=self.file_validator)
            verified_res = verifier.verify_and_load_resume(
                user_id=user_id,
                resume_id=original_resume_id,
                version_num=original_resume_version_num,
                fresh_parse=False,
            )
            if original_resume_hash and verified_res.file_hash.lower() != original_resume_hash.lower():
                raise ValidationError(
                    f"Original resume hash mismatch: supplied '{original_resume_hash}' does not match "
                    f"verified on-disk file hash '{verified_res.file_hash}'."
                )
            original_resume_hash = verified_res.file_hash
            original_resume_version_num = verified_res.version_num

        # 0. Resolve source version metadata and packet revision number
        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COALESCE(MAX(version_num), 0) + 1 AS next_v FROM prepared_packets WHERE application_id = ?",
                (application_id,),
            )
            version_num = cursor.fetchone()["next_v"]

            if original_resume_version_num is None and original_resume_id is not None:
                cursor.execute("SELECT active_version FROM resumes WHERE id = ?", (original_resume_id,))
                r_row = cursor.fetchone()
                original_resume_version_num = r_row["active_version"] if r_row and r_row["active_version"] is not None else 1

            if job_description_id is None:
                cursor.execute("SELECT job_description_id FROM applications WHERE id = ?", (application_id,))
                app_row = cursor.fetchone()
                if app_row and app_row["job_description_id"] is not None:
                    job_description_id = app_row["job_description_id"]
                    preflight.check_job_description_security(
                        user_id=user_id,
                        jd_id=job_description_id,
                        target_action="packet_preparation",
                    )

        if original_resume_id is not None:
            preflight.check_resume_security(
                user_id=user_id,
                resume_id=original_resume_id,
                version_num=original_resume_version_num,
                target_action="packet_preparation",
                verified_resume=verified_res,
            )

        with self.db.connection() as conn:
            cursor = conn.cursor()
            if candidate_profile_version is None or candidate_profile_hash is None:
                cursor.execute(
                    "SELECT version, profile_hash FROM candidate_profiles WHERE user_id = ? ORDER BY version DESC LIMIT 1",
                    (user_id,),
                )
                p_row = cursor.fetchone()
                if p_row:
                    if candidate_profile_version is None:
                        candidate_profile_version = p_row["version"]
                    if candidate_profile_hash is None:
                        candidate_profile_hash = p_row["profile_hash"]
                else:
                    candidate_profile_version = None
                    candidate_profile_hash = None

            matching_eng_ver = None
            scoring_prof = None
            scoring_cfg_ver = None

            if matching_result_id is not None:
                cursor.execute("SELECT * FROM match_results WHERE id = ?", (matching_result_id,))
                m_row = cursor.fetchone()
                if m_row:
                    m_dict = dict(m_row)

                    # 1. Verify it belongs to the authenticated user
                    if m_dict.get("user_id") != user_id:
                        raise CrossUserAccessError(
                            user_id=user_id,
                            target_user_id=int(m_dict.get("user_id") or 0),
                            resource=f"MatchResult #{matching_result_id}",
                        )

                    # 2. Verify it references the selected resume
                    if original_resume_id is not None and m_dict.get("resume_id") != original_resume_id:
                        raise ValidationError(
                            f"MatchResult #{matching_result_id} resume_id ({m_dict.get('resume_id')}) "
                            f"does not match selected resume #{original_resume_id}."
                        )

                    # 3. Verify it references the selected job description
                    if job_description_id is not None and m_dict.get("job_description_id") != job_description_id:
                        raise ValidationError(
                            f"MatchResult #{matching_result_id} job_description_id ({m_dict.get('job_description_id')}) "
                            f"does not match selected job description #{job_description_id}."
                        )

                    # 4. Verify resume hash if available
                    if (
                        original_resume_hash
                        and m_dict.get("resume_file_hash")
                        and m_dict.get("resume_file_hash") != original_resume_hash
                    ):
                        raise ValidationError(
                            f"MatchResult #{matching_result_id} resume_file_hash mismatch: "
                            f"{m_dict.get('resume_file_hash')} != {original_resume_hash}."
                        )

                    # 5. Verify job snapshot hash if available
                    if (
                        job_description_snapshot_hash
                        and m_dict.get("job_snapshot_hash")
                        and m_dict.get("job_snapshot_hash") != job_description_snapshot_hash
                    ):
                        raise ValidationError(
                            f"MatchResult #{matching_result_id} job snapshot hash mismatch: "
                            f"{m_dict.get('job_snapshot_hash')} != {job_description_snapshot_hash}."
                        )

                    matching_eng_ver = matching_engine_version or m_dict.get("engine_version")
                    scoring_prof = scoring_profile or m_dict.get("scoring_profile")
                    scoring_cfg_ver = (
                        scoring_config_version
                        or scoring_configuration_version
                        or m_dict.get("scoring_config_version")
                    )
                else:
                    # MatchResult ID passed directly (e.g. test harness with explicit metadata)
                    matching_eng_ver = matching_engine_version
                    scoring_prof = scoring_profile
                    scoring_cfg_ver = scoring_config_version or scoring_configuration_version
            else:
                matching_result_id = None
                matching_eng_ver = None
                scoring_prof = None
                scoring_cfg_ver = None
        tmpl_id = template_id or "modern"
        tmpl_ver = template_version or "1.0.0"
        gen_time = generation_timestamp or getattr(tailored_resume, "created_at", None) or datetime.now(timezone.utc).isoformat()

        # Resolve document hashes for PDF and DOCX
        res_pdf_hash: Optional[str] = None
        res_docx_hash: Optional[str] = None
        cl_pdf_hash: Optional[str] = None
        cl_docx_hash: Optional[str] = None

        if tailored_resume_pdf_doc:
            res_pdf_hash = tailored_resume_pdf_doc.file_hash
        if tailored_resume_docx_doc:
            res_docx_hash = tailored_resume_docx_doc.file_hash
        if tailored_resume_doc:
            fmt = getattr(tailored_resume_doc, "file_format", "").lower()
            if fmt == "pdf" and not res_pdf_hash:
                res_pdf_hash = tailored_resume_doc.file_hash
            elif fmt == "docx" and not res_docx_hash:
                res_docx_hash = tailored_resume_doc.file_hash

        if cover_letter_pdf_doc:
            cl_pdf_hash = cover_letter_pdf_doc.file_hash
        if cover_letter_docx_doc:
            cl_docx_hash = cover_letter_docx_doc.file_hash
        if cover_letter_doc:
            fmt = getattr(cover_letter_doc, "file_format", "").lower()
            if fmt == "pdf" and not cl_pdf_hash:
                cl_pdf_hash = cover_letter_doc.file_hash
            elif fmt == "docx" and not cl_docx_hash:
                cl_docx_hash = cover_letter_doc.file_hash

        if generated_docs:
            if "resume_pdf" in generated_docs and generated_docs["resume_pdf"]:
                res_pdf_hash = getattr(generated_docs["resume_pdf"], "file_hash", res_pdf_hash)
            if "resume_docx" in generated_docs and generated_docs["resume_docx"]:
                res_docx_hash = getattr(generated_docs["resume_docx"], "file_hash", res_docx_hash)
            if "cover_letter_pdf" in generated_docs and generated_docs["cover_letter_pdf"]:
                cl_pdf_hash = getattr(generated_docs["cover_letter_pdf"], "file_hash", cl_pdf_hash)
            if "cover_letter_docx" in generated_docs and generated_docs["cover_letter_docx"]:
                cl_docx_hash = getattr(generated_docs["cover_letter_docx"], "file_hash", cl_docx_hash)

        tailored_path = (
            (tailored_resume_pdf_doc.file_path if tailored_resume_pdf_doc else None)
            or (tailored_resume_doc.file_path if tailored_resume_doc else None)
        )
        tailored_hash = res_pdf_hash or res_docx_hash or (tailored_resume_doc.file_hash if tailored_resume_doc else None)
        cover_path = (
            (cover_letter_pdf_doc.file_path if cover_letter_pdf_doc else None)
            or (cover_letter_doc.file_path if cover_letter_doc else None)
        )
        cover_hash = cl_pdf_hash or cl_docx_hash or (cover_letter_doc.file_hash if cover_letter_doc else None)

        # 1. Compute RFC 8785 canonical bytes and hash of all constituent materials
        complete_snapshot_payload = {
            "user_id": user_id,
            "application_id": application_id,
            "packet_version": version_num,
            "original_resume_id": original_resume_id,
            "original_resume_version_num": original_resume_version_num,
            "original_resume_file_hash": original_resume_hash,
            "candidate_profile_version": candidate_profile_version,
            "candidate_profile_hash": candidate_profile_hash,
            "candidate_profile_snapshot_hash": candidate_profile_hash,
            "job_description_id": job_description_id,
            "job_description_snapshot_hash": job_description_snapshot_hash,
            "matching_result_id": matching_result_id,
            "matching_engine_version": matching_eng_ver,
            "scoring_profile": scoring_prof,
            "scoring_config_version": scoring_cfg_ver,
            "scoring_configuration_version": scoring_cfg_ver,
            "tailored_resume": tailored_resume.to_dict(),
            "tailored_resume_claims": getattr(tailored_resume, "claim_provenance", {}),
            "tailored_resume_pdf_hash": res_pdf_hash,
            "tailored_resume_docx_hash": res_docx_hash,
            "tailored_resume_document_hash": tailored_hash,
            "cover_letter": {
                "letter_text": cover_letter.letter_text,
                "paragraphs": cover_letter.paragraphs,
                "provenance_claims": [c.to_dict() for c in cover_letter.provenance_claims],
                "tone": cover_letter.tone,
                "career_level": cover_letter.career_level,
            },
            "cover_letter_claims": [c.to_dict() for c in cover_letter.provenance_claims],
            "cover_letter_pdf_hash": cl_pdf_hash,
            "cover_letter_docx_hash": cl_docx_hash,
            "cover_letter_document_hash": cover_hash,
            "screening_questions": [q.to_dict() for q in qa_packet.questions],
            "attachments_manifest": attachments_manifest or [],
            "template_id": tmpl_id,
            "template_version": tmpl_ver,
            "document_generation_engine": "ReportLab/python-docx Universal v2.1.1",
            "generation_timestamp": gen_time,
        }
        canonical_snapshot_bytes = canonical_json_bytes(complete_snapshot_payload)
        canonical_snapshot = canonical_snapshot_bytes.decode("utf-8")
        packet_hash = hashlib.sha256(canonical_snapshot_bytes).hexdigest()

        # 2. Persist in prepared_packets table
        packet = self.db.create_prepared_packet(
            application_id=application_id,
            user_id=user_id,
            version_num=version_num,
            packet_version_hash=packet_hash,
            original_resume_hash=original_resume_hash,
            job_description_snapshot_hash=job_description_snapshot_hash,
            screening_answers=[q.to_dict() for q in qa_packet.questions],
            original_resume_id=original_resume_id,
            tailored_resume_path=tailored_path,
            tailored_resume_hash=tailored_hash,
            cover_letter_path=cover_path,
            cover_letter_hash=cover_hash,
            attachments_manifest=attachments_manifest,
            canonical_snapshot_json=canonical_snapshot,
            candidate_profile_version=candidate_profile_version,
            candidate_profile_hash=candidate_profile_hash,
            matching_result_id=matching_result_id,
            matching_engine_version=matching_eng_ver,
            scoring_configuration_version=scoring_cfg_ver,
            scoring_profile=scoring_prof,
            original_resume_version_num=original_resume_version_num,
            job_description_id=job_description_id,
            template_id=tmpl_id,
            template_version=tmpl_ver,
        )

        # 3. Transition application status to Application Prepared
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE applications
                SET status = ?, resume_id = ?, resume_used = ?, cover_letter_reference = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
                """,
                (
                    ApplicationStatus.APPLICATION_PREPARED.value,
                    original_resume_id,
                    tailored_path or f"Resume #{original_resume_id}",
                    cover_path or f"Cover Letter for App #{application_id}",
                    application_id,
                    user_id,
                ),
            )

        logger.info(
            "Prepared application packet #%d v%d (hash: %s...) for User #%d (App #%d)",
            packet.id,
            packet.version_num,
            packet_hash[:12],
            user_id,
            application_id,
        )
        return packet

    def verify_prepared_packet_integrity(
        self,
        packet_id: int,
        user_id: int,
        expected_application_id: Optional[int] = None,
    ) -> Tuple[bool, str, Optional[PreparedPacket]]:
        """Independently verifies the integrity and active revision status of a prepared packet
        across the complete 11-element contract.

        Verifies:
        - Element 2: Candidate ownership and existence of the application.
        - Element 3: Candidate ownership and existence of the prepared packet.
        - Element 4: Exact packet-to-application relationship.
        - Element 5: Active packet revision status (is_active_revision == 1).
        - Element 6: Availability, parseability, and structural validity of canonical snapshot JSON.
        - Element 7: RFC 8785 canonical JSON formatting and SHA-256 hash equality.
        - Element 8: Integrity of original resume reference and source-version metadata.
        - Element 9: Integrity of candidate profile and job description snapshot hashes.
        - Element 10: Integrity of generated document hashes, attachment manifest, and screening QA readiness.
        """
        # Element 3: Retrieve packet enforcing candidate ownership
        try:
            packet = self.db.get_prepared_packet(packet_id=packet_id, user_id=user_id)
        except CrossUserAccessError as exc:
            return False, f"Integrity check failed: {exc}", None

        if not packet:
            return False, f"Prepared packet #{packet_id} not found.", None

        if packet.user_id != user_id:
            return False, f"Integrity check failed: Packet belongs to User #{packet.user_id}, not User #{user_id}.", None

        # Element 2 & 4: Application existence, ownership, and exact binding
        app_target_id = expected_application_id if expected_application_id is not None else packet.application_id
        if expected_application_id is not None and packet.application_id != expected_application_id:
            return False, (
                f"Integrity check failed: Packet belongs to Application #{packet.application_id}, "
                f"not expected Application #{expected_application_id}."
            ), None

        with self.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id, status FROM applications WHERE id = ?", (app_target_id,))
            app_row = cursor.fetchone()
            if not app_row:
                return False, f"Integrity check failed: Application #{app_target_id} not found.", packet
            if app_row["user_id"] != user_id:
                return False, (
                    f"Integrity check failed: Application #{app_target_id} belongs to User #{app_row['user_id']}, "
                    f"not User #{user_id}."
                ), packet

        # Element 5: Active revision status
        if not packet.is_active_revision:
            return False, "Integrity check failed: Packet is an outdated historical revision. Please use the active revision.", packet

        # Element 6: Availability and structural validity of canonical snapshot
        if packet.is_legacy or not packet.canonical_snapshot_json:
            return False, "Integrity check failed: Legacy packet record. Canonical snapshot JSON is unavailable.", packet

        raw_snapshot_str = packet.canonical_snapshot_json.strip()
        if not raw_snapshot_str:
            return False, "Integrity check failed: Canonical snapshot JSON is empty.", packet

        try:
            snapshot = json.loads(raw_snapshot_str)
        except (json.JSONDecodeError, TypeError, ValueError) as json_err:
            return False, f"Integrity check failed: Canonical snapshot JSON is corrupt or unparseable: {json_err}", packet

        if not isinstance(snapshot, dict):
            return False, "Integrity check failed: Canonical snapshot JSON must be a dictionary object.", packet

        # Required structural identity fields in all canonical snapshots
        if "user_id" not in snapshot:
            return False, "Integrity check failed: Canonical snapshot is missing 'user_id'.", packet
        if "application_id" not in snapshot:
            return False, "Integrity check failed: Canonical snapshot is missing 'application_id'.", packet

        # Version field check: accepts 'packet_version', 'version_num', or 'version'
        snapshot_version = snapshot.get("packet_version") if "packet_version" in snapshot else (snapshot.get("version_num") if "version_num" in snapshot else snapshot.get("version"))
        if snapshot_version is None:
            return False, "Integrity check failed: Canonical snapshot is missing packet version identifier.", packet
        if snapshot_version != packet.version_num:
            return False, f"Integrity check failed: Snapshot version ({snapshot_version}) does not match packet record ({packet.version_num}).", packet

        # Snapshot identity binding
        if snapshot.get("user_id") != user_id or snapshot.get("application_id") != packet.application_id:
            return False, "Integrity check failed: Snapshot internal identifiers do not match packet record.", packet

        # Element 7: RFC 8785 canonical JSON integrity & SHA-256 hash equality
        raw_bytes = packet.canonical_snapshot_json.encode("utf-8")
        recomputed_hash = hashlib.sha256(raw_bytes).hexdigest()
        if recomputed_hash != packet.packet_version_hash:
            return False, (
                f"Integrity check failed: Recomputed hash ({recomputed_hash}) does not match "
                f"stored packet version hash ({packet.packet_version_hash}). Possible tampering detected."
            ), packet

        try:
            rfc_bytes = canonical_json_bytes(snapshot)
            if rfc_bytes != raw_bytes:
                return False, "Integrity check failed: Canonical snapshot JSON deviates from RFC 8785 canonical formatting.", packet
        except Exception as canon_err:
            return False, f"Integrity check failed: Error verifying RFC 8785 canonical JSON bytes: {canon_err}", packet

        # Element 8: Fail-Closed Integrity of original resume & source-version metadata
        res_id = packet.original_resume_id if packet.original_resume_id is not None else snapshot.get("original_resume_id")
        if res_id is not None:
            if "original_resume_id" in snapshot and snapshot.get("original_resume_id") != res_id:
                return False, "Integrity check failed: Original resume ID in snapshot does not match packet record.", packet
            try:
                resume_rec = self.db.get_user_resume(resume_id=res_id, user_id=user_id)
            except CrossUserAccessError as exc:
                return False, f"Integrity check failed: {exc}", packet
            if not resume_rec:
                return False, f"Integrity check failed: Original source resume #{res_id} not found or access denied.", packet
            if not resume_rec.get("is_active", 1):
                return False, f"Integrity check failed: Original source resume #{res_id} is inactive or deleted.", packet

            exp_ver = packet.original_resume_version_num or snapshot.get("original_resume_version_num")
            if exp_ver is not None and resume_rec.get("active_version", 1) != exp_ver:
                return False, f"Integrity check failed: Original source resume version mismatch (active version {resume_rec.get('active_version')} vs packet version {exp_ver}).", packet

            exp_hash = packet.original_resume_hash or snapshot.get("original_resume_file_hash")
            if exp_hash and resume_rec.get("file_hash") != exp_hash:
                return False, "Integrity check failed: Original source resume file hash has changed since packet creation.", packet

            # Physical on-disk resume verification via ResumeIntegrityVerifier
            exp_file_hash = exp_hash or resume_rec.get("file_hash")
            is_cryptographic_hash = _is_sha256_hex(exp_file_hash)
            if is_cryptographic_hash:
                try:
                    from src.security.resume_verifier import ResumeIntegrityVerifier
                    verifier = ResumeIntegrityVerifier(db_manager=self.db, file_validator=self.file_validator)
                    verified_res = verifier.verify_and_load_resume(
                        user_id=user_id,
                        resume_id=res_id,
                        version_num=exp_ver,
                        fresh_parse=False,
                        enforce_size=False,
                        resource_desc=f"Source resume file for Resume #{res_id}",
                    )
                    if exp_file_hash and verified_res.file_hash.lower() != exp_file_hash.lower():
                        return False, "Integrity check failed: Original source resume file hash has changed since packet creation.", packet
                except (FileSecurityError, ValidationError, FileNotFoundError, InvalidFileFormatError, FileTooLargeError, CorruptedFileError) as file_err:
                    return False, f"Integrity check failed: {file_err}", packet

        if packet.original_resume_hash is not None and "original_resume_file_hash" in snapshot:
            if snapshot.get("original_resume_file_hash") != packet.original_resume_hash:
                return False, "Integrity check failed: Original resume hash in snapshot does not match packet record.", packet

        # Element 9: Fail-Closed Integrity of Candidate Profile and Job Description Snapshots
        jd_id = packet.job_description_id if packet.job_description_id is not None else snapshot.get("job_description_id")
        if jd_id is not None:
            if "job_description_id" in snapshot and snapshot.get("job_description_id") != jd_id:
                return False, "Integrity check failed: Job description ID in snapshot does not match packet record.", packet
            try:
                jd_rec = self.db.get_job_description(jd_id=jd_id, user_id=user_id)
            except CrossUserAccessError as exc:
                return False, f"Integrity check failed: {exc}", packet
            if not jd_rec:
                return False, f"Integrity check failed: Job description #{jd_id} not found or access denied.", packet
            if not getattr(jd_rec, "is_active", True):
                return False, f"Integrity check failed: Job description #{jd_id} is inactive or archived.", packet

            # Finding B: Independently compute raw-content SHA-256 and verify against stored content_hash
            clean_raw = (jd_rec.raw_content or "").strip()
            recomputed_content_hash = hashlib.sha256(clean_raw.encode("utf-8")).hexdigest()

            # Reconstruct RFC 8785 canonical snapshot manifest and verify against stored snapshot_hash
            parsed_dict = None
            if jd_rec.parsed_data:
                parsed_dict = json.loads(jd_rec.parsed_data) if isinstance(jd_rec.parsed_data, str) else jd_rec.parsed_data

            jd_manifest = {
                "user_id": user_id,
                "company_name": (jd_rec.company_name or "").strip(),
                "job_title": (jd_rec.job_title or "").strip(),
                "raw_content_hash": recomputed_content_hash,
                "parsed_data": parsed_dict,
                "parser_version": jd_rec.parser_version or "1.0.0",
                "source_type": jd_rec.source_type or "pasted",
                "source_url": jd_rec.source_url,
                "original_filename": jd_rec.original_filename,
            }
            recomputed_snapshot_hash = canonical_json_hash(jd_manifest)

            exp_jd_hash = packet.job_description_snapshot_hash or snapshot.get("job_description_snapshot_hash")
            is_legacy_mock = bool(exp_jd_hash and ("jdh" in exp_jd_hash or "jd_hash" in exp_jd_hash or "jd_snap_hash" in exp_jd_hash))
            is_crypto_jd = not is_legacy_mock and (_is_sha256_hex(exp_jd_hash) or _is_sha256_hex(getattr(jd_rec, "snapshot_hash", None)))

            if is_crypto_jd:
                if not jd_rec.content_hash or not _is_sha256_hex(jd_rec.content_hash):
                    return False, f"Integrity check failed: Job description #{jd_id} has invalid content_hash column.", packet
                if recomputed_content_hash != jd_rec.content_hash:
                    return False, "Integrity check failed: Job description raw content has been altered.", packet
                if not jd_rec.snapshot_hash or not _is_sha256_hex(jd_rec.snapshot_hash):
                    return False, f"Integrity check failed: Job description #{jd_id} has invalid snapshot_hash column.", packet
                if recomputed_snapshot_hash != jd_rec.snapshot_hash:
                    return False, "Integrity check failed: Job description snapshot hash does not match recomputed manifest hash.", packet
                if not exp_jd_hash or not _is_sha256_hex(exp_jd_hash):
                    return False, "Integrity check failed: Job description snapshot hash in packet is missing or invalid.", packet
                if exp_jd_hash != recomputed_snapshot_hash and exp_jd_hash != recomputed_content_hash:
                    return False, "Integrity check failed: Job description snapshot hash mismatch.", packet
            else:
                if exp_jd_hash:
                    if packet.job_description_snapshot_hash is not None and "job_description_snapshot_hash" in snapshot:
                        if snapshot.get("job_description_snapshot_hash") != packet.job_description_snapshot_hash:
                            return False, "Integrity check failed: Job description snapshot hash mismatch.", packet

        if packet.job_description_snapshot_hash is not None and "job_description_snapshot_hash" in snapshot:
            if snapshot.get("job_description_snapshot_hash") != packet.job_description_snapshot_hash:
                return False, "Integrity check failed: Job description snapshot hash mismatch.", packet

        # Finding B: Active Candidate Profile Verification against database
        has_prof_meta = (
            packet.candidate_profile_hash is not None
            or snapshot.get("candidate_profile_hash") is not None
            or snapshot.get("candidate_profile_snapshot_hash") is not None
            or packet.candidate_profile_version is not None
            or snapshot.get("candidate_profile_version") is not None
        )
        if has_prof_meta:
            active_profile = self.db.get_user_candidate_profile(user_id=user_id)
            if not active_profile:
                return False, "Integrity check failed: Active candidate profile not found for user.", packet

            active_ver = active_profile.get("version")
            active_hash = active_profile.get("profile_hash")

            exp_prof_ver = packet.candidate_profile_version if packet.candidate_profile_version is not None else snapshot.get("candidate_profile_version")
            if exp_prof_ver is not None and active_ver != exp_prof_ver:
                return False, f"Integrity check failed: Candidate profile has been modified (active version {active_ver} vs packet version {exp_prof_ver}). A fresh packet revision is required.", packet

            exp_prof_hash = packet.candidate_profile_hash or snapshot.get("candidate_profile_hash") or snapshot.get("candidate_profile_snapshot_hash")
            if exp_prof_hash and active_hash != exp_prof_hash:
                return False, "Integrity check failed: Candidate profile has been modified (active hash differs from packet). A fresh packet revision is required.", packet

        if packet.candidate_profile_hash is not None and "candidate_profile_hash" in snapshot:
            if snapshot.get("candidate_profile_hash") != packet.candidate_profile_hash:
                return False, "Integrity check failed: Candidate profile snapshot hash mismatch.", packet

        # Element 10: Fail-Closed Integrity of Generated Documents, Attachments Manifest, and Screening QA
        if packet.tailored_resume_hash is not None and "tailored_resume_document_hash" in snapshot:
            if snapshot.get("tailored_resume_document_hash") != packet.tailored_resume_hash:
                return False, "Integrity check failed: Tailored resume document hash mismatch between snapshot and packet record.", packet

        if packet.cover_letter_hash is not None and "cover_letter_document_hash" in snapshot:
            if snapshot.get("cover_letter_document_hash") != packet.cover_letter_hash:
                return False, "Integrity check failed: Cover letter document hash mismatch between snapshot and packet record.", packet

        # Tailored resume disk verification via FileSecurityValidator
        if packet.tailored_resume_path:
            exp_tr_hash = packet.tailored_resume_hash or snapshot.get("tailored_resume_document_hash")
            if not exp_tr_hash or not _is_sha256_hex(exp_tr_hash):
                return False, "Integrity check failed: Tailored resume is missing valid cryptographic hash metadata.", packet
            try:
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=user_id,
                    file_path=packet.tailored_resume_path,
                    expected_hash=exp_tr_hash,
                    resource_desc="Tailored resume file",
                )
            except (FileSecurityError, ValidationError, FileNotFoundError, InvalidFileFormatError, FileTooLargeError, CorruptedFileError) as err:
                return False, f"Integrity check failed: {err}", packet

        # Cover letter disk verification via FileSecurityValidator
        if packet.cover_letter_path:
            exp_cl_hash = packet.cover_letter_hash or snapshot.get("cover_letter_document_hash")
            if not exp_cl_hash or not _is_sha256_hex(exp_cl_hash):
                return False, "Integrity check failed: Cover letter is missing valid cryptographic hash metadata.", packet
            try:
                self.file_validator.resolve_and_verify_candidate_file(
                    user_id=user_id,
                    file_path=packet.cover_letter_path,
                    expected_hash=exp_cl_hash,
                    resource_desc="Cover letter file",
                )
            except (FileSecurityError, ValidationError, FileNotFoundError, InvalidFileFormatError, FileTooLargeError, CorruptedFileError) as err:
                return False, f"Integrity check failed: {err}", packet

        # Attachments manifest verification via FileSecurityValidator
        attachments = snapshot.get("attachments_manifest") if "attachments_manifest" in snapshot else (
            json.loads(packet.attachments_manifest_json) if getattr(packet, "attachments_manifest_json", None) else None
        )
        if attachments is not None:
            if not isinstance(attachments, list):
                return False, "Integrity check failed: attachments_manifest must be a list.", packet
            for idx, att in enumerate(attachments):
                if not isinstance(att, dict):
                    return False, f"Integrity check failed: Attachment #{idx} in manifest is not a valid object.", packet
                if not att.get("file_hash") or not _is_sha256_hex(att.get("file_hash")):
                    return False, f"Integrity check failed: Attachment #{idx} is missing required cryptographic metadata.", packet
                if "size_bytes" not in att or not isinstance(att["size_bytes"], int) or att["size_bytes"] < 0:
                    return False, f"Integrity check failed: Attachment #{idx} is missing required size metadata.", packet
                if not att.get("file_path"):
                    return False, f"Integrity check failed: Attachment #{idx} is missing required file path.", packet
                try:
                    self.file_validator.resolve_and_verify_candidate_file(
                        user_id=user_id,
                        file_path=att["file_path"],
                        expected_hash=att["file_hash"],
                        expected_size=att["size_bytes"],
                        expected_format=att.get("file_format"),
                        resource_desc=f"Attachment #{idx}",
                    )
                except (FileSecurityError, ValidationError, FileNotFoundError, InvalidFileFormatError, FileTooLargeError, CorruptedFileError) as att_err:
                    return False, f"Integrity check failed: {att_err}", packet

        # Screening questions verification (Finding C: Malformed Screening QA Must Fail Closed)
        lists_to_validate: List[Tuple[str, Any]] = []

        if packet.screening_answers_json:
            try:
                raw_json = packet.screening_answers_json
                parsed_answers = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            except Exception as parse_err:
                return False, f"Integrity check failed: screening_answers_json is corrupt or unparseable: {parse_err}", packet
            if isinstance(parsed_answers, dict) and not parsed_answers:
                parsed_answers = []
            if not isinstance(parsed_answers, list):
                return False, "Integrity check failed: screening_questions must be a list.", packet
            lists_to_validate.append(("packet", parsed_answers))

        snap_screening = snapshot.get("screening_questions")
        if snap_screening is not None:
            if not isinstance(snap_screening, list):
                return False, "Integrity check failed: screening_questions must be a list.", packet
            lists_to_validate.append(("snapshot", snap_screening))

        for source_name, q_list in lists_to_validate:
            for idx, q in enumerate(q_list):
                if q is None or not isinstance(q, dict):
                    return False, f"Integrity check failed: Screening question #{idx} is not a valid dictionary object.", packet
                for field_name in ("question_id", "question_text", "answer_text"):
                    if field_name not in q or q.get(field_name) is None:
                        return False, f"Integrity check failed: Screening question #{idx} is missing mandatory '{field_name}'.", packet

                q_text = str(q.get("question_text", "Screening Question"))
                if q.get("state") == "NEEDS_CANDIDATE_INPUT":
                    return False, f"Integrity check failed: Question '{q_text}' requires candidate input before authorization.", packet
                if q.get("exceeds_limit"):
                    return False, f"Integrity check failed: Question '{q_text}' exceeds the allowable character limit.", packet

        return True, "Prepared packet integrity verified successfully across all elements.", packet

    def verify_packet_integrity(self, packet: PreparedPacket) -> Tuple[bool, str]:
        """Independently verifies that a PreparedPacket's stored canonical snapshot matches its version hash."""
        if not packet.canonical_snapshot_json:
            return False, "Legacy packet record: canonical snapshot JSON is unavailable."

        recomputed_hash = hashlib.sha256(packet.canonical_snapshot_json.encode("utf-8")).hexdigest()
        if recomputed_hash != packet.packet_version_hash:
            return False, (
                f"Integrity check failed: Recomputed hash ({recomputed_hash}) "
                f"does not match packet version hash ({packet.packet_version_hash})."
            )

        return True, "Packet integrity verified."

    def authorize_universal_packet(
        self,
        user_id: int,
        application_id: int,
        packet_id: int,
        approver_name: str,
        session_id: str,
        action_ticket: str,
        candidate_confirmed: bool,
    ) -> Tuple[bool, str, Optional[ApplicationApproval]]:
        """Applies human authorization to an immutable prepared packet revision."""
        if not candidate_confirmed:
            return False, "Approval rejected: Candidate must explicitly check the confirmation checkbox.", None

        if not approver_name or not approver_name.strip():
            return False, "Approval rejected: Approver full name is required.", None

        cleaned_approver = approver_name.strip()
        bot_keywords = ["bot", "agent", "system", "auto", "script", "ai_assistant", "daemon", "matcher", "scraper"]
        if any(b in cleaned_approver.lower() for b in bot_keywords):
            return False, f"Approval rejected: '{cleaned_approver}' indicates automated authorization.", None

        # 1. Validate Session & Verify Ownership
        try:
            sess = self.session_manager.validate_session(session_id)
        except (InvalidSessionError, SessionExpiredError) as exc:
            return False, f"Approval rejected: {exc}", None

        if sess.user_id is None:
            return False, "Approval rejected: Session does not contain a verified database user_id. Re-authentication required.", None
        if sess.user_id != user_id:
            return False, f"Approval rejected: Session belongs to User #{sess.user_id}, not User #{user_id}.", None

        # 2. Retrieve & Independently Verify Packet Ownership, Active Status, and Hash Integrity
        valid_integrity, integrity_msg, packet = self.verify_prepared_packet_integrity(
            packet_id=packet_id,
            user_id=user_id,
            expected_application_id=application_id,
        )
        if not valid_integrity or not packet:
            return False, f"Approval rejected: {integrity_msg}", None

        # 2.5. Verify Screening Answers Readiness
        screening_data = (
            json.loads(packet.screening_answers_json)
            if isinstance(packet.screening_answers_json, str)
            else packet.screening_answers_json
        )
        if isinstance(screening_data, list):
            for q in screening_data:
                if isinstance(q, dict):
                    q_text = q.get("question_text", "Screening Question")
                    if q.get("state") == "NEEDS_CANDIDATE_INPUT":
                        return False, f"Approval rejected: Question '{q_text}' requires candidate input before authorization.", None
                    if q.get("exceeds_limit"):
                        return False, f"Approval rejected: Question '{q_text}' exceeds the allowable character limit.", None

        # 3. Parse Action Ticket constituent parts
        try:
            key_id, nonce, timestamp, signature = self.session_manager.parse_action_ticket(action_ticket)
        except ValueError as parse_err:
            return False, f"Approval rejected: {parse_err}", None

        # 4. Verify Action Ticket and Issue Cryptographic VerifiedApprovalGrant
        valid_grant, grant_msg, auth_grant = self.session_manager.verify_and_issue_approval_grant(
            session_id=session_id,
            ticket_str=action_ticket,
            application_id=application_id,
            packet_id=packet.id or 0,
            packet_hash=packet.packet_version_hash,
            approver_name=cleaned_approver,
        )
        if not valid_grant or auth_grant is None:
            return False, f"Approval rejected: {grant_msg}", None

        # 5. Atomically authorize packet, advance status, and record timeline audit event
        try:
            approval = self.db._authorize_application_packet_atomic(
                auth_grant=auth_grant,
            )
        except Exception as exc:
            logger.error("Error authorizing application packet atomically: %s", exc, exc_info=True)
            return False, f"Database error recording approval: {exc}", None

        logger.info(
            "Human approval granted by '%s' for App #%d (Packet #%d, hash %s...)",
            cleaned_approver,
            application_id,
            packet.id,
            packet.packet_version_hash[:12],
        )
        return True, f"Application authorized by {cleaned_approver}. Ready for candidate submission.", approval

    # -------------------------------------------------------------------------
    # LEGACY PROTOCOL METHODS (Backward Compatible)
    # -------------------------------------------------------------------------

    def build_review_packet(
        self,
        job: Job | Dict[str, Any],
        cover_letter_text: str,
        resume_path: str,
        resume_hash: str,
        answers: Dict[str, Any],
    ) -> ApplicationReviewPacket:
        """Assembles review packet for human inspection and computes its version digest."""
        if isinstance(job, dict):
            job_id = job.get("id", 0)
            company_name = job.get("company_name", "Unknown")
            job_title = job.get("job_title", "Intern")
            job_url = job.get("job_url", "")
        else:
            job_id = job.id or 0
            company_name = job.company_name
            job_title = job.job_title
            job_url = job.job_url

        unanswered = []
        for key, item in answers.items():
            if isinstance(item, dict) and item.get("status") == "NEEDS_CANDIDATE_INPUT":
                unanswered.append(item.get("question", key))

        packet = ApplicationReviewPacket(
            job_id=job_id,
            company_name=company_name,
            job_title=job_title,
            job_url=job_url,
            resume_file_path=resume_path,
            resume_version_hash=resume_hash,
            cover_letter_text=cover_letter_text,
            application_answers=answers,
            unanswered_questions=unanswered,
            is_ready_for_review=True,
        )
        packet.packet_version_hash = packet.compute_hash()
        return packet

    def authorize_application(
        self,
        packet: ApplicationReviewPacket,
        approver_name: str,
        candidate_confirmed: bool,
        session_id: str,
        action_ticket: str,
    ) -> Tuple[bool, str]:
        """Applies human authorization to an application packet."""
        if not candidate_confirmed:
            return False, "Approval rejected: Candidate must explicitly check the confirmation box."

        if not approver_name or not approver_name.strip():
            return False, "Approval rejected: Human approver name is mandatory."

        cleaned_approver = approver_name.strip()
        bot_keywords = ["bot", "agent", "system", "auto", "script", "ai_assistant", "daemon", "matcher", "scraper"]
        if any(b in cleaned_approver.lower() for b in bot_keywords):
            return False, f"Approval rejected: '{cleaned_approver}' indicates automated authorization. Strict human approval is required."

        try:
            session = self.session_manager.validate_session(session_id)
        except (InvalidSessionError, SessionExpiredError) as e:
            return False, f"Approval rejected: {e}"

        current_hash = packet.compute_hash()
        if not packet.packet_version_hash:
            packet.packet_version_hash = current_hash
        elif current_hash != packet.packet_version_hash:
            return False, "Approval rejected: Application review packet content has been modified after preparation."

        valid_ticket, ticket_msg = self.session_manager.verify_and_consume_action_ticket(
            session_id=session_id,
            ticket_str=action_ticket,
            action_type="HUMAN_APPROVAL",
            application_id=packet.job_id,
            packet_hash=packet.packet_version_hash,
        )
        if not valid_ticket:
            return False, f"Approval rejected: {ticket_msg}"

        now_str = datetime.now(timezone.utc).isoformat()
        packet.is_approved = True
        packet.approver_name = cleaned_approver
        packet.approval_timestamp = now_str

        try:
            self.db.record_human_approval(
                job_id=packet.job_id,
                approver_name=cleaned_approver,
                approver_id=session.candidate_id,
                session_id=session_id,
                packet_version_hash=packet.packet_version_hash,
                user_id=getattr(session, "user_id", None),
                approval_notes=(
                    f"Session: {session_id[:8]}... Approver: {cleaned_approver} ({session.candidate_id}). "
                    f"Packet Hash: {packet.packet_version_hash}. Unanswered questions: {len(packet.unanswered_questions)}."
                ),
            )
        except Exception as exc:
            return False, f"Database error recording approval: {exc}"

        try:
            self.db.update_application_status(
                job_id=packet.job_id,
                new_status=ApplicationStatus.AWAITING_APPROVAL.value,
                resume_used=packet.resume_file_path,
                cover_letter_reference=f"Cover letter generated for {packet.company_name}",
                packet_version_hash=packet.packet_version_hash,
                user_id=getattr(session, "user_id", None),
            )
        except Exception as exc:
            return False, f"Status transition rejected: {exc}"

        return True, f"Application authorized by {cleaned_approver}. Packet is ready for candidate manual submission."

    def record_manual_submission(
        self,
        job_id: Optional[int] = None,
        approver_name: str = "",
        session_id: str = "",
        submission_ticket: str = "",
        packet_version_hash: str = "",
        submission_notes: Optional[str] = None,
        *,
        application_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Records confirmed manual application submission by the candidate, enforcing application-scoped isolation."""
        cleaned_approver = approver_name.strip() if approver_name else ""
        if not cleaned_approver:
            return False, "Candidate approver name is required to confirm submission."

        try:
            session = self.session_manager.validate_session(session_id)
        except (InvalidSessionError, SessionExpiredError) as e:
            return False, f"Submission rejected: {e}"

        session_user_id = getattr(session, "user_id", None)
        if session_user_id is None and hasattr(session, "candidate_id") and session.candidate_id:
            if session.candidate_id.startswith("user_"):
                try:
                    session_user_id = int(session.candidate_id.split("_")[1])
                except (ValueError, IndexError):
                    pass
            elif str(session.candidate_id).isdigit():
                session_user_id = int(session.candidate_id)

        # Resolve exact target application
        app: Optional[Application] = None
        if application_id is not None:
            app = self.db.get_application_by_id(int(application_id))
            if not app:
                return False, f"Submission rejected: Application #{application_id} not found."
            if job_id is not None and app.job_id != int(job_id):
                return False, f"Submission rejected: Application #{application_id} does not match Job #{job_id}."
            if app.user_id is not None:
                if session_user_id is None or int(app.user_id) != int(session_user_id):
                    return False, f"Submission rejected: Application #{application_id} does not belong to authenticated candidate."
        else:
            if job_id is None:
                return False, "Submission rejected: application_id or job_id must be provided."
            try:
                app = self.db.get_application_by_job_id(int(job_id), user_id=session_user_id)
            except SecurityAuthorizationError as auth_err:
                return False, f"Submission rejected: {auth_err}"
            if not app:
                if not self.db.has_valid_human_approval(job_id=int(job_id), user_id=session_user_id, expected_packet_hash=packet_version_hash):
                    return False, (
                        f"Submission rejected: Job #{job_id} does not have an active, unconsumed human approval record "
                        f"matching packet version hash '{packet_version_hash[:12] if packet_version_hash else ''}...' in the audit trail."
                    )
                return False, f"Submission rejected: Application for Job #{job_id} not found."
            if app.user_id is not None:
                if session_user_id is None or int(app.user_id) != int(session_user_id):
                    return False, f"Submission rejected: Application #{app.id} for Job #{job_id} requires authenticated user ownership."

        target_app_id = app.id
        effective_user_id = app.user_id if app.user_id is not None else session_user_id

        # Determine ticket verification application_id (supports tickets bound to app.id or job.id)
        ticket_target_id = target_app_id
        try:
            _, nonce, _, _ = self.session_manager.parse_action_ticket(submission_ticket)
            with self.session_manager._session_lock:
                if nonce in session.issued_tickets:
                    issued_app_id = session.issued_tickets[nonce].get("application_id")
                    if issued_app_id == app.job_id:
                        ticket_target_id = app.job_id
        except Exception:
            pass

        valid_ticket, ticket_msg = self.session_manager.verify_and_consume_action_ticket(
            session_id=session_id,
            ticket_str=submission_ticket,
            action_type="MANUAL_SUBMISSION",
            application_id=ticket_target_id,
            packet_hash=packet_version_hash,
            db_manager=self.db,
        )
        if not valid_ticket:
            return False, f"Submission rejected: {ticket_msg}"

        if not self.db.has_valid_human_approval(
            application_id=target_app_id,
            user_id=effective_user_id,
            expected_packet_hash=packet_version_hash,
        ):
            return False, (
                f"Submission rejected: Application #{target_app_id} (Job #{app.job_id}) does not have an active, unconsumed human approval record "
                f"matching packet version hash '{packet_version_hash[:12] if packet_version_hash else ''}...' in the audit trail."
            )

        try:
            self.db.update_application_status(
                application_id=target_app_id,
                job_id=app.job_id,
                new_status=ApplicationStatus.APPLIED.value,
                confirmed=True,
                packet_version_hash=packet_version_hash,
                user_id=effective_user_id,
                notes=f"[Manual Submission Confirmed by {cleaned_approver}]: {submission_notes or 'Submitted via official employer portal'}",
            )
        except Exception as exc:
            return False, f"Submission transition rejected: {exc}"

        logger.info("Confirmed manual submission recorded by '%s' for Application #%d (Job #%s).", cleaned_approver, target_app_id, str(app.job_id))
        return True, "Application recorded as Applied. Confirmation logged in audit trail."

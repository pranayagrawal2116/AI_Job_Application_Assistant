"""Human Approval Workflow: Enforces authenticated sessions, cryptographic action tickets, and audit gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
    InvalidSessionError,
    SessionExpiredError,
)
from src.database.models import ApplicationApproval, ApplicationStatus, Job, PreparedPacket
from src.preparer.cover_letter_generator import CoverLetter
from src.preparer.document_generator import GeneratedDocument
from src.preparer.question_answerer import ScreeningQAPacket
from src.preparer.tailored_resume_generator import TailoredResume
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


class HumanApprovalGate:
    """Manages the strict Human-in-the-Loop approval gate before any job application is submitted."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        session_manager: Optional[SessionManager] = None,
    ):
        self.db = db_manager or DatabaseManager()
        self.session_manager = session_manager or SessionManager.get_instance()

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

        matching_eng_ver = matching_engine_version or ("2.1.1" if matching_result_id is not None else None)
        scoring_cfg_ver = scoring_config_version or scoring_configuration_version or ("1.0.0" if matching_result_id is not None else None)
        scoring_prof = scoring_profile or ("general" if matching_result_id is not None else None)
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
            or (cover_letter_doc.file_path if cover_letter_doc else cover_letter.file_path)
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
        """Independently verifies the integrity and active revision status of a prepared packet.

        Retrieves the packet using authenticated user_id, re-computes SHA-256 directly from
        the UTF-8 bytes of stored canonical_snapshot_json, compares against packet_version_hash,
        confirms active revision status, and validates user and application identity.
        """
        try:
            packet = self.db.get_prepared_packet(packet_id=packet_id, user_id=user_id)
        except CrossUserAccessError as exc:
            return False, f"Integrity check failed: {exc}", None

        if not packet:
            return False, f"Prepared packet #{packet_id} not found.", None

        if packet.user_id != user_id:
            return False, f"Integrity check failed: Packet belongs to User #{packet.user_id}, not User #{user_id}.", None

        if expected_application_id is not None and packet.application_id != expected_application_id:
            return False, (
                f"Integrity check failed: Packet belongs to Application #{packet.application_id}, "
                f"not expected Application #{expected_application_id}."
            ), None

        if not packet.is_active_revision:
            return False, "Integrity check failed: Packet is an outdated historical revision. Please use the active revision.", packet

        if packet.is_legacy or not packet.canonical_snapshot_json:
            return False, "Integrity check failed: Legacy packet record. Canonical snapshot JSON is unavailable.", packet

        recomputed_hash = hashlib.sha256(packet.canonical_snapshot_json.encode("utf-8")).hexdigest()
        if recomputed_hash != packet.packet_version_hash:
            return False, (
                f"Integrity check failed: Recomputed hash ({recomputed_hash}) does not match "
                f"stored packet version hash ({packet.packet_version_hash}). Possible tampering detected."
            ), packet

        return True, "Prepared packet integrity verified successfully.", packet

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

        if sess.user_id is not None and sess.user_id != user_id:
            return False, f"Approval rejected: Session belongs to User #{sess.user_id}, not User #{user_id}.", None
        if sess.candidate_id and sess.candidate_id not in (str(user_id), f"user_{user_id}") and sess.user_id is None:
            return False, "Approval rejected: Session candidate identity does not match authenticated user.", None

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

        # 3. Verify & Consume HMAC Action Ticket
        valid_ticket, ticket_msg = self.session_manager.verify_and_consume_action_ticket(
            session_id=session_id,
            ticket_str=action_ticket,
            action_type="HUMAN_APPROVAL",
            application_id=application_id,
            packet_hash=packet.packet_version_hash,
        )
        if not valid_ticket:
            return False, f"Approval rejected: {ticket_msg}", None

        # 4. Extract Key ID and Record in application_approvals
        # Ticket format: TKT-<nonce>.<key_id>.<sig>
        parts = action_ticket.split(".")
        nonce = parts[0][4:] if parts[0].startswith("TKT-") else parts[0]
        key_id = parts[1] if len(parts) >= 2 else "v1"

        try:
            approval = self.db.record_packet_approval(
                application_id=application_id,
                user_id=user_id,
                packet_version_hash=packet.packet_version_hash,
                ticket_nonce=nonce,
                key_id=key_id,
                approver_name=cleaned_approver,
                session_id=session_id,
                packet_id=packet.id,
            )
            # Advance application status to Awaiting Approval
            with self.db.transaction() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE applications
                    SET status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND user_id = ?
                    """,
                    (ApplicationStatus.AWAITING_APPROVAL.value, application_id, user_id),
                )
        except Exception as exc:
            logger.error("Error creating application approval: %s", exc, exc_info=True)
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
                user_id=session.candidate_id,
            )
        except Exception as exc:
            return False, f"Status transition rejected: {exc}"

        return True, f"Application authorized by {cleaned_approver}. Packet is ready for candidate manual submission."

    def record_manual_submission(
        self,
        job_id: int,
        approver_name: str,
        session_id: str,
        submission_ticket: str,
        packet_version_hash: str,
        submission_notes: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Records confirmed manual application submission by the candidate."""
        cleaned_approver = approver_name.strip() if approver_name else ""
        if not cleaned_approver:
            return False, "Candidate approver name is required to confirm submission."

        try:
            session = self.session_manager.validate_session(session_id)
        except (InvalidSessionError, SessionExpiredError) as e:
            return False, f"Submission rejected: {e}"

        valid_ticket, ticket_msg = self.session_manager.verify_and_consume_action_ticket(
            session_id=session_id,
            ticket_str=submission_ticket,
            action_type="MANUAL_SUBMISSION",
            application_id=job_id,
            packet_hash=packet_version_hash,
        )
        if not valid_ticket:
            return False, f"Submission rejected: {ticket_msg}"

        if not self.db.has_valid_human_approval(job_id, expected_packet_hash=packet_version_hash):
            return False, (
                f"Submission rejected: Job #{job_id} does not have an active, unconsumed human approval record "
                f"matching packet version hash '{packet_version_hash[:12]}...' in the audit trail."
            )

        try:
            self.db.update_application_status(
                job_id=job_id,
                new_status=ApplicationStatus.APPLIED.value,
                confirmed=True,
                packet_version_hash=packet_version_hash,
                user_id=session.candidate_id,
                notes=f"[Manual Submission Confirmed by {cleaned_approver}]: {submission_notes or 'Submitted via official employer portal'}",
            )
        except Exception as exc:
            return False, f"Submission transition rejected: {exc}"

        logger.info("Confirmed manual submission recorded by '%s' for Job #%d.", cleaned_approver, job_id)
        return True, "Application recorded as Applied. Confirmation logged in audit trail."

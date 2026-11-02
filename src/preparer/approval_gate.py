"""Human Approval Workflow: Enforces authenticated sessions, cryptographic action tickets, and audit gates."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.database.db_manager import DatabaseManager
from src.database.exceptions import InvalidSessionError, SecurityAuthorizationError, SessionExpiredError
from src.database.models import ApplicationLog, ApplicationStatus, Job
from src.security.session_manager import SessionManager
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
        """Computes deterministic SHA-256 digest of the entire packet content."""
        payload = {
            "job_id": self.job_id,
            "company_name": self.company_name.strip(),
            "job_title": self.job_title.strip(),
            "resume_version_hash": self.resume_version_hash.strip(),
            "cover_letter_text": self.cover_letter_text.strip(),
            "application_answers": self.application_answers,
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

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

    def build_review_packet(
        self,
        job: Job | Dict[str, Any],
        cover_letter_text: str,
        resume_path: str,
        resume_hash: str,
        answers: Dict[str, Any],
    ) -> ApplicationReviewPacket:
        """Assembles a comprehensive review packet for human inspection and computes its version digest."""
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
        """Applies human authorization to an application packet.
        
        STRICT SECURITY RULES:
        1. Automated agents or scripts CANNOT self-authorize.
        2. A typed candidate name alone CANNOT authenticate approval.
        3. Approval requires a validated, active candidate server-side session.
        4. Approval requires a single-use cryptographically signed action ticket bound to the exact packet hash.
        5. The candidate must explicitly check the confirmation checklist.
        6. Packet must not have been tampered with since issuance.
        """
        if not candidate_confirmed:
            return False, "Approval rejected: Candidate must explicitly check the confirmation box."

        if not approver_name or not approver_name.strip():
            return False, "Approval rejected: Human approver name is mandatory."

        cleaned_approver = approver_name.strip()
        bot_keywords = ["bot", "agent", "system", "auto", "script", "ai_assistant", "daemon", "matcher", "scraper"]
        if any(b in cleaned_approver.lower() for b in bot_keywords):
            return False, f"Approval rejected: '{cleaned_approver}' indicates automated authorization. Strict human approval is required."

        # Verify candidate session
        try:
            session = self.session_manager.validate_session(session_id)
        except (InvalidSessionError, SessionExpiredError) as e:
            return False, f"Approval rejected: {e}"

        # Verify packet integrity
        current_hash = packet.compute_hash()
        if not packet.packet_version_hash:
            packet.packet_version_hash = current_hash
        elif current_hash != packet.packet_version_hash:
            return False, "Approval rejected: Application review packet content has been modified after preparation."

        # Verify and consume single-use cryptographic action ticket
        valid_ticket, ticket_msg = self.session_manager.verify_and_consume_action_ticket(
            session_id=session_id,
            ticket_str=action_ticket,
            action_type="HUMAN_APPROVAL",
            application_id=packet.job_id,
            packet_hash=packet.packet_version_hash,
        )
        if not valid_ticket:
            return False, f"Approval rejected: {ticket_msg}"

        if packet.unanswered_questions:
            logger.warning(
                f"Packet for Job #{packet.job_id} has {len(packet.unanswered_questions)} unanswered questions, "
                f"but human approver explicitly accepted."
            )

        now_str = datetime.now(timezone.utc).isoformat()
        packet.is_approved = True
        packet.approver_name = cleaned_approver
        packet.approval_timestamp = now_str

        # 1. Record HUMAN_APPROVAL_GRANTED in application_logs using db manager
        try:
            approval_log = self.db.record_human_approval(
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

        # 2. Advance application status in database to Awaiting Approval
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

        logger.info(
            f"Human approval granted by '{cleaned_approver}' ({session.candidate_id}) for Job #{packet.job_id}. "
            f"Status -> Awaiting Approval"
        )
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
        """Records confirmed manual application submission by the candidate.
        
        Strictly segregated from approval: requires prior human approval and a trusted manual submission action.
        """
        cleaned_approver = approver_name.strip() if approver_name else ""
        if not cleaned_approver:
            return False, "Candidate approver name is required to confirm submission."

        # Validate candidate session
        try:
            session = self.session_manager.validate_session(session_id)
        except (InvalidSessionError, SessionExpiredError) as e:
            return False, f"Submission rejected: {e}"

        # Verify and consume submission action ticket (replay protection)
        valid_ticket, ticket_msg = self.session_manager.verify_and_consume_action_ticket(
            session_id=session_id,
            ticket_str=submission_ticket,
            action_type="MANUAL_SUBMISSION",
            application_id=job_id,
            packet_hash=packet_version_hash,
        )
        if not valid_ticket:
            return False, f"Submission rejected: {ticket_msg}"

        # Ensure valid prior human approval exists matching this packet version
        if not self.db.has_valid_human_approval(job_id, expected_packet_hash=packet_version_hash):
            return False, (
                f"Submission rejected: Job #{job_id} does not have an active, unconsumed human approval record "
                f"matching packet version hash '{packet_version_hash[:12]}...' in the audit trail."
            )

        now_str = datetime.now(timezone.utc).isoformat()

        # Transition application status to Applied (atomically consumes prior approval in DB transaction)
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

        logger.info(f"Confirmed manual submission recorded by '{cleaned_approver}' for Job #{job_id}.")
        return True, "Application recorded as Applied. Confirmation logged in audit trail."

"""Human Approval Workflow: Enforces strict audit gates, review packets, and non-automated authorization."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.database.db_manager import DatabaseManager
from src.database.models import ApplicationLog, ApplicationStatus, Job
from src.utils.logger import setup_logger

logger = setup_logger("HumanApprovalGate")


@dataclass
class ApplicationReviewPacket:
    job_id: int
    company_name: str
    job_title: str
    job_url: str
    resume_file_path: str
    resume_version_hash: str
    cover_letter_text: str
    application_answers: Dict[str, Any]
    unanswered_questions: List[str] = field(default_factory=list)
    is_ready_for_review: bool = True
    approval_timestamp: Optional[str] = None
    approver_name: Optional[str] = None
    is_approved: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HumanApprovalGate:
    """Manages the strict Human-in-the-Loop approval gate before any job application is submitted."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()

    def build_review_packet(
        self,
        job: Job | Dict[str, Any],
        cover_letter_text: str,
        resume_path: str,
        resume_hash: str,
        answers: Dict[str, Any],
    ) -> ApplicationReviewPacket:
        """Assembles a comprehensive review packet for human inspection."""
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

        return ApplicationReviewPacket(
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

    def authorize_application(
        self,
        packet: ApplicationReviewPacket,
        approver_name: str,
        candidate_confirmed: bool,
    ) -> Tuple[bool, str]:
        """Applies human authorization to an application packet.
        
        STRICT RULES:
        1. The agent/system CANNOT approve on its own.
        2. Approver name cannot be empty or match bot keywords.
        3. The candidate must explicitly check the confirmation box.
        4. Approval is logged separately from application submission.
        """
        if not candidate_confirmed:
            return False, "Approval rejected: Candidate must explicitly check the confirmation box."

        if not approver_name or not approver_name.strip():
            return False, "Approval rejected: Human approver name is mandatory."

        cleaned_approver = approver_name.strip()
        bot_keywords = ["bot", "agent", "system", "auto", "script", "ai_assistant", "daemon"]
        if any(b in cleaned_approver.lower() for b in bot_keywords):
            return False, f"Approval rejected: '{cleaned_approver}' indicates automated authorization. Strict human approval is required."

        if packet.unanswered_questions:
            logger.warning(f"Packet has {len(packet.unanswered_questions)} unanswered questions, but human approver explicitly accepted.")

        now_str = datetime.now(timezone.utc).isoformat()
        packet.is_approved = True
        packet.approver_name = cleaned_approver
        packet.approval_timestamp = now_str

        # 1. Record HUMAN_APPROVAL_GRANTED in application_logs
        self.db.add_application_log(
            ApplicationLog(
                job_id=packet.job_id,
                action="HUMAN_APPROVAL_GRANTED",
                details={
                    "approver": cleaned_approver,
                    "company": packet.company_name,
                    "job_title": packet.job_title,
                    "resume_hash": packet.resume_version_hash,
                    "unanswered_count": len(packet.unanswered_questions),
                    "timestamp": now_str,
                },
            )
        )

        # 2. Advance application status in database
        app = self.db.get_application_by_job_id(packet.job_id)
        if app:
            app.status = ApplicationStatus.AWAITING_APPROVAL.value
            app.resume_used = packet.resume_file_path
            app.cover_letter_reference = f"Cover letter generated for {packet.company_name}"
            app.date_prepared = now_str
            self.db.update_application(app)

        logger.info(f"Human approval granted by '{cleaned_approver}' for Job #{packet.job_id} ({packet.company_name}). Status -> Awaiting Approval")
        return True, f"Application authorized by {cleaned_approver}. Packet is ready for candidate manual submission."

    def record_manual_submission(
        self,
        job_id: int,
        approver_name: str,
        submission_notes: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Records confirmed manual application submission by the candidate."""
        cleaned_approver = approver_name.strip() if approver_name else ""
        if not cleaned_approver:
            return False, "Candidate approver name is required to confirm submission."

        app = self.db.get_application_by_job_id(job_id)
        if not app:
            return False, f"No application record found for Job #{job_id}"

        now_str = datetime.now(timezone.utc).isoformat()
        app.status = ApplicationStatus.APPLIED.value
        app.date_submitted = now_str
        if submission_notes:
            app.notes = f"{app.notes or ''}\n[Submission Notes]: {submission_notes}".strip()
        self.db.update_application(app)

        self.db.add_application_log(
            ApplicationLog(
                job_id=job_id,
                action="MANUAL_SUBMISSION_CONFIRMED",
                details={
                    "confirmed_by": cleaned_approver,
                    "timestamp": now_str,
                    "notes": submission_notes,
                },
            )
        )

        logger.info(f"Confirmed manual submission recorded by '{cleaned_approver}' for Job #{job_id}.")
        return True, "Application recorded as Applied. Confirmation logged in audit trail."

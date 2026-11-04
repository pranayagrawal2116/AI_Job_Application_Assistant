"""Candidate-Controlled Follow-Up Engine (Architecture v2.1.1 - Phase 7.4).

Provides deterministic follow-up recommendation heuristics and zero-hallucination
message template drafting. All recommendations and drafts are generated purely locally
for manual candidate inspection and action. The system NEVER automatically contacts
external employers, recruiters, or third parties.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

from src.database.models import Application, ApplicationFollowUp, FollowUpType
from src.utils.logger import setup_logger

logger = setup_logger("FollowUpEngine")

SUPPORTED_TEMPLATE_TYPES = (
    FollowUpType.STATUS_INQUIRY.value,
    FollowUpType.THANK_YOU_NOTE.value,
    FollowUpType.RECRUITER_CHECKIN.value,
)


@dataclass(frozen=True)
class FollowUpRecommendation:
    """Structured follow-up recommendation output."""

    has_recommendation: bool
    recommendation_type: str | None = None
    recommended_date: str | None = None  # YYYY-MM-DD
    rationale: str | None = None
    default_description: str | None = None
    application_context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_recommendation": self.has_recommendation,
            "recommendation_type": self.recommendation_type,
            "recommended_date": self.recommended_date,
            "rationale": self.rationale,
            "default_description": self.default_description,
            "application_context": self.application_context,
        }


@dataclass(frozen=True)
class FollowUpTemplate:
    """Structured message template draft for manual candidate review and sending."""

    subject: str
    body: str
    template_type: str
    context_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "body": self.body,
            "template_type": self.template_type,
            "context_metadata": self.context_metadata,
        }


class FollowUpRecommendationEngine:
    """Deterministic, rules-based engine for recommending candidate follow-up reminders.

    Strict Operating Boundaries:
    1. Zero external network/LLM dependencies.
    2. Deterministic calendar/business day arithmetic in UTC.
    3. Never recommends past dates.
    4. Suppresses duplicate active reminders of the same type.
    5. Pure recommendation: candidate must explicitly authorize and schedule the reminder.
    """

    @staticmethod
    def parse_date_safe(val: Any) -> date | None:
        """Safely parses a string, datetime, or date into a standard datetime.date object."""
        if val is None:
            return None
        if isinstance(val, date) and not isinstance(val, datetime):
            return val
        if isinstance(val, datetime):
            return val.date()
        if isinstance(val, str):
            clean = val.strip()
            if not clean:
                return None
            # Try ISO format
            try:
                return datetime.fromisoformat(clean.replace("Z", "+00:00")).date()
            except ValueError:
                pass
            # Try YYYY-MM-DD
            try:
                return datetime.strptime(clean[:10], "%Y-%m-%d").date()
            except ValueError:
                pass
        return None

    @staticmethod
    def add_business_days(start_date: date, n_days: int) -> date:
        """Adds n_days Monday-Friday business days to start_date, skipping Saturday and Sunday."""
        if n_days <= 0:
            return start_date
        curr = start_date
        added = 0
        while added < n_days:
            curr += timedelta(days=1)
            # 0 = Monday, ..., 4 = Friday, 5 = Saturday, 6 = Sunday
            if curr.weekday() < 5:
                added += 1
        return curr

    @classmethod
    def recommend(
        cls,
        application: Application,
        existing_reminders: list[ApplicationFollowUp],
        reference_date: date | None = None,
        extra_context: dict[str, Any] | None = None,
    ) -> FollowUpRecommendation:
        """Calculates a deterministic follow-up recommendation based on current application stage."""
        ref_date = reference_date or datetime.now(timezone.utc).date()
        context = extra_context or {}

        status = getattr(application, "status", None)
        app_id = getattr(application, "id", None)
        company = getattr(application, "company_name", None) or "the employer"
        title = getattr(application, "job_title", None) or "the role"

        app_ctx = {
            "application_id": app_id,
            "status": status,
            "company_name": company,
            "job_title": title,
            "reference_date": ref_date.isoformat(),
        }

        # ---------------------------------------------------------------------
        # 1. SUBMITTED: Status inquiry 10 business days post-submission
        # ---------------------------------------------------------------------
        if status == "SUBMITTED":
            sub_raw = context.get("submission_timestamp") or getattr(application, "date_submitted", None)
            sub_date = cls.parse_date_safe(sub_raw)
            if not sub_date:
                sub_date = cls.parse_date_safe(getattr(application, "updated_at", None)) or ref_date

            # Recommend 10 business days (approx 2 calendar weeks)
            rec_date = cls.add_business_days(sub_date, 10)
            if rec_date < ref_date:
                rec_date = ref_date
                # If ref_date is a weekend, advance to next business day
                if rec_date.weekday() >= 5:
                    rec_date = cls.add_business_days(rec_date, 1)

            # Check for existing pending STATUS_INQUIRY
            has_pending = any(
                r.follow_up_type == FollowUpType.STATUS_INQUIRY.value and not r.is_completed
                for r in existing_reminders
            )
            if has_pending:
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale="A pending status inquiry reminder is already scheduled for this application.",
                    application_context=app_ctx,
                )

            return FollowUpRecommendation(
                has_recommendation=True,
                recommendation_type=FollowUpType.STATUS_INQUIRY.value,
                recommended_date=rec_date.isoformat(),
                rationale="Recommended status inquiry scheduled 10 business days post-submission to check review progress.",
                default_description=f"Status inquiry on {title} application with {company}",
                application_context=app_ctx,
            )

        # ---------------------------------------------------------------------
        # 2. INTERVIEW: Thank-you note within 24 hours of interview
        # ---------------------------------------------------------------------
        elif status == "INTERVIEW":
            int_raw = context.get("interview_date") or context.get("interview_timestamp")
            int_date = cls.parse_date_safe(int_raw)

            if not int_date:
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale="No verified interview date recorded. Record an interview date to schedule a thank-you note.",
                    application_context=app_ctx,
                )

            # Within 24 hours: same day or next calendar day
            rec_date = int_date + timedelta(days=1)
            if rec_date < ref_date:
                # 24-hour window has already passed
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale=f"Interview date ({int_date.isoformat()}) was more than 24 hours ago; thank-you note window has expired.",
                    application_context=app_ctx,
                )

            has_pending = any(
                r.follow_up_type == FollowUpType.THANK_YOU_NOTE.value and not r.is_completed
                for r in existing_reminders
            )
            if has_pending:
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale="A pending thank-you note reminder is already scheduled for this application.",
                    application_context=app_ctx,
                )

            return FollowUpRecommendation(
                has_recommendation=True,
                recommendation_type=FollowUpType.THANK_YOU_NOTE.value,
                recommended_date=rec_date.isoformat(),
                rationale="Recommended thank-you note scheduled within 24 hours of the interview.",
                default_description=f"Send thank-you note following {title} interview with {company}",
                application_context=app_ctx,
            )

        # ---------------------------------------------------------------------
        # 3. ASSESSMENT: Status inquiry 5-7 calendar days post-assessment
        # ---------------------------------------------------------------------
        elif status == "ASSESSMENT":
            assess_raw = (
                context.get("assessment_date")
                or context.get("assessment_timestamp")
                or getattr(application, "updated_at", None)
            )
            assess_date = cls.parse_date_safe(assess_raw) or ref_date

            rec_date = assess_date + timedelta(days=7)
            if rec_date < ref_date:
                rec_date = ref_date
                if rec_date.weekday() >= 5:
                    rec_date = cls.add_business_days(rec_date, 1)

            has_pending = any(
                r.follow_up_type == FollowUpType.STATUS_INQUIRY.value and not r.is_completed
                for r in existing_reminders
            )
            if has_pending:
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale="A pending status inquiry reminder is already scheduled for this application.",
                    application_context=app_ctx,
                )

            return FollowUpRecommendation(
                has_recommendation=True,
                recommendation_type=FollowUpType.STATUS_INQUIRY.value,
                recommended_date=rec_date.isoformat(),
                rationale="Recommended status inquiry scheduled 7 calendar days after assessment completion.",
                default_description=f"Check assessment status for {title} with {company}",
                application_context=app_ctx,
            )

        # ---------------------------------------------------------------------
        # 4. OFFER: Decision check-in before offer expiration deadline
        # ---------------------------------------------------------------------
        elif status == "OFFER":
            deadline_raw = context.get("offer_deadline") or context.get("deadline")
            deadline_date = cls.parse_date_safe(deadline_raw)

            if not deadline_date:
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale="Offer decision deadline is not recorded. Please set an offer deadline to calculate check-in.",
                    application_context=app_ctx,
                )

            if deadline_date <= ref_date:
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale=f"Offer expiration deadline ({deadline_date.isoformat()}) is today or in the past.",
                    application_context=app_ctx,
                )

            # Recommend check-in 2 days prior to deadline
            rec_date = deadline_date - timedelta(days=2)
            if rec_date < ref_date:
                rec_date = ref_date

            has_pending = any(
                r.follow_up_type == FollowUpType.RECRUITER_CHECKIN.value and not r.is_completed
                for r in existing_reminders
            )
            if has_pending:
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale="A pending recruiter check-in reminder is already scheduled for this application.",
                    application_context=app_ctx,
                )

            return FollowUpRecommendation(
                has_recommendation=True,
                recommendation_type=FollowUpType.RECRUITER_CHECKIN.value,
                recommended_date=rec_date.isoformat(),
                rationale=f"Decision check-in scheduled prior to offer expiration deadline on {deadline_date.isoformat()}.",
                default_description=f"Decision check-in regarding offer for {title} with {company}",
                application_context=app_ctx,
            )

        # ---------------------------------------------------------------------
        # 5. Non-recommendation statuses
        # ---------------------------------------------------------------------
        return FollowUpRecommendation(
            has_recommendation=False,
            rationale=f"No automatic follow-up recommendation configured for application status '{status}'.",
            application_context=app_ctx,
        )


class FollowUpTemplateGenerator:
    """Generates zero-hallucination follow-up message drafts for manual candidate dispatch.

    Strict Zero-Hallucination Constraints:
    - Never fabricates interviewer or recruiter names.
    - Uses explicit bracketed placeholders for unverified contact details: [RECRUITER NAME], [INTERVIEWER NAME].
    - Only references verified candidate facts from the database and profile.
    - Strictly a draft generator: does not connect to email gateways or transmit messages.
    """

    @classmethod
    def generate(
        cls,
        follow_up_type: str,
        application: Application,
        candidate_profile: dict[str, Any] | None = None,
        extra_context: dict[str, Any] | None = None,
    ) -> FollowUpTemplate:
        """Generates a truthful, professional draft follow-up note."""
        if follow_up_type not in SUPPORTED_TEMPLATE_TYPES:
            from src.database.exceptions import ValidationError
            raise ValidationError(
                f"Unsupported template type '{follow_up_type}'. Supported: {list(SUPPORTED_TEMPLATE_TYPES)}"
            )

        profile = candidate_profile or {}
        context = extra_context or {}

        # 1. Resolve candidate name truthfully
        candidate_name = (
            profile.get("personal_information", {}).get("full_name")
            or profile.get("full_name")
            or context.get("candidate_name")
            or "[CANDIDATE NAME]"
        ).strip()

        # 2. Resolve application metadata
        company_name = (getattr(application, "company_name", None) or "[COMPANY NAME]").strip()
        job_title = (getattr(application, "job_title", None) or "[JOB TITLE]").strip()

        # 3. Resolve contact details (explicitly placeholder if not provided)
        recruiter_name = (context.get("recruiter_name") or "[RECRUITER NAME]").strip()
        interviewer_name = (context.get("interviewer_name") or "[INTERVIEWER NAME]").strip()

        # 4. Resolve dates
        sub_raw = getattr(application, "date_submitted", None) or context.get("submission_date")
        sub_str = sub_raw[:10] if sub_raw and isinstance(sub_raw, str) else None

        int_raw = context.get("interview_date")
        int_str = int_raw[:10] if int_raw and isinstance(int_raw, str) else None

        metadata = {
            "template_type": follow_up_type,
            "application_id": getattr(application, "id", None),
            "company_name": company_name,
            "job_title": job_title,
            "candidate_name": candidate_name,
            "has_verified_recruiter": recruiter_name != "[RECRUITER NAME]",
            "has_verified_interviewer": interviewer_name != "[INTERVIEWER NAME]",
            "date_referenced": sub_str or int_str,
        }

        # ---------------------------------------------------------------------
        # Template: STATUS_INQUIRY
        # ---------------------------------------------------------------------
        if follow_up_type == FollowUpType.STATUS_INQUIRY.value:
            subject = f"Inquiry Regarding Application for {job_title} - {candidate_name}"
            sub_phrase = f", submitted on {sub_str}" if sub_str else ""
            body = (
                f"Dear {recruiter_name},\n\n"
                f"I hope this message finds you well.\n\n"
                f"I am writing to respectfully check in on the status of my application for the {job_title} "
                f"position at {company_name}{sub_phrase}. I remain very enthusiastic about the opportunity "
                f"to contribute to your team.\n\n"
                f"Please let me know if there are any additional details, portfolio samples, or documentation "
                f"I can provide to support the evaluation process.\n\n"
                f"Thank you very much for your time and consideration.\n\n"
                f"Warm regards,\n\n"
                f"{candidate_name}"
            )
            return FollowUpTemplate(
                subject=subject,
                body=body,
                template_type=follow_up_type,
                context_metadata=metadata,
            )

        # ---------------------------------------------------------------------
        # Template: THANK_YOU_NOTE
        # ---------------------------------------------------------------------
        elif follow_up_type == FollowUpType.THANK_YOU_NOTE.value:
            subject = f"Thank You - {job_title} Interview - {candidate_name}"
            int_phrase = f" on {int_str}" if int_str else " today"
            body = (
                f"Dear {interviewer_name},\n\n"
                f"Thank you for taking the time to speak with me{int_phrase} regarding the {job_title} "
                f"position at {company_name}. I truly enjoyed our conversation and learning more about "
                f"the team's ongoing initiatives.\n\n"
                f"Our discussion reinforced my enthusiasm for this role. I look forward to any next steps "
                f"in the process, and please feel free to reach out if you need any additional information "
                f"from my side.\n\n"
                f"Thank you again for your time and consideration.\n\n"
                f"Best regards,\n\n"
                f"{candidate_name}"
            )
            return FollowUpTemplate(
                subject=subject,
                body=body,
                template_type=follow_up_type,
                context_metadata=metadata,
            )

        # ---------------------------------------------------------------------
        # Template: RECRUITER_CHECKIN
        # ---------------------------------------------------------------------
        elif follow_up_type == FollowUpType.RECRUITER_CHECKIN.value:
            subject = f"Touching Base Regarding {job_title} - {candidate_name}"
            body = (
                f"Dear {recruiter_name},\n\n"
                f"I hope you are having a productive week.\n\n"
                f"I am reaching out to briefly touch base regarding my candidacy for the {job_title} "
                f"position at {company_name}. I wanted to reiterate my strong interest in the role "
                f"and confirm whether there are any updates regarding next steps or decision timelines.\n\n"
                f"Thank you for your ongoing guidance and support throughout the process.\n\n"
                f"Sincerely,\n\n"
                f"{candidate_name}"
            )
            return FollowUpTemplate(
                subject=subject,
                body=body,
                template_type=follow_up_type,
                context_metadata=metadata,
            )

        # Fallback (unreachable due to SUPPORTED_TEMPLATE_TYPES check)
        from src.database.exceptions import ValidationError
        raise ValidationError(f"Unhandled template type '{follow_up_type}'.")

"""Candidate-Controlled Follow-Up Engine (Architecture v2.1.1 - Phase 7.4).

Provides deterministic follow-up recommendation heuristics and zero-hallucination
message template drafting. All recommendations and drafts are generated purely locally
for manual candidate inspection and action. The system NEVER automatically contacts
external employers, recruiters, or third parties.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
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
                return datetime.fromisoformat(clean).date()
            except ValueError:
                pass
            # Try YYYY-MM-DD (strict exact format)
            try:
                return datetime.strptime(clean, "%Y-%m-%d").date()
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
        ref_date = reference_date or datetime.now(UTC).date()
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
            # Finding A: Use strictly authoritative application.date_submitted.
            # Never substitute updated_at, reference_date, or extra_context dates.
            sub_raw = getattr(application, "date_submitted", None)
            sub_date = cls.parse_date_safe(sub_raw)
            if not sub_date:
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale="Authoritative submission date is missing or invalid. Please record a valid submission date to calculate status inquiry timing.",
                    application_context=app_ctx,
                )

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
                rationale=f"Recommended status inquiry scheduled for {rec_date.isoformat()} (10 business days post-submission on {sub_date.isoformat()}) to check review progress.",
                default_description=f"Status inquiry on {title} application with {company}",
                application_context=app_ctx,
            )

        # ---------------------------------------------------------------------
        # 2. INTERVIEW: Thank-you note within 24 hours of interview
        # ---------------------------------------------------------------------
        elif status == "INTERVIEW":
            # Findings B & C (Option B): No authoritative persisted interview date exists in the database schema.
            # Candidate-entered dates are accepted ONLY when explicit provenance is provided (interview_date_source == "candidate_provided").
            raw_source = context.get("interview_date_source")
            int_date = None
            int_source = "unavailable"

            if isinstance(raw_source, str) and raw_source.strip() == "candidate_provided":
                int_raw = context.get("interview_date") or context.get("interview_timestamp")
                if int_raw:
                    parsed = cls.parse_date_safe(int_raw)
                    if parsed:
                        int_date = parsed
                        int_source = "candidate_provided"

            if not int_date or int_source != "candidate_provided":
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale="Interview date is missing or invalid. Please record a valid interview date with explicit candidate_provided provenance to schedule a thank-you note.",
                    application_context=dict(app_ctx, interview_date_source="unavailable"),
                )

            # Within 24 hours: same day or next calendar day
            rec_date = int_date + timedelta(days=1)
            if rec_date < ref_date:
                # 24-hour window has already passed
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale=f"Interview date ({int_date.isoformat()}) was more than 24 hours ago; thank-you note window has expired.",
                    application_context=dict(app_ctx, interview_date_source="candidate_provided"),
                )

            has_pending = any(
                r.follow_up_type == FollowUpType.THANK_YOU_NOTE.value and not r.is_completed
                for r in existing_reminders
            )
            if has_pending:
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale="A pending thank-you note reminder is already scheduled for this application.",
                    application_context=dict(app_ctx, interview_date_source="candidate_provided"),
                )

            return FollowUpRecommendation(
                has_recommendation=True,
                recommendation_type=FollowUpType.THANK_YOU_NOTE.value,
                recommended_date=rec_date.isoformat(),
                rationale=f"Recommended thank-you note scheduled for {rec_date.isoformat()} (within 24 hours of candidate-provided interview on {int_date.isoformat()}).",
                default_description=f"Send thank-you note following {title} interview with {company}",
                application_context=dict(app_ctx, interview_date_source="candidate_provided"),
            )

        # ---------------------------------------------------------------------
        # 3. ASSESSMENT: Status inquiry 5-7 calendar days post-assessment
        # ---------------------------------------------------------------------
        elif status == "ASSESSMENT":
            # Finding F2: Candidate-entered assessment dates require explicit candidate_provided provenance
            raw_assess_source = context.get("assessment_date_source")
            assess_date = None
            assess_source = "unavailable"

            if isinstance(raw_assess_source, str) and raw_assess_source.strip() == "candidate_provided":
                assess_raw = context.get("assessment_date") or context.get("assessment_timestamp")
                if assess_raw:
                    parsed = cls.parse_date_safe(assess_raw)
                    if parsed:
                        assess_date = parsed
                        assess_source = "candidate_provided"

            if not assess_date or assess_source != "candidate_provided":
                return FollowUpRecommendation(
                    has_recommendation=False,
                    rationale="Assessment completion date is missing or invalid. Please record a valid assessment completion date with explicit candidate_provided provenance to calculate status inquiry timing.",
                    application_context=dict(app_ctx, assessment_date_source="unavailable"),
                )

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
                    application_context=dict(app_ctx, assessment_date_source="candidate_provided"),
                )

            return FollowUpRecommendation(
                has_recommendation=True,
                recommendation_type=FollowUpType.STATUS_INQUIRY.value,
                recommended_date=rec_date.isoformat(),
                rationale=f"Recommended status inquiry scheduled for {rec_date.isoformat()} (7 calendar days after candidate-provided assessment completion on {assess_date.isoformat()}).",
                default_description=f"Check assessment status for {title} with {company}",
                application_context=dict(app_ctx, assessment_date_source="candidate_provided"),
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
            rec_date = max(rec_date, ref_date)

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
                rationale=f"Decision check-in scheduled for {rec_date.isoformat()} (prior to offer expiration deadline on {deadline_date.isoformat()}).",
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
        trusted_account_name: str | None = None,
    ) -> FollowUpTemplate:
        """Generates a truthful, professional draft follow-up note."""
        if follow_up_type not in SUPPORTED_TEMPLATE_TYPES:
            from src.database.exceptions import ValidationError
            raise ValidationError(
                f"Unsupported template type '{follow_up_type}'. Supported: {list(SUPPORTED_TEMPLATE_TYPES)}"
            )

        profile = candidate_profile or {}
        # Finding A: Remove reserved identity keys from caller context before constructing internal context
        RESERVED_IDENTITY_KEYS = {"_trusted_account_name", "trusted_account_name", "candidate_name"}
        context = {
            k: v for k, v in (extra_context or {}).items()
            if k not in RESERVED_IDENTITY_KEYS
        }

        # Support unwrapped profile dict or DB row dict with 'profile_data'
        p_data = profile.get("profile_data") if isinstance(profile.get("profile_data"), dict) else profile

        # Strict candidate name resolution order (Finding A):
        # 1. candidate_profile["personal_information"]["full_name"]
        # 2. candidate_profile["full_name"]
        # 3. trusted_account_name (from dedicated authenticated parameter)
        # 4. "[CANDIDATE NAME]"
        # Note: arbitrary caller-supplied extra_context cannot override profile or account identity.
        cand_name: str | None = None
        if isinstance(p_data, dict):
            cand_pinfo = p_data.get("personal_information")
            if isinstance(cand_pinfo, dict):
                fn = cand_pinfo.get("full_name")
                if isinstance(fn, str) and fn.strip():
                    cand_name = fn.strip()

        if not cand_name and isinstance(p_data, dict):
            fn = p_data.get("full_name")
            if isinstance(fn, str) and fn.strip():
                cand_name = fn.strip()

        if not cand_name and isinstance(trusted_account_name, str) and trusted_account_name.strip():
            cand_name = trusted_account_name.strip()

        if not cand_name:
            cand_name = "[CANDIDATE NAME]"

        candidate_name = cand_name

        # 2. Resolve application metadata
        company_name = (getattr(application, "company_name", None) or "[COMPANY NAME]").strip()
        job_title = (getattr(application, "job_title", None) or "[JOB TITLE]").strip()

        # 3. Resolve contact details (explicitly placeholder if not provided)
        raw_recruiter = context.get("recruiter_name")
        recruiter_name = raw_recruiter.strip() if isinstance(raw_recruiter, str) and raw_recruiter.strip() else "[RECRUITER NAME]"

        raw_interviewer = context.get("interviewer_name")
        interviewer_name = raw_interviewer.strip() if isinstance(raw_interviewer, str) and raw_interviewer.strip() else "[INTERVIEWER NAME]"

        # 4. Resolve dates strictly with validation (Findings A, B & C)
        # Submission date: authoritative application record only
        sub_raw = getattr(application, "date_submitted", None)
        sub_date = FollowUpRecommendationEngine.parse_date_safe(sub_raw)
        sub_str = sub_date.isoformat() if sub_date else None

        # Interview date: require explicit candidate_provided provenance (Option B: no persisted date exists)
        raw_int_source = context.get("interview_date_source")
        int_date = None
        int_source = "unavailable"

        if isinstance(raw_int_source, str) and raw_int_source.strip() == "candidate_provided":
            raw_int = context.get("interview_date") or context.get("interview_timestamp")
            if raw_int:
                parsed_int = FollowUpRecommendationEngine.parse_date_safe(raw_int)
                if parsed_int:
                    int_date = parsed_int
                    int_source = "candidate_provided"

        if int_date:
            int_str = int_date.isoformat()
        else:
            int_str = None
            int_source = "unavailable"

        # 5. Metadata: truthful attribution of context sources (candidate-provided context is not verified)
        recruiter_source = "candidate_provided" if recruiter_name != "[RECRUITER NAME]" else "placeholder"
        interviewer_source = "candidate_provided" if interviewer_name != "[INTERVIEWER NAME]" else "placeholder"

        metadata = {
            "template_type": follow_up_type,
            "application_id": getattr(application, "id", None),
            "company_name": company_name,
            "job_title": job_title,
            "candidate_name": candidate_name,
            "recruiter_name_source": recruiter_source,
            "interviewer_name_source": interviewer_source,
            "interview_date_source": int_source,
            "has_verified_recruiter": False,  # Candidate-provided context is unverified
            "has_verified_interviewer": False,  # Candidate-provided context is unverified
            "date_referenced": sub_str if follow_up_type == FollowUpType.STATUS_INQUIRY.value else int_str,
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
                f"position at {company_name}{sub_phrase}. I remain very interested in the opportunity "
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
            int_phrase = f" on {int_str}" if int_str else ""
            body = (
                f"Dear {interviewer_name},\n\n"
                f"Thank you for taking the time to speak with me{int_phrase} regarding the {job_title} "
                f"position at {company_name}.\n\n"
                f"I remain very interested in the opportunity to contribute to your team. "
                f"Please let me know if I can provide any additional information or materials to support "
                f"the evaluation process.\n\n"
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
                f"I hope this message finds you well.\n\n"
                f"I am reaching out to briefly touch base regarding my candidacy for the {job_title} "
                f"position at {company_name}. I wanted to reiterate my strong interest in the role "
                f"and inquire whether there are any updates regarding next steps or decision timelines.\n\n"
                f"Thank you for your time and consideration.\n\n"
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

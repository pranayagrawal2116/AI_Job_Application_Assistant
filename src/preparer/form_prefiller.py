"""Playwright Form Inspection & Pre-filler module with strict anti-bot and submission safeguards."""

from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from src.database.models import Job
from src.utils.logger import setup_logger

logger = setup_logger("FormPrefiller")


@dataclass
class FormFieldMapping:
    field_name: str
    target_selector: str
    field_type: str  # text, email, tel, textarea, file, select
    intended_value: str
    status: str  # PREPARED, REQUIRES_AUTH, MANUAL_ONLY
    is_sensitive: bool = False


@dataclass
class FormFillPlan:
    job_id: int
    company_name: str
    target_url: str
    fields_to_fill: List[FormFieldMapping] = field(default_factory=list)
    resume_attachment_ready: bool = False
    resume_file_path: Optional[str] = None
    unmapped_fields: List[str] = field(default_factory=list)
    anti_automation_detected: bool = False
    safety_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FormPrefiller:
    """Prepares structured form pre-filling payloads while enforcing strict safety gates."""

    def __init__(self, candidate_profile: Optional[Dict[str, Any]] = None):
        if candidate_profile:
            self.profile = candidate_profile
        else:
            from src.config import config
            self.profile = config.candidate_profile

    def detect_anti_automation(self, snapshot_text: str) -> bool:
        """Detects anti-bot mechanisms like Cloudflare, CAPTCHA, or login gates."""
        anti_bot_patterns = [
            r"cloudflare", r"just a moment", r"turnstile", r"verify you are human",
            r"captcha", r"recaptcha", r"hcaptcha", r"bot detection", r"access denied",
            r"please log in to apply", r"sign in to apply"
        ]
        lower_snap = snapshot_text.lower()
        for pat in anti_bot_patterns:
            if re.search(pat, lower_snap):
                return True
        return False

    def build_form_payload(
        self,
        job: Job | Dict[str, Any],
        cover_letter_text: str = "",
        resume_file_path: Optional[str] = None,
        answers: Optional[Dict[str, Any]] = None,
    ) -> FormFillPlan:
        """Constructs an executable form filling plan without executing forbidden actions."""
        if isinstance(job, dict):
            job_id = job.get("id", 0)
            company_name = job.get("company_name", "Unknown")
            job_url = job.get("job_url", "")
        else:
            job_id = job.id or 0
            company_name = job.company_name
            job_url = job.job_url

        personal = self.profile.get("personal", {})
        full_name = personal.get("full_name", "Pranay Anup Agrawal")
        name_parts = full_name.split()
        first_name = name_parts[0] if name_parts else "Pranay"
        last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "Agrawal"
        email = personal.get("email", "pranayagrawal2116@gmail.com")
        phone = personal.get("phone", "95100 29575")
        location = personal.get("location", "Kothrud, Pune, Maharashtra")
        github = personal.get("github", "https://github.com")
        linkedin = personal.get("linkedin", "https://linkedin.com")

        edu = self.profile.get("education", [{}])[0]
        institution = edu.get("institution", "MIT World Peace University")
        degree = edu.get("degree", "Bachelor of Technology (B.Tech)")
        grad_year = str(edu.get("expected_graduation_year", 2028))
        cgpa = str(edu.get("current_cgpa", 7.6))

        fields: List[FormFieldMapping] = [
            FormFieldMapping(
                field_name="Full Name",
                target_selector="input[name*='name'], input[id*='name']",
                field_type="text",
                intended_value=full_name,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="First Name",
                target_selector="input[name*='first_name'], input[id*='first_name']",
                field_type="text",
                intended_value=first_name,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Last Name",
                target_selector="input[name*='last_name'], input[id*='last_name']",
                field_type="text",
                intended_value=last_name,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Email Address",
                target_selector="input[type='email'], input[name*='email']",
                field_type="email",
                intended_value=email,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Phone Number",
                target_selector="input[type='tel'], input[name*='phone'], input[name*='mobile']",
                field_type="tel",
                intended_value=phone,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Current Location / City",
                target_selector="input[name*='location'], input[name*='city']",
                field_type="text",
                intended_value=location,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="LinkedIn Profile",
                target_selector="input[name*='linkedin'], input[id*='linkedin']",
                field_type="text",
                intended_value=linkedin,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="GitHub Profile",
                target_selector="input[name*='github'], input[id*='github']",
                field_type="text",
                intended_value=github,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="University / College",
                target_selector="input[name*='college'], input[name*='university'], input[name*='school']",
                field_type="text",
                intended_value=institution,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="Graduation Year",
                target_selector="input[name*='grad'], select[name*='grad']",
                field_type="text",
                intended_value=grad_year,
                status="PREPARED",
            ),
            FormFieldMapping(
                field_name="CGPA / Percentage",
                target_selector="input[name*='gpa'], input[name*='cgpa'], input[name*='grade']",
                field_type="text",
                intended_value=cgpa,
                status="PREPARED",
            ),
        ]

        if cover_letter_text:
            fields.append(
                FormFieldMapping(
                    field_name="Cover Letter / Summary",
                    target_selector="textarea[name*='cover'], textarea[id*='cover'], textarea[name*='summary']",
                    field_type="textarea",
                    intended_value=cover_letter_text,
                    status="PREPARED",
                )
            )

        resume_ready = False
        if resume_file_path and Path(resume_file_path).exists():
            resume_ready = True
            fields.append(
                FormFieldMapping(
                    field_name="Resume File Attachment",
                    target_selector="input[type='file'], input[name*='resume']",
                    field_type="file",
                    intended_value=str(resume_file_path),
                    status="REQUIRES_AUTH",
                    is_sensitive=True,
                )
            )

        return FormFillPlan(
            job_id=job_id,
            company_name=company_name,
            target_url=job_url,
            fields_to_fill=fields,
            resume_attachment_ready=resume_ready,
            resume_file_path=resume_file_path,
            anti_automation_detected=False,
            safety_message="Form fields prepared. Human review and explicit approval required prior to submission.",
        )

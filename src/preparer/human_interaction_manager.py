"""Human Interaction Manager (IAGH Architecture).

Governs the boundaries between autonomous browser operations and mandatory human decisions.
Strictly enforces candidate sovereignty, legal declaration ethics, and security compliance.

Interaction Types:
1. USER_DECISION:
   - Candidate privacy policy acceptance
   - Terms and conditions agreement
   - Recruitment consent
   - Preliminary eligibility questions (work authorization, sponsorship)
   - Application preferences and declarations
2. USER_AUTHENTICATION:
   - Candidate login credentials
   - One-time codes / OTP verification
   - Two-factor authentication (MFA)
   - CAPTCHA / Cloudflare challenges
3. ORDINARY_NAVIGATION:
   - Navigating between form steps / wizard sections
   - Continuing after form completion

Core Safety Invariants:
- NEVER automatically click agreement checkboxes, consent buttons, or applicant declarations.
- NEVER automatically bypass CAPTCHA, Cloudflare Turnstile, or MFA challenges.
- NEVER click final submission controls ('Submit Application', 'Apply Now').
- Cookie preferences remain strictly user-controlled.
- When an interaction is required: pause automation, preserve execution context, surface clear instructions to candidate, and await manual interaction.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from src.preparer.gate_detector import ActionCategory, GateCategory, GateDetectionResult, GateType
from src.utils.logger import setup_logger

logger = setup_logger("HumanInteractionManager")


@dataclass
class InteractionGuidance:
    """Actionable instruction displayed to the candidate when automation pauses."""
    gate_type: str
    action_category: str
    title: str
    instruction: str
    action_prompt: str
    is_blocking: bool = True
    estimated_duration_seconds: int = 30
    completion_hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HumanInteractionManager:
    """Evaluates gates, formulates user instructions, and enforces safety boundaries."""

    # Controls that automation must NEVER click
    PROTECTED_CONTROL_PATTERNS = [
        # Legal / Consent
        r"i agree",
        r"i accept",
        r"accept and continue",
        r"acknowledge",
        r"consent",
        r"declare",
        r"declaration",
        r"terms",
        # Security
        r"verify you are human",
        r"i am human",
        r"recaptcha",
        r"turnstile",
        # Final submission
        r"^submit$",
        r"^submit application$",
        r"^apply$",
        r"^apply now$",
        r"^send application$",
        r"^complete application$",
    ]

    def __init__(self) -> None:
        pass

    def evaluate_gate_interaction(self, gate_result: GateDetectionResult) -> InteractionGuidance:
        """Constructs candidate instructions and verifies interaction requirements."""
        gate_type = gate_result.gate_type
        category = gate_result.category

        # Default fallback
        title = "Action Required"
        instruction = "Please review the employer portal in the other tab."
        action_prompt = "Perform action in employer tab"
        action_cat = gate_result.action_category
        hint = "JobFlow will resume automatically once completed."

        if category == GateCategory.LEGAL_PRIVACY.value:
            if gate_type in (GateType.PRIVACY_POLICY.value, GateType.CANDIDATE_PRIVACY_NOTICE.value):
                title = "Candidate Privacy Notice Review"
                instruction = (
                    "The employer requires you to review and acknowledge their Candidate Privacy Notice before "
                    "accepting your application. Please review their policy in the employer tab and make your decision."
                )
                action_prompt = "Review & Accept Privacy Notice in Employer Tab"
                hint = "JobFlow will resume immediately after you make your decision."
            elif gate_type == GateType.TERMS_AND_CONDITIONS.value:
                title = "Terms & Conditions Agreement"
                instruction = (
                    "The employer portal requires you to review and accept their Terms & Conditions. "
                    "Please review the terms in the employer tab and proceed if you agree."
                )
                action_prompt = "Review & Accept Terms in Employer Tab"
                hint = "JobFlow will resume automatically once you accept."
            elif gate_type == GateType.RECRUITMENT_CONSENT.value:
                title = "Recruitment Data Consent"
                instruction = (
                    "The employer requests your explicit consent to collect and process your recruitment data. "
                    "Please review the consent request in the employer tab."
                )
                action_prompt = "Confirm Consent in Employer Tab"
                hint = "JobFlow will resume automatically."
            elif gate_type == GateType.APPLICANT_DECLARATION.value:
                title = "Applicant Declaration"
                instruction = (
                    "The employer requires you to confirm an applicant declaration before proceeding. "
                    "Please review and confirm the statement in the employer tab."
                )
                action_prompt = "Confirm Declaration in Employer Tab"
                hint = "JobFlow will resume automatically."

        elif category == GateCategory.COOKIE.value:
            title = "Cookie Consent Preferences"
            instruction = (
                "The employer portal displays a cookie consent banner. Please choose your preferred cookie settings "
                "in the employer tab so the application page can load cleanly."
            )
            action_prompt = "Select Cookie Preferences in Employer Tab"
            hint = "JobFlow will continue once the banner is dismissed."

        elif category == GateCategory.AUTHENTICATION.value:
            if gate_type == GateType.MFA_OTP.value:
                title = "Security Verification Code (OTP)"
                instruction = (
                    "The employer has sent a verification code to your email or mobile device. "
                    "Please enter the code in the employer tab."
                )
                action_prompt = "Enter OTP in Employer Tab"
                hint = "JobFlow will resume once verified."
            elif gate_type == GateType.LOGIN_REQUIRED.value:
                title = "Employer Portal Sign-In Required"
                instruction = (
                    "The employer requires you to sign in to your candidate account to access the application form. "
                    "Please sign in using your credentials in the employer tab."
                )
                action_prompt = "Sign In in Employer Tab"
                hint = "JobFlow will detect when authentication is complete and continue."
            elif gate_type == GateType.REGISTRATION_REQUIRED.value:
                title = "Candidate Registration Required"
                instruction = (
                    "The employer portal requires creating a candidate profile before applying. "
                    "Please create your candidate credentials in the employer tab."
                )
                action_prompt = "Register in Employer Tab"
                hint = "JobFlow will resume once your account is active."

        elif category == GateCategory.SECURITY.value:
            if gate_type == GateType.CLOUDFLARE_VERIFICATION.value:
                title = "Cloudflare Security Verification"
                instruction = (
                    "The employer uses Cloudflare to verify that visitors are human. "
                    "Please complete the Cloudflare checkbox or challenge in the employer tab."
                )
                action_prompt = "Complete Verification in Employer Tab"
                hint = "JobFlow will continue automatically once the verification passes."
            elif gate_type == GateType.CAPTCHA_CHALLENGE.value:
                title = "Security Challenge Required"
                instruction = (
                    "The employer page presents a security challenge (CAPTCHA). "
                    "Please solve the challenge in the employer tab."
                )
                action_prompt = "Solve Challenge in Employer Tab"
                hint = "JobFlow will resume when the challenge is solved."
            elif gate_type == GateType.RESTRICTED_ACCESS.value:
                title = "Access Restricted"
                instruction = (
                    "The employer portal is temporarily restricting access. "
                    "Please check the employer tab directly to see if access can be restored."
                )
                action_prompt = "Inspect Restriction in Employer Tab"
                hint = "JobFlow will retry once the page becomes accessible."

        elif category == GateCategory.ELIGIBILITY.value:
            title = "Eligibility Screening Questions"
            instruction = (
                "The employer requires you to answer preliminary eligibility questions (e.g. work authorization, "
                "visa sponsorship). Please answer these questions truthfully in the employer tab."
            )
            action_prompt = "Answer Questions in Employer Tab"
            hint = "JobFlow will resume after you complete the preliminary questions."

        return InteractionGuidance(
            gate_type=gate_type,
            action_category=action_cat,
            title=title,
            instruction=instruction,
            action_prompt=action_prompt,
            is_blocking=gate_result.is_blocking,
            completion_hint=hint,
        )

    def is_automated_action_permitted(self, control_text: str, control_type: str = "button") -> bool:
        """Strict invariant check: ensures automation never clicks protected human controls."""
        if not control_text:
            return True
        import re
        clean_text = control_text.strip().lower()
        for pat in self.PROTECTED_CONTROL_PATTERNS:
            if re.search(pat, clean_text, re.I):
                logger.warning(
                    f"Automated action blocked by safety policy: Control '{clean_text}' matches protected pattern '{pat}'."
                )
                return False
        return True

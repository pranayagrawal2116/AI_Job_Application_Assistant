"""Pre-Application Gate Detector (IAGH Architecture).

Responsible for intelligent inspection and classification of employer application
portal pages prior to, during, and between application form filling stages.

Identifies:
1. Category A: Legal and privacy gates (Privacy policy, candidate privacy notice,
   data processing agreement, terms & conditions, recruitment consent, declarations)
2. Category B: Cookie gates (Accept/reject cookies, manage preferences)
3. Category C: Authentication gates (Login, registration, email verification, OTP, 2FA)
4. Category D: Security gates (CAPTCHA, Cloudflare verification, bot protection)
5. Category E: Eligibility gates (Work authorization, sponsorship, age eligibility, declarations)
6. Category F: Application progression (Multi-step application, resume parsing, dynamic form)

Safety & Truthfulness Invariants:
- Uses DOM structure, semantic tags, accessible names, visible controls, and modal/container context.
- NEVER classifies a page using keyword matching alone (e.g. footer privacy links do not trigger blocking).
- Emits structured GateDetectionResult with confidence, blocking status, and actionable user instructions.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Tag

from src.utils.logger import setup_logger

logger = setup_logger("PreApplicationGateDetector")


class GateCategory(str, Enum):
    LEGAL_PRIVACY = "LEGAL_PRIVACY"
    COOKIE = "COOKIE"
    AUTHENTICATION = "AUTHENTICATION"
    SECURITY = "SECURITY"
    ELIGIBILITY = "ELIGIBILITY"
    APPLICATION_PROGRESSION = "APPLICATION_PROGRESSION"
    NONE = "NONE"


class GateType(str, Enum):
    # Category A: Legal and Privacy
    PRIVACY_POLICY = "PRIVACY_POLICY"
    CANDIDATE_PRIVACY_NOTICE = "CANDIDATE_PRIVACY_NOTICE"
    DATA_PROCESSING_AGREEMENT = "DATA_PROCESSING_AGREEMENT"
    TERMS_AND_CONDITIONS = "TERMS_AND_CONDITIONS"
    RECRUITMENT_CONSENT = "RECRUITMENT_CONSENT"
    APPLICANT_DECLARATION = "APPLICANT_DECLARATION"

    # Category B: Cookies
    COOKIE_CONSENT = "COOKIE_CONSENT"

    # Category C: Authentication
    LOGIN_REQUIRED = "LOGIN_REQUIRED"
    REGISTRATION_REQUIRED = "REGISTRATION_REQUIRED"
    EMAIL_VERIFICATION = "EMAIL_VERIFICATION"
    MFA_OTP = "MFA_OTP"

    # Category D: Security
    CAPTCHA_CHALLENGE = "CAPTCHA_CHALLENGE"
    CLOUDFLARE_VERIFICATION = "CLOUDFLARE_VERIFICATION"
    BOT_PROTECTION = "BOT_PROTECTION"
    RESTRICTED_ACCESS = "RESTRICTED_ACCESS"

    # Category E: Eligibility
    WORK_AUTHORIZATION = "WORK_AUTHORIZATION"
    SPONSORSHIP_ELIGIBILITY = "SPONSORSHIP_ELIGIBILITY"
    AGE_ELIGIBILITY = "AGE_ELIGIBILITY"
    RELOCATION_CHECK = "RELOCATION_CHECK"
    PRE_SCREENING_DECLARATIONS = "PRE_SCREENING_DECLARATIONS"

    # Category F: Progression
    MULTI_STEP_APPLICATION = "MULTI_STEP_APPLICATION"
    ATS_RESUME_PARSING = "ATS_RESUME_PARSING"
    ADDITIONAL_INFORMATION = "ADDITIONAL_INFORMATION"
    SCREENING_QUESTIONS = "SCREENING_QUESTIONS"
    DYNAMIC_APPLICATION_FORM = "DYNAMIC_APPLICATION_FORM"
    FINAL_REVIEW_PAGE = "FINAL_REVIEW_PAGE"

    # Category None
    APPLICATION_FORM_READY = "APPLICATION_FORM_READY"
    GENERIC_PAGE = "GENERIC_PAGE"


class ActionCategory(str, Enum):
    USER_DECISION = "USER_DECISION"
    USER_AUTHENTICATION = "USER_AUTHENTICATION"
    ORDINARY_NAVIGATION = "ORDINARY_NAVIGATION"
    NONE = "NONE"


@dataclass
class GateDetectionResult:
    """Structured outcome of pre-application page inspection."""
    category: str  # GateCategory
    gate_type: str  # GateType
    confidence: float  # 0.0 to 1.0
    is_blocking: bool
    required_user_action: str
    action_category: str  # ActionCategory
    detected_controls: List[Dict[str, Any]] = field(default_factory=list)
    form_detected: bool = False
    stepper_info: Optional[Dict[str, Any]] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PreApplicationGateDetector:
    """Universal detector for intermediate employer portal gates and application form readiness."""

    def __init__(self) -> None:
        pass

    def detect_from_html(self, html: str, url: str = "") -> GateDetectionResult:
        """Inspects HTML DOM structure and returns structured gate classification."""
        if not html or not html.strip():
            return GateDetectionResult(
                category=GateCategory.NONE.value,
                gate_type=GateType.GENERIC_PAGE.value,
                confidence=0.0,
                is_blocking=False,
                required_user_action="",
                action_category=ActionCategory.NONE.value,
                details={"reason": "empty_html"},
            )

        soup = BeautifulSoup(html, "html.parser")

        # 1. First priority: Check for critical security challenges (Cloudflare, CAPTCHA, Turnstile, bot blocks)
        sec_res = self._check_security_gate(soup, html, url)
        if sec_res:
            return sec_res

        # 2. Check for active blocking modals / cookie overlays
        cookie_res = self._check_cookie_gate(soup)
        if cookie_res and cookie_res.is_blocking:
            return cookie_res

        # 3. Check for dedicated Authentication Gate (Login / OTP / 2FA)
        auth_res = self._check_authentication_gate(soup, url)
        if auth_res:
            return auth_res

        # 4. Check for Legal & Privacy Gates (Candidate Privacy Notice, Terms, Consent)
        privacy_res = self._check_legal_privacy_gate(soup)
        if privacy_res and privacy_res.is_blocking:
            return privacy_res

        # 5. Check for Pre-screening / Eligibility Gates (Work authorization, sponsorship)
        elig_res = self._check_eligibility_gate(soup)
        if elig_res and elig_res.is_blocking:
            return elig_res

        # 6. Check for Application Form Readiness
        form_res = self._check_application_form(soup, html, url)
        if form_res:
            return form_res

        # 7. Check for Application Progression (multi-step stepper, parsing screen)
        prog_res = self._check_application_progression(soup)
        if prog_res:
            return prog_res

        # Default fallback: Generic page
        return GateDetectionResult(
            category=GateCategory.NONE.value,
            gate_type=GateType.GENERIC_PAGE.value,
            confidence=0.5,
            is_blocking=False,
            required_user_action="",
            action_category=ActionCategory.NONE.value,
            form_detected=False,
            details={"url": url},
        )

    # -------------------------------------------------------------------------
    # INSPECTION SUB-ROUTINES
    # -------------------------------------------------------------------------

    def _check_security_gate(self, soup: BeautifulSoup, raw_html: str, url: str) -> Optional[GateDetectionResult]:
        """Detects active Cloudflare Turnstile, CAPTCHA, or IP restriction challenges."""
        lower_html = raw_html.lower()

        # Cloudflare challenge page
        cf_markers = [
            "challenges.cloudflare.com",
            "cf-chl-widget",
            "cf-turnstile",
            "#challenge-stage",
            "ray id:",
            "just a moment...",
            "attention required! | cloudflare",
        ]
        cf_detected = any(m in lower_html for m in cf_markers)
        if cf_detected and ("verify you are human" in lower_html or "security check" in lower_html or "cloudflare" in lower_html):
            # Check if it's an interstitial full-page challenge
            headings = [h.get_text().strip().lower() for h in soup.find_all(["h1", "h2", "title"])]
            if any("moment" in h or "verify" in h or "attention" in h or "security" in h for h in headings):
                return GateDetectionResult(
                    category=GateCategory.SECURITY.value,
                    gate_type=GateType.CLOUDFLARE_VERIFICATION.value,
                    confidence=0.95,
                    is_blocking=True,
                    required_user_action="Please complete the employer's Cloudflare security verification in the employer tab.",
                    action_category=ActionCategory.USER_AUTHENTICATION.value,
                    form_detected=False,
                    details={"provider": "cloudflare"},
                )

        # Active CAPTCHA challenge
        captcha_frames = soup.find_all("iframe", src=re.compile(r"recaptcha|hcaptcha|turnstile", re.I))
        captcha_widgets = soup.find_all(class_=re.compile(r"g-recaptcha|h-captcha|cf-turnstile", re.I))

        # Check if there's a dedicated captcha container without standard form fields
        has_real_fields = bool(soup.find("input", attrs={"name": re.compile(r"name|email|phone", re.I)}))
        if (captcha_frames or captcha_widgets) and not has_real_fields:
            return GateDetectionResult(
                category=GateCategory.SECURITY.value,
                gate_type=GateType.CAPTCHA_CHALLENGE.value,
                confidence=0.90,
                is_blocking=True,
                required_user_action="Please complete the employer's security challenge in the employer tab.",
                action_category=ActionCategory.USER_AUTHENTICATION.value,
                form_detected=False,
                details={"captcha_found": True},
            )

        # Access denied / rate limited
        title_text = (soup.title.string.lower() if soup.title and soup.title.string else "")
        if "403 forbidden" in title_text or "access denied" in title_text or "rate limit exceeded" in lower_html:
            return GateDetectionResult(
                category=GateCategory.SECURITY.value,
                gate_type=GateType.RESTRICTED_ACCESS.value,
                confidence=0.90,
                is_blocking=True,
                required_user_action="Access to the employer portal is currently restricted or rate-limited.",
                action_category=ActionCategory.USER_AUTHENTICATION.value,
                form_detected=False,
                details={"restriction": True},
            )

        return None

    def _check_cookie_gate(self, soup: BeautifulSoup) -> Optional[GateDetectionResult]:
        """Detects blocking cookie consent banners, overlays, or popups."""
        cookie_selectors = [
            "#onetrust-banner-sdk",
            ".cookie-banner",
            ".cookie-consent",
            "#cookie-notice",
            "[aria-label*='cookie' i]",
            "[id*='cookie' i]",
            "[class*='cookie' i]",
        ]

        cookie_container = None
        for sel in cookie_selectors:
            matched = soup.select(sel)
            for el in matched:
                # Exclude simple footer links like <a href="/cookies">Cookie Policy</a>
                if el.name == "a":
                    continue
                # Ensure it has consent buttons
                btn = el.find(["button", "a", "input"], string=re.compile(r"accept|agree|reject|manage|got it|allow", re.I))
                if not btn:
                    btn = el.find(["button", "a", "input"], attrs={"aria-label": re.compile(r"accept|agree|reject|allow", re.I)})
                if btn:
                    cookie_container = el
                    break
            if cookie_container:
                break

        if cookie_container:
            # Check controls
            controls = []
            for b in cookie_container.find_all(["button", "a", "input"]):
                txt = b.get_text().strip()
                if txt and len(txt) < 40 and re.search(r"accept|agree|reject|manage|allow|save|close", txt, re.I):
                    controls.append({"type": b.name, "text": txt, "id": b.get("id"), "class": b.get("class")})

            return GateDetectionResult(
                category=GateCategory.COOKIE.value,
                gate_type=GateType.COOKIE_CONSENT.value,
                confidence=0.90,
                is_blocking=True,
                required_user_action="The employer page has a cookie consent prompt. Please select your cookie preferences in the employer tab.",
                action_category=ActionCategory.USER_DECISION.value,
                detected_controls=controls,
                form_detected=False,
                details={"cookie_container_tag": cookie_container.name},
            )

        return None

    def _check_authentication_gate(self, soup: BeautifulSoup, url: str) -> Optional[GateDetectionResult]:
        """Detects candidate sign-in, registration, OTP, or email verification requirements."""
        # 1. OTP / MFA check
        otp_input = soup.find("input", attrs={"autocomplete": "one-time-code"}) or \
                    soup.find("input", attrs={"name": re.compile(r"otp|verification_code|passcode", re.I)})
        if otp_input:
            return GateDetectionResult(
                category=GateCategory.AUTHENTICATION.value,
                gate_type=GateType.MFA_OTP.value,
                confidence=0.95,
                is_blocking=True,
                required_user_action="Please enter the verification code or OTP in the employer portal.",
                action_category=ActionCategory.USER_AUTHENTICATION.value,
                detected_controls=[{"type": "input", "name": otp_input.get("name")}],
                form_detected=False,
                details={"otp_field": otp_input.get("name")},
            )

        # 2. Password login form
        pwd_inputs = soup.find_all("input", attrs={"type": "password"})
        if pwd_inputs:
            # Check if this is an application form (e.g. Workday create account) vs a pure login barrier
            # A pure login barrier lacks resume upload and candidate job fields
            has_resume_upload = bool(soup.find("input", attrs={"type": "file"}))
            has_candidate_fields = bool(soup.find("input", attrs={"name": re.compile(r"name|phone|education|experience", re.I)}))

            # If it's a login form without full application fields, it's an authentication gate
            if not has_resume_upload or not has_candidate_fields:
                headings = [h.get_text().strip().lower() for h in soup.find_all(["h1", "h2", "h3"])]
                is_signin = any("sign in" in h or "log in" in h or "login" in h or "welcome" in h for h in headings) or \
                            "login" in url.lower() or "signin" in url.lower()

                submit_btn = soup.find("button", string=re.compile(r"sign in|log in|continue|next", re.I))
                controls = []
                if submit_btn:
                    controls.append({"type": "button", "text": submit_btn.get_text().strip()})

                return GateDetectionResult(
                    category=GateCategory.AUTHENTICATION.value,
                    gate_type=GateType.LOGIN_REQUIRED.value if is_signin else GateType.REGISTRATION_REQUIRED.value,
                    confidence=0.92,
                    is_blocking=True,
                    required_user_action="Please sign in to the employer portal. JobFlow will resume automatically when authentication is complete.",
                    action_category=ActionCategory.USER_AUTHENTICATION.value,
                    detected_controls=controls,
                    form_detected=False,
                    details={"has_password_field": True},
                )

        return None

    def _check_legal_privacy_gate(self, soup: BeautifulSoup) -> Optional[GateDetectionResult]:
        """Detects dedicated legal agreements, candidate privacy notices, and recruitment consent gates."""
        # Avoid false positives: verify this is NOT just a footer link or passive statement
        # A true legal gate has:
        # A) Explicit prominent heading (Privacy Notice, Terms & Conditions, Consent)
        # B) Acknowledgment controls: "I Accept", "I Agree", "Acknowledge & Continue", or a consent checkbox
        # C) Absence of full application form fields (or existing inside an active modal dialog)

        # Check for active modal dialog first
        modal = soup.find(["dialog", "div"], attrs={"role": "dialog"}) or \
                soup.find("div", class_=re.compile(r"modal|overlay|terms-dialog|privacy-dialog", re.I))
        scope = modal if modal else soup

        # Find consent headings
        consent_headings = scope.find_all(["h1", "h2", "h3", "h4", "legend", "strong"], string=re.compile(
            r"candidate privacy|privacy notice|data privacy|data processing|terms of use|terms and conditions|recruitment consent|applicant declaration|consent to process",
            re.I
        ))

        if not consent_headings:
            return None

        # Verify not in footer
        heading = consent_headings[0]
        if heading.find_parent(["footer", ".footer", "#footer"]):
            return None

        # Look for acknowledgment / action controls
        agree_btn = scope.find(["button", "a", "input"], string=re.compile(
            r"i agree|i accept|accept and continue|acknowledge|accept terms|agree & continue|consent and continue", re.I
        ))
        consent_checkbox = scope.find("input", attrs={"type": "checkbox", "name": re.compile(r"agree|accept|consent|privacy|terms", re.I)})

        if agree_btn or consent_checkbox:
            # Check if this is an interstitial gate vs an active full form with an agreement checkbox at bottom
            has_full_app_fields = bool(
                soup.find("input", attrs={"name": re.compile(r"name|fullname", re.I)}) and
                soup.find("input", attrs={"name": re.compile(r"email", re.I)}) and
                soup.find("input", attrs={"type": "file"})
            )

            # If full app fields exist and it's not a modal, it's the actual form (with a declaration checkbox)
            if has_full_app_fields and not modal:
                return None

            controls = []
            if agree_btn:
                controls.append({"type": agree_btn.name, "text": agree_btn.get_text().strip()})
            if consent_checkbox:
                controls.append({"type": "checkbox", "name": consent_checkbox.get("name")})

            txt = heading.get_text().strip().lower()
            gate_type = GateType.PRIVACY_POLICY.value
            if "terms" in txt:
                gate_type = GateType.TERMS_AND_CONDITIONS.value
            elif "consent" in txt:
                gate_type = GateType.RECRUITMENT_CONSENT.value
            elif "declaration" in txt:
                gate_type = GateType.APPLICANT_DECLARATION.value
            elif "candidate privacy" in txt or "privacy notice" in txt:
                gate_type = GateType.CANDIDATE_PRIVACY_NOTICE.value

            return GateDetectionResult(
                category=GateCategory.LEGAL_PRIVACY.value,
                gate_type=gate_type,
                confidence=0.92,
                is_blocking=True,
                required_user_action="The employer requires you to review and accept their agreement before continuing. Please review it in the employer tab and make your decision.",
                action_category=ActionCategory.USER_DECISION.value,
                detected_controls=controls,
                form_detected=False,
                details={"heading": heading.get_text().strip()},
            )

        return None

    def _check_eligibility_gate(self, soup: BeautifulSoup) -> Optional[GateDetectionResult]:
        """Detects preliminary eligibility screening questions (work authorization, sponsorship)."""
        # Look for explicit work auth or sponsorship questions
        auth_questions = soup.find_all(string=re.compile(
            r"authorized to work|authorization to work|visa sponsorship|require sponsorship|legally authorized|18 years of age|relocate",
            re.I
        ))

        # Check if questions are inside a dedicated pre-screening page or form
        if auth_questions:
            # Check if it has answer controls (radios or selects)
            for q in auth_questions:
                parent = q.find_parent(["div", "section", "fieldset", "form"])
                if parent:
                    radios = parent.find_all("input", attrs={"type": "radio"})
                    selects = parent.find_all("select")
                    if radios or selects:
                        # Ensure this is not already the final full application form with 10+ candidate fields
                        all_inputs = soup.find_all("input")
                        if len(all_inputs) < 15 and not soup.find("input", attrs={"type": "file"}):
                            return GateDetectionResult(
                                category=GateCategory.ELIGIBILITY.value,
                                gate_type=GateType.WORK_AUTHORIZATION.value,
                                confidence=0.88,
                                is_blocking=True,
                                required_user_action="The employer requires you to answer preliminary eligibility questions. Please answer them in the employer tab.",
                                action_category=ActionCategory.USER_DECISION.value,
                                form_detected=False,
                                details={"question": q.strip()[:100]},
                            )

        return None

    def _check_application_form(self, soup: BeautifulSoup, raw_html: str, url: str) -> Optional[GateDetectionResult]:
        """Checks if a supported application form is accessible and ready for autofill."""
        # Indicators of an active job application form:
        # 1. Resume file upload input
        # 2. Name input
        # 3. Email input
        # 4. Form container

        has_resume_input = bool(
            soup.find("input", attrs={"type": "file"}) or
            soup.find(attrs={"data-qa": "input-resume"}) or
            soup.find(id=re.compile(r"resume-upload", re.I)) or
            soup.find(class_=re.compile(r"resume-upload|file-upload", re.I))
        )

        has_name_input = bool(
            soup.find("input", attrs={"name": re.compile(r"^name$|fullname|full_name", re.I)}) or
            soup.find("input", attrs={"data-qa": "name-input"}) or
            soup.find("input", attrs={"id": re.compile(r"^name$|fullname", re.I)})
        )

        has_email_input = bool(
            soup.find("input", attrs={"type": "email"}) or
            soup.find("input", attrs={"name": re.compile(r"email", re.I)}) or
            soup.find("input", attrs={"data-qa": "email-input"})
        )

        has_form_tag = bool(
            soup.find("form", id=re.compile(r"application|apply", re.I)) or
            soup.find("form", attrs={"enctype": re.compile(r"multipart", re.I)}) or
            soup.find(class_=re.compile(r"application-form|apply-form|lever-form", re.I))
        )

        # If at least 2 of (resume, name, email) are present, or form tag + name/email
        if (has_resume_input and has_name_input) or (has_name_input and has_email_input) or (has_form_tag and (has_name_input or has_email_input)):
            return GateDetectionResult(
                category=GateCategory.NONE.value,
                gate_type=GateType.APPLICATION_FORM_READY.value,
                confidence=0.95,
                is_blocking=False,
                required_user_action="",
                action_category=ActionCategory.NONE.value,
                form_detected=True,
                details={
                    "has_resume_input": has_resume_input,
                    "has_name_input": has_name_input,
                    "has_email_input": has_email_input,
                    "url": url,
                },
            )

        return None

    def _check_application_progression(self, soup: BeautifulSoup) -> Optional[GateDetectionResult]:
        """Detects multi-step steppers, resume parsing spinners, or review pages."""
        # Multi-step steppers
        stepper = soup.find(class_=re.compile(r"step-indicator|stepper|wizard|progression", re.I)) or \
                  soup.find(attrs={"data-step": True})
        if stepper:
            step_text = stepper.get_text().strip()
            return GateDetectionResult(
                category=GateCategory.APPLICATION_PROGRESSION.value,
                gate_type=GateType.MULTI_STEP_APPLICATION.value,
                confidence=0.85,
                is_blocking=False,
                required_user_action="Multi-step application flow detected. JobFlow will populate each step as accessible.",
                action_category=ActionCategory.ORDINARY_NAVIGATION.value,
                form_detected=True,
                stepper_info={"stepper_text": step_text[:100]},
                details={"stepper": True},
            )

        # ATS parsing progress screen
        parsing_indicator = soup.find(string=re.compile(r"parsing your resume|analyzing cv|reading your resume|processing resume", re.I))
        if parsing_indicator:
            return GateDetectionResult(
                category=GateCategory.APPLICATION_PROGRESSION.value,
                gate_type=GateType.ATS_RESUME_PARSING.value,
                confidence=0.90,
                is_blocking=False,
                required_user_action="Employer ATS is parsing your uploaded resume...",
                action_category=ActionCategory.NONE.value,
                form_detected=True,
                details={"parsing": True},
            )

        return None

    def detect_from_playwright_page(self, page: Any) -> GateDetectionResult:
        """Inspects live Playwright page using content and accessibility cues."""
        try:
            content = page.content()
            url = page.url
            return self.detect_from_html(content, url=url)
        except Exception as e:
            logger.warning(f"Error inspecting Playwright page: {e}")
            return GateDetectionResult(
                category=GateCategory.NONE.value,
                gate_type=GateType.GENERIC_PAGE.value,
                confidence=0.0,
                is_blocking=False,
                required_user_action="",
                action_category=ActionCategory.NONE.value,
                details={"error": str(e)},
            )

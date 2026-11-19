"""ATS Adapter Registry (IAGH Architecture).

Provides a modular, extensible provider registration system for external employer
Applicant Tracking Systems (ATS), including Lever, Greenhouse, Workday, RippleHire,
Keka, and Universal fallbacks.

Each adapter provides:
- Page and URL identification patterns
- Known gate detection hints (e.g. Workday account creation, RippleHire consent)
- ATS-specific resume file input selectors
- Asynchronous resume parsing indicators
- Form field selectors and container markers
- Protected submission button selectors (to ensure automation never clicks them)
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.utils.logger import setup_logger

logger = setup_logger("ATSAdapterRegistry")


class BaseATSAdapter(ABC):
    """Abstract base class for employer ATS platform adapters."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Uppercase identifier for the ATS provider."""
        pass

    @abstractmethod
    def matches(self, url: str, html_snippet: str = "") -> bool:
        """Returns True if the current URL or DOM matches this ATS platform."""
        pass

    @abstractmethod
    def get_resume_selectors(self) -> List[str]:
        """Ordered selectors for locating the resume upload input element."""
        pass

    @abstractmethod
    def get_parsing_indicators(self) -> List[str]:
        """Selectors or text markers indicating asynchronous resume parsing is occurring."""
        pass

    @abstractmethod
    def get_form_selectors(self) -> List[str]:
        """Selectors identifying the main application form container."""
        pass

    @abstractmethod
    def get_submit_selectors(self) -> List[str]:
        """Selectors for final submission controls, strictly protected from automated clicks."""
        pass

    def get_known_gate_hints(self) -> Dict[str, Any]:
        """Returns known platform-specific gate behaviors (e.g. Workday login requirement)."""
        return {}


class LeverATSAdapter(BaseATSAdapter):
    """Adapter for Lever ATS (e.g. jobs.lever.co)."""

    @property
    def provider_name(self) -> str:
        return "LEVER"

    def matches(self, url: str, html_snippet: str = "") -> bool:
        parsed = urlparse(url or "")
        host = (parsed.hostname or "").lower()
        lower_html = html_snippet.lower() if html_snippet else ""
        return (
            "lever.co" in host or
            "jobs.lever.co" in host or
            "data-qa=\"name-input\"" in lower_html or
            "lever-form" in lower_html
        )

    def get_resume_selectors(self) -> List[str]:
        return [
            "input[data-qa='input-resume']",
            "#resume-upload-input",
            "input[type='file'][name='resume']",
            ".section-resume input[type='file']",
            "input[type='file']",
        ]

    def get_parsing_indicators(self) -> List[str]:
        return [
            ".application-file-upload .file-name",
            "[data-qa='resume-upload-success']",
            ".section-resume .file-name",
            ".resume-uploaded",
        ]

    def get_form_selectors(self) -> List[str]:
        return [
            "form#application-form",
            ".application-form",
            "form[action*='lever']",
            "form",
        ]

    def get_submit_selectors(self) -> List[str]:
        return [
            "button#hcaptchaSubmitBtn",
            "button[type='submit'][data-qa='btn-submit']",
            "#application-form button[type='submit']",
            "button[type='submit']",
        ]

    def get_known_gate_hints(self) -> Dict[str, Any]:
        return {
            "has_hcaptcha_submit_button": True,
            "requires_google_location_autocomplete": True,
        }


class GreenhouseATSAdapter(BaseATSAdapter):
    """Adapter for Greenhouse ATS (e.g. boards.greenhouse.io)."""

    @property
    def provider_name(self) -> str:
        return "GREENHOUSE"

    def matches(self, url: str, html_snippet: str = "") -> bool:
        parsed = urlparse(url or "")
        host = (parsed.hostname or "").lower()
        lower_html = html_snippet.lower() if html_snippet else ""
        return (
            "greenhouse.io" in host or
            "grnh.se" in host or
            "gh_src" in url or
            "job_application" in lower_html or
            "id=\"application_form\"" in lower_html
        )

    def get_resume_selectors(self) -> List[str]:
        return [
            "input#resume[type='file']",
            "input[name='resume'][type='file']",
            "input[data-field='resume']",
            "#resume_fieldset input[type='file']",
            "input[type='file']",
        ]

    def get_parsing_indicators(self) -> List[str]:
        return [
            "#resume_filename",
            ".filename",
            "[data-qa='file-name']",
            ".progress-bar",
        ]

    def get_form_selectors(self) -> List[str]:
        return [
            "form#application_form",
            "#apply_form",
            "form[action*='greenhouse']",
            "form",
        ]

    def get_submit_selectors(self) -> List[str]:
        return [
            "input#submit_app[type='submit']",
            "button#submit_app",
            "#application_form input[type='submit']",
            "input[type='submit']",
        ]


class WorkdayATSAdapter(BaseATSAdapter):
    """Adapter for Workday ATS (e.g. myworkdayjobs.com)."""

    @property
    def provider_name(self) -> str:
        return "WORKDAY"

    def matches(self, url: str, html_snippet: str = "") -> bool:
        parsed = urlparse(url or "")
        host = (parsed.hostname or "").lower()
        lower_html = html_snippet.lower() if html_snippet else ""
        return (
            "myworkdayjobs.com" in host or
            "workday" in host or
            "wd-command" in lower_html or
            "data-automation-id" in lower_html
        )

    def get_resume_selectors(self) -> List[str]:
        return [
            "input[data-automation-id='file-upload-input-ref']",
            "[data-automation-id='resumeDropZone'] input[type='file']",
            "input[type='file']",
        ]

    def get_parsing_indicators(self) -> List[str]:
        return [
            "[data-automation-id='uploadedFile']",
            "[data-automation-id='file-upload-item']",
            ".wd-loading-spinner",
        ]

    def get_form_selectors(self) -> List[str]:
        return [
            "[data-automation-id='applicationForm']",
            "[data-automation-id='applyPage']",
            "form",
        ]

    def get_submit_selectors(self) -> List[str]:
        return [
            "[data-automation-id='bottom-navigation-next-button']",
            "[data-automation-id='submitButton']",
            "button[data-automation-id='pageHeaderSubmitButton']",
        ]

    def get_known_gate_hints(self) -> Dict[str, Any]:
        return {
            "frequent_login_required": True,
            "multi_step_wizard": True,
        }


class KekaATSAdapter(BaseATSAdapter):
    """Adapter for Keka Hire ATS (e.g. blueflamelabs.keka.com)."""

    @property
    def provider_name(self) -> str:
        return "KEKA"

    def matches(self, url: str, html_snippet: str = "") -> bool:
        parsed = urlparse(url or "")
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        lower_html = html_snippet.lower() if html_snippet else ""
        return (
            "keka.com" in host or
            "/careers/applyjob" in path or
            "/careers/jobdetails" in path or
            "resumeuploadsettings" in lower_html or
            "kekahire" in lower_html
        )

    def get_resume_selectors(self) -> List[str]:
        return [
            "#resume-upload",
            ".resume-upload",
            "input[type='file'][name*='resume']",
            "input[type='file']",
        ]

    def get_parsing_indicators(self) -> List[str]:
        return [
            ".uploaded-resume-info",
            ".file-upload-progress",
            ".resume-parsed-badge",
        ]

    def get_form_selectors(self) -> List[str]:
        return [
            "form#keka-apply-form",
            ".apply-job-form",
            "form",
        ]

    def get_submit_selectors(self) -> List[str]:
        return [
            "button#submit-application",
            "button[type='submit'].btn-apply",
            "button[type='submit']",
        ]


class RippleHireATSAdapter(BaseATSAdapter):
    """Adapter for RippleHire ATS."""

    @property
    def provider_name(self) -> str:
        return "RIPPLEHIRE"

    def matches(self, url: str, html_snippet: str = "") -> bool:
        parsed = urlparse(url or "")
        host = (parsed.hostname or "").lower()
        lower_html = html_snippet.lower() if html_snippet else ""
        return (
            "ripplehire.com" in host or
            "candidate.ripplehire" in host or
            "ripplehire" in lower_html
        )

    def get_resume_selectors(self) -> List[str]:
        return [
            "input[id*='resume'][type='file']",
            "input[name*='resume'][type='file']",
            ".dropzone input[type='file']",
            "input[type='file']",
        ]

    def get_parsing_indicators(self) -> List[str]:
        return [
            ".resume-success",
            ".parsing-loader",
            ".file-uploaded",
        ]

    def get_form_selectors(self) -> List[str]:
        return [
            "#candidateApplyForm",
            ".apply-form-container",
            "form",
        ]

    def get_submit_selectors(self) -> List[str]:
        return [
            "#submitApplicationBtn",
            "button[type='submit']",
        ]

    def get_known_gate_hints(self) -> Dict[str, Any]:
        return {
            "has_candidate_consent_modal": True,
            "has_mobile_otp_verification": True,
        }


class UniversalATSAdapter(BaseATSAdapter):
    """Universal fallback adapter for generic employer career sites."""

    @property
    def provider_name(self) -> str:
        return "UNIVERSAL"

    def matches(self, url: str, html_snippet: str = "") -> bool:
        return True  # Fallback matches everything

    def get_resume_selectors(self) -> List[str]:
        return [
            "input[data-qa='input-resume']",
            "#resume-upload-input",
            "input[type='file'][name*='resume']",
            "input[type='file'][id*='resume']",
            "#resume-upload",
            ".resume-upload",
            "input[type='file']",
        ]

    def get_parsing_indicators(self) -> List[str]:
        return [
            ".file-name",
            ".uploaded-file",
            ".resume-success",
            ".parsing-complete",
        ]

    def get_form_selectors(self) -> List[str]:
        return [
            "form#application-form",
            "form.application-form",
            "form#apply-form",
            "form",
        ]

    def get_submit_selectors(self) -> List[str]:
        return [
            "button#hcaptchaSubmitBtn",
            "button[type='submit'][name*='submit']",
            "button[type='submit'][name*='apply']",
            "button[type='submit']",
            "input[type='submit']",
        ]


class ATSAdapterRegistry:
    """Registry coordinating discovery and resolution of platform adapters."""

    _adapters: List[BaseATSAdapter] = [
        LeverATSAdapter(),
        GreenhouseATSAdapter(),
        WorkdayATSAdapter(),
        KekaATSAdapter(),
        RippleHireATSAdapter(),
    ]
    _fallback_adapter: BaseATSAdapter = UniversalATSAdapter()

    @classmethod
    def register(cls, adapter: BaseATSAdapter) -> None:
        """Registers a new ATS adapter before the fallback."""
        if not any(a.provider_name == adapter.provider_name for a in cls._adapters):
            cls._adapters.insert(0, adapter)
            logger.info("Registered ATS adapter: %s", adapter.provider_name)

    @classmethod
    def resolve(cls, url: str, html_snippet: str = "") -> BaseATSAdapter:
        """Resolves the most specific matching ATS adapter for a given URL and DOM."""
        if not url:
            return cls._fallback_adapter

        for adapter in cls._adapters:
            try:
                if adapter.matches(url, html_snippet):
                    return adapter
            except Exception as e:
                logger.warning(f"Error matching adapter {adapter.provider_name}: {e}")

        return cls._fallback_adapter

    @classmethod
    def list_supported_providers(cls) -> List[str]:
        """Returns list of supported provider names."""
        return [a.provider_name for a in cls._adapters] + [cls._fallback_adapter.provider_name]

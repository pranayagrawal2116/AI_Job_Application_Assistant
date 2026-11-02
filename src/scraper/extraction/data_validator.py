"""Data validation, anti-bot detection, and quality validation for scraped jobs."""

from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Any, Dict, List, Optional

from src.database.url_normalizer import normalize_job_url
from src.scraper.extraction.extraction_schema import ExtractedJobPayload

# Anti-automation, bot-block, and authentication triggers
RESTRICTION_PATTERNS = [
    (r"just a moment|checking your browser|cloudflare|attention required", "Cloudflare anti-bot challenge"),
    (r"recaptcha|hcaptcha|arkose|geetest|security check|verify you are human", "CAPTCHA challenge detected"),
    (r"sign in to linkedin|join linkedin|sign in to continue|log in to see more", "Platform authentication required (login wall)"),
    (r"access denied|403 forbidden|request blocked|rate limit exceeded|too many requests", "HTTP 403/429 access restriction"),
    (r"robot check|automated access detected|bot detection", "Automated access blocked by portal"),
]

# Expired or closed listing indicators
EXPIRED_PATTERNS = [
    r"no longer accepting applications",
    r"this job has expired",
    r"this position has been filled",
    r"this listing has closed",
    r"applications are closed",
    r"job is no longer available",
    r"posting has expired",
]


@dataclass
class ValidationResult:
    """Outcome of validating an extracted job payload."""
    is_valid: bool
    is_restricted: bool = False
    is_expired: bool = False
    restriction_reason: Optional[str] = None
    sanitized_payload: Optional[ExtractedJobPayload] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    official_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "is_restricted": self.is_restricted,
            "is_expired": self.is_expired,
            "restriction_reason": self.restriction_reason,
            "errors": self.errors,
            "warnings": self.warnings,
            "official_url": self.official_url,
        }


class DataValidator:
    """Validates raw extracted payloads, sanitizes fields, evaluates quality, and detects restrictions."""

    def validate(self, payload: ExtractedJobPayload) -> ValidationResult:
        """Validates and cleans an extracted job opportunity."""
        errors: List[str] = []
        warnings: List[str] = []
        is_expired = False

        # 1. URL Validation
        raw_url = (payload.page_url or "").strip()
        if not raw_url:
            return ValidationResult(
                is_valid=False,
                errors=["Payload page_url cannot be empty."],
                official_url=raw_url,
            )

        if not raw_url.startswith(("http://", "https://")):
            errors.append(f"Invalid URL protocol for '{raw_url}'. Must start with http:// or https://")

        # 2. Access Restriction & Anti-Automation Detection
        text_to_scan = f"{payload.page_title or ''} {payload.job_description or ''} {payload.page_url or ''}".lower()
        for pattern, reason in RESTRICTION_PATTERNS:
            if re.search(pattern, text_to_scan):
                payload.is_restricted = True
                payload.restriction_reason = reason
                payload.listing_status = "RESTRICTED"
                return ValidationResult(
                    is_valid=False,
                    is_restricted=True,
                    restriction_reason=reason,
                    sanitized_payload=payload,
                    errors=[f"Automated access restricted: {reason}. Manual visit required."],
                    official_url=payload.page_url,
                )

        # 3. Expired / Closed Listing Detection
        for pat in EXPIRED_PATTERNS:
            if re.search(pat, text_to_scan):
                is_expired = True
                payload.listing_status = "EXPIRED"
                warnings.append("Job posting detected as closed or no longer accepting applications.")
                break

        # Check deadline date expiration
        if payload.application_deadline:
            try:
                deadline_dt = datetime.fromisoformat(payload.application_deadline.replace("Z", "+00:00"))
                if deadline_dt.date() < datetime.now().date():
                    is_expired = True
                    payload.listing_status = "EXPIRED"
                    warnings.append(f"Application deadline ({payload.application_deadline}) has passed.")
            except Exception:
                pass

        # 4. Core Field Presence & Sanitization
        company = self._clean_string(payload.company_name)
        title = self._clean_string(payload.job_title)
        desc = self._clean_string(payload.job_description)
        location = self._clean_string(payload.location)
        stipend = self._clean_string(payload.stipend)
        deadline = self._clean_string(payload.application_deadline)
        pub_date = self._clean_string(payload.publication_date)
        duration = self._clean_string(payload.internship_duration)
        app_url = (payload.application_url or "").strip() or payload.page_url

        if not title:
            errors.append("Missing required field 'job_title'.")
        if not company:
            warnings.append("Company name was not identified; defaults to 'Unknown Company'.")
            company = "Unknown Company"

        if not desc:
            warnings.append("Job description is empty; eligibility checks may be limited.")

        # 5. Work Arrangement Determination
        work_arr = payload.work_arrangement
        if not work_arr:
            comb = f"{location or ''} {desc or ''} {title or ''}".lower()
            if any(k in comb for k in ["remote", "work from home", "wfh", "virtual"]):
                work_arr = "Remote"
            elif "hybrid" in comb:
                work_arr = "Hybrid"
            elif any(k in comb for k in ["on-site", "in-office", "onsite"]):
                work_arr = "On-site"
            else:
                work_arr = "Unspecified"

        # 6. Normalize URLs
        normalized_url = normalize_job_url(payload.page_url)
        normalized_app_url = normalize_job_url(app_url) if app_url else normalized_url

        # 7. Sanitize Skills List
        sanitized_skills = self._sanitize_skills(payload.required_skills)

        # 8. Validate & Normalize Eligibility Criteria
        sanitized_criteria = self._sanitize_criteria(payload.eligibility_criteria)

        # 9. Compute Extraction Confidence
        confidence = self._compute_confidence(title, company, desc, location, sanitized_skills)

        if errors:
            return ValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                official_url=payload.page_url,
            )

        # Listing status
        status = "EXPIRED" if is_expired else ("UNVERIFIED" if confidence < 0.5 else "ACTIVE")

        # Create clean sanitized payload
        cleaned_payload = ExtractedJobPayload(
            page_url=normalized_url,
            page_title=self._clean_string(payload.page_title),
            company_name=company,
            job_title=title,
            location=location or "India (Location Unspecified)",
            job_description=desc,
            required_skills=sanitized_skills,
            eligibility_criteria=sanitized_criteria,
            stipend=stipend,
            application_deadline=deadline,
            application_url=normalized_app_url,
            platform=payload.platform or "Direct",
            work_arrangement=work_arr,
            publication_date=pub_date,
            internship_duration=duration,
            listing_status=status,
            last_verified=datetime.now().isoformat(),
            extraction_confidence=confidence,
            is_restricted=False,
            restriction_reason=None,
            extracted_at=payload.extracted_at,
            extraction_metadata=payload.extraction_metadata,
        )

        return ValidationResult(
            is_valid=True,
            is_restricted=False,
            is_expired=is_expired,
            sanitized_payload=cleaned_payload,
            warnings=warnings,
            official_url=cleaned_payload.page_url,
        )

    def _clean_string(self, text: Optional[str]) -> Optional[str]:
        """Strips HTML tags, collapses excess whitespace, and trims string."""
        if not text or not isinstance(text, str):
            return None
        clean = re.sub(r"<[^>]+>", " ", text)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean or None

    def _sanitize_skills(self, skills: Any) -> List[str]:
        """Cleans, strips, and deduplicates extracted skills."""
        if not skills:
            return []
        raw_list = skills if isinstance(skills, list) else str(skills).split(",")
        seen = set()
        sanitized = []
        for s in raw_list:
            clean = str(s).strip()
            if clean and clean.lower() not in seen:
                seen.add(clean.lower())
                sanitized.append(clean)
        return sanitized

    def _sanitize_criteria(self, criteria: Any) -> Dict[str, Any]:
        """Normalizes structured criteria dictionary."""
        if not isinstance(criteria, dict):
            return {}
        cleaned: Dict[str, Any] = {}
        for k, v in criteria.items():
            if k in ("min_cgpa", "cgpa_cutoff") and v is not None:
                try:
                    cleaned[k] = float(v)
                except (ValueError, TypeError):
                    cleaned[k] = v
            elif k in ("graduation_years", "target_batches") and isinstance(v, list):
                cleaned[k] = [int(y) for y in v if str(y).isdigit()]
            else:
                cleaned[k] = v
        return cleaned

    def _compute_confidence(
        self,
        title: Optional[str],
        company: Optional[str],
        desc: Optional[str],
        location: Optional[str],
        skills: List[str],
    ) -> float:
        """Calculates an extraction confidence score between 0.0 and 1.0."""
        score = 0.0
        if title:
            score += 0.3
        if company and company != "Unknown Company":
            score += 0.2
        if desc and len(desc) >= 100:
            score += 0.3
        elif desc and len(desc) >= 30:
            score += 0.15
        if location:
            score += 0.1
        if skills:
            score += 0.1
        return round(min(1.0, score), 2)


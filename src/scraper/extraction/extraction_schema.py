"""Extraction schema for structured job opportunity payloads with quality attributes."""

from dataclasses import asdict, dataclass, field
from datetime import datetime
import json
from typing import Any, Dict, List, Optional


@dataclass
class ExtractedJobPayload:
    """Structured data payload extracted from web pages or job feeds.

    Fields with unknown or unavailable information remain None or empty to adhere
    strictly to the Zero Fabrication Policy.
    """
    page_url: str
    page_title: Optional[str] = None
    company_name: Optional[str] = None
    job_title: Optional[str] = None
    location: Optional[str] = None
    job_description: Optional[str] = None
    required_skills: List[str] = field(default_factory=list)
    eligibility_criteria: Dict[str, Any] = field(default_factory=dict)
    stipend: Optional[str] = None
    application_deadline: Optional[str] = None
    application_url: Optional[str] = None
    platform: str = "Direct"
    work_arrangement: Optional[str] = None  # 'Remote', 'Hybrid', 'On-site', 'Unspecified'
    publication_date: Optional[str] = None
    internship_duration: Optional[str] = None
    listing_status: str = "ACTIVE"          # 'ACTIVE', 'EXPIRED', 'UNVERIFIED', 'RESTRICTED'
    last_verified: Optional[str] = None
    extraction_confidence: float = 1.0     # 0.0 to 1.0
    is_restricted: bool = False
    restriction_reason: Optional[str] = None
    extracted_at: str = field(default_factory=lambda: datetime.now().isoformat())
    extraction_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts payload to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExtractedJobPayload":
        """Instantiates payload from dictionary, ignoring extraneous keys."""
        valid_keys = {
            "page_url",
            "page_title",
            "company_name",
            "job_title",
            "location",
            "job_description",
            "required_skills",
            "eligibility_criteria",
            "stipend",
            "application_deadline",
            "application_url",
            "platform",
            "work_arrangement",
            "publication_date",
            "internship_duration",
            "listing_status",
            "last_verified",
            "extraction_confidence",
            "is_restricted",
            "restriction_reason",
            "extracted_at",
            "extraction_metadata",
        }
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    def to_json(self) -> str:
        """Serializes payload to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


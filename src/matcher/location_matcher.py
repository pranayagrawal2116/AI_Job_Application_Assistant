"""Location Preference Matcher module."""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List

from src.database.models import Job


@dataclass
class LocationMatchResult:
    score: float
    max_points: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "max_points": self.max_points,
            "details": self.details,
        }


class LocationMatcher:
    """Evaluates geographic compatibility with candidate preferences (India, Remote, Work from Home)."""

    def __init__(self, scoring_rules: Dict[str, Any]):
        loc_cfg = scoring_rules.get("weights", {}).get("location_preference", {})
        self.max_points = float(loc_cfg.get("max_points", 10))
        self.rules = loc_cfg.get("rules", {})
        self.preferred_cities = [c.lower() for c in loc_cfg.get("preferred_locations", []) if c.lower() not in ["remote", "work from home", "india"]]

    def match(self, job: Job) -> LocationMatchResult:
        """Calculates location preference score."""
        loc = (job.location or "").lower()
        desc = (job.job_description or "").lower()
        combined = f"{loc} {desc}"

        # 1. Remote / Work from Home check (Full 10 points)
        if any(term in combined for term in ["remote", "work from home", "wfh", "virtual", "anywhere"]):
            score = float(self.rules.get("remote_or_home", 10))
            category = "REMOTE_OR_WORK_FROM_HOME"

        # 2. Preferred Indian City check (8 points)
        elif any(re.search(r"\b" + re.escape(city) + r"\b", combined) for city in self.preferred_cities):
            score = float(self.rules.get("preferred_indian_city", 8))
            category = "PREFERRED_INDIAN_CITY"

        # 3. Any India Location check (6 points)
        elif any(re.search(r"\b" + re.escape(term) + r"\b", combined) for term in ["india", "in", "pan india"]):
            score = float(self.rules.get("any_india_location", 6))
            category = "ANY_INDIA_LOCATION"

        # 4. Check for foreign mandatory on-site (0 points)
        elif any(fc in loc for fc in ["usa", "united states", "uk", "london", "germany", "singapore", "canada", "australia"]):
            score = float(self.rules.get("international_relocation_required", 0))
            category = "FOREIGN_RELOCATION_REQUIRED"

        # 5. Default Indian internship fallback
        else:
            score = float(self.rules.get("any_india_location", 6))
            category = "UNSPECIFIED_DEFAULT_DOMESTIC"

        return LocationMatchResult(
            score=min(score, self.max_points),
            max_points=self.max_points,
            details={
                "job_location": job.location,
                "category": category,
            },
        )


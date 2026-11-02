"""Experience Compatibility Matcher module."""

from dataclasses import dataclass, field
import re
from typing import Any, Dict

from src.database.models import Job


@dataclass
class ExperienceMatchResult:
    score: float
    max_points: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "max_points": self.max_points,
            "details": self.details,
        }


class ExperienceMatcher:
    """Evaluates compatibility with student/fresher experience level."""

    def __init__(self, scoring_rules: Dict[str, Any]):
        exp_cfg = scoring_rules.get("weights", {}).get("experience_compatibility", {})
        self.max_points = float(exp_cfg.get("max_points", 10))
        self.rules = exp_cfg.get("rules", {})

    def match(self, job: Job) -> ExperienceMatchResult:
        """Calculates experience compatibility points."""
        text = f"{job.job_title} {job.job_description or ''}".lower()

        # Check for 2+ years experience
        exp_2plus = re.search(r"(?:minimum|at least|requires?)\s*([2-9]|\d{2})\+?\s*(?:years?|yrs?)", text)
        is_0_to_1 = re.search(r"(?:0\s*(?:-|to)\s*1\s*(?:years?|yrs?)|freshers? welcome|no prior experience required)", text)
        is_1_to_2 = re.search(r"(?:1\s*(?:-|to)\s*2\s*(?:years?|yrs?)|at least 1 year)", text)
        is_intern_fresher = re.search(r"(?:intern|internship|fresher|college student|trainee|entry level)", text)

        if exp_2plus and not is_0_to_1 and not is_intern_fresher:
            score = float(self.rules.get("requires_2_plus_years", 0))
            category = "REQUIRES_2_PLUS_YEARS"
        elif is_1_to_2:
            score = float(self.rules.get("requires_1_to_2_years", 3))
            category = "REQUIRES_1_TO_2_YEARS"
        elif is_0_to_1:
            score = float(self.rules.get("requires_0_to_1_years", 8))
            category = "REQUIRES_0_TO_1_YEARS"
        elif is_intern_fresher:
            score = float(self.rules.get("explicitly_for_freshers_or_interns", 10))
            category = "EXPLICIT_FRESHER_OR_INTERN"
        else:
            score = float(self.rules.get("requires_0_to_1_years", 8))
            category = "DEFAULT_ENTRY_LEVEL"

        return ExperienceMatchResult(
            score=min(score, self.max_points),
            max_points=self.max_points,
            details={
                "category": category,
            },
        )


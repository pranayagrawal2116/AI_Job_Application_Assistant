"""Duration Compatibility Matcher module."""

from dataclasses import dataclass, field
import re
from typing import Any, Dict

from src.database.models import Job


@dataclass
class DurationMatchResult:
    score: float
    max_points: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "max_points": self.max_points,
            "details": self.details,
        }


class DurationMatcher:
    """Evaluates internship length and scheduling flexibility with student commitments."""

    def __init__(self, scoring_rules: Dict[str, Any]):
        dur_cfg = scoring_rules.get("weights", {}).get("duration_compatibility", {})
        self.max_points = float(dur_cfg.get("max_points", 5))
        self.rules = dur_cfg.get("rules", {})

    def match(self, job: Job) -> DurationMatchResult:
        """Calculates duration compatibility points."""
        text = f"{job.job_title} {job.job_description or ''}".lower()

        is_flexible_or_part_time = bool(re.search(r"(?:part[-\s]?time|flexible hours?|flexible schedule|10-20 hrs)", text))
        is_summer_winter = bool(re.search(r"(?:summer intern|winter intern|2\s*months?|3\s*months?|8\s*weeks?|12\s*weeks?)", text))
        is_6_months = bool(re.search(r"6\s*months?", text))
        is_remote = bool(re.search(r"(?:remote|wfh|work from home)", text))

        if is_flexible_or_part_time:
            score = float(self.rules.get("flexible_or_part_time", 5))
            category = "FLEXIBLE_OR_PART_TIME"
        elif is_summer_winter:
            score = float(self.rules.get("standard_summer_winter_internship", 5))
            category = "STANDARD_SUMMER_WINTER"
        elif is_6_months and is_remote:
            score = float(self.rules.get("full_time_6_months_with_remote", 4))
            category = "SIX_MONTHS_REMOTE"
        elif is_6_months and not is_remote:
            score = float(self.rules.get("requires_full_time_on_site_during_semester", 1))
            category = "RIGID_FULL_TIME_ON_SITE"
        else:
            # Standard internship default
            score = float(self.rules.get("standard_summer_winter_internship", 5))
            category = "STANDARD_DURATION"

        return DurationMatchResult(
            score=min(score, self.max_points),
            max_points=self.max_points,
            details={"category": category},
        )


"""Educational Eligibility Matcher module."""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List

from src.database.models import Job


@dataclass
class EducationMatchResult:
    score: float
    max_points: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "max_points": self.max_points,
            "details": self.details,
        }


class EducationMatcher:
    """Evaluates degree relevance, student graduation timeline, and CGPA compatibility."""

    def __init__(self, candidate_profile: Dict[str, Any], scoring_rules: Dict[str, Any]):
        edu_cfg = scoring_rules.get("weights", {}).get("educational_eligibility", {})
        self.max_points = float(edu_cfg.get("max_points", 20))
        self.rules = edu_cfg.get("rules", {})

        edu_list = candidate_profile.get("education", [])
        self.education = edu_list[0] if edu_list else {}
        self.candidate_cgpa = float(self.education.get("current_cgpa", 7.6))
        self.candidate_grad_year = int(self.education.get("expected_graduation_year", 2028))
        self.candidate_degree = str(self.education.get("major", "Computer Science Engineering – AI & Data Science"))

    def match(self, job: Job) -> EducationMatchResult:
        """Calculates educational compatibility points."""
        text = f"{job.job_title} {job.job_description or ''}".lower()

        # 1. Degree Match Analysis
        exact_degree_keywords = [
            "computer science", "ai", "artificial intelligence", "data science",
            "cse", "engineering", "b.tech", "b.e", "information technology", "it", "stem", "any degree"
        ]
        non_cs_engineering = ["mechanical", "civil", "chemical", "aerospace", "metallurgy", "biotechnology"]
        unrelated_degree_keywords = ["mbbs", "llb", "chartered accountant", "ca", "pharmacy", "nursing", "arts only", "commerce only"]

        is_unrelated = any(re.search(r"\b" + re.escape(k) + r"\b", text) for k in unrelated_degree_keywords)
        is_exact = any(re.search(r"\b" + re.escape(k) + r"\b", text) for k in exact_degree_keywords)
        is_non_cs_eng = any(re.search(r"\b" + re.escape(k) + r"\b", text) for k in non_cs_engineering) and not any(
            re.search(r"\b" + re.escape(k) + r"\b", text) for k in ["computer science", "ai", "data science", "cse"]
        )

        # 2. CGPA Analysis
        cgpa_cutoff = self._extract_cgpa_cutoff(job, text)

        # 3. Score determination
        if is_unrelated and not is_exact:
            score = float(self.rules.get("non_eligible_degree", 0))
            degree_status = "UNRELATED"
        elif cgpa_cutoff is not None and self.candidate_cgpa < cgpa_cutoff:
            # Below employer cutoff: deduction
            score = float(self.rules.get("exact_degree_match_below_employer_cutoff", 10))
            degree_status = "BELOW_CGPA_CUTOFF"
        elif is_non_cs_eng:
            score = float(self.rules.get("general_engineering_match", 15))
            degree_status = "NON_CS_ENGINEERING"
        else:
            # Direct match meets cutoff or no cutoff specified
            score = float(self.rules.get("exact_degree_match_meets_or_no_cgpa_cutoff", 20))
            degree_status = "EXACT_OR_UNRESTRICTED"

        return EducationMatchResult(
            score=min(score, self.max_points),
            max_points=self.max_points,
            details={
                "candidate_degree": self.candidate_degree,
                "candidate_cgpa": self.candidate_cgpa,
                "candidate_grad_year": self.candidate_grad_year,
                "employer_cgpa_cutoff": cgpa_cutoff,
                "degree_status": degree_status,
                "cgpa_evaluated": "Compared against explicit employer cutoff (No penalty if unstated)",
            },
        )

    def _extract_cgpa_cutoff(self, job: Job, text: str) -> float | None:
        """Extracts employer's explicit minimum CGPA requirement if present."""
        criteria = job.eligibility_criteria if isinstance(job.eligibility_criteria, dict) else {}
        explicit_min = criteria.get("min_cgpa") or criteria.get("cgpa_cutoff")
        if explicit_min is not None:
            try:
                return float(explicit_min)
            except (ValueError, TypeError):
                pass

        patterns = [
            r"(?:minimum|min|at least|above)\s+([0-9]+(?:\.[0-9]+)?)\s*(?:cgpa|gpa)",
            r"(?:cgpa|gpa)\s*(?:cutoff|requirement|of|>=|>|:)\s*([0-9]+(?:\.[0-9]+)?)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    val = float(match.group(1))
                    if val <= 10.0:
                        return val
                except ValueError:
                    pass
        return None

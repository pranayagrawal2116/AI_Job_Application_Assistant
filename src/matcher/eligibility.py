"""Eligibility Evaluation Engine for AI Job Application Assistant."""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Tuple

from src.database.models import Job


class EligibilityState(str, Enum):
    """Permitted candidate eligibility outcomes."""
    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE = "INELIGIBLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class EligibilityResult:
    """Structured result of an eligibility evaluation."""
    status: EligibilityState
    is_eligible: bool  # True if ELIGIBLE or UNKNOWN; False if strictly INELIGIBLE
    disqualification_reasons: List[str] = field(default_factory=list)
    criteria_checks: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "is_eligible": self.is_eligible,
            "disqualification_reasons": self.disqualification_reasons,
            "criteria_checks": self.criteria_checks,
        }


class EligibilityEvaluator:
    """Evaluates job postings against mandatory candidate constraints without conflating with numerical scores."""

    def __init__(self, candidate_profile: Dict[str, Any]):
        self.candidate = candidate_profile
        edu_list = self.candidate.get("education", [])
        self.education = edu_list[0] if edu_list else {}
        self.candidate_cgpa = float(self.education.get("current_cgpa", 7.6))
        self.candidate_grad_year = int(self.education.get("expected_graduation_year", 2028))
        self.candidate_degree = str(self.education.get("major", "Computer Science Engineering – AI & Data Science"))
        self.candidate_country = str(self.candidate.get("personal", {}).get("location", {}).get("country", "India"))

    def evaluate(self, job: Job) -> EligibilityResult:
        """Evaluates whether the candidate meets all non-negotiable employer requirements."""
        text = f"{job.job_title} {job.job_description or ''} {job.location or ''}".lower()
        checks: Dict[str, Any] = {}
        disqualifications: List[str] = []
        is_ambiguous = False

        # If job description is completely empty or minimal, mark UNKNOWN
        if not (job.job_description or "").strip() and not (job.required_skills or []):
            return EligibilityResult(
                status=EligibilityState.UNKNOWN,
                is_eligible=True,
                disqualification_reasons=["Job details are insufficient to determine eligibility with certainty."],
                criteria_checks={"insufficient_data": True},
            )

        # 1. CGPA CUTOFF CHECK
        cgpa_passed, cgpa_reason, cgpa_detail = self._check_cgpa(job, text)
        checks["cgpa_check"] = cgpa_detail
        if not cgpa_passed:
            disqualifications.append(cgpa_reason)

        # 2. GRADUATION YEAR & STUDENT STATUS CHECK
        grad_passed, grad_reason, grad_detail = self._check_graduation(job, text)
        checks["graduation_check"] = grad_detail
        if not grad_passed:
            disqualifications.append(grad_reason)

        # 3. EXPERIENCE CAP CHECK
        exp_passed, exp_reason, exp_detail = self._check_experience(job, text)
        checks["experience_check"] = exp_detail
        if not exp_passed:
            disqualifications.append(exp_reason)

        # 4. LOCATION & WORK AUTHORIZATION CHECK
        loc_passed, loc_reason, loc_detail = self._check_location(job, text)
        checks["location_check"] = loc_detail
        if not loc_passed:
            disqualifications.append(loc_reason)

        # 5. DEGREE & ADVANCED DEGREE RESTRICTION CHECK
        deg_passed, deg_reason, deg_detail = self._check_degree_restriction(job, text)
        checks["degree_check"] = deg_detail
        if not deg_passed:
            disqualifications.append(deg_reason)

        # Determine overall eligibility state
        if disqualifications:
            return EligibilityResult(
                status=EligibilityState.INELIGIBLE,
                is_eligible=False,
                disqualification_reasons=disqualifications,
                criteria_checks=checks,
            )

        # Check if key criteria were completely unstated
        if checks.get("graduation_check", {}).get("status") == "UNKNOWN" and checks.get("cgpa_check", {}).get("status") == "NOT_SPECIFIED":
            # Valid candidate with no disqualifying factors
            return EligibilityResult(
                status=EligibilityState.ELIGIBLE,
                is_eligible=True,
                disqualification_reasons=[],
                criteria_checks=checks,
            )

        return EligibilityResult(
            status=EligibilityState.ELIGIBLE,
            is_eligible=True,
            disqualification_reasons=[],
            criteria_checks=checks,
        )

    def _check_cgpa(self, job: Job, text: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Compares candidate CGPA against explicit employer requirement.

        If no CGPA requirement is specified, candidate is NOT penalized or disqualified.
        """
        # Look in structured eligibility_criteria first
        criteria = job.eligibility_criteria if isinstance(job.eligibility_criteria, dict) else {}
        explicit_min = criteria.get("min_cgpa") or criteria.get("cgpa_cutoff")

        if explicit_min is not None:
            try:
                min_val = float(explicit_min)
                if self.candidate_cgpa < min_val:
                    return False, f"Employer requires minimum CGPA of {min_val}, candidate CGPA is {self.candidate_cgpa}.", {
                        "employer_min_cgpa": min_val,
                        "candidate_cgpa": self.candidate_cgpa,
                        "status": "FAILED",
                    }
                return True, "", {
                    "employer_min_cgpa": min_val,
                    "candidate_cgpa": self.candidate_cgpa,
                    "status": "PASSED",
                }
            except (ValueError, TypeError):
                pass

        # Regex search in job description
        # Matches: "minimum 8.0 cgpa", "cgpa >= 8", "cgpa of 7.5", "cutoff 8 cgpa"
        patterns = [
            r"(?:minimum|min|at least|above)\s+([0-9]+(?:\.[0-9]+)?)\s*(?:cgpa|gpa)",
            r"(?:cgpa|gpa)\s*(?:cutoff|requirement|of|>=|>|:)\s*([0-9]+(?:\.[0-9]+)?)",
            r"([0-9]+(?:\.[0-9]+)?)\s*\+?\s*(?:cgpa|gpa)\s*(?:and above|or above|cutoff)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    cutoff = float(match.group(1))
                    # Ignore percentages (e.g. 70%, 80%) misparsed as CGPA
                    if cutoff > 10.0:
                        continue
                    if self.candidate_cgpa < cutoff:
                        return False, f"Employer specifies minimum CGPA of {cutoff}; candidate CGPA is {self.candidate_cgpa}.", {
                            "employer_min_cgpa": cutoff,
                            "candidate_cgpa": self.candidate_cgpa,
                            "status": "FAILED",
                        }
                    return True, "", {
                        "employer_min_cgpa": cutoff,
                        "candidate_cgpa": self.candidate_cgpa,
                        "status": "PASSED",
                    }
                except ValueError:
                    pass

        return True, "", {
            "employer_min_cgpa": None,
            "candidate_cgpa": self.candidate_cgpa,
            "status": "NOT_SPECIFIED",
            "note": "No CGPA cutoff specified by employer; full eligibility preserved.",
        }

    def _check_graduation(self, job: Job, text: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Verifies candidate graduation year compatibility (2028)."""
        criteria = job.eligibility_criteria if isinstance(job.eligibility_criteria, dict) else {}
        allowed_years = criteria.get("graduation_years") or criteria.get("target_batches")

        if allowed_years:
            if isinstance(allowed_years, list) and self.candidate_grad_year in allowed_years:
                return True, "", {"target_batches": allowed_years, "status": "PASSED"}
            elif isinstance(allowed_years, list) and all(y < self.candidate_grad_year for y in allowed_years):
                return False, f"Job is restricted to {allowed_years} graduates; candidate graduates in {self.candidate_grad_year}.", {
                    "target_batches": allowed_years,
                    "candidate_graduation_year": self.candidate_grad_year,
                    "status": "FAILED",
                }

        # Check for restrictive prior batches: e.g. "batch of 2024 or 2025 only", "only 2024/2025 graduates"
        prior_batches_pattern = r"(?:batch(?:es)? of|only for|graduating in)\s*(?:2023|2024|2025)\s*(?:or|and|,|\/)\s*(?:2024|2025)\s*(?:only|graduates)?"
        if re.search(prior_batches_pattern, text) and not re.search(r"2027|2028|pre-final|any batch", text):
            return False, f"Position is strictly reserved for earlier batches (2024/2025); candidate graduates in {self.candidate_grad_year}.", {
                "status": "FAILED",
                "candidate_graduation_year": self.candidate_grad_year,
            }

        # If accepts ongoing/pre-final/current students:
        if re.search(r"(?:pre-final|current student|college student|pursuing|b\.tech student|internship for students)", text):
            return True, "", {"status": "PASSED", "student_friendly": True}

        return True, "", {"status": "ELIGIBLE_DEFAULT", "candidate_graduation_year": self.candidate_grad_year}

    def _check_experience(self, job: Job, text: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Checks for excessive professional experience requirements."""
        # Detect explicit multi-year experience requirements (e.g. "3+ years of experience", "minimum 3 years of ML engineering experience")
        exp_pattern = r"(?:minimum|at least|requires?)\s*([2-9]|\d{2})\+?\s*(?:years?|yrs?)|([2-9]|\d{2})\+?\s*(?:years?|yrs?)(?:\s+of)?(?:\s+[\w\-]+){0,4}\s*(?:experience|exp)"
        match = re.search(exp_pattern, text)
        if match:
            demanded_years = match.group(1) or match.group(2)
            # Ensure it's not saying "requires 0-2 years" or "0 to 1 year"
            if not re.search(r"0\s*(?:-|to)\s*[1-2]\s*years?", text):
                return False, f"Demands {demanded_years}+ years of professional experience; incompatible with student/fresher profile.", {
                    "demanded_experience": f"{demanded_years}+ years",
                    "status": "FAILED",
                }

        return True, "", {"status": "PASSED", "note": "Experience demands are compatible with fresher/student."}

    def _check_location(self, job: Job, text: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Checks if on-site presence is strictly mandated outside India."""
        loc = (job.location or "").lower()
        is_remote = any(k in loc or k in text for k in ["remote", "work from home", "wfh", "virtual", "anywhere"])

        if is_remote:
            return True, "", {"status": "PASSED", "remote": True}

        # Check if location specifies non-India countries without remote option
        foreign_countries = [
            "united states", "usa", "uk", "united kingdom", "london", "germany",
            "berlin", "canada", "toronto", "singapore", "australia", "sydney"
        ]
        is_foreign = any(fc in loc for fc in foreign_countries)
        is_india = any(ic in loc or ic in text for ic in ["india", "pune", "bengaluru", "bangalore", "hyderabad", "mumbai", "delhi", "noida", "gurgaon"])

        if is_foreign and not is_india and not is_remote:
            return False, f"Position mandates on-site presence in '{job.location}' outside India without remote option.", {
                "job_location": job.location,
                "status": "FAILED",
            }

        return True, "", {"status": "PASSED", "location": job.location}

    def _check_degree_restriction(self, job: Job, text: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Checks for advanced degree mandates like PhD or MBA required."""
        if re.search(r"(?:phd required|ph\.d required|must have a phd|doctorate required)", text):
            return False, "Job strictly mandates a PhD / Doctorate degree.", {"status": "FAILED", "reason": "PhD required"}

        return True, "", {"status": "PASSED"}

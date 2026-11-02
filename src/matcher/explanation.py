"""Transparent Match Explanation Generator module."""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from src.matcher.eligibility import EligibilityResult, EligibilityState
from src.matcher.score_calculator import ScoreCalculationResult
from src.matcher.skill_matcher import SkillMatchResult


@dataclass
class MatchExplanation:
    """Structured human-readable explanation of an evaluation."""
    summary: str
    total_score: float
    classification: str
    eligibility_status: str
    is_eligible: bool
    score_breakdown: Dict[str, float]
    matching_skills: Dict[str, List[str]]
    missing_skills: List[str]
    relevant_qualifications: List[str]
    disqualification_reasons: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "total_score": self.total_score,
            "classification": self.classification,
            "eligibility_status": self.eligibility_status,
            "is_eligible": self.is_eligible,
            "score_breakdown": self.score_breakdown,
            "matching_skills": self.matching_skills,
            "missing_skills": self.missing_skills,
            "relevant_qualifications": self.relevant_qualifications,
            "disqualification_reasons": self.disqualification_reasons,
            "recommendations": self.recommendations,
        }

    def format_text(self) -> str:
        """Returns a formatted Markdown report."""
        lines = [
            f"### Match Summary: {self.total_score}/100 ({self.classification})",
            f"**Eligibility Status:** `{self.eligibility_status}`",
            "",
            "#### Score Breakdown:",
        ]
        for k, v in self.score_breakdown.items():
            label = k.replace("_", " ").title()
            lines.append(f"- **{label}:** {v} pts")

        lines.extend([
            "",
            f"#### Matching Skills ({len(self.matching_skills.get('confirmed', []))} Confirmed, {len(self.matching_skills.get('related', []))} Related):",
            f"- **Confirmed:** {', '.join(self.matching_skills.get('confirmed', [])) or 'None'}",
            f"- **Related:** {', '.join(self.matching_skills.get('related', [])) or 'None'}",
        ])

        if self.missing_skills:
            lines.extend([
                "",
                f"#### Missing Skills ({len(self.missing_skills)}):",
                f"- {', '.join(self.missing_skills)}",
            ])

        if self.disqualification_reasons:
            lines.extend([
                "",
                "#### ⚠️ Disqualification Reasons:",
            ])
            for reason in self.disqualification_reasons:
                lines.append(f"- {reason}")

        if self.recommendations:
            lines.extend([
                "",
                "#### Recommendations:",
            ])
            for rec in self.recommendations:
                lines.append(f"- {rec}")

        return "\n".join(lines)


class ExplanationGenerator:
    """Produces detailed human-readable match explanations and actionable recommendations."""

    def __init__(self, candidate_profile: Dict[str, Any]):
        self.candidate = candidate_profile

    def generate(
        self,
        score_res: ScoreCalculationResult,
        eligibility_res: EligibilityResult,
        skill_res: SkillMatchResult,
        job_title: str,
        company_name: str,
    ) -> MatchExplanation:
        """Generates a complete explanation package."""
        # 1. Relevant candidate qualifications
        qualifications: List[str] = [
            "B.Tech Computer Science Engineering (AI & Data Science) at MIT World Peace University (Graduating 2028, CGPA 7.6)",
            "Hands-on ML Project: Diabetes Risk Prediction using Machine Learning",
            "Full-Stack Mobile Applications: Hospital Management Application, Factory Management Application",
        ]

        # 2. Summary
        if eligibility_res.status == EligibilityState.INELIGIBLE:
            summary = (
                f"Candidate scored {score_res.total_score}/100 ({score_res.classification}), but is marked INELIGIBLE "
                f"due to mandatory employer criteria: {'; '.join(eligibility_res.disqualification_reasons)}."
            )
        elif eligibility_res.status == EligibilityState.UNKNOWN:
            summary = (
                f"Candidate scored {score_res.total_score}/100 ({score_res.classification}). "
                f"Eligibility is UNKNOWN due to limited job description details."
            )
        else:
            summary = (
                f"Candidate is a strong {score_res.classification} match ({score_res.total_score}/100) and ELIGIBLE "
                f"for the {job_title} role at {company_name}."
            )

        # 3. Actionable recommendations
        recommendations: List[str] = []
        if eligibility_res.status == EligibilityState.INELIGIBLE:
            recommendations.append(
                "Do not submit application; mandatory qualification criteria are not met."
            )
        else:
            if score_res.total_score >= 85:
                recommendations.append("Priority application: Candidate has high domain and technical alignment.")
            elif score_res.total_score >= 70:
                recommendations.append("Good match: Highlight relevant ML coursework and project outcomes in cover letter.")

            if skill_res.missing_skills:
                missing_str = ", ".join(skill_res.missing_skills[:3])
                recommendations.append(
                    f"Address missing tools ({missing_str}) by highlighting fast learning capacity and related Python/ML foundational experience."
                )

            # Recommend highlighting specific project
            if any(term in job_title.lower() for term in ["health", "bio", "predict", "model", "ml", "machine learning"]):
                recommendations.append(
                    "Showcase 'Diabetes Risk Prediction using Machine Learning' in application responses."
                )
            if any(term in job_title.lower() for term in ["flutter", "mobile", "app", "ui"]):
                recommendations.append(
                    "Highlight 'Hospital Management' and 'Factory Management' Flutter applications."
                )

        return MatchExplanation(
            summary=summary,
            total_score=score_res.total_score,
            classification=score_res.classification,
            eligibility_status=eligibility_res.status.value,
            is_eligible=eligibility_res.is_eligible,
            score_breakdown=score_res.breakdown,
            matching_skills={
                "confirmed": skill_res.confirmed_skills,
                "related": skill_res.related_skills,
            },
            missing_skills=skill_res.missing_skills,
            relevant_qualifications=qualifications,
            disqualification_reasons=eligibility_res.disqualification_reasons,
            recommendations=recommendations,
        )


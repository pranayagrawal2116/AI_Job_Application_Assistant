"""Score Calculator module aggregating sub-scores and determining classifications."""

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class ScoreCalculationResult:
    total_score: float
    classification: str
    breakdown: Dict[str, float] = field(default_factory=dict)
    max_points: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_score": round(self.total_score, 1),
            "classification": self.classification,
            "breakdown": {k: round(v, 1) for k, v in self.breakdown.items()},
            "max_points": self.max_points,
        }


class ScoreCalculator:
    """Aggregates sub-matcher scores strictly using weights and thresholds from scoring_rules.yaml."""

    def __init__(self, scoring_rules: Dict[str, Any]):
        weights = scoring_rules.get("weights", {})
        self.max_weights = {
            "domain_relevance": float(weights.get("domain_relevance", {}).get("max_points", 30)),
            "technical_skills": float(weights.get("technical_skills", {}).get("max_points", 25)),
            "educational_eligibility": float(weights.get("educational_eligibility", {}).get("max_points", 20)),
            "experience_compatibility": float(weights.get("experience_compatibility", {}).get("max_points", 10)),
            "location_preference": float(weights.get("location_preference", {}).get("max_points", 10)),
            "duration_compatibility": float(weights.get("duration_compatibility", {}).get("max_points", 5)),
        }
        self.thresholds = scoring_rules.get("thresholds", {})

    def calculate(
        self,
        domain_score: float,
        skills_score: float,
        education_score: float,
        experience_score: float,
        location_score: float,
        duration_score: float,
    ) -> ScoreCalculationResult:
        """Computes capped total score and determines match classification."""
        breakdown = {
            "domain_relevance": min(domain_score, self.max_weights["domain_relevance"]),
            "technical_skills": min(skills_score, self.max_weights["technical_skills"]),
            "educational_eligibility": min(education_score, self.max_weights["educational_eligibility"]),
            "experience_compatibility": min(experience_score, self.max_weights["experience_compatibility"]),
            "location_preference": min(location_score, self.max_weights["location_preference"]),
            "duration_compatibility": min(duration_score, self.max_weights["duration_compatibility"]),
        }

        raw_total = sum(breakdown.values())
        total_score = max(0.0, min(100.0, raw_total))

        # Classification based on thresholds in scoring_rules.yaml
        classification = self._classify(total_score)

        return ScoreCalculationResult(
            total_score=total_score,
            classification=classification,
            breakdown=breakdown,
            max_points=self.max_weights,
        )

    def _classify(self, score: float) -> str:
        """Maps score to configured classification thresholds."""
        exc_min = self.thresholds.get("excellent_match", {}).get("min_score", 85)
        good_min = self.thresholds.get("good_match", {}).get("min_score", 70)
        mod_min = self.thresholds.get("moderate_match", {}).get("min_score", 50)

        if score >= exc_min:
            return "Excellent"
        elif score >= good_min:
            return "Good"
        elif score >= mod_min:
            return "Moderate"
        else:
            return "Low"


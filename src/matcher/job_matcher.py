"""Master Job Matcher module coordinating all sub-matchers, eligibility, and explanations."""

from dataclasses import dataclass, field
from datetime import datetime
import json
from typing import Any, Dict, List, Optional, Union

from src.config import AppConfig, config as default_config
from src.database.db_manager import DatabaseManager
from src.database.models import Job
from src.matcher.domain_matcher import DomainMatcher
from src.matcher.duration_matcher import DurationMatcher
from src.matcher.education_matcher import EducationMatcher
from src.matcher.eligibility import EligibilityEvaluator, EligibilityResult, EligibilityState
from src.matcher.experience_matcher import ExperienceMatcher
from src.matcher.explanation import ExplanationGenerator, MatchExplanation
from src.matcher.location_matcher import LocationMatcher
from src.matcher.score_calculator import ScoreCalculator
from src.matcher.skill_matcher import SkillMatcher
from src.utils.logger import setup_logger

logger = setup_logger("JobMatcher")


@dataclass
class EvaluationResult:
    """Consolidated evaluation output for a job opportunity."""
    job_id: Optional[int]
    job_title: str
    company_name: str
    match_score: float
    match_classification: str
    eligibility_status: EligibilityState
    is_eligible: bool
    score_breakdown: Dict[str, Any]
    explanation: MatchExplanation
    evaluated_at: str
    scoring_version: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "job_title": self.job_title,
            "company_name": self.company_name,
            "match_score": self.match_score,
            "match_classification": self.match_classification,
            "eligibility_status": self.eligibility_status.value,
            "is_eligible": self.is_eligible,
            "score_breakdown": self.score_breakdown,
            "explanation": self.explanation.to_dict(),
            "evaluated_at": self.evaluated_at,
            "scoring_version": self.scoring_version,
        }


class JobMatcher:
    """Coordinates multi-factor matching, eligibility verification, and explanation generation."""

    def __init__(
        self,
        app_config: Optional[AppConfig] = None,
        candidate_profile: Optional[Dict[str, Any]] = None,
        scoring_rules: Optional[Dict[str, Any]] = None,
        db_manager: Optional[DatabaseManager] = None,
    ):
        self.app_config = app_config or default_config
        self.candidate = candidate_profile or self.app_config.candidate_profile
        self.scoring_rules = scoring_rules or self.app_config.scoring_rules
        self.db = db_manager
        self.scoring_version = str(self.scoring_rules.get("version", "1.0.0"))

        # Initialize sub-matchers
        self.domain_matcher = DomainMatcher(self.scoring_rules)
        self.skill_matcher = SkillMatcher(self.candidate, self.scoring_rules)
        self.education_matcher = EducationMatcher(self.candidate, self.scoring_rules)
        self.location_matcher = LocationMatcher(self.scoring_rules)
        self.experience_matcher = ExperienceMatcher(self.scoring_rules)
        self.duration_matcher = DurationMatcher(self.scoring_rules)
        self.eligibility_evaluator = EligibilityEvaluator(self.candidate)
        self.score_calculator = ScoreCalculator(self.scoring_rules)
        self.explanation_generator = ExplanationGenerator(self.candidate)

    def evaluate_job(self, job: Job) -> EvaluationResult:
        """Evaluates a single job posting against all matching dimensions and eligibility constraints."""
        # 1. Sub-matcher evaluations
        domain_res = self.domain_matcher.match(job)
        skill_res = self.skill_matcher.match(job)
        edu_res = self.education_matcher.match(job)
        loc_res = self.location_matcher.match(job)
        exp_res = self.experience_matcher.match(job)
        dur_res = self.duration_matcher.match(job)

        # 2. Score aggregation & classification
        score_res = self.score_calculator.calculate(
            domain_score=domain_res.score,
            skills_score=skill_res.score,
            education_score=edu_res.score,
            experience_score=exp_res.score,
            location_score=loc_res.score,
            duration_score=dur_res.score,
        )

        # 3. Independent eligibility verification
        eligibility_res = self.eligibility_evaluator.evaluate(job)

        # 4. Generate structured human-readable explanation
        explanation = self.explanation_generator.generate(
            score_res=score_res,
            eligibility_res=eligibility_res,
            skill_res=skill_res,
            job_title=job.job_title,
            company_name=job.company_name,
        )

        evaluated_at = datetime.now().isoformat()

        # Detailed score breakdown preserving evaluation audit trail
        full_breakdown = {
            "scores": score_res.breakdown,
            "max_weights": score_res.max_points,
            "eligibility": eligibility_res.to_dict(),
            "matching_skills": explanation.matching_skills,
            "missing_skills": explanation.missing_skills,
            "disqualification_reasons": eligibility_res.disqualification_reasons,
            "recommendations": explanation.recommendations,
            "evaluated_at": evaluated_at,
            "scoring_rules_version": self.scoring_version,
        }

        return EvaluationResult(
            job_id=job.id,
            job_title=job.job_title,
            company_name=job.company_name,
            match_score=score_res.total_score,
            match_classification=score_res.classification,
            eligibility_status=eligibility_res.status,
            is_eligible=eligibility_res.is_eligible,
            score_breakdown=full_breakdown,
            explanation=explanation,
            evaluated_at=evaluated_at,
            scoring_version=self.scoring_version,
        )

    def evaluate_and_update_job(
        self, job: Job, db: Optional[DatabaseManager] = None
    ) -> Job:
        """Evaluates job and updates SQLite database with evaluation results."""
        target_db = db or self.db
        result = self.evaluate_job(job)

        # Update in-memory job model without modifying original job description
        job.match_score = result.match_score
        job.match_classification = result.match_classification
        job.is_eligible = result.is_eligible
        job.score_breakdown = result.score_breakdown

        if target_db and job.id:
            target_db.update_job(job)
            logger.info(
                "Updated job %d evaluation in DB: Score %.1f (%s) - Eligibility: %s",
                job.id,
                job.match_score,
                job.match_classification,
                result.eligibility_status.value,
            )

        return job

    def evaluate_all_jobs(
        self, db: Optional[DatabaseManager] = None, only_unevaluated: bool = False
    ) -> List[Job]:
        """Batch evaluates all jobs in the database."""
        target_db = db or self.db
        if not target_db:
            raise ValueError("DatabaseManager is required for batch job evaluation.")

        all_jobs = target_db.list_jobs()
        evaluated: List[Job] = []

        for job in all_jobs:
            if only_unevaluated and job.match_score > 0.0:
                continue
            updated_job = self.evaluate_and_update_job(job, db=target_db)
            evaluated.append(updated_job)

        logger.info("Batch evaluated %d jobs in database.", len(evaluated))
        return evaluated


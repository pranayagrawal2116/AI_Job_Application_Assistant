"""Matcher package for 100-point job scoring and eligibility analysis."""

from src.matcher.domain_matcher import DomainMatcher, DomainMatchResult
from src.matcher.duration_matcher import DurationMatcher, DurationMatchResult
from src.matcher.education_matcher import EducationMatcher, EducationMatchResult
from src.matcher.eligibility import EligibilityEvaluator, EligibilityResult, EligibilityState
from src.matcher.experience_matcher import ExperienceMatcher, ExperienceMatchResult
from src.matcher.explanation import ExplanationGenerator, MatchExplanation
from src.matcher.job_matcher import EvaluationResult, JobMatcher
from src.matcher.location_matcher import LocationMatcher, LocationMatchResult
from src.matcher.score_calculator import ScoreCalculationResult, ScoreCalculator
from src.matcher.skill_matcher import SkillMatcher, SkillMatchResult

__all__ = [
    "JobMatcher",
    "EvaluationResult",
    "EligibilityEvaluator",
    "EligibilityResult",
    "EligibilityState",
    "DomainMatcher",
    "DomainMatchResult",
    "SkillMatcher",
    "SkillMatchResult",
    "EducationMatcher",
    "EducationMatchResult",
    "LocationMatcher",
    "LocationMatchResult",
    "ExperienceMatcher",
    "ExperienceMatchResult",
    "DurationMatcher",
    "DurationMatchResult",
    "ScoreCalculator",
    "ScoreCalculationResult",
    "ExplanationGenerator",
    "MatchExplanation",
]

"""Job matching evaluation schemas."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class EvaluateMatchRequest(BaseModel):
    resume_id: int
    job_id: Optional[int] = None
    job_description_id: Optional[int] = None
    scoring_profile: Optional[str] = "student_intern"


class MatchEvaluationResponse(BaseModel):
    id: Optional[int] = None
    match_score: float
    match_classification: str
    eligibility_status: str
    dimension_breakdown: Dict[str, Any] = {}
    matching_skills: List[str] = []
    missing_skills: List[str] = []
    related_skills: List[str] = []
    scoring_explanations: List[str] = []
    recommendations: List[str] = []
    education_analysis: Optional[Dict[str, Any]] = None
    experience_analysis: Optional[Dict[str, Any]] = None
    scoring_profile: str = "student_intern"

"""Job opportunity and job description schemas."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class JobIngestTextRequest(BaseModel):
    raw_text: str
    hint_title: Optional[str] = None
    hint_company: Optional[str] = None
    hint_location: Optional[str] = None


class JobIngestUrlRequest(BaseModel):
    url: str
    hint_title: Optional[str] = None
    hint_company: Optional[str] = None


class JobItemResponse(BaseModel):
    id: int
    company_name: str
    job_title: str
    job_description: Optional[str] = None
    job_url: Optional[str] = None
    location: Optional[str] = None
    stipend: Optional[str] = None
    required_skills: List[str] = []
    eligibility_criteria: Optional[str] = None
    application_deadline: Optional[str] = None
    match_score: Optional[float] = None
    match_classification: Optional[str] = None
    is_eligible: Optional[bool] = None
    platform: Optional[str] = "Manual"
    work_arrangement: Optional[str] = "Onsite"
    internship_duration: Optional[str] = None
    is_shortlisted: bool = False
    source: str = "catalog"
    matching_skills: List[str] = []
    missing_skills: List[str] = []
    match_explanation: Optional[str] = None
    score_breakdown: Optional[Dict[str, Any]] = None
    is_pending_evaluation: bool = False


class JobDescriptionResponse(BaseModel):
    id: int
    user_id: int
    company_name: str
    job_title: str
    raw_content: str
    source_type: str
    parsed_data: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    is_active: bool = True

"""Job matching evaluation endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from dashboard.services.dashboard_service import DashboardService
from backend.api.dependencies.auth import get_current_user_and_session
from backend.api.schemas.matching import (
    EvaluateMatchRequest,
    MatchEvaluationResponse,
)

router = APIRouter(prefix="/api/matching", tags=["Matching"])


@router.get("/profiles")
def list_scoring_profiles():
    """Lists available scoring profiles and their descriptive purposes."""
    service = DashboardService.get_instance()
    profiles = service.get_available_scoring_profiles()
    return {"profiles": profiles}


@router.post("/evaluate", response_model=MatchEvaluationResponse)
def evaluate_match(
    req: EvaluateMatchRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Executes deterministic 100-point multi-dimensional job match evaluation."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    success, msg, match_res = service.run_match_evaluation(
        user_id=user_id,
        resume_id=req.resume_id,
        job_description_id=req.job_description_id,
        catalog_job_id=req.job_id,
        scoring_profile=req.scoring_profile or "student_intern",
    )
    if not success or not match_res:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg or "Match evaluation failed.")
        
    return MatchEvaluationResponse(
        id=getattr(match_res, "id", None),
        match_score=float(match_res.match_score),
        match_classification=match_res.match_classification,
        eligibility_status=match_res.eligibility_status,
        dimension_breakdown=match_res.dimension_breakdown or {},
        matching_skills=match_res.matching_skills or [],
        missing_skills=match_res.missing_skills or [],
        related_skills=match_res.related_skills or [],
        scoring_explanations=match_res.scoring_explanations or [],
        recommendations=match_res.recommendations or [],
        education_analysis=match_res.education_analysis or {},
        experience_analysis=match_res.experience_analysis or {},
        scoring_profile=req.scoring_profile or "student_intern",
    )


@router.get("/history", response_model=List[MatchEvaluationResponse])
def get_match_history(
    job_id: Optional[int] = Query(None),
    job_description_id: Optional[int] = Query(None),
    auth_ctx=Depends(get_current_user_and_session),
):
    """Retrieves previous match evaluations for the authenticated candidate."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    history = service.get_user_match_history(
        user_id=user_id,
        job_id=job_id,
        job_description_id=job_description_id,
    )
    return [
        MatchEvaluationResponse(
            id=m.id,
            match_score=float(m.match_score),
            match_classification=m.match_classification,
            eligibility_status=m.eligibility_status,
            dimension_breakdown=m.dimension_breakdown or {},
            matching_skills=m.matching_skills or [],
            missing_skills=m.missing_skills or [],
            related_skills=m.related_skills or [],
            scoring_explanations=m.scoring_explanations or [],
            recommendations=m.recommendations or [],
            scoring_profile=m.scoring_profile or "student_intern",
        )
        for m in history
    ]

"""Job discovery, exploration, and manual ingestion endpoints."""

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from dashboard.services.dashboard_service import DashboardService
from backend.api.dependencies.auth import get_current_user_and_session
from backend.api.schemas.jobs import (
    JobDescriptionResponse,
    JobIngestTextRequest,
    JobIngestUrlRequest,
    JobItemResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs", tags=["Jobs"])


def _normalize_skill_list(raw: Any) -> List[str]:
    """Safely normalizes raw skill data (str, JSON str, list of dicts) into a list of strings."""
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                raw = parsed
            else:
                return [s.strip() for s in raw.split(",") if s.strip()]
        except Exception:
            return [s.strip() for s in raw.split(",") if s.strip()]
    if isinstance(raw, list):
        out = []
        for item in raw:
            if isinstance(item, dict):
                name = item.get("job_skill") or item.get("name") or item.get("candidate_skill") or ""
                if name:
                    out.append(str(name))
            elif isinstance(item, str) and item.strip():
                out.append(item.strip())
        return out
    return []


def _normalize_dict(raw: Any) -> Dict[str, Any]:
    """Safely normalizes raw dict data (dict or JSON str) into a dictionary."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    return {}


@router.get("", response_model=List[JobItemResponse])
def list_jobs(
    search: Optional[str] = Query(None),
    arrangement: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    min_score: Optional[float] = Query(None),
    only_eligible: Optional[bool] = Query(None),
    saved_only: Optional[bool] = Query(False),
    recommended_only: Optional[bool] = Query(False),
    auth_ctx=Depends(get_current_user_and_session),
):
    """Lists catalog job opportunities with multi-dimensional filtering and candidate-personalized matching."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    df = service.get_all_jobs_df()
    if df.empty:
        return []
        
    # Get user's saved/shortlisted jobs
    user_apps = service.list_candidate_applications(session_id=session.session_id, client_user_id=user_id, limit=None)
    saved_job_ids = {a.job_id for a in user_apps if a.job_id is not None}

    # Fetch candidate-scoped personalized match results for catalog jobs
    all_job_ids = [int(r["id"]) for _, r in df.iterrows()]
    user_matches = service.db.get_user_match_results_for_jobs(user_id=user_id, job_ids=all_job_ids)
    
    items: List[JobItemResponse] = []
    for _, row in df.iterrows():
        jid = int(row["id"])
        is_saved = jid in saved_job_ids
        
        if saved_only and not is_saved:
            continue
            
        # Parse skills
        raw_skills = row.get("required_skills", "")
        skills_list = _normalize_skill_list(raw_skills)

        # Candidate-specific match overlay
        user_match = user_matches.get(jid)
        if user_match:
            score = float(user_match.match_score)
            eligible = (user_match.eligibility_status != "INELIGIBLE")
            match_classification = user_match.match_classification
            matching_skills = _normalize_skill_list(user_match.matching_skills)
            missing_skills = _normalize_skill_list(user_match.missing_skills)
            explanation = user_match.explanation or ""
            breakdown = _normalize_dict(user_match.score_breakdown)
        else:
            score = float(row.get("match_score", 0.0) or 0.0)
            eligible = bool(row.get("is_eligible", 1))
            match_classification = str(row.get("match_classification", "") or "Moderate")
            matching_skills = []
            missing_skills = []
            explanation = ""
            breakdown = {}

        work_arr = str(row.get("work_arrangement", "Onsite") or "Onsite")
        plat = str(row.get("platform", "Manual") or "Manual")
        
        # Apply filters
        if arrangement and arrangement.lower() not in work_arr.lower():
            continue
        if platform and platform.lower() not in plat.lower():
            continue
        if min_score is not None and score < min_score:
            continue
        if only_eligible and not eligible:
            continue
        if search:
            q = search.lower()
            title = str(row.get("job_title", "")).lower()
            comp = str(row.get("company_name", "")).lower()
            loc = str(row.get("location", "")).lower()
            if q not in title and q not in comp and q not in loc:
                continue
                
        items.append(
            JobItemResponse(
                id=jid,
                company_name=str(row.get("company_name", "")),
                job_title=str(row.get("job_title", "")),
                job_description=str(row.get("job_description", "") or ""),
                job_url=str(row.get("job_url", "") or ""),
                location=str(row.get("location", "") or "India"),
                stipend=str(row.get("stipend", "") or "Not Disclosed"),
                required_skills=skills_list,
                eligibility_criteria=str(row.get("eligibility_criteria", "") or ""),
                application_deadline=str(row.get("application_deadline", "") or ""),
                match_score=score,
                match_classification=match_classification,
                is_eligible=eligible,
                platform=plat,
                work_arrangement=work_arr,
                internship_duration=str(row.get("internship_duration", "") or "Flexible"),
                is_shortlisted=is_saved,
                source="catalog",
                matching_skills=matching_skills,
                missing_skills=missing_skills,
                match_explanation=explanation,
                score_breakdown=breakdown,
            )
        )
        
    # Sort by match_score descending if recommended_only or default sorting
    if recommended_only:
        items.sort(key=lambda j: j.match_score, reverse=True)

    return items


@router.get("/{job_id}", response_model=JobItemResponse)
def get_job(job_id: int, auth_ctx=Depends(get_current_user_and_session)):
    """Retrieves detailed record for a specific catalog job."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    job = service.get_job_detail(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job #{job_id} not found")
        
    user_apps = service.list_candidate_applications(session_id=session.session_id, client_user_id=user_id, limit=None)
    is_saved = any(a.job_id == job_id for a in user_apps)
    
    # Skills
    raw_skills = job.required_skills or ""
    skills_list = []
    if isinstance(raw_skills, str) and raw_skills.strip():
        try:
            parsed = json.loads(raw_skills)
            if isinstance(parsed, list):
                skills_list = parsed
        except Exception:
            skills_list = [s.strip() for s in raw_skills.split(",") if s.strip()]
    elif isinstance(raw_skills, list):
        skills_list = raw_skills
        
    return JobItemResponse(
        id=job.id,
        company_name=job.company_name,
        job_title=job.job_title,
        job_description=job.job_description or "",
        job_url=job.job_url or "",
        location=job.location or "India",
        stipend=job.stipend or "Not Disclosed",
        required_skills=skills_list,
        eligibility_criteria=job.eligibility_criteria or "",
        application_deadline=job.application_deadline or "",
        match_score=float(job.match_score or 0.0),
        match_classification=job.match_classification or "Moderate",
        is_eligible=bool(job.is_eligible),
        platform=job.platform or "Manual",
        work_arrangement=job.work_arrangement or "Onsite",
        internship_duration=job.internship_duration or "Flexible",
        is_shortlisted=is_saved,
        source="catalog",
    )


@router.get("/{job_id}/match-explanation")
def get_job_match_explanation(job_id: int, auth_ctx=Depends(get_current_user_and_session)):
    """Retrieves deep 100-point personalized match breakdown and explanation for the candidate."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()

    job = service.get_job_detail(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job #{job_id} not found")

    match_rec = service.db.get_latest_match_result(user_id=user_id, job_id=job_id)

    # If no match yet, compute on the fly if user has primary resume
    if not match_rec:
        resumes = service.get_user_resumes(user_id)
        primary_res = next((r for r in resumes if r.get("is_primary")), resumes[0] if resumes else None)
        if primary_res:
            try:
                service.run_match_evaluation(
                    user_id=user_id,
                    resume_id=primary_res["id"],
                    job_id=job_id,
                )
                match_rec = service.db.get_latest_match_result(user_id=user_id, job_id=job_id)
            except Exception as e:
                logger.warning("On-the-fly match evaluation failed for job %s: %s", job_id, e)

    if match_rec:
        return {
            "job_id": job_id,
            "match_score": float(match_rec.match_score),
            "match_classification": match_rec.match_classification,
            "eligibility_status": match_rec.eligibility_status,
            "is_eligible": match_rec.eligibility_status != "INELIGIBLE",
            "score_breakdown": _normalize_dict(match_rec.score_breakdown),
            "explanation": match_rec.explanation,
            "matching_skills": _normalize_skill_list(match_rec.matching_skills),
            "missing_skills": _normalize_skill_list(match_rec.missing_skills),
            "education_analysis": match_rec.education_analysis,
            "experience_analysis": match_rec.experience_analysis,
            "eligibility_reasons": match_rec.eligibility_reasons,
            "recommendations": match_rec.recommendations,
            "evaluated_at": match_rec.evaluated_at,
        }

    return {
        "job_id": job_id,
        "match_score": float(job.match_score or 0.0),
        "match_classification": job.match_classification or "Moderate",
        "eligibility_status": "ELIGIBLE" if job.is_eligible else "INELIGIBLE",
        "is_eligible": bool(job.is_eligible),
        "score_breakdown": _normalize_dict(job.score_breakdown),
        "explanation": "Calculated based on general catalog scoring criteria.",
        "matching_skills": [],
        "missing_skills": [],
        "evaluated_at": job.discovery_date,
    }


@router.post("/{job_id}/shortlist")
def toggle_shortlist(job_id: int, auth_ctx=Depends(get_current_user_and_session)):
    """Toggles bookmark / shortlist status for a catalog job."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    job = service.get_job_detail(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job #{job_id} not found")
        
    # Check if application already exists for this job
    user_apps = service.list_candidate_applications(session_id=session.session_id, client_user_id=user_id, limit=None)
    existing_app = next((a for a in user_apps if a.job_id == job_id), None)
    
    if existing_app:
        # Archive or delete saved application
        service.archive_candidate_application(application_id=existing_app.id, session_id=session.session_id, client_user_id=user_id)
        return {"status": "ok", "is_shortlisted": False, "message": "Removed from saved opportunities"}
    else:
        # Create new application in DRAFT status
        app = service.create_candidate_application(
            session_id=session.session_id,
            company_name=job.company_name,
            job_title=job.job_title,
            status="DRAFT",
            job_url=job.job_url,
            location=job.location,
            client_user_id=user_id,
        )
        return {"status": "ok", "is_shortlisted": True, "application_id": app.id, "message": "Saved opportunity"}


@router.post("/ingest/text", response_model=JobDescriptionResponse, status_code=status.HTTP_201_CREATED)
def ingest_text(
    req: JobIngestTextRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Parses and ingests raw pasted job description text."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    success, msg, jd_rec = service.ingest_job_text(
        user_id=user_id,
        raw_text=req.raw_text,
        hint_title=req.hint_title,
        hint_company=req.hint_company,
        hint_location=req.hint_location,
    )
    if not success or not jd_rec:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        
    return JobDescriptionResponse(
        id=jd_rec.id,
        user_id=jd_rec.user_id,
        company_name=jd_rec.company_name,
        job_title=jd_rec.job_title,
        raw_content=jd_rec.raw_content,
        source_type=jd_rec.source_type,
        parsed_data=jd_rec.parsed_data if isinstance(jd_rec.parsed_data, dict) else {},
        created_at=str(jd_rec.created_at) if hasattr(jd_rec, "created_at") else None,
        is_active=bool(getattr(jd_rec, "is_active", 1)),
    )


@router.post("/ingest/file", response_model=JobDescriptionResponse, status_code=status.HTTP_201_CREATED)
async def ingest_file(
    file: UploadFile = File(...),
    hint_title: Optional[str] = Form(None),
    hint_company: Optional[str] = Form(None),
    auth_ctx=Depends(get_current_user_and_session),
):
    """Uploads and parses a job description document (PDF or DOCX)."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")
        
    success, msg, jd_rec = service.ingest_job_file(
        user_id=user_id,
        file_bytes=contents,
        filename=file.filename or "job_description.pdf",
        hint_title=hint_title,
        hint_company=hint_company,
    )
    if not success or not jd_rec:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        
    return JobDescriptionResponse(
        id=jd_rec.id,
        user_id=jd_rec.user_id,
        company_name=jd_rec.company_name,
        job_title=jd_rec.job_title,
        raw_content=jd_rec.raw_content,
        source_type=jd_rec.source_type,
        parsed_data=jd_rec.parsed_data if isinstance(jd_rec.parsed_data, dict) else {},
        created_at=str(jd_rec.created_at) if hasattr(jd_rec, "created_at") else None,
        is_active=bool(getattr(jd_rec, "is_active", 1)),
    )


@router.post("/ingest/url", response_model=JobDescriptionResponse, status_code=status.HTTP_201_CREATED)
def ingest_url(
    req: JobIngestUrlRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Fetches and parses a public job listing URL with SSRF defenses."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    success, msg, jd_rec = service.ingest_job_url(
        user_id=user_id,
        url=req.url,
        hint_title=req.hint_title,
        hint_company=req.hint_company,
    )
    if not success or not jd_rec:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        
    return JobDescriptionResponse(
        id=jd_rec.id,
        user_id=jd_rec.user_id,
        company_name=jd_rec.company_name,
        job_title=jd_rec.job_title,
        raw_content=jd_rec.raw_content,
        source_type=jd_rec.source_type,
        parsed_data=jd_rec.parsed_data if isinstance(jd_rec.parsed_data, dict) else {},
        created_at=str(jd_rec.created_at) if hasattr(jd_rec, "created_at") else None,
        is_active=bool(getattr(jd_rec, "is_active", 1)),
    )


@router.get("/custom/mine", response_model=List[JobDescriptionResponse])
def list_custom_job_descriptions(auth_ctx=Depends(get_current_user_and_session)):
    """Lists all custom job descriptions ingested by the authenticated candidate."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    jds = service.get_user_job_descriptions(user_id)
    return [
        JobDescriptionResponse(
            id=jd.id,
            user_id=jd.user_id,
            company_name=jd.company_name,
            job_title=jd.job_title,
            raw_content=jd.raw_content,
            source_type=jd.source_type,
            parsed_data=jd.parsed_data if isinstance(jd.parsed_data, dict) else {},
            created_at=str(jd.created_at) if hasattr(jd, "created_at") else None,
            is_active=bool(getattr(jd, "is_active", 1)),
        )
        for jd in jds
    ]

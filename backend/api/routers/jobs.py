"""Job discovery, exploration, and manual ingestion endpoints."""

import json
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

router = APIRouter(prefix="/api/jobs", tags=["Jobs"])


@router.get("", response_model=List[JobItemResponse])
def list_jobs(
    search: Optional[str] = Query(None),
    arrangement: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    min_score: Optional[float] = Query(None),
    only_eligible: Optional[bool] = Query(None),
    saved_only: Optional[bool] = Query(False),
    auth_ctx=Depends(get_current_user_and_session),
):
    """Lists catalog job opportunities with multi-dimensional filtering."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    df = service.get_all_jobs_df()
    if df.empty:
        return []
        
    # Get user's saved/shortlisted jobs
    user_apps = service.list_candidate_applications(session_id=session.session_id, client_user_id=user_id, limit=None)
    saved_job_ids = {a.job_id for a in user_apps if a.job_id is not None}
    
    items: List[JobItemResponse] = []
    for _, row in df.iterrows():
        jid = int(row["id"])
        is_saved = jid in saved_job_ids
        
        if saved_only and not is_saved:
            continue
            
        # Parse skills
        raw_skills = row.get("required_skills", "")
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
            
        score = float(row.get("match_score", 0.0) or 0.0)
        eligible = bool(row.get("is_eligible", 1))
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
                match_classification=str(row.get("match_classification", "") or "Moderate"),
                is_eligible=eligible,
                platform=plat,
                work_arrangement=work_arr,
                internship_duration=str(row.get("internship_duration", "") or "Flexible"),
                is_shortlisted=is_saved,
                source="catalog",
            )
        )
        
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

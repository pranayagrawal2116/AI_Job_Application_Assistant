"""Job discovery, exploration, and manual ingestion endpoints."""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from pydantic import BaseModel
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
    
    # 1. Authoritative candidate career context
    career_ctx = service.resolve_candidate_career_context(user_id)

    # 2. Get user's saved/shortlisted jobs
    user_apps = service.list_candidate_applications(session_id=session.session_id, client_user_id=user_id, limit=None)
    saved_job_ids = {a.job_id for a in user_apps if a.job_id is not None}

    df = service.get_all_jobs_df()
    if df.empty:
        return []

    is_manual_search = bool(search and search.strip())

    if saved_only:
        df = df[df["id"].isin(saved_job_ids)]
        if df.empty:
            return []
    elif is_manual_search:
        # Manual search queries catalog across fields without affecting automatic recommendations
        q = search.lower().strip()
        skills_str = df["required_skills"].apply(lambda s: " ".join(s) if isinstance(s, list) else str(s or ""))
        mask = (
            df["job_title"].str.lower().str.contains(q, na=False) |
            df["company_name"].str.lower().str.contains(q, na=False) |
            df["location"].str.lower().str.contains(q, na=False) |
            skills_str.str.lower().str.contains(q, na=False) |
            df["job_description"].str.lower().str.contains(q, na=False)
        )
        df = df[mask]
        if df.empty:
            return []
    else:
        # Default Explore Jobs Feed: strictly candidate-scoped to current resume discovery run!
        if not career_ctx.has_primary_resume:
            return []

        candidate_job_ids = set(service.db.get_candidate_discovered_job_ids(
            user_id=user_id,
            resume_fingerprint=career_ctx.resume_fingerprint,
        ))

        # Also include any jobs explicitly evaluated for this candidate's primary resume
        if career_ctx.primary_resume_id:
            eval_matches = service.db.get_user_match_results(
                user_id=user_id,
                resume_id=career_ctx.primary_resume_id,
            )
            for m in eval_matches:
                if m.job_id:
                    candidate_job_ids.add(m.job_id)

        if not candidate_job_ids:
            return []

        df = df[df["id"].isin(candidate_job_ids)]
        if df.empty:
            return []

    # Fetch candidate-scoped personalized match results strictly for the current primary resume
    candidate_job_ids_in_df = [int(r["id"]) for _, r in df.iterrows()]
    user_matches = service.db.get_user_match_results_for_jobs(
        user_id=user_id,
        job_ids=candidate_job_ids_in_df,
        resume_id=career_ctx.primary_resume_id,
        resume_file_hash=career_ctx.primary_resume_file_hash,
    )

    items: List[JobItemResponse] = []
    for _, row in df.iterrows():
        jid = int(row["id"])
        is_saved = jid in saved_job_ids

        job_title = str(row.get("job_title", ""))
        comp_name = str(row.get("company_name", ""))
        desc = str(row.get("job_description", "") or "")

        # In default Explore Jobs feed, validate relevance against candidate career domain
        if not is_manual_search and not saved_only:
            if not service.is_job_relevant_for_candidate(job_title, desc, career_ctx):
                continue

        # Parse skills
        raw_skills = row.get("required_skills", "")
        skills_list = _normalize_skill_list(raw_skills)

        # Candidate-specific match overlay (Zero fallback to shared catalogue scores)
        user_match = user_matches.get(jid)
        if user_match:
            score = float(user_match.match_score)
            eligible = (user_match.eligibility_status != "INELIGIBLE")
            match_classification = user_match.match_classification
            matching_skills = _normalize_skill_list(user_match.matching_skills)
            missing_skills = _normalize_skill_list(user_match.missing_skills)
            explanation = user_match.explanation or ""
            breakdown = _normalize_dict(user_match.score_breakdown)
            is_pending = False
        else:
            # Candidate has not been evaluated for this job under the current resume yet
            score = None
            eligible = None
            match_classification = "PENDING_EVALUATION"
            matching_skills = []
            missing_skills = []
            explanation = "Personalized evaluation pending for your current resume."
            breakdown = {}
            is_pending = True

        work_arr = str(row.get("work_arrangement", "Onsite") or "Onsite")
        plat = str(row.get("platform", "Manual") or "Manual")

        # Apply filters
        if arrangement and arrangement.lower() not in work_arr.lower():
            continue
        if platform and platform.lower() not in plat.lower():
            continue
        if min_score is not None and (score is None or score < min_score):
            continue
        if only_eligible and eligible is not True:
            continue

        item_source = "search" if is_manual_search else ("saved" if saved_only else "recommended")

        items.append(
            JobItemResponse(
                id=jid,
                company_name=comp_name,
                job_title=job_title,
                job_description=desc,
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
                source=item_source,
                matching_skills=matching_skills,
                missing_skills=missing_skills,
                match_explanation=explanation,
                score_breakdown=breakdown,
                is_pending_evaluation=is_pending,
            )
        )
        
        # Deduplicate catalog listings by composite (company, title, location) and normalized URL
    seen_keys = set()
    deduped_items = []
    for item in items:
        norm_key = (item.company_name.lower().strip(), item.job_title.lower().strip(), item.location.lower().strip())
        norm_url = item.job_url.split("?")[0].rstrip("/").lower() if item.job_url else ""
        if norm_key in seen_keys or (norm_url and norm_url in seen_keys):
            continue
        seen_keys.add(norm_key)
        if norm_url:
            seen_keys.add(norm_url)
        deduped_items.append(item)
    items = deduped_items

    # Sort by match_score descending if recommended_only or default sorting
    if recommended_only:
        items.sort(key=lambda j: (j.match_score if j.match_score is not None else -1.0), reverse=True)

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
        is_eligible = (
            True if match_rec.eligibility_status == "ELIGIBLE"
            else (False if match_rec.eligibility_status == "INELIGIBLE" else None)
        )
        return {
            "job_id": job_id,
            "is_evaluated": True,
            "match_score": float(match_rec.match_score),
            "match_classification": match_rec.match_classification,
            "eligibility_status": match_rec.eligibility_status,
            "is_eligible": is_eligible,
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
        "is_evaluated": False,
        "match_score": None,
        "match_classification": "Not Evaluated",
        "eligibility_status": "UNKNOWN",
        "is_eligible": None,
        "score_breakdown": {},
        "explanation": "This opportunity has not yet been evaluated against your resume.",
        "matching_skills": [],
        "missing_skills": [],
        "education_analysis": None,
        "experience_analysis": None,
        "eligibility_reasons": [],
        "recommendations": ["Upload a primary resume or initiate discovery to evaluate your match."],
        "evaluated_at": None,
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


class JobsDiscoveryRequest(BaseModel):
    roles: Optional[List[str]] = None
    locations: Optional[List[str]] = None


@router.post("/discovery")
def trigger_jobs_discovery(
    req: Optional[JobsDiscoveryRequest] = None,
    background_tasks: BackgroundTasks = None,
    request: Request = None,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Initiates non-blocking background job discovery and returns run identifier immediately."""
    if request:
        discovery_ready = getattr(request.app.state, "discovery_ready", True)
        if not discovery_ready:
            rec_err = getattr(request.app.state, "discovery_recovery_error", "Unknown startup recovery error")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Discovery subsystem degraded due to startup recovery failure ({rec_err}). Please inspect database lock or restart the server.",
            )

    user_id, session = auth_ctx
    service = DashboardService.get_instance()

    active_run = service.db.get_active_discovery_run(user_id)
    if active_run:
        return {
            "run_id": active_run["id"],
            "status": "already_running",
            "message": "A discovery run is already in progress for your profile.",
            "started_at": active_run.get("started_at") or datetime.now(timezone.utc).isoformat(),
        }

    # 1. Authoritative candidate career context resolution
    career_ctx = service.resolve_candidate_career_context(user_id)
    if not career_ctx.has_primary_resume and not (req and req.roles) and not career_ctx.selected_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No primary resume found. Please upload a resume first to initiate personalized discovery.",
        )

    roles = req.roles if req else None
    locations = req.locations if req else None

    target_roles = list(roles) if roles and len(roles) > 0 else list(career_ctx.selected_roles)
    target_locations = list(locations) if locations and len(locations) > 0 else list(career_ctx.target_locations)

    if not target_roles:
        target_roles = ["Specialist", "Associate"]
    if not target_locations:
        target_locations = ["Remote"]

    try:
        run_rec = service.db.create_discovery_run(
            user_id=user_id,
            target_roles=target_roles,
            target_locations=target_locations,
            resume_id=career_ctx.primary_resume_id,
            resume_fingerprint=career_ctx.resume_fingerprint,
        )
    except Exception as e:
        from src.database.exceptions import DuplicateDiscoveryRunError
        if isinstance(e, DuplicateDiscoveryRunError):
            act = service.db.get_active_discovery_run(user_id)
            return {
                "run_id": act["id"] if act else None,
                "status": "already_running",
                "message": "A discovery run is already in progress for your profile.",
                "started_at": act.get("started_at") if act else datetime.now(timezone.utc).isoformat(),
            }
        raise

    run_id = run_rec["id"]
    service.db.update_discovery_run(run_id, status="RUNNING")

    def _execute():
        try:
            summary = service.coordinator.run_discovery(
                roles=target_roles,
                locations=target_locations,
                max_queries=5,
                max_results_per_source=5,
                enable_evaluation=False,
            )
            # Identify all relevant unique job IDs from this discovery run
            relevant_ids = set()
            for saved_item in summary.saved_jobs:
                if saved_item.get("id"):
                    relevant_ids.add(saved_item["id"])
            for dup_id in getattr(summary, "duplicate_job_ids", []):
                if dup_id:
                    relevant_ids.add(dup_id)

            # Record candidate-to-job association to prevent repeated discovery runs from inflating metrics
            if relevant_ids:
                service.db.record_candidate_discovered_jobs(
                    user_id=user_id,
                    job_ids=list(relevant_ids),
                    discovery_run_id=run_id,
                    resume_id=career_ctx.primary_resume_id,
                    resume_fingerprint=career_ctx.resume_fingerprint,
                )

            # Evaluate personalized scores for candidate strictly against all unique jobs discovered
            if career_ctx.primary_resume_id and relevant_ids:
                verified_res = None
                try:
                    from src.security.resume_verifier import ResumeIntegrityVerifier
                    from src.security.file_security import FileSecurityValidator

                    f_val = FileSecurityValidator(base_storage_dir=service.storage_base_dir) if service.storage_base_dir else None
                    verifier = ResumeIntegrityVerifier(db_manager=service.db, file_validator=f_val)
                    res_rec = service.db.get_user_resume(career_ctx.primary_resume_id, user_id)
                    act_ver = res_rec.get("active_version", 1) if res_rec else 1
                    verified_res = verifier.verify_and_load_resume(
                        user_id=user_id,
                        resume_id=career_ctx.primary_resume_id,
                        version_num=act_ver,
                        fresh_parse=True,
                    )
                except Exception as ver_err:
                    logger.warning("Pre-verification of resume for batch evaluation failed: %s", ver_err)

                for job_id_to_eval in relevant_ids:
                    try:
                        service.run_match_evaluation(
                            user_id=user_id,
                            resume_id=career_ctx.primary_resume_id,
                            job_id=job_id_to_eval,
                            verified_resume=verified_res,
                        )
                    except Exception as eval_err:
                        logger.warning("Personalized evaluation failed for discovered job %s: %s", job_id_to_eval, eval_err)

            final_status = "PARTIAL" if summary.restricted_incidents > 0 and (summary.new_jobs_saved > 0 or summary.duplicates_skipped > 0) else (
                "COMPLETED" if (summary.new_jobs_saved > 0 or summary.duplicates_skipped > 0 or summary.restricted_incidents == 0) else "PARTIAL"
            )
            service.db.update_discovery_run(
                run_id=run_id,
                status=final_status,
                total_discovered=summary.total_discovered,
                new_jobs_saved=summary.new_jobs_saved,
                duplicates_skipped=summary.duplicates_skipped,
                restricted_count=summary.restricted_incidents,
                source_outcomes=summary.platform_breakdown,
            )
        except Exception as exc:
            logger.exception("Discovery background task failed: %s", exc)
            service.db.update_discovery_run(run_id, status="FAILED", error_message=str(exc))

    if background_tasks is not None:
        background_tasks.add_task(_execute)
    else:
        import threading
        t = threading.Thread(target=_execute, daemon=True)
        t.start()

    return {
        "run_id": run_id,
        "id": run_id,
        "status": "RUNNING",
        "message": "Discovery initiated. Searching permitted sources and computing personalized matches.",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/discovery/latest")
def get_latest_discovery_run_status(auth_ctx=Depends(get_current_user_and_session)):
    """Retrieves latest discovery run for the candidate."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    career_ctx = service.resolve_candidate_career_context(user_id)
    latest = service.db.get_latest_discovery_run(user_id)
    latest_for_current = (
        service.db.get_latest_discovery_run(user_id, resume_fingerprint=career_ctx.resume_fingerprint)
        if career_ctx.resume_fingerprint
        else None
    )
    is_completed_current = (
        latest_for_current is not None and latest_for_current["status"] in ("COMPLETED", "PARTIAL")
    )
    if not latest:
        return {
            "has_run": False,
            "run": None,
            "has_primary_resume": career_ctx.has_primary_resume,
            "resume_fingerprint": career_ctx.resume_fingerprint,
            "completed_for_current_resume": False,
        }
    return {
        "has_run": True,
        "run": latest,
        "has_primary_resume": career_ctx.has_primary_resume,
        "resume_fingerprint": career_ctx.resume_fingerprint,
        "completed_for_current_resume": is_completed_current,
    }


@router.get("/discovery/{run_id}")
def get_jobs_discovery_status(run_id: int, auth_ctx=Depends(get_current_user_and_session)):
    """Retrieves current execution status, progress, and discovered counts for a discovery run."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()

    run = service.db.get_discovery_run(run_id, user_id=user_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery run not found.")

    return run

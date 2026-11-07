"""Application preparation workspace, approval gate, and tracker endpoints."""

import hashlib
import json
import logging
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from dashboard.services.dashboard_service import DashboardService
from backend.api.dependencies.auth import get_current_user_and_session
from backend.api.schemas.applications import (
    ApplicationCreateRequest,
    ApplicationResponse,
    ApplicationStatusUpdateRequest,
    AuthorizePacketRequest,
    ConfirmSubmissionRequest,
    CoverLetterRequest,
    FollowUpCreateRequest,
    FollowUpResponse,
    IssueTicketResponse,
    PreparationStateResponse,
    PreparedPacketResponse,
    ScreeningQuestionsRequest,
    TailorResumeRequest,
)
from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    JobDescriptionNotFoundError,
    QuarantinedSourceError,
    ResumeIntegrityError,
    ResumeNotFoundError,
    SecurityAuthorizationError,
    ValidationError,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/applications", tags=["Applications"])


@router.get("", response_model=List[ApplicationResponse])
def list_applications(
    status_filter: Optional[str] = Query(None),
    auth_ctx=Depends(get_current_user_and_session),
):
    """Lists applications tracked by candidate."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    apps = service.list_candidate_applications(session_id=session.session_id, client_user_id=user_id, limit=None)
    if status_filter:
        apps = [a for a in apps if a.status.lower() == status_filter.lower()]
        
    return [
        ApplicationResponse(
            id=a.id,
            user_id=a.user_id,
            company_name=a.company_name,
            job_title=a.job_title,
            status=a.status,
            job_id=a.job_id,
            job_description_id=a.job_description_id,
            resume_id=a.resume_id,
            external_application_url=a.external_application_url,
            target_role=a.target_role,
            location=a.location,
            application_deadline=str(a.application_deadline) if a.application_deadline else None,
            date_prepared=str(a.date_prepared) if a.date_prepared else None,
            date_submitted=str(a.date_submitted) if a.date_submitted else None,
            notes=a.notes,
            created_at=str(a.created_at) if a.created_at else None,
            updated_at=str(a.updated_at) if a.updated_at else None,
            is_archived=bool(a.is_archived),
        )
        for a in apps
    ]


@router.post("", response_model=ApplicationResponse, status_code=status.HTTP_201_CREATED)
def create_application_workspace(
    req: ApplicationCreateRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Initializes or opens an application workspace for a job."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    company = req.company_name
    title = req.job_title
    
    if req.job_id:
        job = service.db.get_job_by_id(req.job_id)
        if job:
            company = company or job.company_name
            title = title or job.job_title
            
    app = service.create_candidate_application(
        session_id=session.session_id,
        company_name=company or "Company",
        job_title=title or "Opportunity",
        job_id=req.job_id,
        job_description_id=req.job_description_id,
        resume_id=req.resume_id,
        status="DRAFT",
        client_user_id=user_id,
    )
    
    return ApplicationResponse(
        id=app.id,
        user_id=app.user_id,
        company_name=app.company_name,
        job_title=app.job_title,
        status=app.status,
        job_id=app.job_id,
        job_description_id=app.job_description_id,
        resume_id=app.resume_id,
        created_at=str(app.created_at) if app.created_at else None,
    )


@router.get("/{app_id}", response_model=ApplicationResponse)
def get_application(app_id: int, auth_ctx=Depends(get_current_user_and_session)):
    """Retrieves full application workspace record."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    try:
        app = service.get_candidate_application(application_id=app_id, session_id=session.session_id, client_user_id=user_id)
        return ApplicationResponse(
            id=app.id,
            user_id=app.user_id,
            company_name=app.company_name,
            job_title=app.job_title,
            status=app.status,
            job_id=app.job_id,
            job_description_id=app.job_description_id,
            resume_id=app.resume_id,
            external_application_url=app.external_application_url,
            target_role=app.target_role,
            location=app.location,
            application_deadline=str(a_deadline) if (a_deadline := getattr(app, "application_deadline", None)) else None,
            date_prepared=str(a_prep) if (a_prep := getattr(app, "date_prepared", None)) else None,
            date_submitted=str(a_sub) if (a_sub := getattr(app, "date_submitted", None)) else None,
            notes=app.notes,
            created_at=str(app.created_at) if app.created_at else None,
            updated_at=str(app.updated_at) if app.updated_at else None,
            is_archived=bool(getattr(app, "is_archived", 0)),
        )
    except ApplicationNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Application #{app_id} not found")
    except CrossUserAccessError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")


@router.patch("/{app_id}/status", response_model=ApplicationResponse)
def update_application_status(
    app_id: int,
    req: ApplicationStatusUpdateRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Transitions application to a new valid lifecycle status."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    try:
        app = service.transition_application_status(
            application_id=app_id,
            session_id=session.session_id,
            new_status=req.status,
            client_user_id=user_id,
        )
        return get_application(app_id, auth_ctx)
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Transition failed: {str(e)}")


def _resolve_application_resume(
    service: DashboardService,
    user_id: int,
    app: Any,
    req_resume_id: Optional[int] = None,
) -> Tuple[Dict[str, Any], int]:
    """Resolves and validates candidate resume under strict selection priority and security checks."""
    resumes = service.get_user_resumes(user_id)
    active_resumes = [r for r in resumes if r.get("is_active", 1)]

    target_res_id: Optional[int] = None
    selected_res: Optional[Dict[str, Any]] = None

    # Priority 1: Explicitly selected resume in request
    if req_resume_id is not None:
        target_res_id = req_resume_id
        matched = next((r for r in active_resumes if r.get("id") == target_res_id), None)
        if not matched:
            with service.db.connection() as conn:
                c = conn.cursor()
                c.execute("SELECT id, user_id, is_active FROM resumes WHERE id = ?", (target_res_id,))
                res_row = c.fetchone()
            if not res_row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Resume #{target_res_id} not found.",
                )
            if res_row["user_id"] != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to requested resume.",
                )
            if not res_row["is_active"]:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Resume #{target_res_id} is inactive or archived.",
                )
            matched = dict(res_row)
        selected_res = matched
    # Priority 2: Resume already attached to this application
    elif getattr(app, "resume_id", None) is not None:
        target_res_id = app.resume_id
        selected_res = next((r for r in active_resumes if r.get("id") == target_res_id), None)
        if not selected_res:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Attached resume #{target_res_id} is inactive or no longer exists.",
            )
    # Priority 3: Candidate's authoritative primary resume
    else:
        if not active_resumes:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="No resumes found. Please upload a resume in My Profile before generating.",
            )
        primary_resumes = [r for r in active_resumes if r.get("is_primary") == 1]
        if len(primary_resumes) == 1:
            selected_res = primary_resumes[0]
            target_res_id = selected_res["id"]
        elif len(active_resumes) == 1:
            selected_res = active_resumes[0]
            target_res_id = selected_res["id"]
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Multiple resumes available. Please select a resume to use for tailoring.",
            )

    # Persist resolved resume to application record if not already linked
    if getattr(app, "resume_id", None) != target_res_id:
        service.db.update_application_resume_and_job(app.id, user_id=user_id, resume_id=target_res_id)
        app.resume_id = target_res_id

    return selected_res, target_res_id


def _resolve_application_job_context(
    service: DashboardService,
    user_id: int,
    app: Any,
) -> Dict[str, Any]:
    """Resolves job description context from candidate-owned JD or public catalog job."""
    # Source A: Candidate-owned ingested job description
    if getattr(app, "job_description_id", None):
        jd = service.db.get_job_description(app.job_description_id, user_id=user_id)
        if not jd:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job description #{app.job_description_id} not found.",
            )
        jd_dict_obj = jd.to_dict() if hasattr(jd, "to_dict") else {}
        parsed_data = jd_dict_obj.get("parsed_data") or getattr(jd, "parsed_data", {}) or {}
        req_skills = parsed_data.get("required_skills") or getattr(jd, "required_skills", [])
        pref_skills = parsed_data.get("preferred_skills") or getattr(jd, "preferred_skills", [])
        raw_text = getattr(jd, "raw_content", "") or ""
        return {
            "id": jd.id,
            "company_name": getattr(jd, "company_name", None) or app.company_name,
            "role_title": getattr(jd, "job_title", getattr(jd, "role_title", app.job_title)),
            "required_skills": req_skills,
            "preferred_skills": pref_skills,
            "raw_content": raw_text,
            "job_description": raw_text,
        }

    # Source B: Public catalog job
    if getattr(app, "job_id", None):
        job = service.db.get_job_by_id(app.job_id)
        if job:
            skills = []
            if getattr(job, "required_skills", None):
                if isinstance(job.required_skills, str):
                    try:
                        skills = json.loads(job.required_skills)
                    except Exception:
                        skills = [s.strip() for s in job.required_skills.split(",") if s.strip()]
                elif isinstance(job.required_skills, list):
                    skills = job.required_skills
            desc = getattr(job, "job_description", "") or ""
            return {
                "id": None,
                "company_name": job.company_name or app.company_name,
                "role_title": job.job_title or app.job_title,
                "required_skills": skills,
                "preferred_skills": [],
                "raw_content": desc,
                "job_description": desc,
            }

    # Source C: Fallback to matching catalog job by company_name & job_title
    with service.db.connection() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, company_name, job_title, required_skills, job_description FROM jobs WHERE company_name = ? AND job_title = ? LIMIT 1",
            (app.company_name, app.job_title),
        )
        row = c.fetchone()
    if row:
        skills = []
        if row["required_skills"]:
            if isinstance(row["required_skills"], str):
                try:
                    skills = json.loads(row["required_skills"])
                except Exception:
                    skills = [s.strip() for s in row["required_skills"].split(",") if s.strip()]
            elif isinstance(row["required_skills"], list):
                skills = row["required_skills"]
        desc = row["job_description"] or ""
        service.db.update_application_resume_and_job(app.id, user_id=user_id, job_id=row["id"])
        app.job_id = row["id"]
        return {
            "id": None,
            "company_name": row["company_name"],
            "role_title": row["job_title"],
            "required_skills": skills,
            "preferred_skills": [],
            "raw_content": desc,
            "job_description": desc,
        }

    # Default fallback when no JD exists
    return {
        "id": None,
        "company_name": app.company_name,
        "role_title": app.job_title,
        "required_skills": [],
        "preferred_skills": [],
        "raw_content": "",
        "job_description": "",
    }


def _get_app_storage_dir(service: DashboardService, user_id: int, app_id: int) -> Path:
    p = service.file_validator.get_candidate_storage_root(user_id) / "applications" / str(app_id)
    p.mkdir(parents=True, exist_ok=True)
    return p


@router.post("/{app_id}/tailor-resume")
def tailor_resume(
    app_id: int,
    req: TailorResumeRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Tailors candidate's resume for the specific application opportunity."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    correlation_id = uuid.uuid4().hex[:12]

    try:
        app = service.get_candidate_application(
            application_id=app_id,
            session_id=session.session_id,
            client_user_id=user_id,
        )
        selected_res_meta, res_id = _resolve_application_resume(
            service=service,
            user_id=user_id,
            app=app,
            req_resume_id=req.resume_id,
        )
        jd_dict = _resolve_application_job_context(
            service=service,
            user_id=user_id,
            app=app,
        )
        candidate_profile = service.db.get_user_candidate_profile(user_id) or {}

        active_ver = selected_res_meta.get("active_version", 1) if selected_res_meta else 1
        if req.resume_version_num:
            active_ver = req.resume_version_num

        tailored = service.generate_tailored_resume(
            user_id=user_id,
            candidate_profile=candidate_profile,
            resume_data=selected_res_meta,
            job_description=jd_dict,
            custom_instructions=req.custom_instructions,
            resume_id=res_id,
            resume_version_num=active_ver,
        )

        tailored_dict = tailored.to_dict() if hasattr(tailored, "to_dict") else tailored

        # Persist generated tailored resume in workspace directory
        app_dir = _get_app_storage_dir(service, user_id, app_id)
        (app_dir / "tailored_resume.json").write_text(json.dumps(tailored_dict, indent=2))

        # Advance status to PREPARING if currently DRAFT
        if app.status == "DRAFT":
            try:
                service.transition_application_status(
                    application_id=app_id,
                    new_status="PREPARING",
                    session_id=session.session_id,
                    client_user_id=user_id,
                )
            except Exception:
                pass

        return {
            "status": "ok",
            "tailored_resume": tailored_dict,
        }
    except HTTPException:
        raise
    except CrossUserAccessError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    except ApplicationNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Application #{app_id} not found.")
    except (ResumeIntegrityError, QuarantinedSourceError, SecurityAuthorizationError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except Exception as e:
        logger.exception(f"[{correlation_id}] Tailor resume failed unexpectedly: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Resume tailoring encountered an unexpected internal error (Correlation ID: {correlation_id}).",
        )


@router.post("/{app_id}/cover-letter")
def generate_cover_letter(
    app_id: int,
    req: CoverLetterRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Generates a personalized tailored cover letter across selected professional tone."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    correlation_id = uuid.uuid4().hex[:12]

    try:
        app = service.get_candidate_application(
            application_id=app_id,
            session_id=session.session_id,
            client_user_id=user_id,
        )
        selected_res_meta, res_id = _resolve_application_resume(
            service=service,
            user_id=user_id,
            app=app,
            req_resume_id=req.resume_id,
        )
        jd_dict = _resolve_application_job_context(
            service=service,
            user_id=user_id,
            app=app,
        )
        candidate_profile = service.db.get_user_candidate_profile(user_id) or {}

        active_ver = selected_res_meta.get("active_version", 1) if selected_res_meta else 1

        cl = service.generate_universal_cover_letter(
            user_id=user_id,
            candidate_profile=candidate_profile,
            job_description=jd_dict,
            resume_data=selected_res_meta,
            tone=req.tone or "Professional & Direct",
            resume_id=res_id,
            resume_version_num=active_ver,
        )

        cl_dict = cl.to_dict() if hasattr(cl, "to_dict") else cl

        # Persist generated cover letter in workspace directory
        app_dir = _get_app_storage_dir(service, user_id, app_id)
        (app_dir / "cover_letter.json").write_text(json.dumps(cl_dict, indent=2))

        return {
            "status": "ok",
            "cover_letter": cl_dict,
        }
    except HTTPException:
        raise
    except CrossUserAccessError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    except ApplicationNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Application #{app_id} not found.")
    except (ResumeIntegrityError, QuarantinedSourceError, SecurityAuthorizationError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except Exception as e:
        logger.exception(f"[{correlation_id}] Cover letter generation failed unexpectedly: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cover letter generation encountered an unexpected internal error (Correlation ID: {correlation_id}).",
        )


@router.post("/{app_id}/screening-qa")
def answer_screening_questions(
    app_id: int,
    req: ScreeningQuestionsRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Answers candidate screening questions grounded strictly in verified evidence."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    correlation_id = uuid.uuid4().hex[:12]

    try:
        app = service.get_candidate_application(
            application_id=app_id,
            session_id=session.session_id,
            client_user_id=user_id,
        )
        selected_res_meta, res_id = _resolve_application_resume(
            service=service,
            user_id=user_id,
            app=app,
            req_resume_id=req.resume_id,
        )
        jd_dict = _resolve_application_job_context(
            service=service,
            user_id=user_id,
            app=app,
        )
        candidate_profile = service.db.get_user_candidate_profile(user_id) or {}

        questions_list: List[str] = []
        if req.questions:
            for q in req.questions:
                if isinstance(q, str):
                    questions_list.append(q)
                elif isinstance(q, dict) and "q" in q:
                    questions_list.append(q["q"])
                elif isinstance(q, dict) and "question" in q:
                    questions_list.append(q["question"])

        if not questions_list:
            role = app.job_title or "Target Role"
            company = app.company_name or "Target Company"
            questions_list = [
                f"Why are you interested in joining {company} as a {role}?",
                f"How does your technical experience align with the requirements for this {role}?",
                "What is your earliest available start date and expected compensation?",
            ]

        qa_packet = service.batch_answer_screening_questions(
            questions=questions_list,
            user_id=user_id,
            candidate_profile=candidate_profile,
            resume_data=selected_res_meta,
            job_description=jd_dict,
            resume_id=res_id,
            resume_version_num=selected_res_meta.get("active_version", 1),
        )

        qa_dict = qa_packet.to_dict() if hasattr(qa_packet, "to_dict") else qa_packet
        items = qa_dict.get("answers", []) if isinstance(qa_dict, dict) else qa_dict

        formatted_qa = []
        for item in items:
            item_dict = item.to_dict() if hasattr(item, "to_dict") else (item if isinstance(item, dict) else {})
            q_text = item_dict.get("question_text") or item_dict.get("question") or getattr(item, "question_text", str(item))
            a_text = item_dict.get("answer_text") or item_dict.get("draft_answer") or item_dict.get("answer") or getattr(item, "answer_text", getattr(item, "draft_answer", ""))
            rev_state = item_dict.get("state") or item_dict.get("review_state") or getattr(item, "state", "GENERATED_DRAFT")
            if hasattr(rev_state, "value"):
                rev_state = rev_state.value
            needs_input = rev_state == "NEEDS_CANDIDATE_INPUT"
            formatted_qa.append({
                "q": q_text,
                "a": a_text,
                "needsInput": needs_input,
                "review_state": rev_state,
                "category": item_dict.get("category", getattr(item, "category", "GENERAL")),
            })

        app_dir = _get_app_storage_dir(service, user_id, app_id)
        (app_dir / "screening_qa.json").write_text(json.dumps(formatted_qa, indent=2))

        return {
            "status": "ok",
            "screening_qa": formatted_qa,
        }
    except HTTPException:
        raise
    except CrossUserAccessError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    except ApplicationNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Application #{app_id} not found.")
    except (ResumeIntegrityError, QuarantinedSourceError, SecurityAuthorizationError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except Exception as e:
        logger.exception(f"[{correlation_id}] Screening QA generation failed unexpectedly: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Screening QA encountered an unexpected internal error (Correlation ID: {correlation_id}).",
        )


@router.get("/{app_id}/preparation-state", response_model=PreparationStateResponse)
def get_preparation_state(
    app_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Retrieves full preparation workspace state for instant restoration across page reloads."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()

    try:
        app = service.get_candidate_application(
            application_id=app_id,
            session_id=session.session_id,
            client_user_id=user_id,
        )

        app_dir = _get_app_storage_dir(service, user_id, app_id)

        tailored_resume: Optional[Dict[str, Any]] = None
        cover_letter: Optional[Dict[str, Any]] = None
        screening_qa: Optional[List[Dict[str, Any]]] = None

        resume_file = app_dir / "tailored_resume.json"
        if resume_file.exists():
            try:
                tailored_resume = json.loads(resume_file.read_text())
            except Exception:
                pass

        cl_file = app_dir / "cover_letter.json"
        if cl_file.exists():
            try:
                cover_letter = json.loads(cl_file.read_text())
            except Exception:
                pass

        qa_file = app_dir / "screening_qa.json"
        if qa_file.exists():
            try:
                screening_qa = json.loads(qa_file.read_text())
            except Exception:
                pass

        packet = service.db.get_active_prepared_packet(application_id=app_id, user_id=user_id)
        has_packet = packet is not None
        packet_info: Optional[Dict[str, Any]] = None
        if packet:
            packet_info = {
                "id": packet.id,
                "packet_version": getattr(packet, "packet_version", getattr(packet, "version_num", 1)),
                "packet_version_hash": packet.packet_version_hash,
                "is_active_revision": bool(packet.is_active_revision),
                "status": getattr(packet, "status", "SEALED"),
                "created_at": str(packet.created_at),
            }
            if packet.canonical_snapshot_json:
                try:
                    snap = json.loads(packet.canonical_snapshot_json)
                    if not tailored_resume and snap.get("tailored_resume"):
                        tailored_resume = snap["tailored_resume"]
                    if not cover_letter and snap.get("cover_letter"):
                        cover_letter = snap["cover_letter"]
                    if not screening_qa and snap.get("screening_qa"):
                        screening_qa = snap["screening_qa"]
                except Exception:
                    pass

        is_approved = app.status in ("APPROVED", "Approved", "SUBMITTED", "Applied", "In Progress", "IN_PROGRESS")
        is_submitted = app.status in ("SUBMITTED", "Applied", "In Progress", "IN_PROGRESS")

        return PreparationStateResponse(
            application_id=app.id,
            selected_resume_id=app.resume_id,
            company_name=app.company_name,
            job_title=app.job_title,
            status=app.status,
            tailored_resume=tailored_resume,
            cover_letter=cover_letter,
            screening_qa=screening_qa,
            has_packet=has_packet,
            packet=packet_info,
            is_approved=is_approved,
            is_submitted=is_submitted,
        )
    except ApplicationNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Application #{app_id} not found.")
    except CrossUserAccessError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")


@router.post("/{app_id}/prepare-packet")
def prepare_packet(
    app_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Generates documents and seals immutable PreparedPacket revision for approval gate."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    app = service.get_candidate_application(application_id=app_id, session_id=session.session_id, client_user_id=user_id)
    candidate_profile = service.db.get_user_candidate_profile(user_id) or {}
    selected_res, _ = _resolve_application_resume(service=service, user_id=user_id, app=app)
    jd_dict = _resolve_application_job_context(service=service, user_id=user_id, app=app)

    try:
        # 1. Generate tailored resume
        tailored_resume = service.generate_universal_tailored_resume(
            user_id=user_id,
            candidate_profile=candidate_profile,
            resume_data=selected_res,
            job_description=jd_dict,
            resume_id=selected_res["id"],
            resume_version_num=selected_res.get("active_version", 1),
        )
        
        # 2. Generate cover letter
        cover_letter = service.generate_universal_cover_letter(
            user_id=user_id,
            candidate_profile=candidate_profile,
            job_description=jd_dict,
            resume_data=selected_res,
            tone="Professional & Direct",
            resume_id=selected_res["id"],
            resume_version_num=selected_res.get("active_version", 1),
        )

        # 3. Answer screening questions if available
        from src.preparer.question_answerer import ScreeningQAPacket, ScreeningQuestion, AnswerState, QuestionCategory
        app_dir = _get_app_storage_dir(service, user_id, app_id)
        sq_file = app_dir / "screening_qa.json"
        questions_objs = []
        if sq_file.exists():
            try:
                qa_data = json.loads(sq_file.read_text())
                for item in qa_data:
                    q_text = item.get("q", "")
                    a_text = item.get("a", "")
                    st = AnswerState.USER_APPROVED if item.get("review_state") == "USER_APPROVED" else AnswerState.GENERATED_DRAFT
                    questions_objs.append(ScreeningQuestion(
                        question_id=f"sq_{uuid.uuid4().hex[:6]}",
                        user_id=user_id,
                        category=QuestionCategory.EXPERIENCE,
                        question_text=q_text,
                        draft_answer=a_text,
                        state=st,
                    ))
            except Exception:
                pass

        if not questions_objs:
            answered = service.batch_answer_screening_questions(
                questions=[],
                user_id=user_id,
                candidate_profile=candidate_profile,
                job_description=jd_dict,
                resume_data=selected_res,
                resume_id=selected_res["id"],
                resume_version_num=selected_res.get("active_version", 1),
            )
            questions_objs = answered if isinstance(answered, list) else getattr(answered, "questions", [])

        qa_packet = ScreeningQAPacket(
            user_id=user_id,
            job_description_id=getattr(app, "job_description_id", None),
            questions=questions_objs,
        )

        # 4. Generate documents
        generated_docs = service.generate_universal_application_documents(
            user_id=user_id,
            application_id=app_id,
            resume=tailored_resume,
            cover_letter=cover_letter,
            qa_packet=qa_packet,
        )

        # 5. Build attachments manifest
        attachments_manifest = []
        for doc_key, doc_obj in generated_docs.items():
            if doc_obj and getattr(doc_obj, "file_path", None):
                p = Path(doc_obj.file_path)
                if p.exists():
                    sz = getattr(doc_obj, "file_size_bytes", p.stat().st_size)
                    attachments_manifest.append({
                        "doc_key": doc_key,
                        "filename": p.name,
                        "file_path": str(p),
                        "file_format": getattr(doc_obj, "file_format", p.suffix.lstrip(".")),
                        "size_bytes": sz,
                        "file_size": sz,
                        "file_hash": getattr(doc_obj, "file_hash", ""),
                    })

        # 6. Seal prepared packet
        pkt = service.prepare_universal_application_packet(
            user_id=user_id,
            application_id=app_id,
            original_resume_id=selected_res["id"],
            original_resume_hash=selected_res.get("file_hash", ""),
            tailored_resume=tailored_resume,
            cover_letter=cover_letter,
            qa_packet=qa_packet,
            job_description_snapshot_hash=jd_dict.get("snapshot_hash") or hashlib.sha256((jd_dict.get("raw_content", "") or jd_dict.get("job_description", "")).encode("utf-8")).hexdigest() or "GENESIS",
            tailored_resume_doc=generated_docs.get("resume_pdf"),
            cover_letter_doc=generated_docs.get("cover_letter_pdf"),
            attachments_manifest=attachments_manifest,
            candidate_profile_version=candidate_profile.get("version", 1),
            candidate_profile_hash=candidate_profile.get("profile_hash"),
            template_id="modern",
            template_version="1.0",
            original_resume_version_num=selected_res.get("active_version", 1),
            job_description_id=app.job_description_id,
            generated_docs=generated_docs,
            tailored_resume_pdf_doc=generated_docs.get("resume_pdf"),
            tailored_resume_docx_doc=generated_docs.get("resume_docx"),
            cover_letter_pdf_doc=generated_docs.get("cover_letter_pdf"),
            cover_letter_docx_doc=generated_docs.get("cover_letter_docx"),
        )
        
        # Refresh app status to verify transition
        refreshed_app = service.db.get_user_application(app_id, user_id=user_id)
        current_status = getattr(refreshed_app, "status", None) if refreshed_app else None
        if current_status not in ("READY_FOR_REVIEW", "AWAITING_APPROVAL", "APPROVED", "APPLIED", "SUBMITTED"):
            try:
                service.transition_application_status(
                    application_id=app_id,
                    new_status="READY_FOR_REVIEW",
                    session_id=session.session_id,
                    client_user_id=user_id,
                )
            except Exception:
                pass

        return {
            "status": "ok",
            "message": "Application packet prepared successfully.",
            "packet": {
                "id": pkt.id,
                "packet_version": getattr(pkt, "packet_version", getattr(pkt, "version_num", 1)),
                "packet_version_hash": pkt.packet_version_hash,
                "is_active_revision": bool(pkt.is_active_revision),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Packet preparation failed: {str(e)}")


@router.get("/{app_id}/documents/{doc_type}/{doc_format}")
def download_document(
    app_id: int,
    doc_type: str,
    doc_format: str,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Downloads ATS-optimized application documents with strict ownership validation."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    app = service.get_candidate_application(application_id=app_id, session_id=session.session_id, client_user_id=user_id)
    if app.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    doc_type_clean = doc_type.lower().replace("-", "_")
    doc_format_clean = doc_format.lower()
    
    if doc_format_clean not in ("pdf", "docx"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported format. Only pdf and docx are supported.")
        
    valid_types = {
        "resume": f"resume_{doc_format_clean}",
        "cover_letter": f"cover_letter_{doc_format_clean}",
        "screening_qa": f"screening_qa_{doc_format_clean}",
        "packet": f"packet_{doc_format_clean}",
    }
    
    doc_key = valid_types.get(doc_type_clean)
    if not doc_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown document type '{doc_type}'.")

    app_dir = service.file_validator.get_candidate_storage_root(user_id) / "applications" / str(app_id)
    target_files = list(app_dir.glob(f"*{doc_type_clean}*.{doc_format_clean}")) if app_dir.exists() else []

    if not target_files:
        try:
            candidate_profile = service.db.get_user_candidate_profile(user_id) or {}
            selected_res, _ = _resolve_application_resume(service=service, user_id=user_id, app=app)
            jd_dict = _resolve_application_job_context(service=service, user_id=user_id, app=app)
            
            tailored_resume = service.generate_universal_tailored_resume(
                user_id=user_id,
                candidate_profile=candidate_profile,
                resume_data=selected_res,
                job_description=jd_dict,
                resume_id=selected_res["id"],
                resume_version_num=selected_res.get("active_version", 1),
            )
            cover_letter = service.generate_universal_cover_letter(
                user_id=user_id,
                candidate_profile=candidate_profile,
                job_description=jd_dict,
                resume_data=selected_res,
                tone="Professional & Direct",
                resume_id=selected_res["id"],
                resume_version_num=selected_res.get("active_version", 1),
            )
            qa_packet = service.batch_answer_screening_questions(
                user_id=user_id,
                questions=[],
                candidate_profile=candidate_profile,
                job_description=jd_dict,
                resume_data=selected_res,
            )
            generated_docs = service.generate_universal_application_documents(
                user_id=user_id,
                application_id=app_id,
                resume=tailored_resume,
                cover_letter=cover_letter,
                qa_packet=qa_packet,
            )
            doc_obj = generated_docs.get(doc_key)
            if doc_obj and getattr(doc_obj, "file_path", None):
                p = Path(doc_obj.file_path)
                if p.exists():
                    target_files.append(p)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to generate document: {str(e)}")

    if not target_files:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Document {doc_type} ({doc_format}) could not be located or generated.")

    chosen_file = Path(target_files[0])
    
    # Path traversal protection
    try:
        chosen_file.resolve().relative_to(service.file_validator.get_candidate_storage_root(user_id).resolve())
    except ValueError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Illegal document path traversal.")

    media_type = "application/pdf" if doc_format_clean == "pdf" else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    clean_company = "".join(c for c in app.company_name if c.isalnum() or c in (" ", "_", "-")).strip() or "Application"
    clean_title = "".join(c for c in app.job_title if c.isalnum() or c in (" ", "_", "-")).strip() or "Opportunity"
    download_filename = f"{clean_company}_{clean_title}_{doc_type_clean}.{doc_format_clean}"

    return FileResponse(
        path=str(chosen_file),
        filename=download_filename,
        media_type=media_type,
    )


@router.get("/{app_id}/packets/latest")
def get_latest_packet(
    app_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Retrieves active PreparedPacket revision for application."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    packet = service.db.get_active_prepared_packet(application_id=app_id, user_id=user_id)
    if not packet:
        return {"has_packet": False}
        
    return {
        "has_packet": True,
        "packet": {
            "id": packet.id,
            "packet_version": getattr(packet, "packet_version", getattr(packet, "version_num", 1)),
            "packet_version_hash": packet.packet_version_hash,
            "is_active_revision": bool(packet.is_active_revision),
            "status": getattr(packet, "status", "SEALED"),
            "created_at": str(packet.created_at),
        },
    }


@router.post("/{app_id}/tickets/approval", response_model=IssueTicketResponse)
def issue_approval_ticket(
    app_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Issues single-use HMAC action ticket required for Human Approval Gate."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    packet = service.db.get_active_prepared_packet(application_id=app_id, user_id=user_id)
    if not packet:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active prepared packet found to approve.")
        
    ticket = service.issue_approval_ticket(
        session_id=session.session_id,
        job_id=app_id,
        packet_hash=packet.packet_version_hash,
    )
    return IssueTicketResponse(
        ticket=ticket,
        action_type="HUMAN_APPROVAL",
        application_id=app_id,
        packet_hash=packet.packet_version_hash,
    )


@router.post("/{app_id}/approve")
def approve_packet(
    app_id: int,
    req: AuthorizePacketRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Explicitly authorizes prepared application packet under strict human governance."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    packet = service.db.get_active_prepared_packet(application_id=app_id, user_id=user_id)
    if not packet:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active prepared packet found.")
        
    success, msg, approval = service.authorize_universal_application_packet(
        user_id=user_id,
        application_id=app_id,
        packet_id=packet.id,
        approver_name=req.approver_name,
        session_id=session.session_id,
        action_ticket=req.action_ticket,
        candidate_confirmed=req.candidate_confirmed,
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        
    return {
        "status": "ok",
        "message": "Application packet approved successfully. Ready for manual submission.",
        "approval_id": getattr(approval, "id", None),
    }


@router.post("/{app_id}/tickets/submission", response_model=IssueTicketResponse)
def issue_submission_ticket(
    app_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Issues single-use HMAC ticket for candidate manual submission confirmation."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    packet = service.db.get_active_prepared_packet(application_id=app_id, user_id=user_id)
    if not packet:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active prepared packet found.")
        
    ticket = service.issue_manual_submission_ticket(
        session_id=session.session_id,
        application_id=app_id,
        packet_hash=packet.packet_version_hash,
    )
    return IssueTicketResponse(
        ticket=ticket,
        action_type="MANUAL_SUBMISSION",
        application_id=app_id,
        packet_hash=packet.packet_version_hash,
    )


@router.post("/{app_id}/confirm-submission")
def confirm_submission(
    app_id: int,
    req: ConfirmSubmissionRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Records candidate manual submission confirmation on external employer portal."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    try:
        channel_map = {
            "EMPLOYER_PORTAL": "COMPANY_PORTAL",
            "LINKEDIN_EASY_APPLY": "LINKEDIN",
            "INTERNSHALA": "OTHER",
            "INDEED_APPLY": "INDEED",
        }
        clean_channel = channel_map.get(req.submission_channel, req.submission_channel)
        conf = service.record_candidate_manual_submission(
            application_id=app_id,
            session_id=session.session_id,
            submission_ticket=req.submission_ticket,
            candidate_confirmed=req.candidate_confirmed,
            submission_channel=clean_channel,
            confirmation_reference=req.confirmation_reference,
            candidate_notes=req.candidate_notes,
        )
        return {
            "status": "ok",
            "message": "Manual submission confirmed successfully.",
            "confirmation_id": getattr(conf, "id", None),
        }
    except SecurityAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Submission confirmation failed: {str(e)}")


@router.get("/{app_id}/timeline")
def get_timeline(
    app_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Retrieves immutable chronological audit event timeline for application."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    timeline = service.get_application_timeline(application_id=app_id, session_id=session.session_id, client_user_id=user_id)
    return {"timeline": timeline}


@router.get("/{app_id}/followups", response_model=List[FollowUpResponse])
def get_followups(
    app_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Retrieves candidate-scheduled follow-up reminders."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    fus = service.list_application_follow_ups(session_id=session.session_id, application_id=app_id, client_user_id=user_id)
    return [
        FollowUpResponse(
            id=f.id,
            application_id=f.application_id,
            user_id=f.user_id,
            follow_up_type=f.follow_up_type,
            scheduled_date=str(f.follow_up_date),
            is_completed=bool(f.is_completed),
            completed_at=str(f.completed_at) if f.completed_at else None,
            outcome_notes=f.outcome_notes,
        )
        for f in fus
    ]


@router.post("/{app_id}/followups", response_model=FollowUpResponse, status_code=status.HTTP_201_CREATED)
def create_followup(
    app_id: int,
    req: FollowUpCreateRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Schedules a new follow-up reminder."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    fu_type = req.follow_up_type
    type_map = {
        "status inquiry": "STATUS_INQUIRY",
        "check application status": "STATUS_INQUIRY",
        "thank you note": "THANK_YOU_NOTE",
        "portfolio update": "PORTFOLIO_UPDATE",
        "recruiter checkin": "RECRUITER_CHECKIN",
        "phone call": "PHONE_CALL",
        "other": "OTHER",
    }
    canonical_type = type_map.get(fu_type.strip().lower(), fu_type.strip().upper())
    
    fu = service.create_application_follow_up(
        session_id=session.session_id,
        application_id=app_id,
        follow_up_date=req.scheduled_date,
        follow_up_type=canonical_type,
        description=req.notes or f"Follow up on {canonical_type}",
        outcome_notes=None,
        client_user_id=user_id,
    )
    return FollowUpResponse(
        id=fu.id,
        application_id=fu.application_id,
        user_id=fu.user_id,
        follow_up_type=fu.follow_up_type,
        scheduled_date=str(fu.follow_up_date),
        is_completed=bool(fu.is_completed),
    )

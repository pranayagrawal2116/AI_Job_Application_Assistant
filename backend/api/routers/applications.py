"""Application preparation workspace, approval gate, and tracker endpoints."""

from typing import Any, Dict, List, Optional
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
    PreparedPacketResponse,
    TailorResumeRequest,
)
from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    SecurityAuthorizationError,
    ValidationError,
)

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
        job = service.get_job_detail(req.job_id)
        if job:
            company = company or job.company_name
            title = title or job.job_title
            
    app = service.create_candidate_application(
        session_id=session.session_id,
        company_name=company or "Company",
        job_title=title or "Opportunity",
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


@router.post("/{app_id}/tailor-resume")
def tailor_resume(
    app_id: int,
    req: TailorResumeRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Tailors candidate's resume for the specific application opportunity."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    app = service.get_candidate_application(application_id=app_id, session_id=session.session_id, client_user_id=user_id)
    resumes = service.get_user_resumes(user_id)
    res_id = app.resume_id or req.resume_id
    if not res_id:
        if not resumes:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No resume uploaded yet.")
        res_id = resumes[0]["id"]
        
    selected_res_meta = next((r for r in resumes if r.get("id") == res_id), resumes[0] if resumes else None)
    candidate_profile = service.db.get_user_candidate_profile(user_id) or {}
    
    selected_jd = service.db.get_job_description(app.job_description_id, user_id=user_id) if app.job_description_id else None
    jd_parsed = (selected_jd.to_dict().get("parsed_data") if selected_jd else {}) or {}
    jd_dict = {
        "id": selected_jd.id if selected_jd else None,
        "company_name": selected_jd.company_name if selected_jd else app.company_name,
        "role_title": getattr(selected_jd, "job_title", getattr(selected_jd, "role_title", app.job_title)) if selected_jd else app.job_title,
        "required_skills": jd_parsed.get("required_skills") or getattr(selected_jd, "required_skills", []),
        "preferred_skills": jd_parsed.get("preferred_skills") or getattr(selected_jd, "preferred_skills", []),
    }
        
    try:
        tailored = service.generate_tailored_resume(
            user_id=user_id,
            candidate_profile=candidate_profile,
            resume_data=selected_res_meta,
            job_description=jd_dict,
            custom_instructions=req.custom_instructions,
            resume_id=res_id,
            resume_version_num=selected_res_meta.get("active_version", 1) if selected_res_meta else 1,
        )
        return {
            "status": "ok",
            "tailored_resume": tailored.to_dict() if hasattr(tailored, "to_dict") else tailored,
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Resume tailoring failed: {str(e)}")


@router.post("/{app_id}/cover-letter")
def generate_cover_letter(
    app_id: int,
    req: CoverLetterRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Generates a personalized tailored cover letter across selected professional tone."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    app = service.get_candidate_application(application_id=app_id, session_id=session.session_id, client_user_id=user_id)
    candidate_profile = service.db.get_user_candidate_profile(user_id) or {}
    resumes = service.get_user_resumes(user_id)
    selected_res_meta = next((r for r in resumes if r.get("id") == app.resume_id), resumes[0] if resumes else None)
    selected_jd = service.db.get_job_description(app.job_description_id, user_id=user_id) if app.job_description_id else None
    jd_dict = {
        "id": selected_jd.id if selected_jd else None,
        "company_name": selected_jd.company_name if selected_jd else app.company_name,
        "role_title": getattr(selected_jd, "job_title", getattr(selected_jd, "role_title", app.job_title)) if selected_jd else app.job_title,
    }

    try:
        cl = service.generate_universal_cover_letter(
            user_id=user_id,
            candidate_profile=candidate_profile,
            job_description=jd_dict,
            resume_data=selected_res_meta,
            tone=req.tone or "Professional & Direct",
            resume_id=app.resume_id,
            resume_version_num=selected_res_meta.get("active_version", 1) if selected_res_meta else 1,
        )
        return {
            "status": "ok",
            "cover_letter": cl.to_dict() if hasattr(cl, "to_dict") else cl,
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cover letter generation failed: {str(e)}")


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
    resumes = service.get_user_resumes(user_id)
    selected_res = next((r for r in resumes if r.get("id") == app.resume_id), resumes[0] if resumes else None)
    if not selected_res:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No resume linked to this application. Please upload a resume first.")
        
    selected_jd = service.db.get_job_description(app.job_description_id, user_id=user_id) if app.job_description_id else None
    jd_dict = {
        "id": selected_jd.id if selected_jd else None,
        "company_name": selected_jd.company_name if selected_jd else app.company_name,
        "role_title": getattr(selected_jd, "job_title", getattr(selected_jd, "role_title", app.job_title)) if selected_jd else app.job_title,
        "raw_content": getattr(selected_jd, "raw_content", ""),
        "parsed_data": getattr(selected_jd, "parsed_data", {}),
    }

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
        qa_packet = service.batch_answer_screening_questions(
            user_id=user_id,
            questions=[],
            candidate_profile=candidate_profile,
            job_description=jd_dict,
            resume_data=selected_res,
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
            if doc_obj and hasattr(doc_obj, "file_path") and doc_obj.file_path.exists():
                attachments_manifest.append({
                    "doc_key": doc_key,
                    "filename": doc_obj.file_path.name,
                    "file_format": doc_obj.file_format,
                    "file_size": doc_obj.file_size_bytes,
                    "file_hash": doc_obj.file_hash,
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
            job_description_snapshot_hash=getattr(selected_jd, "snapshot_hash", "GENESIS"),
            tailored_resume_doc=generated_docs.get("resume_pdf"),
            cover_letter_doc=generated_docs.get("cover_letter_pdf"),
            attachments_manifest=attachments_manifest,
            candidate_profile_version=1,
            candidate_profile_hash="profile_hash",
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
        
        # Advance status to READY_FOR_REVIEW if currently DRAFT or PREPARING
        if app.status in ("DRAFT", "PREPARING"):
            service.transition_application_status(
                application_id=app_id,
                new_status="READY_FOR_REVIEW",
                session_id=session.session_id,
                client_user_id=user_id,
            )

        return {
            "status": "ok",
            "message": "Application packet prepared successfully.",
            "packet": {
                "id": pkt.id,
                "packet_version": pkt.packet_version,
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
            resumes = service.get_user_resumes(user_id)
            selected_res = next((r for r in resumes if r.get("id") == app.resume_id), resumes[0] if resumes else None)
            if not selected_res:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No resume available to render document.")
                
            selected_jd = service.db.get_job_description(app.job_description_id, user_id=user_id) if app.job_description_id else None
            jd_dict = {
                "id": selected_jd.id if selected_jd else None,
                "company_name": selected_jd.company_name if selected_jd else app.company_name,
                "role_title": getattr(selected_jd, "job_title", getattr(selected_jd, "role_title", app.job_title)) if selected_jd else app.job_title,
                "raw_content": getattr(selected_jd, "raw_content", ""),
                "parsed_data": getattr(selected_jd, "parsed_data", {}),
            }
            
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
            if doc_obj and hasattr(doc_obj, "file_path") and doc_obj.file_path.exists():
                target_files.append(doc_obj.file_path)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to generate document: {str(e)}")

    if not target_files:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Document {doc_type} ({doc_format}) could not be located or generated.")

    chosen_file = target_files[0]
    
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
            "packet_version": packet.packet_version,
            "packet_version_hash": packet.packet_version_hash,
            "is_active_revision": bool(packet.is_active_revision),
            "status": packet.status,
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
        conf = service.record_candidate_manual_submission(
            application_id=app_id,
            session_id=session.session_id,
            submission_ticket=req.submission_ticket,
            candidate_confirmed=req.candidate_confirmed,
            submission_channel=req.submission_channel,
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

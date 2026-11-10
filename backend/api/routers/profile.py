"""Candidate profile and resume management endpoints."""

import hashlib
import logging
from typing import List
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from dashboard.services.dashboard_service import DashboardService
from backend.api.dependencies.auth import get_current_user_and_session
from backend.api.schemas.profile import (
    ProfileResponse,
    ProfileUpdateRequest,
    ResumeResponse,
    ResumeSyncResponse,
)
from src.database.exceptions import (
    DuplicateResumeError,
    FileSecurityError,
    ResumeNotFoundError,
    ValidationError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/profile", tags=["Profile & Resumes"])


@router.get("", response_model=ProfileResponse)
def get_profile(auth_ctx=Depends(get_current_user_and_session)):
    """Retrieves current candidate's profile data."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    prof_rec = service.db.get_user_candidate_profile(user_id)
    if not prof_rec:
        return ProfileResponse(
            user_id=user_id,
            profile_data={
                "personal": {},
                "education": [],
                "work_experience": [],
                "skills": [],
                "technical_skills": {},
                "projects": [],
                "certifications": [],
                "statutory_licenses": [],
                "career_preferences": {},
            },
            version=1,
        )
        
    return ProfileResponse(
        user_id=user_id,
        profile_data=prof_rec.get("profile_data", {}),
        version=prof_rec.get("version", 1),
        updated_at=prof_rec.get("updated_at"),
    )


@router.put("", response_model=ProfileResponse)
def update_profile(
    req: ProfileUpdateRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Updates candidate profile data with version snapshot tracking."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    success, msg = service.save_user_candidate_profile(
        user_id=user_id,
        profile_data=req.profile_data,
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        
    return get_profile(auth_ctx)


@router.get("/resumes", response_model=List[ResumeResponse])
def list_resumes(auth_ctx=Depends(get_current_user_and_session)):
    """Lists all resumes uploaded by the authenticated candidate."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    resumes = service.get_user_resumes(user_id)
    return [
        ResumeResponse(
            id=r["id"],
            user_id=r["user_id"],
            original_filename=r["original_filename"],
            file_format=r["file_format"],
            file_size_bytes=r["file_size_bytes"],
            file_hash=r["file_hash"],
            is_primary=bool(r.get("is_primary", False)),
            upload_date=r.get("upload_date"),
            created_at=r.get("created_at"),
        )
        for r in resumes
    ]


@router.post("/resumes", response_model=ResumeResponse, status_code=status.HTTP_201_CREATED)
@router.post("/resumes/upload", response_model=ResumeResponse, status_code=status.HTTP_201_CREATED)
async def upload_resume(
    file: UploadFile = File(...),
    auto_sync_profile: bool = Form(True),
    auth_ctx=Depends(get_current_user_and_session),
):
    """Uploads a PDF or DOCX resume, validates magic bytes, and parses details."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")
        
    try:
        resume_rec = service.db.upload_user_resume(
            user_id=user_id,
            file_bytes=contents,
            original_filename=file.filename or "resume.pdf",
        )
        
        # Authoritative Single-Pass Profile Synchronization
        sync_status = "SYNCED"
        sync_error = None
        if auto_sync_profile:
            try:
                service.sync_user_profile_from_resume_id(
                    user_id=user_id,
                    resume_id=resume_rec["id"],
                )
            except Exception as sync_err:
                logger.error("Profile synchronization error on resume upload: %s", sync_err)
                sync_status = "FAILED"
                sync_error = str(sync_err)
                
        return ResumeResponse(
            id=resume_rec["id"],
            user_id=resume_rec["user_id"],
            original_filename=resume_rec["original_filename"],
            file_format=resume_rec["file_format"],
            file_size_bytes=resume_rec["file_size_bytes"],
            file_hash=resume_rec["file_hash"],
            is_primary=bool(resume_rec.get("is_primary", False)),
            upload_date=resume_rec.get("upload_date"),
            sync_status=sync_status,
            sync_error=sync_error,
        )
    except FileSecurityError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"File validation failed: {str(e)}")
    except DuplicateResumeError as e:
        # User already uploaded this exact resume. Gracefully retrieve and return it!
        file_hash = hashlib.sha256(contents).hexdigest()
        with service.db.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE user_id = ? AND file_hash = ?", (user_id, file_hash))
            existing_row = cursor.fetchone()

        if existing_row:
            existing_dict = dict(existing_row)
            sync_status = "SYNCED"
            sync_error = None
            if auto_sync_profile:
                try:
                    service.sync_user_profile_from_resume_id(user_id=user_id, resume_id=existing_dict["id"])
                except Exception as sync_err:
                    logger.warning("Profile re-sync error on duplicate upload: %s", sync_err)
                    sync_status = "FAILED"
                    sync_error = str(sync_err)

            # Re-verify and recover security scan under current active signing key if needed
            try:
                service.recover_unverifiable_resume_scan(
                    user_id=user_id,
                    resume_id=existing_dict["id"],
                    recovery_reason="Explicit candidate resume re-upload",
                )
            except Exception as rec_err:
                logger.warning("Scan recovery on re-upload non-fatal error: %s", rec_err)

            return ResumeResponse(
                id=existing_dict["id"],
                user_id=existing_dict["user_id"],
                original_filename=existing_dict["original_filename"],
                file_format=existing_dict["file_format"],
                file_size_bytes=existing_dict["file_size_bytes"],
                file_hash=existing_dict["file_hash"],
                is_primary=bool(existing_dict.get("is_primary", False)),
                upload_date=existing_dict.get("upload_date"),
                sync_status=sync_status,
                sync_error=sync_error,
            )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Duplicate resume: {str(e)}")
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except Exception as e:
        logger.exception("Resume upload failed unexpectedly for user %s: %s", user_id, e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Resume upload failed: {str(e)}")


@router.post("/resumes/{resume_id}/primary")
def set_primary_resume(
    resume_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Marks a resume as the candidate's primary default resume."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    try:
        service.set_primary_resume(user_id=user_id, resume_id=resume_id)
        return {"status": "ok", "message": f"Resume #{resume_id} is now primary"}
    except ResumeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Resume #{resume_id} not found")


@router.delete("/resumes/{resume_id}")
def delete_resume(
    resume_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Deletes or archives a resume file."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    try:
        deleted = service.delete_user_resume(user_id=user_id, resume_id=resume_id)
        return {"status": "ok", "deleted": deleted}
    except ResumeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Resume #{resume_id} not found")


@router.post("/resumes/{resume_id}/sync", response_model=ResumeSyncResponse)
def sync_resume_to_profile(
    resume_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Parses resume and synchronizes candidate profile sections."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    try:
        result = service.sync_user_profile_from_resume_id(user_id=user_id, resume_id=resume_id)
        return ResumeSyncResponse(
            success=True,
            message="Profile successfully synchronized from resume",
            updated_fields=result if isinstance(result, list) else ["skills", "education", "experience"],
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Sync failed: {str(e)}")


@router.post("/resumes/{resume_id}/recover-scan")
def recover_resume_scan(
    resume_id: int,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Explicit authorized recovery of an unverifiable historical resume scan whose signing key was lost."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    try:
        result = service.recover_unverifiable_resume_scan(
            user_id=user_id,
            resume_id=resume_id,
            recovery_reason="Direct candidate scan recovery request",
        )
        return {
            "status": "ok",
            "message": "Resume security scan successfully re-established with current active signing key.",
            "classification": result.classification,
            "risk_score": result.risk_score,
            "resume_id": resume_id,
            "version_num": result.source_version,
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

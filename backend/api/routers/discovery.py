"""Discovery and Personalized Recommendation Router."""

import logging
from typing import List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from dashboard.services.dashboard_service import DashboardService
from backend.api.dependencies.auth import get_current_user_and_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/discovery", tags=["Discovery"])


class SearchPreferencesRequest(BaseModel):
    target_roles: Optional[List[str]] = Field(default_factory=list)
    target_locations: Optional[List[str]] = Field(default_factory=list)
    auto_discover_enabled: Optional[bool] = True


class TriggerDiscoveryRequest(BaseModel):
    roles: Optional[List[str]] = None
    locations: Optional[List[str]] = None


def _background_discovery_task(user_id: int, roles: Optional[List[str]], locations: Optional[List[str]]) -> None:
    """Executes discovery and personalized matching asynchronously in background."""
    try:
        service = DashboardService.get_instance()
        service.run_candidate_discovery(user_id=user_id, roles=roles, locations=locations)
    except Exception as e:
        logger.exception("Background discovery failed for user %s: %s", user_id, e)


@router.post("/trigger")
def trigger_discovery(
    req: Optional[TriggerDiscoveryRequest] = None,
    background_tasks: BackgroundTasks = None,
    request: Request = None,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Triggers candidate-scoped job discovery in the background (delegates to canonical jobs discovery)."""
    from backend.api.routers.jobs import trigger_jobs_discovery, JobsDiscoveryRequest
    job_req = JobsDiscoveryRequest(roles=req.roles if req else None, locations=req.locations if req else None)
    return trigger_jobs_discovery(req=job_req, background_tasks=background_tasks, request=request, auth_ctx=auth_ctx)


@router.get("/status")
def get_discovery_status(auth_ctx=Depends(get_current_user_and_session)):
    """Returns current discovery execution status, latest metrics, and search preferences."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()

    career_ctx = service.resolve_candidate_career_context(user_id)
    active_run = service.db.get_active_discovery_run(user_id)
    latest_run = service.db.get_latest_discovery_run(user_id)

    latest_run_for_fingerprint = (
        service.db.get_latest_discovery_run(
            user_id,
            resume_fingerprint=career_ctx.resume_fingerprint,
            status_in=["COMPLETED", "PARTIAL"],
        )
        if career_ctx.resume_fingerprint
        else None
    )

    suggested_roles = [r.to_dict() if hasattr(r, "to_dict") else r for r in career_ctx.inferred_roles]

    return {
        "is_running": active_run is not None,
        "active_run": active_run,
        "latest_run": latest_run,
        "suggested_roles": suggested_roles,
        "target_roles": career_ctx.selected_roles,
        "target_locations": career_ctx.target_locations,
        "auto_discover_enabled": True,
        "has_primary_resume": career_ctx.has_primary_resume,
        "primary_resume_id": career_ctx.primary_resume_id,
        "resume_fingerprint": career_ctx.resume_fingerprint,
        "career_domain": career_ctx.career_domain,
        "candidate_category": career_ctx.candidate_category,
        "completed_for_current_resume": latest_run_for_fingerprint is not None,
        "role_source": career_ctx.role_source,
        "inference_confidence": round(career_ctx.inference_confidence, 2),
    }


@router.get("/suggested-roles")
def get_suggested_roles(auth_ctx=Depends(get_current_user_and_session)):
    """Infers and returns empirical search roles dynamically from candidate resume evidence."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    career_ctx = service.resolve_candidate_career_context(user_id)

    return {
        "suggested_roles": [r.to_dict() if hasattr(r, "to_dict") else r for r in career_ctx.inferred_roles],
        "suggested_locations": career_ctx.target_locations,
        "career_domain": career_ctx.career_domain,
        "candidate_category": career_ctx.candidate_category,
    }


@router.post("/preferences")
def update_search_preferences(
    req: SearchPreferencesRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Updates candidate-confirmed search roles, target locations, and discovery settings."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    career_ctx = service.resolve_candidate_career_context(user_id)

    prof_rec = service.db.get_user_candidate_profile(user_id)
    prof_data = prof_rec.get("profile_data", {}) if prof_rec else {}

    search_prefs = {
        "target_roles": req.target_roles or [],
        "target_locations": req.target_locations or ["Remote", "India"],
        "auto_discover_enabled": bool(req.auto_discover_enabled),
        "suggested_roles": [r.to_dict() if hasattr(r, "to_dict") else r for r in career_ctx.inferred_roles],
        "is_user_override": True,
        "explicit_user_override": True,
        "resume_fingerprint": career_ctx.resume_fingerprint,
    }

    prof_data["search_preferences"] = search_prefs
    prof_data["preferences"] = search_prefs

    success, msg = service.save_user_candidate_profile(user_id=user_id, profile_data=prof_data)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    return {
        "message": "Search preferences updated successfully.",
        "preferences": search_prefs,
    }

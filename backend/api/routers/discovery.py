"""Discovery and Personalized Recommendation Router."""

import logging
from typing import List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field

from dashboard.services.dashboard_service import DashboardService
from backend.api.dependencies.auth import get_current_user_and_session
from src.preparer.career_role_inferencer import CareerRoleInferencer

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
    auth_ctx=Depends(get_current_user_and_session),
):
    """Triggers candidate-scoped job discovery in the background."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()

    # Check if a discovery run is already in progress
    active_run = service.db.get_active_discovery_run(user_id)
    if active_run:
        return {
            "status": "already_running",
            "message": "A discovery run is already in progress for your profile.",
            "run_id": active_run["id"],
        }

    # Resolve roles and locations
    roles = req.roles if req else None
    locations = req.locations if req else None

    # Run in background
    if background_tasks is not None:
        background_tasks.add_task(_background_discovery_task, user_id, roles, locations)
        return {
            "status": "started",
            "message": "Discovery initiated. Searching permitted sources and computing personalized matches.",
        }
    else:
        # Fallback sync
        result = service.run_candidate_discovery(user_id=user_id, roles=roles, locations=locations)
        return result


@router.get("/status")
def get_discovery_status(auth_ctx=Depends(get_current_user_and_session)):
    """Returns current discovery execution status, latest metrics, and search preferences."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()

    active_run = service.db.get_active_discovery_run(user_id)
    latest_run = service.db.get_latest_discovery_run(user_id)

    prof_rec = service.db.get_user_candidate_profile(user_id)
    prof_data = prof_rec.get("profile_data", {}) if prof_rec else {}
    prefs = prof_data.get("search_preferences", {}) or prof_data.get("preferences", {})

    # Inferred roles from primary resume
    suggested_roles = prefs.get("suggested_roles", [])
    if not suggested_roles:
        resumes = service.get_user_resumes(user_id)
        if resumes:
            inferencer = CareerRoleInferencer()
            inferred = inferencer.infer_roles(prof_data)
            suggested_roles = [r.to_dict() for r in inferred]

    return {
        "is_running": active_run is not None,
        "active_run": active_run,
        "latest_run": latest_run,
        "suggested_roles": suggested_roles,
        "target_roles": prefs.get("target_roles", [r["role_title"] for r in suggested_roles[:5]]),
        "target_locations": prefs.get("target_locations", ["Remote", "India"]),
        "auto_discover_enabled": bool(prefs.get("auto_discover_enabled", True)),
    }


@router.get("/suggested-roles")
def get_suggested_roles(auth_ctx=Depends(get_current_user_and_session)):
    """Infers and returns empirical search roles dynamically from candidate resume evidence."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()

    prof_rec = service.db.get_user_candidate_profile(user_id)
    prof_data = prof_rec.get("profile_data", {}) if prof_rec else {}

    inferencer = CareerRoleInferencer()
    roles = inferencer.infer_roles(prof_data)
    locations = inferencer.infer_locations(prof_data)

    return {
        "suggested_roles": [r.to_dict() for r in roles],
        "suggested_locations": locations,
    }


@router.post("/preferences")
def update_search_preferences(
    req: SearchPreferencesRequest,
    auth_ctx=Depends(get_current_user_and_session),
):
    """Updates candidate-confirmed search roles, target locations, and discovery settings."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()

    prof_rec = service.db.get_user_candidate_profile(user_id)
    prof_data = prof_rec.get("profile_data", {}) if prof_rec else {}

    search_prefs = {
        "target_roles": req.target_roles or [],
        "target_locations": req.target_locations or ["Remote", "India"],
        "auto_discover_enabled": bool(req.auto_discover_enabled),
        "suggested_roles": prof_data.get("search_preferences", {}).get("suggested_roles", []),
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

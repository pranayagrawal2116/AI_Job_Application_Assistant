"""Dashboard overview and metrics endpoints."""

from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from dashboard.services.dashboard_service import DashboardService
from backend.api.dependencies.auth import get_current_user_and_session

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary")
def get_dashboard_summary(auth_ctx=Depends(get_current_user_and_session)):
    """Computes high-level candidate metrics and recommends the next best action."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    # 1. Tracker metrics
    tracker_metrics = service.get_candidate_tracker_metrics(session_id=session.session_id, client_user_id=user_id)
    
    # 2. Resumes & Profile
    resumes = service.get_user_resumes(user_id)
    profile_rec = service.db.get_user_candidate_profile(user_id)
    profile_data = profile_rec.get("profile_data", {}) if profile_rec else {}
    
    # Calculate profile completeness
    completeness_score = 0
    if profile_data.get("personal", {}).get("full_name"):
        completeness_score += 20
    if profile_data.get("education"):
        completeness_score += 20
    if profile_data.get("skills") or profile_data.get("technical_skills"):
        completeness_score += 20
    if profile_data.get("work_experience"):
        completeness_score += 20
    if len(resumes) > 0:
        completeness_score += 20
        
    # 3. Catalog jobs count
    jobs_df = service.get_all_jobs_df()
    total_catalog_jobs = len(jobs_df) if not jobs_df.empty else 0
    eligible_jobs = len(jobs_df[jobs_df["is_eligible"] == 1]) if not jobs_df.empty and "is_eligible" in jobs_df.columns else 0
    
    # 4. User applications
    user_apps = service.list_candidate_applications(session_id=session.session_id, client_user_id=user_id, limit=None)
    saved_count = sum(1 for a in user_apps if a.status in ("Saved", "Shortlisted", "Discovered"))
    preparing_count = sum(1 for a in user_apps if a.status in ("Preparing", "Application Prepared", "DRAFT", "PREPARING"))
    review_count = sum(1 for a in user_apps if a.status in ("Ready for Review", "Awaiting Approval", "READY_FOR_REVIEW", "APPROVED"))
    submitted_count = sum(1 for a in user_apps if a.status in ("Applied", "SUBMITTED", "IN_PROGRESS"))
    interview_count = sum(1 for a in user_apps if a.status in ("Interview", "INTERVIEW", "ASSESSMENT"))
    
    # 5. Follow-ups pending
    follow_ups = service.list_application_follow_ups(session_id=session.session_id, client_user_id=user_id, is_completed=False)
    
    # Determine Next Recommended Action
    if len(resumes) == 0:
        recommended_action = {
            "title": "Upload your resume",
            "description": "Upload a PDF or DOCX resume to automatically extract your skills and start matching with jobs.",
            "cta_label": "Upload Resume",
            "cta_url": "/profile?tab=resumes",
            "priority": "HIGH",
        }
    elif completeness_score < 60:
        recommended_action = {
            "title": "Complete your profile",
            "description": "Add your education, key projects, and verified skills to increase matching accuracy.",
            "cta_label": "Complete Profile",
            "cta_url": "/profile",
            "priority": "MEDIUM",
        }
    elif review_count > 0:
        recommended_action = {
            "title": f"Review {review_count} prepared application(s)",
            "description": "You have tailored applications ready for your review and authorization at the Human Approval Gate.",
            "cta_label": "Review Applications",
            "cta_url": "/applications?tab=review",
            "priority": "HIGH",
        }
    elif saved_count > 0:
        recommended_action = {
            "title": "Start an application",
            "description": "You have saved opportunities waiting. Tailor your resume and cover letter with one click.",
            "cta_label": "View Saved Jobs",
            "cta_url": "/applications",
            "priority": "MEDIUM",
        }
    else:
        recommended_action = {
            "title": "Explore relevant opportunities",
            "description": "Discover internships and AI/ML roles matching your verified skills and academic background.",
            "cta_label": "Find Jobs",
            "cta_url": "/jobs",
            "priority": "NORMAL",
        }
        
    return {
        "profile_completeness": completeness_score,
        "resume_count": len(resumes),
        "total_opportunities": total_catalog_jobs,
        "eligible_opportunities": eligible_jobs,
        "saved_jobs_count": saved_count,
        "preparing_count": preparing_count,
        "awaiting_review_count": review_count,
        "submitted_count": submitted_count,
        "interview_count": interview_count,
        "pending_follow_ups_count": len(follow_ups),
        "recommended_action": recommended_action,
        "recent_applications": [
            {
                "id": a.id,
                "company_name": a.company_name,
                "job_title": a.job_title,
                "status": a.status,
                "updated_at": a.updated_at,
            }
            for a in user_apps[:5]
        ],
    }

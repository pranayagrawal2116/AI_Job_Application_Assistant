"""Dashboard overview and metrics endpoints."""

from fastapi import APIRouter, Depends
from dashboard.services.dashboard_service import DashboardService
from backend.api.dependencies.auth import get_current_user_and_session
from src.preparer.career_role_inferencer import CareerRoleInferencer

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary")
def get_dashboard_summary(auth_ctx=Depends(get_current_user_and_session)):
    """Computes high-level candidate metrics and recommends the next best action."""
    user_id, session = auth_ctx
    service = DashboardService.get_instance()
    
    # 1. Resumes & Candidate Profile
    resumes = service.get_user_resumes(user_id)
    profile_rec = service.db.get_user_candidate_profile(user_id)
    profile_data = profile_rec.get("profile_data", {}) if profile_rec else {}
    
    # 3. Dynamic Candidate Classification & Non-Penalizing Completeness
    inferencer = CareerRoleInferencer()
    completeness_info = inferencer.calculate_profile_completeness(profile_data, resumes_count=len(resumes))
    completeness_score = completeness_info["completeness_score"]
    candidate_category = completeness_info["candidate_category"]
    category_label = completeness_info["category_label"]
    missing_sections = completeness_info.get("missing_sections", [])
    
    # 4. Candidate-Specific Matching Metrics (Scoped to user_id, no global catalog score leakage)
    matching_metrics = service.get_candidate_dashboard_metrics(user_id)
    total_catalog_jobs = matching_metrics.get("total_catalog_jobs", 0)
    jobs_discovered_for_user = matching_metrics.get("jobs_discovered_for_user", 0)
    evaluated_matches_count = matching_metrics.get("evaluated_matches_count", 0)
    eligible_matches_count = matching_metrics.get("eligible_matches_count", 0)
    
    # 5. User applications & pipeline breakdown
    user_apps = service.list_candidate_applications(session_id=session.session_id, client_user_id=user_id, limit=None)
    saved_count = sum(1 for a in user_apps if a.status in ("Saved", "Shortlisted", "Discovered", "DRAFT"))
    preparing_count = sum(1 for a in user_apps if a.status in ("Preparing", "Application Prepared", "PREPARING"))
    review_count = sum(1 for a in user_apps if a.status in ("Ready for Review", "Awaiting Approval", "READY_FOR_REVIEW", "APPROVED"))
    submitted_count = sum(1 for a in user_apps if a.status in ("Applied", "SUBMITTED", "IN_PROGRESS"))
    interview_count = sum(1 for a in user_apps if a.status in ("Interview", "INTERVIEW", "ASSESSMENT"))
    apps_in_progress = preparing_count + review_count + submitted_count + interview_count
    
    # 6. Follow-ups pending
    follow_ups = service.list_application_follow_ups(session_id=session.session_id, client_user_id=user_id, is_completed=False)
    
    # 7. Active Discovery Run & Career Role Inference
    active_run = service.db.get_active_discovery_run(user_id)
    inferred_roles = inferencer.infer_roles(profile_data)
    suggested_role_titles = [r.role_title for r in inferred_roles] if inferred_roles else []
    top_role = suggested_role_titles[0] if suggested_role_titles else None
    
    # 8. Contextual Recommended Next Action (Profession-Specific, No Hardcoded AI/ML Assumptions)
    if len(resumes) == 0:
        recommended_action = {
            "title": "Upload your resume",
            "description": "Upload a PDF or DOCX resume to automatically extract your verified credentials and discover matching roles.",
            "cta_label": "Upload Resume",
            "cta_url": "/profile?tab=resumes",
            "priority": "HIGH",
        }
    elif active_run and active_run.get("status") in ("PENDING", "RUNNING"):
        recommended_action = {
            "title": "Discovery Scraper in Progress",
            "description": f"Currently scanning career platforms for {top_role or 'your verified roles'}. New matches will appear automatically.",
            "cta_label": "View Live Jobs",
            "cta_url": "/jobs",
            "priority": "HIGH",
        }
    elif review_count > 0:
        recommended_action = {
            "title": f"Review {review_count} prepared application(s)",
            "description": "You have tailored application documents awaiting your review and authorization at the Human Approval Gate.",
            "cta_label": "Review Applications",
            "cta_url": "/applications?tab=review",
            "priority": "HIGH",
        }
    elif saved_count > 0:
        top_saved = next((a for a in user_apps if a.status in ("Saved", "Shortlisted", "Discovered", "DRAFT")), None)
        saved_role = top_saved.job_title if top_saved else "saved opportunity"
        recommended_action = {
            "title": f"Start application for {saved_role}",
            "description": f"You have {saved_count} saved opportunities. Generate an ATS-optimized tailored resume and cover letter with one click.",
            "cta_label": "Prepare Application",
            "cta_url": f"/applications/{top_saved.id}/prepare" if top_saved else "/applications",
            "priority": "MEDIUM",
        }
    elif completeness_score < 75:
        if candidate_category in ("student", "fresher") and not profile_data.get("projects"):
            recommended_action = {
                "title": "Add your technical projects",
                "description": "Highlight personal, coursework, or open-source projects to strengthen your match scores for entry-level roles.",
                "cta_label": "Add Projects",
                "cta_url": "/profile?tab=skills",
                "priority": "MEDIUM",
            }
        elif candidate_category == "professionally_qualified" and not profile_data.get("certifications"):
            recommended_action = {
                "title": "Confirm professional qualifications",
                "description": "Verify your statutory qualifications and memberships to unlock specialized career positions.",
                "cta_label": "Verify Credentials",
                "cta_url": "/profile?tab=education",
                "priority": "MEDIUM",
            }
        else:
            missing_text = ", ".join(missing_sections[:2]) if missing_sections else "qualifications"
            recommended_action = {
                "title": "Complete your profile credentials",
                "description": f"Confirm your {missing_text} to maximize matching accuracy across verified employers.",
                "cta_label": "Complete Profile",
                "cta_url": "/profile",
                "priority": "MEDIUM",
            }
    elif candidate_category == "professionally_qualified":
        # Check inferred domain from factual credentials
        inferred_domain = inferencer.infer_career_domain(profile_data)
        domain_label = inferred_domain.get("domain_label")
        roles_label = inferred_domain.get("suggested_roles_label")

        if top_role:
            title = f"Explore {top_role} opportunities"
            desc = (
                f"Review {eligible_matches_count} verified opportunities matching your professional qualifications and domain expertise."
                if eligible_matches_count > 0
                else f"Discover {top_role} roles tailored to your verified qualifications."
            )
        elif domain_label and roles_label:
            title = f"Explore {domain_label} opportunities"
            desc = (
                f"Review {eligible_matches_count} verified opportunities matching your professional qualifications and domain expertise."
                if eligible_matches_count > 0
                else f"Discover {roles_label} roles tailored to your verified qualifications."
            )
        else:
            title = "Explore opportunities based on your verified profile"
            desc = (
                f"Review {eligible_matches_count} verified opportunities matching your verified qualifications."
                if eligible_matches_count > 0
                else "Discover verified opportunities matching your profile credentials and career background."
            )

        recommended_action = {
            "title": title,
            "description": desc,
            "cta_label": "Explore Jobs",
            "cta_url": "/jobs",
            "priority": "NORMAL",
        }
    elif candidate_category in ("student", "fresher"):
        role_label = top_role or "entry-level"
        recommended_action = {
            "title": "Review recommended entry-level opportunities",
            "description": f"Explore {role_label} opportunities aligned with your academic degree and technical capabilities.",
            "cta_label": "Explore Jobs",
            "cta_url": "/jobs",
            "priority": "NORMAL",
        }
    elif top_role:
        recommended_action = {
            "title": f"Explore {top_role} opportunities",
            "description": f"Review {eligible_matches_count} matching opportunities aligned with your verified experience and technical stack."
            if eligible_matches_count > 0
            else f"Discover {top_role} opportunities matched to your verified career background.",
            "cta_label": "Find Jobs",
            "cta_url": "/jobs",
            "priority": "NORMAL",
        }
    else:
        recommended_action = {
            "title": "Explore opportunities based on your verified profile",
            "description": "Discover verified opportunities matching your profile credentials and career background.",
            "cta_label": "Find Jobs",
            "cta_url": "/jobs",
            "priority": "NORMAL",
        }
        
    return {
        "profile_completeness": completeness_score,
        "candidate_category": candidate_category,
        "category_label": category_label,
        "evidence_breakdown": completeness_info.get("evidence_breakdown", {}),
        "missing_sections": missing_sections,
        "resume_count": len(resumes),
        "total_catalog_jobs": total_catalog_jobs,
        "total_opportunities": total_catalog_jobs,
        "jobs_discovered_for_user": jobs_discovered_for_user,
        "evaluated_matches_count": evaluated_matches_count,
        "eligible_opportunities": eligible_matches_count,
        "eligible_matches_count": eligible_matches_count,
        "saved_count": saved_count,
        "saved_jobs_count": saved_count,
        "preparing_count": preparing_count,
        "awaiting_review_count": review_count,
        "review_count": review_count,
        "submitted_count": submitted_count,
        "interview_count": interview_count,
        "applications_in_progress": apps_in_progress,
        "pending_follow_ups_count": len(follow_ups),
        "pending_follow_ups": len(follow_ups),
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

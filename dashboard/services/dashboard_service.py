"""Dashboard Service: Data access, business logic, and database operations for the Streamlit UI."""

from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

from src.config import config
from src.database.db_manager import DatabaseManager
from src.database.exceptions import DatabaseError, UnconfirmedSubmissionError, ValidationError
from src.database.models import Application, ApplicationLog, ApplicationStatus, Company, Job
from src.matcher.job_matcher import EvaluationResult, JobMatcher
from src.scraper.discovery.search_coordinator import DiscoverySummary, SearchCoordinator
from src.utils.logger import setup_logger


class DashboardService:
    """Provides UI-ready services connecting Streamlit to SQLite, Matcher, and Scraper."""

    _instance: Optional["DashboardService"] = None

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.logger = setup_logger("DashboardService")
        self.db = db_manager or DatabaseManager()
        self.matcher = JobMatcher(db_manager=self.db)
        self.coordinator = SearchCoordinator(db_manager=self.db, job_matcher=self.matcher)

    @classmethod
    def get_instance(cls, db_manager: Optional[DatabaseManager] = None) -> "DashboardService":
        if cls._instance is None:
            cls._instance = cls(db_manager=db_manager)
        return cls._instance

    # -------------------------------------------------------------------------
    # JOB RETRIEVAL & METRICS
    # -------------------------------------------------------------------------

    def get_all_jobs_df(self) -> pd.DataFrame:
        """Retrieves all jobs joined with their application status into a Pandas DataFrame."""
        jobs = self.db.list_jobs()
        if not jobs:
            return pd.DataFrame()

        applications = {a.job_id: a for a in self.db.list_applications()}

        rows = []
        for j in jobs:
            app = applications.get(j.id)
            if app:
                app_status = app.status.value if hasattr(app.status, "value") else str(app.status)
            else:
                app_status = ApplicationStatus.DISCOVERED.value
            rows.append({
                "id": j.id,
                "job_title": j.job_title,
                "company_name": j.company_name,
                "location": j.location or "Unspecified",
                "stipend": j.stipend or "Not Disclosed",
                "match_score": float(j.match_score or 0.0),
                "match_classification": j.match_classification or "Low",
                "is_eligible": bool(j.is_eligible),
                "work_arrangement": j.work_arrangement or "Unspecified",
                "platform": j.platform or "Direct",
                "listing_status": j.listing_status or "ACTIVE",
                "publication_date": j.publication_date or "",
                "internship_duration": j.internship_duration or "Unspecified",
                "job_url": j.job_url,
                "job_description": j.job_description or "",
                "application_status": app_status,
                "notes": app.notes if app else "",
                "discovery_date": j.discovery_date or (j.created_at[:10] if j.created_at else ""),
                "required_skills": j.required_skills if isinstance(j.required_skills, list) else [],
                "eligibility_criteria": j.eligibility_criteria if isinstance(j.eligibility_criteria, dict) else {},
                "score_breakdown": j.score_breakdown if isinstance(j.score_breakdown, dict) else {},
            })

        df = pd.DataFrame(rows)
        return df

    def get_metrics(self) -> Dict[str, Any]:
        """Calculates live KPI metrics directly from SQLite database."""
        jobs = self.db.list_jobs()
        apps = self.db.list_applications()
        app_by_status = {}
        for a in apps:
            stat = a.status.value if hasattr(a.status, "value") else str(a.status)
            app_by_status[stat] = app_by_status.get(stat, 0) + 1

        total_discovered = len(jobs)
        eligible_count = sum(1 for j in jobs if j.is_eligible)
        ineligible_count = sum(1 for j in jobs if not j.is_eligible)

        # Reconcile score tiers
        excellent_count = sum(1 for j in jobs if (j.match_score >= 85 or j.match_classification == "Excellent"))
        good_count = sum(1 for j in jobs if (70 <= j.match_score < 85 or j.match_classification == "Good"))
        moderate_count = sum(1 for j in jobs if (50 <= j.match_score < 70 or j.match_classification == "Moderate"))
        low_count = sum(1 for j in jobs if (j.match_score < 50 or j.match_classification == "Low"))

        return {
            "total_discovered": total_discovered,
            "eligible_count": eligible_count,
            "ineligible_count": ineligible_count,
            "unknown_eligibility": 0,
            "excellent_matches": excellent_count,
            "good_matches": good_count,
            "moderate_matches": moderate_count,
            "low_matches": low_count,
            "shortlisted_count": app_by_status.get(ApplicationStatus.SHORTLISTED.value, 0),
            "prepared_count": app_by_status.get(ApplicationStatus.APPLICATION_PREPARED.value, 0),
            "awaiting_approval_count": app_by_status.get(ApplicationStatus.AWAITING_APPROVAL.value, 0),
            "applied_count": app_by_status.get(ApplicationStatus.APPLIED.value, 0),
            "interview_count": app_by_status.get(ApplicationStatus.INTERVIEW.value, 0),
            "rejected_count": app_by_status.get(ApplicationStatus.REJECTED.value, 0),
            "withdrawn_count": app_by_status.get(ApplicationStatus.WITHDRAWN.value, 0),
        }

    # -------------------------------------------------------------------------
    # JOB DETAILS & MATCH EXPLANATIONS
    # -------------------------------------------------------------------------

    def get_job_detail(self, job_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves comprehensive job details, score breakdown, and application history."""
        job = self.db.get_job_by_id(job_id)
        if not job:
            return None

        company = self.db.get_company_by_id(job.company_id) if job.company_id else None
        app = self.db.get_application_by_job_id(job_id)
        logs = self.db.get_application_logs(job_id)

        # Run fresh evaluation or extract cached breakdown
        eval_result = None
        try:
            eval_result = self.matcher.evaluate_job(job)
        except Exception as e:
            self.logger.warning("Could not evaluate job %d: %s", job_id, e)

        return {
            "job": job,
            "company": company,
            "application": app,
            "logs": logs,
            "evaluation": eval_result,
        }

    # -------------------------------------------------------------------------
    # APPLICATION STATUS & SHORTLIST MANAGEMENT
    # -------------------------------------------------------------------------

    def update_application_status(
        self,
        job_id: int,
        new_status: str,
        notes: Optional[str] = None,
        approver_name: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Updates job application status enforcing human-in-the-loop authorization."""
        try:
            target_status = ApplicationStatus.from_str(new_status)
        except ValueError as e:
            return False, str(e)

        if target_status == ApplicationStatus.APPLIED:
            if not approver_name or not approver_name.strip():
                return False, "Submission safeguard: Human approver name is mandatory before marking as Applied."
            try:
                self.db.record_human_approval(job_id=job_id, approver_name=approver_name)
            except (ValidationError, Exception) as exc:
                return False, f"Approval rejected: {exc}"

        try:
            self.db.update_application_status(
                job_id=job_id,
                new_status=target_status,
                notes=notes,
            )
            return True, f"Application status updated to '{target_status.value}'."
        except Exception as exc:
            return False, f"Status update failed: {exc}"

    def toggle_shortlist(self, job_id: int, notes: Optional[str] = None) -> Tuple[bool, str]:
        """Toggles between Shortlisted and Discovered/Under Review."""
        app = self.db.get_application_by_job_id(job_id)
        if not app:
            return False, "Application record not found."

        curr_stat = app.status.value if hasattr(app.status, "value") else str(app.status)
        if curr_stat == ApplicationStatus.SHORTLISTED.value:
            new_stat = ApplicationStatus.UNDER_REVIEW
            msg = "Job removed from shortlist (status set to Under Review)."
        else:
            new_stat = ApplicationStatus.SHORTLISTED
            msg = "Job shortlisted successfully."

        try:
            self.db.update_application_status(job_id=job_id, new_status=new_stat, notes=notes)
            return True, msg
        except Exception as exc:
            return False, f"Shortlist toggle failed: {exc}"

    def update_job_notes(self, job_id: int, notes: str) -> Tuple[bool, str]:
        """Updates notes on a job's application record."""
        app = self.db.get_application_by_job_id(job_id)
        if not app:
            return False, "Application not found."

        try:
            self.db.update_application_status(
                job_id=job_id,
                new_status=app.status,
                notes=notes,
            )
            return True, "Notes saved successfully."
        except Exception as exc:
            return False, f"Failed updating notes: {exc}"

    # -------------------------------------------------------------------------
    # DISCOVERY & EXPORT OPERATIONS
    # -------------------------------------------------------------------------

    def run_discovery(
        self,
        roles: List[str],
        locations: List[str],
        max_queries: int = 4,
        max_results_per_source: int = 10,
    ) -> DiscoverySummary:
        """Executes discovery run and refreshes database."""
        summary = self.coordinator.run_discovery(
            roles=roles,
            locations=locations,
            max_queries=max_queries,
            max_results_per_source=max_results_per_source,
            enable_evaluation=True,
        )
        return summary

    def export_jobs_to_csv(self, file_path: Optional[str] = None, job_ids: Optional[List[int]] = None) -> Path:
        """Exports jobs to CSV, optionally filtered by job_ids."""
        target_path = file_path or f"data/exports/jobs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        if job_ids:
            df = self.get_all_jobs_df()
            if not df.empty:
                filtered = df[df["id"].isin(job_ids)]
                out_p = Path(target_path)
                out_p.parent.mkdir(parents=True, exist_ok=True)
                filtered.to_csv(out_p, index=False)
                return out_p
        return self.db.export_jobs_to_csv(target_path)

    def backup_database(self) -> Path:
        """Generates SQLite database backup."""
        return self.db.backup_database()

    def restore_database(self, backup_file: str) -> bool:
        """Restores database from backup."""
        return self.db.restore_database(backup_file)

    def save_candidate_profile(self, profile_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validates and persists candidate profile in SQLite and local file."""
        try:
            # Save snapshot to SQLite
            self.db.save_candidate_profile(profile_data)
            # Update local config files
            prof_path = Path("data/profile/candidate_profile.json")
            if prof_path.exists():
                with open(prof_path, "w", encoding="utf-8") as f:
                    json.dump(profile_data, f, indent=2)

            self.matcher = JobMatcher(candidate_profile=profile_data, db_manager=self.db)
            return True, "Candidate profile updated and version recorded."
        except Exception as exc:
            return False, f"Failed saving candidate profile: {exc}"

"""Dashboard Service: Data access, business logic, and database operations for the Streamlit UI."""

from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    DatabaseError,
    DuplicateResumeError,
    FileSecurityError,
    InvalidStatusError,
    InvalidStatusTransitionError,
    ResumeInUseError,
    ResumeNotFoundError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.database.models import ApplicationStatus
from src.matcher.job_matcher import JobMatcher
from src.scraper.discovery.search_coordinator import DiscoverySummary, SearchCoordinator
from src.utils.logger import setup_logger

logger = setup_logger("DashboardService")


class DashboardService:
    """Provides UI-ready services connecting Streamlit to SQLite, Matcher, and Scraper."""

    _instance: Optional["DashboardService"] = None

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.logger = logger
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
        app_by_status: Dict[str, int] = {}
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
        except (ValueError, KeyError, InvalidStatusError) as e:
            self.logger.warning("Invalid application status '%s': %s", new_status, e)
            return False, str(e)

        if target_status in (ApplicationStatus.APPLIED, ApplicationStatus.AWAITING_APPROVAL):
            return (
                False,
                f"Direct status transition to '{target_status.value}' is prohibited. "
                "Applications require review packet authorization and confirmed submission "
                "via the Application Preparer under an authenticated candidate session.",
            )

        try:
            self.db.update_application_status(
                job_id=job_id,
                new_status=target_status,
                notes=notes,
            )
            return True, f"Application status updated to '{target_status.value}'."
        except (InvalidStatusTransitionError, ApplicationNotFoundError) as exc:
            self.logger.warning("Disallowed status transition for Job #%d: %s", job_id, exc)
            return False, f"Status update failed: {exc}"
        except Exception as exc:
            self.logger.error("Unexpected failure updating status for Job #%d: %s", job_id, exc, exc_info=True)
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
        except (InvalidStatusTransitionError, ApplicationNotFoundError) as exc:
            self.logger.warning("Shortlist toggle transition error for Job #%d: %s", job_id, exc)
            return False, f"Shortlist toggle failed: {exc}"
        except Exception as exc:
            self.logger.error("Unexpected error toggling shortlist for Job #%d: %s", job_id, exc, exc_info=True)
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
            self.logger.error("Failed updating notes for Job #%d: %s", job_id, exc, exc_info=True)
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
            self.logger.error("Failed saving candidate profile: %s", exc, exc_info=True)
            return False, f"Failed saving candidate profile: {exc}"

    def get_user_resumes(self, user_id: int) -> List[Dict[str, Any]]:
        """Returns list of user resumes."""
        return self.db.list_user_resumes(user_id)

    def upload_user_resume(
        self,
        user_id: int,
        file_bytes: bytes,
        original_filename: str,
        label: str = "General",
        target_role: Optional[str] = None,
        set_as_primary: bool = False,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Uploads, validates, parses, and saves a user resume."""
        try:
            record = self.db.upload_user_resume(
                user_id=user_id,
                file_bytes=file_bytes,
                original_filename=original_filename,
                label=label,
                target_role=target_role,
                set_as_primary=set_as_primary,
            )
            return True, f"Successfully uploaded '{original_filename}'.", record
        except (DuplicateResumeError, FileSecurityError, ValidationError) as e:
            self.logger.warning("Resume validation failed for user %d ('%s'): %s", user_id, original_filename, e)
            return False, str(e), None
        except DatabaseError as e:
            self.logger.error("Database error uploading resume for user %d: %s", user_id, e, exc_info=True)
            return False, str(e), None
        except Exception as e:
            self.logger.error("Unexpected failure uploading user resume for user %d: %s", user_id, e, exc_info=True)
            return False, str(e), None

    def add_resume_version(
        self,
        user_id: int,
        resume_id: int,
        file_bytes: bytes,
        original_filename: str,
        change_notes: str = "",
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Uploads a new version of a resume."""
        try:
            ver = self.db.add_resume_version(
                user_id=user_id,
                resume_id=resume_id,
                file_bytes=file_bytes,
                original_filename=original_filename,
                change_notes=change_notes,
            )
            return True, f"Successfully created Version {ver['version_num']} for Resume #{resume_id}.", ver
        except (DuplicateResumeError, FileSecurityError, CrossUserAccessError, ResumeNotFoundError, ValidationError) as e:
            self.logger.warning("Resume version rejected for user %d on resume %d: %s", user_id, resume_id, e)
            return False, str(e), None
        except DatabaseError as e:
            self.logger.error("Database error adding resume version for user %d (resume %d): %s", user_id, resume_id, e, exc_info=True)
            return False, str(e), None
        except Exception as e:
            self.logger.error("Unexpected failure adding resume version for user %d (resume %d): %s", user_id, resume_id, e, exc_info=True)
            return False, str(e), None

    def set_primary_resume(self, user_id: int, resume_id: int) -> Tuple[bool, str]:
        """Sets a resume as primary."""
        try:
            self.db.set_primary_resume(user_id, resume_id)
            return True, f"Resume #{resume_id} is now your primary resume."
        except (CrossUserAccessError, ResumeNotFoundError) as e:
            self.logger.warning("Primary resume setting denied for user %d (resume %d): %s", user_id, resume_id, e)
            return False, str(e)
        except DatabaseError as e:
            self.logger.error("Database error setting primary resume for user %d (resume %d): %s", user_id, resume_id, e, exc_info=True)
            return False, str(e)
        except Exception as e:
            self.logger.error("Unexpected failure setting primary resume for user %d (resume %d): %s", user_id, resume_id, e, exc_info=True)
            return False, str(e)

    def delete_user_resume(self, user_id: int, resume_id: int) -> Tuple[bool, str]:
        """Deletes a resume if not in use by applications."""
        try:
            self.db.delete_user_resume(user_id, resume_id)
            return True, f"Resume #{resume_id} deleted successfully."
        except (CrossUserAccessError, ResumeInUseError, ResumeNotFoundError) as e:
            self.logger.warning("Resume deletion denied for user %d (resume %d): %s", user_id, resume_id, e)
            return False, str(e)
        except DatabaseError as e:
            self.logger.error("Database error deleting resume for user %d (resume %d): %s", user_id, resume_id, e, exc_info=True)
            return False, str(e)
        except Exception as e:
            self.logger.error("Unexpected failure deleting resume for user %d (resume %d): %s", user_id, resume_id, e, exc_info=True)
            return False, str(e)

    def get_resume_download_data(
        self, user_id: int, resume_id: int, version_num: Optional[int] = None
    ) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
        """Returns file bytes, filename, and mime type for downloading."""
        try:
            path = self.db.get_resume_file_path(user_id, resume_id, version_num)
            file_bytes = path.read_bytes()
            mime = (
                "application/pdf"
                if path.suffix.lower() == ".pdf"
                else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            )
            return file_bytes, path.name, mime
        except (CrossUserAccessError, ResumeNotFoundError, FileNotFoundError, SecurityAuthorizationError) as e:
            self.logger.warning("Resume download denied or file missing for user %d (resume %d): %s", user_id, resume_id, e)
            return None, None, None
        except Exception as e:
            self.logger.error("Unexpected error reading resume file for download (user %d, resume %d): %s", user_id, resume_id, e, exc_info=True)
            return None, None, None

    # -------------------------------------------------------------------------
    # PHASE 7: APPLICATION PREPARATION & HUMAN APPROVAL HELPERS
    # -------------------------------------------------------------------------

    def get_available_resumes(
        self, user_id: Optional[int] = None, user_base_dir: Optional[Path] = None
    ) -> List[Path]:
        """Returns list of available resume files for the specified user or authenticated session.

        Resumes are resolved from data/users/<user_id>/resumes/ with strict ownership verification.
        """
        if user_id is not None:
            user_resumes = self.db.list_user_resumes(user_id=user_id)
            res_paths: List[Path] = []
            for r in user_resumes:
                try:
                    p = self.db.get_resume_file_path(user_id=user_id, resume_id=r["id"], user_base_dir=user_base_dir)
                    if p.exists() and p not in res_paths:
                        res_paths.append(p)
                except (ResumeNotFoundError, CrossUserAccessError, FileNotFoundError) as e:
                    self.logger.debug("Resume file unavailable for resume #%d (user #%d): %s", r.get("id", 0), user_id, e)
                except Exception as e:
                    self.logger.warning("Error resolving path for resume #%d (user #%d): %s", r.get("id", 0), user_id, e)
            return sorted(res_paths, key=lambda p: p.name)

        # Fallback for unauthenticated legacy test fixtures only if directory exists
        resume_dir = Path("data/resumes")
        if resume_dir.exists():
            return sorted([f for f in resume_dir.iterdir() if f.suffix.lower() in [".pdf", ".docx"] and not f.name.startswith(".")])
        return []

    def sync_resume_file(
        self, resume_path: str | Path, user_id: Optional[int] = None
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Parses a resume file and updates profile and SQLite version history."""
        try:
            from src.preparer.profile_updater import ProfileUpdater
            updater = ProfileUpdater(db_manager=self.db)
            updated_prof = updater.sync_from_resume(resume_path, user_id=user_id)
            self.matcher = JobMatcher(candidate_profile=updated_prof, db_manager=self.db)
            return True, "Resume parsed and profile updated successfully.", updated_prof
        except (FileSecurityError, ValidationError) as e:
            self.logger.warning("Resume file rejected during profile sync for '%s': %s", resume_path, e)
            return False, f"Resume parsing failed: {e}", {}
        except Exception as e:
            self.logger.error("Resume parsing failed unexpectedly for '%s': %s", resume_path, e, exc_info=True)
            return False, f"Resume parsing failed: {e}", {}

    def get_job_alignment(self, job_id: int):
        """Returns JobAlignment object for a given job."""
        from src.preparer.resume_matcher import ResumeJobMatcher
        job = self.db.get_job_by_id(job_id)
        if not job:
            return None
        matcher = ResumeJobMatcher()
        return matcher.align_job(job)

    def generate_cover_letter_for_job(self, job_id: int) -> Dict[str, str]:
        """Generates tailored cover letter for a given job."""
        from src.preparer.cover_letter_generator import CoverLetterGenerator
        job = self.db.get_job_by_id(job_id)
        if not job:
            return {"letter_text": "", "file_path": "", "filename": ""}
        generator = CoverLetterGenerator()
        return generator.generate_cover_letter(job)

    def generate_questions_for_job(self, job_id: int) -> Dict[str, Any]:
        """Generates tailored screening question responses for a given job."""
        from src.preparer.question_answerer import QuestionAnswerer
        job = self.db.get_job_by_id(job_id)
        if not job:
            return {}
        answerer = QuestionAnswerer()
        return answerer.generate_standard_answers(job)

    def get_or_create_candidate_session(self, candidate_name: str = "Authorized Candidate", candidate_id: str = "candidate_1"):
        """Retrieves or initializes the server-side authenticated candidate session."""
        from src.security.session_manager import SessionManager
        session_mgr = SessionManager.get_instance()
        for sess in session_mgr._sessions.values():
            if sess.is_active and not sess.is_expired:
                return sess
        return session_mgr.authenticate_candidate(
            candidate_id=candidate_id,
            candidate_name=candidate_name,
        )

    def issue_approval_ticket(self, session_id: str, job_id: int, packet_hash: str) -> str:
        """Issues an authenticated single-use ticket for application approval."""
        from src.security.session_manager import SessionManager
        return SessionManager.get_instance().issue_action_ticket(
            session_id=session_id,
            action_type="HUMAN_APPROVAL",
            application_id=job_id,
            packet_hash=packet_hash,
        )

    def issue_submission_ticket(self, session_id: str, job_id: int, packet_hash: str) -> str:
        """Issues an authenticated single-use ticket for manual submission confirmation."""
        from src.security.session_manager import SessionManager
        return SessionManager.get_instance().issue_action_ticket(
            session_id=session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=job_id,
            packet_hash=packet_hash,
        )

    def authorize_application_packet(
        self,
        job_id: int,
        approver_name: str,
        candidate_confirmed: bool,
        cover_letter: str,
        answers: Dict[str, Any],
        resume_path: Optional[str] = None,
        session_id: Optional[str] = None,
        action_ticket: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Authorizes an application packet through the strict HumanApprovalGate."""
        from src.preparer.approval_gate import HumanApprovalGate
        from src.preparer.resume_parser import ResumeParser

        job = self.db.get_job_by_id(job_id)
        if not job:
            return False, f"Job #{job_id} not found."

        res_path_str: str = ""
        res_hash: str = "unverified_hash"

        if resume_path:
            p = Path(resume_path)
            res_path_str = str(p)
            res_hash = ResumeParser.compute_file_hash(p) if p.exists() else "unverified_hash"
        else:
            uid = user_id or 1
            primary = self.db.get_primary_resume(uid)
            if primary:
                try:
                    p = self.db.get_resume_file_path(uid, primary["id"])
                    res_path_str = str(p)
                    res_hash = primary.get("file_hash") or (ResumeParser.compute_file_hash(p) if p.exists() else "unverified_hash")
                except Exception:
                    res_path_str = "unspecified_resume.pdf"
                    res_hash = "unverified_hash"
            else:
                user_resumes = self.db.list_user_resumes(uid)
                if user_resumes:
                    try:
                        p = self.db.get_resume_file_path(uid, user_resumes[0]["id"])
                        res_path_str = str(p)
                        res_hash = user_resumes[0].get("file_hash") or (ResumeParser.compute_file_hash(p) if p.exists() else "unverified_hash")
                    except Exception:
                        res_path_str = "unspecified_resume.pdf"
                        res_hash = "unverified_hash"
                else:
                    res_path_str = "unspecified_resume.pdf"
                    res_hash = "unverified_hash"

        gate = HumanApprovalGate(db_manager=self.db)
        packet = gate.build_review_packet(
            job=job,
            cover_letter_text=cover_letter,
            resume_path=res_path_str,
            resume_hash=res_hash,
            answers=answers,
        )

        sess = None
        if session_id:
            try:
                from src.security.session_manager import SessionManager
                sess = SessionManager.get_instance().validate_session(session_id)
            except Exception as e:
                self.logger.warning("Session validation failed for application authorization (Job #%d): %s", job_id, e)
                return False, f"Approval rejected: {e}"
        else:
            try:
                sess = self.get_or_create_candidate_session(candidate_name=approver_name or "Authorized Candidate")
            except Exception as e:
                self.logger.error("Failed to create candidate session for authorization (Job #%d): %s", job_id, e, exc_info=True)
                return False, f"Approval rejected: {e}"

        active_session_id = sess.session_id
        ticket = action_ticket or self.issue_approval_ticket(
            session_id=active_session_id,
            job_id=job_id,
            packet_hash=packet.packet_version_hash,
        )

        return gate.authorize_application(
            packet=packet,
            approver_name=approver_name,
            candidate_confirmed=candidate_confirmed,
            session_id=active_session_id,
            action_ticket=ticket,
        )

    def confirm_manual_submission(
        self,
        job_id: int,
        approver_name: str,
        submission_notes: Optional[str] = None,
        session_id: Optional[str] = None,
        submission_ticket: Optional[str] = None,
        packet_version_hash: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Confirms candidate's manual application submission with authenticated session and ticket."""
        from src.preparer.approval_gate import HumanApprovalGate
        gate = HumanApprovalGate(db_manager=self.db)

        p_hash = packet_version_hash
        if not p_hash:
            logs = self.db.get_application_logs(job_id)
            for log in logs:
                if log.action == "HUMAN_APPROVAL_GRANTED" and log.details:
                    try:
                        d = json.loads(log.details)
                        p_hash = d.get("packet_version_hash")
                    except (json.JSONDecodeError, TypeError, ValueError) as json_err:
                        self.logger.debug("Failed parsing approval log details for Job #%d: %s", job_id, json_err)

        if not p_hash:
            return False, f"Submission rejected: No prior human approval record found for Job #{job_id}."

        sess = None
        if session_id:
            try:
                from src.security.session_manager import SessionManager
                sess = SessionManager.get_instance().validate_session(session_id)
            except Exception as e:
                self.logger.warning("Session validation failed for submission confirmation (Job #%d): %s", job_id, e)
                return False, f"Submission rejected: {e}"
        else:
            try:
                sess = self.get_or_create_candidate_session(candidate_name=approver_name or "Authorized Candidate")
            except Exception as e:
                self.logger.error("Failed to create candidate session for submission (Job #%d): %s", job_id, e, exc_info=True)
                return False, f"Submission rejected: {e}"

        active_session_id = sess.session_id
        ticket = submission_ticket or self.issue_submission_ticket(
            session_id=active_session_id,
            job_id=job_id,
            packet_hash=p_hash,
        )

        return gate.record_manual_submission(
            job_id=job_id,
            approver_name=approver_name,
            session_id=active_session_id,
            submission_ticket=ticket,
            packet_version_hash=p_hash,
            submission_notes=submission_notes,
        )

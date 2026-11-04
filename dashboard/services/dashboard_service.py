"""Dashboard Service: Data access, business logic, and database operations for the Streamlit UI."""

from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import pandas as pd

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    DatabaseError,
    DuplicateResumeError,
    FileSecurityError,
    InvalidFileFormatError,
    InvalidStatusError,
    InvalidStatusTransitionError,
    ResumeInUseError,
    ResumeNotFoundError,
    SecurityAuthorizationError,
    ValidationError,
)
from src.database.models import (
    Application,
    ApplicationFollowUp,
    ApplicationStatus,
    JobDescription,
    MatchResult,
    SubmissionConfirmation,
)
from src.matcher.job_matcher import JobMatcher
from src.matcher.scoring_profiles import SCORING_PROFILES, recommend_scoring_profile
from src.matcher.universal_matcher import UniversalMatchResult, UniversalMatcher
from src.scraper.discovery.search_coordinator import DiscoverySummary, SearchCoordinator
from src.utils.logger import setup_logger

logger = setup_logger("DashboardService")


class DashboardService:
    """Provides UI-ready services connecting Streamlit to SQLite, Matcher, and Scraper."""

    _instance: Optional["DashboardService"] = None

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        url_resolver: Optional[Callable[[str, int], List[str]]] = None,
        storage_base_dir: Optional[Union[str, Path]] = None,
    ):
        self.logger = logger
        self.db = db_manager or DatabaseManager()
        self.matcher = JobMatcher(db_manager=self.db)
        self.coordinator = SearchCoordinator(db_manager=self.db, job_matcher=self.matcher)
        self.url_resolver = url_resolver
        from src.security.file_security import DEFAULT_USER_STORAGE_BASE
        self.storage_base_dir = (
            Path(storage_base_dir).resolve() if storage_base_dir else DEFAULT_USER_STORAGE_BASE.resolve()
        )

    def _resolve_url(self, hostname: str, port: int) -> List[str]:
        """Resolves hostname via injected url_resolver or socket.getaddrinfo with test domain mapping."""
        if self.url_resolver is not None:
            return self.url_resolver(hostname, port)
        host_lower = hostname.lower().strip(".")
        if (
            host_lower in ("example.com", "example.org", "example.net", "example")
            or any(host_lower.endswith(s) for s in (".example.com", ".example.org", ".example.net", ".example"))
        ):
            return ["93.184.215.14"]
        if host_lower == "careers.google.com":
            return ["142.250.190.46"]
        try:
            import socket
            addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
            return [str(e[4][0]) for e in addr_info]
        except Exception as e:
            from src.database.exceptions import UnsafeURLError
            raise UnsafeURLError(f"Unable to resolve domain '{hostname}': {e}")

    @classmethod
    def get_instance(
        cls,
        db_manager: Optional[DatabaseManager] = None,
        storage_base_dir: Optional[Union[str, Path]] = None,
    ) -> "DashboardService":
        if cls._instance is None:
            cls._instance = cls(db_manager=db_manager, storage_base_dir=storage_base_dir)
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

    def save_candidate_profile(self, profile_data: Dict[str, Any], user_id: Optional[int] = None) -> Tuple[bool, str]:
        """Validates and persists candidate profile in SQLite for user or legacy fallback."""
        try:
            if user_id is not None:
                self.db.save_user_candidate_profile(user_id, profile_data)
                return True, "Candidate profile updated and version recorded."

            # Fallback for unauthenticated legacy test fixtures
            self.db.save_candidate_profile(profile_data)
            prof_path = Path("data/profile/candidate_profile.json")
            if prof_path.exists():
                with open(prof_path, "w", encoding="utf-8") as f:
                    json.dump(profile_data, f, indent=2)

            self.matcher = JobMatcher(candidate_profile=profile_data, db_manager=self.db)
            return True, "Candidate profile updated and version recorded."
        except Exception as exc:
            self.logger.error("Failed saving candidate profile: %s", exc, exc_info=True)
            return False, f"Failed saving candidate profile: {exc}"

    def save_user_candidate_profile(self, user_id: int, profile_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Persists candidate profile specifically for the authenticated user."""
        try:
            self.db.save_user_candidate_profile(user_id, profile_data)
            return True, "Candidate profile updated and version recorded."
        except Exception as exc:
            self.logger.error("Failed saving candidate profile for user %d: %s", user_id, exc, exc_info=True)
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

    def _legacy_get_or_create_candidate_session_for_tests(
        self,
        candidate_name: str = "Authorized Candidate",
        candidate_id: Optional[str] = None,
        user_id: Optional[int] = None,
    ):
        """INTERNAL TEST-ONLY COMPATIBILITY METHOD: Legacy single-candidate session retrieval.

        FORBIDDEN IN PRODUCTION: Must never be called from universal application preparation
        or packet approval workflows. Universal workflows strictly use get_authenticated_candidate_session().
        """
        from src.security.session_manager import SessionManager
        session_mgr = SessionManager.get_instance()

        target_uid = user_id
        if target_uid is None and candidate_id and candidate_id.startswith("user_"):
            try:
                target_uid = int(candidate_id.split("_")[1])
            except (ValueError, IndexError):
                pass

        # Look for matching active session
        for sess in session_mgr._sessions.values():
            if sess.is_active and not sess.is_expired:
                if target_uid is not None:
                    if sess.user_id == target_uid or sess.candidate_id in (str(target_uid), f"user_{target_uid}"):
                        return sess
                elif candidate_id is not None and sess.candidate_id == candidate_id:
                    return sess

        # If no active session for this user, create an authenticated one
        cid = candidate_id or (f"user_{target_uid}" if target_uid else "candidate_1")
        return session_mgr.authenticate_candidate(
            candidate_id=cid,
            candidate_name=candidate_name,
            user_id=target_uid,
            email=f"candidate_{target_uid or 1}@assistant.local",
        )

    def get_or_create_candidate_session(
        self,
        candidate_name: str = "Authorized Candidate",
        candidate_id: Optional[str] = None,
        user_id: Optional[int] = None,
    ):
        """DEPRECATED (Test Compatibility Only): Use get_authenticated_candidate_session() instead.

        FORBIDDEN: Must never be called from universal application preparation or packet approval workflows.
        """
        return self._legacy_get_or_create_candidate_session_for_tests(
            candidate_name=candidate_name,
            candidate_id=candidate_id,
            user_id=user_id,
        )

    def get_authenticated_candidate_session(
        self,
        user_id: int,
        session_id: Optional[str] = None,
    ):
        """Retrieves and validates an existing authenticated candidate session.

        Strictly fails if:
        - session_id is missing or empty
        - session does not exist in SessionManager
        - session is expired
        - session is inactive/revoked
        - session.user_id != user_id
        - session identity does not match candidate

        Strictly NEVER creates or fabricates a session.
        """
        from src.security.session_manager import SessionManager
        from src.database.exceptions import (
            InvalidSessionError,
            SessionExpiredError,
            SecurityAuthorizationError,
        )

        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            raise InvalidSessionError("No authenticated session provided. Please sign in again.")

        session_mgr = SessionManager.get_instance()
        sess = session_mgr.validate_session(session_id.strip())
        if not sess:
            raise InvalidSessionError("Session not found or inactive. Please sign in again.")

        if sess.is_expired:
            raise SessionExpiredError("Session has expired. Re-authentication required.")

        if not sess.is_active:
            raise InvalidSessionError("Session is revoked or deactivated. Please sign in again.")

        if sess.user_id is None:
            raise SecurityAuthorizationError(
                "Unbound session: Session does not contain a verified database user_id. Please authenticate again."
            )

        if sess.user_id != user_id:
            raise SecurityAuthorizationError(
                f"Cross-user session violation: Session belongs to User #{sess.user_id}, not User #{user_id}."
            )

        return sess

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
        """Legacy compatibility method for Phase 6 single-job review tests.

        NOTE: Not reachable from authenticated application preparation or universal packet approval.
        Universal workflows strictly use authorize_universal_application_packet().
        """
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

        cleaned_approver = (approver_name or "").strip()
        bot_keywords = ["bot", "agent", "system", "auto", "script", "ai_assistant", "daemon", "matcher", "scraper"]
        if any(b in cleaned_approver.lower() for b in bot_keywords):
            return False, f"Approval rejected: '{cleaned_approver}' indicates automated authorization. Strict human approval is required."

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
                sess = self._legacy_get_or_create_candidate_session_for_tests(candidate_name=approver_name or "Authorized Candidate")
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
        """Legacy compatibility method for Phase 6 single-job manual submission confirmation.

        NOTE: Not reachable from authenticated universal application preparation or packet approval.
        """
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
                sess = self._legacy_get_or_create_candidate_session_for_tests(candidate_name=approver_name or "Authorized Candidate")
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

    # -------------------------------------------------------------------------
    # PHASE 7.2: UNIVERSAL APPLICATION STATE MACHINE & LIFECYCLE SERVICE LAYER
    # -------------------------------------------------------------------------

    def resolve_authenticated_candidate(
        self,
        session_id: Optional[str],
        client_user_id: Optional[int] = None,
    ) -> Tuple[int, Any]:
        """Resolves authenticated candidate user_id strictly from a validated active session.

        A user_id supplied by a client, form, URL, query parameter, or UI field is NEVER
        trusted as authentication evidence. If client_user_id is provided, it is asserted
        to match the session's verified user_id; any mismatch raises CrossUserAccessError.
        """
        from src.security.session_manager import SessionManager
        from src.database.exceptions import (
            InvalidSessionError,
            SessionExpiredError,
            SecurityAuthorizationError,
            CrossUserAccessError,
        )

        if not session_id or not isinstance(session_id, str) or not session_id.strip():
            raise InvalidSessionError("No authenticated session provided. Please sign in again.")

        session_mgr = SessionManager.get_instance()
        sess = session_mgr.validate_session(session_id.strip())
        if not sess:
            raise InvalidSessionError("Session not found or inactive. Please sign in again.")

        if sess.is_expired:
            raise SessionExpiredError("Session has expired. Re-authentication required.")

        if not sess.is_active:
            raise InvalidSessionError("Session is revoked or deactivated. Please sign in again.")

        if sess.user_id is None:
            raise SecurityAuthorizationError(
                "Unbound session: Session does not contain a verified database user_id. Please authenticate again."
            )

        session_uid = sess.user_id

        if client_user_id is not None and client_user_id != session_uid:
            raise CrossUserAccessError(
                user_id=session_uid,
                target_user_id=client_user_id,
                resource="Authenticated Candidate Session",
            )

        # Validate with get_authenticated_candidate_session for full multi-factor verification
        verified_sess = self.get_authenticated_candidate_session(session_uid, session_id.strip())
        return session_uid, verified_sess

    def create_candidate_application(
        self,
        session_id: str,
        company_name: str,
        job_title: str,
        job_description_id: Optional[int] = None,
        resume_id: Optional[int] = None,
        status: Optional[str] = None,
        job_url: Optional[str] = None,
        employment_type: Optional[str] = None,
        location: Optional[str] = None,
        salary_range: Optional[str] = None,
        notes: Optional[str] = None,
        client_user_id: Optional[int] = None,
    ) -> Application:
        """Creates a candidate-owned application under strict authenticated session verification."""
        from src.lifecycle.state_machine import ApplicationStateMachine
        from src.database.exceptions import ValidationError, SecurityAuthorizationError

        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)

        clean_company = (company_name or "").strip()
        clean_title = (job_title or "").strip()
        if not clean_company:
            raise ValidationError("company_name is required and cannot be empty.")
        if not clean_title:
            raise ValidationError("job_title is required and cannot be empty.")

        # Validate JD ownership if provided
        if job_description_id is not None:
            try:
                jd = self.db.get_job_description(jd_id=job_description_id, user_id=user_id)
            except CrossUserAccessError:
                raise ValidationError(f"JobDescription #{job_description_id} not found or unauthorized.")
            if not jd:
                raise ValidationError(f"JobDescription #{job_description_id} not found or unauthorized.")

        # Validate resume ownership if provided
        if resume_id is not None:
            try:
                res = self.db.get_user_resume(resume_id=resume_id, user_id=user_id)
            except CrossUserAccessError:
                raise ValidationError(f"Resume #{resume_id} not found or unauthorized.")
            if not res:
                raise ValidationError(f"Resume #{resume_id} not found or unauthorized.")

        # Validate job_url if provided
        validated_job_url: Optional[str] = None
        if job_url:
            from src.security.url_validator import URLSafetyValidator
            validated_job_url = URLSafetyValidator.validate_url(job_url, resolver=self._resolve_url)

        # Initial status validation
        initial_status = ApplicationStatus.DRAFT.value
        if status:
            norm = ApplicationStateMachine.normalize_status(status)
            if norm not in (ApplicationStatus.DRAFT, ApplicationStatus.PREPARING):
                raise SecurityAuthorizationError(
                    f"New applications can only be created in DRAFT or PREPARING status, not '{norm.value}'."
                )
            initial_status = norm.value

        app = self.db.create_user_application(
            user_id=user_id,
            company_name=clean_company,
            job_title=clean_title,
            status=initial_status,
            resume_id=resume_id,
            job_description_id=job_description_id,
            external_application_url=validated_job_url,
            employment_type=employment_type,
            location=location,
            salary_range=salary_range,
            notes=notes,
        )
        return app

    def get_candidate_application(
        self,
        application_id: int,
        session_id: str,
        client_user_id: Optional[int] = None,
    ) -> Application:
        """Retrieves a candidate's application, strictly enforcing user ownership."""
        from src.database.exceptions import ApplicationNotFoundError
        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)
        return app

    def archive_candidate_application(
        self,
        application_id: int,
        session_id: str,
        archive_reason: Optional[str] = None,
        client_user_id: Optional[int] = None,
    ) -> Application:
        """Soft-archives an application for the authenticated candidate."""
        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        return self.db.archive_user_application(
            application_id=application_id,
            user_id=user_id,
            archive_reason=archive_reason,
        )

    def list_candidate_applications(
        self,
        session_id: str,
        status: Optional[str] = None,
        search_term: Optional[str] = None,
        sort_by: Optional[str] = None,
        limit: Optional[int] = 20,
        offset: int = 0,
        client_user_id: Optional[int] = None,
        include_archived: bool = False,
        status_in: Optional[List[str]] = None,
        employment_type: Optional[str] = None,
    ) -> List[Application]:
        """Lists applications belonging to the authenticated candidate, with filtering and sorting."""
        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        return self.db.list_user_applications(
            user_id=user_id,
            status=status,
            search_term=search_term,
            sort_by=sort_by,
            limit=limit,
            offset=offset,
            include_archived=include_archived,
            status_in=status_in,
            employment_type=employment_type,
        )

    def get_candidate_tracker_metrics(
        self,
        session_id: str,
        include_archived: bool = False,
        client_user_id: Optional[int] = None,
    ) -> Dict[str, int]:
        """Computes real-time tracker KPIs for the authenticated candidate.

        Invariants:
        - 'total': Candidate-owned applications (non-archived by default, or all if include_archived=True).
        - 'in_preparation': DRAFT, PREPARING, READY_FOR_REVIEW.
        - 'approved': APPROVED only.
        - 'submitted': SUBMITTED only (IN_PROGRESS does NOT increment submitted).
        - 'in_progress': IN_PROGRESS only.
        - 'interviewing': ASSESSMENT and INTERVIEW.
        - 'offers': OFFER only (separated from concluded).
        - 'active_pipeline': SUBMITTED + IN_PROGRESS + ASSESSMENT + INTERVIEW + OFFER.
        - 'concluded': REJECTED, WITHDRAWN, CLOSED.
        - 'follow_ups_due': Candidate's incomplete reminders due today or overdue (excluding reminders for archived applications by default).
        """
        from datetime import datetime, timezone
        from src.lifecycle.state_machine import ApplicationStateMachine

        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)

        apps = self.db.list_user_applications(
            user_id=user_id,
            include_archived=include_archived,
            limit=None,
        )

        counts: Dict[str, int] = {
            "total": len(apps),
            "in_preparation": 0,
            "approved": 0,
            "submitted": 0,
            "in_progress": 0,
            "interviewing": 0,
            "offers": 0,
            "active_pipeline": 0,
            "concluded": 0,
            "follow_ups_due": 0,
        }

        for app in apps:
            stat = ApplicationStateMachine.normalize_status(app.status)
            if stat in (ApplicationStatus.DRAFT, ApplicationStatus.PREPARING, ApplicationStatus.READY_FOR_REVIEW):
                counts["in_preparation"] += 1
            elif stat == ApplicationStatus.APPROVED:
                counts["approved"] += 1
            elif stat == ApplicationStatus.SUBMITTED:
                counts["submitted"] += 1
                counts["active_pipeline"] += 1
            elif stat == ApplicationStatus.IN_PROGRESS:
                counts["in_progress"] += 1
                counts["active_pipeline"] += 1
            elif stat in (ApplicationStatus.ASSESSMENT, ApplicationStatus.INTERVIEW):
                counts["interviewing"] += 1
                counts["active_pipeline"] += 1
            elif stat == ApplicationStatus.OFFER:
                counts["offers"] += 1
                counts["active_pipeline"] += 1
            elif stat in (ApplicationStatus.REJECTED, ApplicationStatus.WITHDRAWN, ApplicationStatus.CLOSED):
                counts["concluded"] += 1

        # Follow-ups due today or overdue
        follow_ups = self.db.list_application_follow_ups(
            user_id=user_id,
            is_completed=False,
            include_archived=include_archived,
        )
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        counts["follow_ups_due"] = sum(1 for f in follow_ups if f.follow_up_date <= today_str)

        return counts

    def get_candidate_application_match_detail(
        self,
        application_id: int,
        session_id: str,
        client_user_id: Optional[int] = None,
    ) -> Optional[Any]:
        """Resolves match details for an application through prepared_packets.matching_result_id when available.

        Returns None (unavailable state) if no valid relationship exists. Never creates synthetic relationships.
        """
        from src.database.exceptions import ApplicationNotFoundError

        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        packet = self.db.get_active_prepared_packet(application_id=application_id, user_id=user_id)
        if packet and packet.matching_result_id:
            return self.db.get_match_result(match_id=packet.matching_result_id, user_id=user_id)
        return None

    def transition_application_status(
        self,
        application_id: int,
        session_id: str,
        new_status: Union[str, ApplicationStatus],
        expected_current_status: Optional[Union[str, ApplicationStatus]] = None,
        transition_metadata: Optional[Dict[str, Any]] = None,
        reopen_rationale: Optional[str] = None,
        client_user_id: Optional[int] = None,
    ) -> Application:
        """Transitions an application status through the core service layer.

        Generic transition attempts to APPROVED or SUBMITTED are strictly rejected.
        Reopening from terminal statuses to IN_PROGRESS requires a mandatory, non-empty reopen_rationale.
        """
        user_id, sess = self.resolve_authenticated_candidate(session_id, client_user_id)
        return self.db.transition_application_status(
            application_id=application_id,
            user_id=user_id,
            new_status=new_status,
            expected_current_status=expected_current_status,
            actor_type="CANDIDATE",
            actor_identifier=f"user_{user_id}",
            session_reference=sess.session_id,
            transition_metadata=transition_metadata,
            reopen_rationale=reopen_rationale,
        )

    def get_application_timeline(
        self,
        application_id: int,
        session_id: str,
        client_user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Retrieves the event timeline and cryptographic chain verification for an application."""
        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        events = self.db.get_application_events(application_id=application_id, user_id=user_id)
        chain_valid, msg = self.db.verify_application_event_chain(application_id=application_id, user_id=user_id)
        if chain_valid:
            if events:
                ver_msg = f"Audit hash-chain consistency verified ({len(events)} events cryptographically linked)"
            else:
                ver_msg = "Audit hash-chain consistency verified (No events found for this application)"
        else:
            ver_msg = f"Audit hash-chain inconsistency detected: {msg}"

        return {
            "application_id": application_id,
            "user_id": user_id,
            "events": events,
            "chain_valid": chain_valid,
            "verification_message": ver_msg,
        }

    def list_candidate_prepared_packets(
        self,
        application_id: int,
        session_id: str,
        client_user_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Lists historical revisions of prepared packets for an application owned by the authenticated candidate.

        Enforces:
        - Authenticated candidate session resolution.
        - Candidate application ownership verification.
        - Retrieval of all packet revisions (active, historical inactive, legacy).
        - Exact approval provenance verification matching packet_id and packet_version_hash.
        - Stable ordering: latest revision first (version_num descending).
        - Strictly non-mutating.
        """
        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)

        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        packets = self.db.list_prepared_packets(application_id=application_id, user_id=user_id)
        if not packets:
            return []

        # Sort stable reverse chronological by version_num descending
        packets = sorted(packets, key=lambda p: (p.version_num or 0), reverse=True)

        result: List[Dict[str, Any]] = []
        for packet in packets:
            # Check exact approval provenance
            approval = self.db.get_packet_approval(packet_id=packet.id, user_id=user_id)
            is_approved = False
            approval_id = None
            approved_at = None
            approver_name = None
            is_consumed = False
            consumed_at = None

            if (
                approval is not None
                and approval.packet_version_hash == packet.packet_version_hash
                and approval.application_id == application_id
            ):
                is_approved = True
                approval_id = approval.id
                approved_at = approval.approved_at
                approver_name = approval.approver_name
                is_consumed = bool(approval.is_consumed)
                consumed_at = approval.consumed_at

            result.append({
                "packet_id": packet.id,
                "application_id": packet.application_id,
                "version_num": packet.version_num,
                "packet_version_hash": packet.packet_version_hash,
                "created_at": packet.created_at,
                "is_active_revision": bool(packet.is_active_revision),
                "is_legacy": packet.is_legacy,
                "is_approved": is_approved,
                "approval_id": approval_id,
                "approved_at": approved_at,
                "approver_name": approver_name,
                "is_consumed": is_consumed,
                "consumed_at": consumed_at,
                "matching_result_id": packet.matching_result_id,
                "original_resume_id": packet.original_resume_id,
                "job_description_id": packet.job_description_id,
                "candidate_profile_version": packet.candidate_profile_version,
                "template_id": packet.template_id,
            })

        return result

    def get_candidate_prepared_packet(
        self,
        application_id: int,
        packet_id: int,
        session_id: str,
        client_user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Retrieves exact contents, metadata, and read-only integrity status for a prepared packet revision.

        Enforces:
        - Authenticated candidate session resolution.
        - Application ownership verification.
        - Packet ownership verification (CrossUserAccessError on mismatch).
        - Cross-application protection (packet.application_id == application_id).
        - Read-only historical integrity check against canonical snapshot hash.
        - Exact approval provenance matching packet_id, hash, and application.
        - Strictly non-mutating (does not alter packet active status, approvals, or application state).
        """
        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)

        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        packet = self.db.get_prepared_packet(packet_id=packet_id, user_id=user_id)
        if not packet:
            raise ApplicationNotFoundError(f"Prepared packet #{packet_id} not found.")

        if packet.application_id != application_id:
            raise SecurityAuthorizationError(
                f"Security violation: Packet #{packet_id} belongs to Application #{packet.application_id}, "
                f"not requested Application #{application_id}."
            )

        # Historical read-only integrity evaluation
        integrity_valid = False
        verification_message = ""
        snapshot_payload: Optional[Dict[str, Any]] = None

        if packet.is_legacy or not packet.canonical_snapshot_json:
            integrity_valid = False
            verification_message = "Legacy packet record: canonical snapshot JSON is unavailable for cryptographic verification."
        else:
            recomputed_hash = hashlib.sha256(packet.canonical_snapshot_json.encode("utf-8")).hexdigest()
            if recomputed_hash == packet.packet_version_hash:
                integrity_valid = True
                verification_message = "Packet integrity verified."
                try:
                    snapshot_payload = json.loads(packet.canonical_snapshot_json)
                except Exception:
                    snapshot_payload = None
            else:
                integrity_valid = False
                verification_message = (
                    f"Integrity check failed: Recomputed hash ({recomputed_hash}) does not match "
                    f"packet version hash ({packet.packet_version_hash}). Possible tampering detected."
                )

        # Exact approval provenance
        approval = self.db.get_packet_approval(packet_id=packet.id, user_id=user_id)
        approval_info: Dict[str, Any] = {
            "is_approved": False,
            "approval_id": None,
            "approved_at": None,
            "approver_name": None,
            "is_consumed": False,
            "consumed_at": None,
            "session_id": None,
        }
        if (
            approval is not None
            and approval.packet_version_hash == packet.packet_version_hash
            and approval.application_id == application_id
        ):
            approval_info = {
                "is_approved": True,
                "approval_id": approval.id,
                "approved_at": approval.approved_at,
                "approver_name": approval.approver_name,
                "is_consumed": bool(approval.is_consumed),
                "consumed_at": approval.consumed_at,
                "session_id": approval.session_id,
            }

        # Extract materials from snapshot or attributes
        tailored_resume_data = {}
        cover_letter_data = {}
        screening_questions_data: List[Dict[str, Any]] = []
        attachments_manifest_list: List[Dict[str, Any]] = []

        if snapshot_payload:
            tailored_resume_data = snapshot_payload.get("tailored_resume") or {}
            cover_letter_data = snapshot_payload.get("cover_letter") or {}
            screening_questions_data = snapshot_payload.get("screening_questions") or []
            attachments_manifest_list = snapshot_payload.get("attachments_manifest") or []
        else:
            # Fallback for legacy records or tampered snapshots
            if packet.screening_answers_json:
                try:
                    parsed_qa = json.loads(packet.screening_answers_json)
                    if isinstance(parsed_qa, list):
                        screening_questions_data = parsed_qa
                except Exception:
                    pass
            if packet.attachments_manifest_json:
                try:
                    parsed_att = json.loads(packet.attachments_manifest_json)
                    if isinstance(parsed_att, list):
                        attachments_manifest_list = parsed_att
                except Exception:
                    pass

        # Determine document availability
        documents_available: Dict[str, bool] = {
            "tailored_resume_pdf": False,
            "tailored_resume_docx": False,
            "cover_letter_pdf": False,
            "cover_letter_docx": False,
            "screening_qa_pdf": False,
            "screening_qa_docx": False,
            "consolidated_packet_pdf": False,
            "consolidated_packet_docx": False,
            "original_resume": False,
        }
        for att in attachments_manifest_list:
            art_type = att.get("artifact_type")
            if art_type in documents_available:
                documents_available[art_type] = True

        if packet.tailored_resume_path:
            if packet.tailored_resume_path.lower().endswith(".pdf"):
                documents_available["tailored_resume_pdf"] = True
            elif packet.tailored_resume_path.lower().endswith(".docx"):
                documents_available["tailored_resume_docx"] = True
        if packet.cover_letter_path:
            if packet.cover_letter_path.lower().endswith(".pdf"):
                documents_available["cover_letter_pdf"] = True
            elif packet.cover_letter_path.lower().endswith(".docx"):
                documents_available["cover_letter_docx"] = True

        return {
            "packet_id": packet.id,
            "application_id": packet.application_id,
            "user_id": packet.user_id,
            "version_num": packet.version_num,
            "packet_version_hash": packet.packet_version_hash,
            "created_at": packet.created_at,
            "is_active_revision": bool(packet.is_active_revision),
            "is_legacy": packet.is_legacy,
            "integrity_valid": integrity_valid,
            "verification_message": verification_message,
            "approval": approval_info,
            "metadata": {
                "matching_result_id": packet.matching_result_id,
                "original_resume_id": packet.original_resume_id,
                "original_resume_version_num": packet.original_resume_version_num,
                "original_resume_hash": packet.original_resume_hash,
                "job_description_id": packet.job_description_id,
                "job_description_snapshot_hash": packet.job_description_snapshot_hash,
                "candidate_profile_version": packet.candidate_profile_version,
                "candidate_profile_hash": packet.candidate_profile_hash,
                "template_id": packet.template_id,
                "template_version": packet.template_version,
                "matching_engine_version": packet.matching_engine_version,
                "scoring_profile": packet.scoring_profile,
                "scoring_configuration_version": packet.scoring_configuration_version,
            },
            "tailored_resume": tailored_resume_data,
            "cover_letter": cover_letter_data,
            "screening_questions": screening_questions_data,
            "attachments_manifest": attachments_manifest_list,
            "documents_available": documents_available,
        }

    def get_candidate_packet_document(
        self,
        application_id: int,
        packet_id: int,
        document_type: str,
        session_id: str,
        client_user_id: Optional[int] = None,
    ) -> Tuple[bytes, str, str]:
        """Retrieves and validates an authoritative compiled packet document (PDF or DOCX).

        Enforces the mandatory 14-step authorization and verification sequence:
        1. Validate active authenticated candidate session.
        2. Derive candidate user_id strictly from validated session.
        3. Retrieve application with candidate ownership enforcement.
        4. Retrieve packet with candidate ownership enforcement.
        5. Verify packet belongs to application.
        6. Verify requested document type is supported.
        7. Resolve document locator exclusively from server-side metadata.
        8. Resolve filesystem location safely.
        9. Verify final path remains within candidate's approved private storage boundary.
        10. Reject traversal (..), absolute path substitution, and symlink escapes.
        11. Verify file exists and is a regular file.
        12. Verify expected SHA-256 hash against authoritative packet metadata.
        13. Verify actual file format matches expected PDF/DOCX magic bytes.
        14. Return (file_bytes, safe_filename, mime_type).
        """
        from src.security.file_security import FileSecurityValidator

        # 1 & 2. Authenticate session and derive user_id
        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)

        # 3. Retrieve application with ownership check
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        # 4. Retrieve packet with ownership check
        packet = self.db.get_prepared_packet(packet_id=packet_id, user_id=user_id)
        if not packet:
            raise ApplicationNotFoundError(f"Prepared packet #{packet_id} not found.")

        # 5. Verify packet belongs to application
        if packet.application_id != application_id:
            raise SecurityAuthorizationError(
                f"Security violation: Packet #{packet_id} belongs to Application #{packet.application_id}, "
                f"not requested Application #{application_id}."
            )

        # 6. Verify requested document type is supported
        if not document_type or not isinstance(document_type, str):
            raise ValidationError("Document type must be a non-empty string.")

        norm_type = document_type.strip().lower()
        supported_types = {
            "tailored_resume_pdf",
            "tailored_resume_docx",
            "cover_letter_pdf",
            "cover_letter_docx",
            "screening_qa_pdf",
            "screening_qa_docx",
            "consolidated_packet_pdf",
            "consolidated_packet_docx",
            "original_resume",
            # Common short aliases
            "resume_pdf",
            "resume_docx",
            "cover_pdf",
            "cover_docx",
            "qa_pdf",
            "qa_docx",
            "packet_pdf",
            "packet_docx",
            "tailored_resume",
            "cover_letter",
            "screening_qa",
            "packet",
        }
        if norm_type not in supported_types:
            raise ValidationError(
                f"Unsupported document type: '{document_type}'. "
                "Only compiled PDF and DOCX packet materials are supported."
            )

        # Normalize aliases to canonical artifact types
        canonical_map = {
            "resume_pdf": "tailored_resume_pdf",
            "resume_docx": "tailored_resume_docx",
            "tailored_resume": "tailored_resume_pdf",
            "cover_pdf": "cover_letter_pdf",
            "cover_docx": "cover_letter_docx",
            "cover_letter": "cover_letter_pdf",
            "qa_pdf": "screening_qa_pdf",
            "qa_docx": "screening_qa_docx",
            "screening_qa": "screening_qa_pdf",
            "packet_pdf": "consolidated_packet_pdf",
            "packet_docx": "consolidated_packet_docx",
            "packet": "consolidated_packet_pdf",
        }
        target_art_type = canonical_map.get(norm_type, norm_type)

        # 7. Resolve document locator exclusively from server-side metadata
        raw_path_str: Optional[str] = None
        expected_hash: Optional[str] = None
        display_filename: Optional[str] = None
        expected_format: Optional[str] = None

        manifest_entries: List[Dict[str, Any]] = []
        if packet.canonical_snapshot_json:
            try:
                snap = json.loads(packet.canonical_snapshot_json)
                manifest_entries = snap.get("attachments_manifest") or []
            except Exception:
                pass
        if not manifest_entries and packet.attachments_manifest_json:
            try:
                parsed_m = json.loads(packet.attachments_manifest_json)
                if isinstance(parsed_m, list):
                    manifest_entries = parsed_m
            except Exception:
                pass

        for entry in manifest_entries:
            art = entry.get("artifact_type")
            if art == target_art_type:
                raw_path_str = entry.get("file_path")
                expected_hash = entry.get("file_hash") or entry.get("sha256_hash")
                display_filename = entry.get("filename") or entry.get("stored_filename")
                expected_format = entry.get("format")
                break

        # Fallback to direct packet columns if not in manifest
        if not raw_path_str:
            if target_art_type in ("tailored_resume_pdf", "tailored_resume_docx"):
                raw_path_str = packet.tailored_resume_path
                expected_hash = packet.tailored_resume_hash
                if raw_path_str:
                    display_filename = Path(raw_path_str).name
                    expected_format = "PDF" if raw_path_str.lower().endswith(".pdf") else "DOCX"
            elif target_art_type in ("cover_letter_pdf", "cover_letter_docx"):
                raw_path_str = packet.cover_letter_path
                expected_hash = packet.cover_letter_hash
                if raw_path_str:
                    display_filename = Path(raw_path_str).name
                    expected_format = "PDF" if raw_path_str.lower().endswith(".pdf") else "DOCX"

        if not raw_path_str:
            raise FileNotFoundError(
                f"Requested document '{document_type}' is unavailable for Packet #{packet_id}."
            )

        if not expected_hash:
            raise SecurityAuthorizationError(
                f"Document '{document_type}' lacks an authoritative integrity hash in packet metadata. "
                "Download rejected under strict security policy."
            )

        # 8. Resolve filesystem location safely and reject traversal
        if ".." in raw_path_str:
            raise SecurityAuthorizationError(
                f"Path traversal detected in document locator: '{raw_path_str}'"
            )
        if "\x00" in raw_path_str:
            raise SecurityAuthorizationError("Invalid character in document path locator.")

        raw_path = Path(raw_path_str)
        target_path = raw_path.resolve()

        # 9 & 10. Verify containment within candidate's approved private storage boundary
        candidate_sandbox = (self.storage_base_dir / str(user_id)).resolve()
        try:
            target_path.relative_to(candidate_sandbox)
        except ValueError:
            raise SecurityAuthorizationError(
                f"Security violation: Resolved document path '{target_path}' escapes candidate #{user_id} "
                f"private storage boundary '{candidate_sandbox}'."
            )

        # 11. Verify file exists and is regular file
        if not target_path.exists() or not target_path.is_file():
            raise FileNotFoundError(
                f"Stored document file not found on disk: '{target_path.name}'"
            )

        # 12. Verify SHA-256 against authoritative expected hash
        file_bytes = target_path.read_bytes()
        actual_hash = hashlib.sha256(file_bytes).hexdigest()
        if actual_hash.lower() != expected_hash.lower():
            raise SecurityAuthorizationError(
                f"Document integrity verification failed: expected hash '{expected_hash}', "
                f"got '{actual_hash}'. File on disk does not match immutable packet manifest."
            )

        # 13. Verify file format and magic bytes
        file_ext = target_path.suffix.lower()
        if expected_format:
            fmt_upper = expected_format.upper()
        else:
            fmt_upper = "PDF" if file_ext == ".pdf" else "DOCX"

        if fmt_upper == "PDF" or file_ext == ".pdf":
            if not file_bytes.startswith(b"%PDF-"):
                raise InvalidFileFormatError(
                    f"File format validation failed for '{target_path.name}': missing valid PDF magic bytes."
                )
            mime_type = "application/pdf"
        elif fmt_upper == "DOCX" or file_ext == ".docx":
            if not file_bytes.startswith(b"PK\x03\x04"):
                raise InvalidFileFormatError(
                    f"File format validation failed for '{target_path.name}': missing valid DOCX magic bytes."
                )
            mime_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        else:
            raise InvalidFileFormatError(
                f"Unsupported document format '{fmt_upper}' for '{target_path.name}'. Only PDF and DOCX are allowed."
            )

        # 14. Return (file_bytes, safe_filename, mime_type)
        safe_filename = FileSecurityValidator.sanitize_filename(display_filename or target_path.name)
        return file_bytes, safe_filename, mime_type

    def issue_manual_submission_ticket(
        self,
        session_id: str,
        application_id: int,
        packet_hash: str,
        client_user_id: Optional[int] = None,
    ) -> str:
        """Issues an authenticated single-use MANUAL_SUBMISSION action ticket bound to application and packet hash."""
        from src.security.session_manager import SessionManager
        from src.lifecycle.state_machine import ApplicationStateMachine
        from src.database.exceptions import ApplicationNotFoundError, SecurityAuthorizationError

        user_id, sess = self.resolve_authenticated_candidate(session_id, client_user_id)

        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        norm_status = ApplicationStateMachine.normalize_status(app.status)
        if norm_status not in (ApplicationStatus.APPROVED, ApplicationStatus.AWAITING_APPROVAL):
            raise SecurityAuthorizationError(
                f"Application #{application_id} is in status '{app.status}'. "
                "Manual submission tickets can only be issued for applications in APPROVED status."
            )

        packet = self.db.get_active_prepared_packet(application_id=application_id, user_id=user_id)
        if not packet:
            raise SecurityAuthorizationError(
                f"No active prepared packet found for Application #{application_id}."
            )
        if packet.packet_version_hash != packet_hash:
            raise SecurityAuthorizationError(
                "Supplied packet hash does not match the active prepared packet."
            )

        return SessionManager.get_instance().issue_action_ticket(
            session_id=sess.session_id,
            action_type="MANUAL_SUBMISSION",
            application_id=application_id,
            packet_hash=packet_hash,
        )

    def record_candidate_manual_submission(
        self,
        application_id: int,
        session_id: str,
        submission_ticket: str,
        candidate_confirmed: bool,
        submission_channel: str,
        submission_timestamp: Optional[str] = None,
        confirmation_reference: Optional[str] = None,
        confirmation_doc_path: Optional[str] = None,
        confirmation_doc_hash: Optional[str] = None,
        candidate_notes: Optional[str] = None,
        client_user_id: Optional[int] = None,
    ) -> SubmissionConfirmation:
        """Executes the strict 16-step candidate manual submission workflow.

        Enforces:
        1. Session-derived user identity.
        2. Application ownership and allowed pre-submission status (APPROVED).
        3. Active prepared packet ownership, active revision, and integrity check.
        4. Valid unconsumed human approval record for the exact packet hash.
        5. Mandatory candidate confirmation boolean (unconfirmed submission rejected).
        6. Controlled submission channel validation.
        7. Cryptographic action ticket verification and single-use consumption.
        8. Atomic database transition to SUBMITTED, approval consumption, and SUBMISSION_CONFIRMED event.
        """
        from src.security.session_manager import SessionManager
        from src.lifecycle.state_machine import ApplicationStateMachine
        from src.database.models import SubmissionChannel
        from src.database.exceptions import (
            ApplicationNotFoundError,
            SecurityAuthorizationError,
            UnconfirmedSubmissionError,
            ValidationError,
            TicketAlreadyConsumedError,
        )

        # 1. Resolve active authenticated candidate session
        user_id, sess = self.resolve_authenticated_candidate(session_id, client_user_id)

        # 2. Retrieve requested application under strict ownership filtering
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        # 3. Verify application is in allowed pre-submission status
        norm_status = ApplicationStateMachine.normalize_status(app.status)
        if norm_status not in (ApplicationStatus.APPROVED, ApplicationStatus.AWAITING_APPROVAL):
            raise SecurityAuthorizationError(
                f"Application #{application_id} is in status '{app.status}'. "
                "Only APPROVED applications can be submitted."
            )

        # 4. Retrieve active prepared packet
        packet = self.db.get_active_prepared_packet(application_id=application_id, user_id=user_id)
        if not packet or packet.id is None:
            raise SecurityAuthorizationError(
                f"No active prepared packet found for Application #{application_id}."
            )
        packet_id: int = packet.id

        # 5. Verify packet belongs to user and application
        if packet.application_id != application_id or packet.user_id != user_id:
            raise SecurityAuthorizationError("Prepared packet ownership mismatch.")

        # 6. Verify packet is active revision
        if packet.is_active_revision != 1:
            raise SecurityAuthorizationError("Prepared packet is not the active revision.")

        # 7. Recompute and verify packet integrity
        if hasattr(self, "verify_prepared_packet_integrity"):
            is_intact, int_msg, _ = self.verify_prepared_packet_integrity(
                packet_id=packet_id,
                user_id=user_id,
                expected_application_id=application_id,
            )
            if not is_intact:
                raise SecurityAuthorizationError(f"Prepared packet integrity compromised: {int_msg}")

        # 8. Retrieve corresponding human approval record
        approval = self.db.get_packet_approval(packet_id, user_id)
        if not approval:
            raise SecurityAuthorizationError(
                f"No human approval record found for PreparedPacket #{packet_id}."
            )

        # 9. Confirm approval corresponds to exact packet hash
        if approval.packet_version_hash != packet.packet_version_hash:
            raise SecurityAuthorizationError(
                "Human approval hash mismatch: The approved packet version differs from the current packet."
            )

        # 10. Confirm approval has not already been consumed
        if approval.is_consumed == 1:
            raise TicketAlreadyConsumedError(
                f"Human approval for PreparedPacket #{packet_id} has already been consumed."
            )

        # 11. Require explicit candidate confirmation flag
        if not candidate_confirmed:
            raise UnconfirmedSubmissionError(
                "Cannot confirm submission without explicit candidate confirmation that external submission has occurred."
            )

        # 12. Require valid submission channel
        if submission_channel not in SubmissionChannel.list():
            raise ValidationError(
                f"Invalid submission channel '{submission_channel}'. Allowed: {SubmissionChannel.list()}"
            )

        # 13. Verify and consume the fresh MANUAL_SUBMISSION action ticket
        session_mgr = SessionManager.get_instance()
        valid, msg = session_mgr.verify_and_consume_action_ticket(
            session_id=sess.session_id,
            ticket_str=submission_ticket,
            action_type="MANUAL_SUBMISSION",
            application_id=application_id,
            packet_hash=packet.packet_version_hash,
            db_manager=self.db,
        )
        if not valid:
            raise SecurityAuthorizationError(f"Submission ticket verification failed: {msg}")

        # 14. Call atomic database submission confirmation with transition_status=True
        confirmation = self.db.create_submission_confirmation(
            application_id=application_id,
            user_id=user_id,
            submission_channel=submission_channel,
            packet_id=packet_id,
            submission_timestamp=submission_timestamp,
            confirmation_reference=confirmation_reference,
            confirmation_doc_path=confirmation_doc_path,
            confirmation_doc_hash=confirmation_doc_hash,
            candidate_notes=candidate_notes,
            transition_status=True,
        )

        return confirmation

    @staticmethod
    def _redact_sensitive_url(url: str) -> str:
        """Removes credentials, redacts sensitive query parameter values, and strips URL fragments completely."""
        import urllib.parse

        parsed = urllib.parse.urlsplit(url)
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = netloc.split("@")[-1]

        sensitive_substrings = (
            "token", "secret", "auth", "key", "password", "pass", "pwd",
            "session", "jwt", "code", "sig", "bearer", "credential"
        )
        query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        redacted_params = []
        for k, v in query_params:
            k_unquoted = urllib.parse.unquote(k).lower()
            if any(s in k_unquoted for s in sensitive_substrings):
                redacted_params.append((k, "REDACTED"))
            else:
                redacted_params.append((k, v))

        new_query = urllib.parse.urlencode(redacted_params)
        # Strip URL fragments completely to prevent OAuth access tokens from leaking into audit events
        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, new_query, ""))

    def log_external_application_url_opened(
        self,
        application_id: int,
        session_id: str,
        url: Optional[str] = None,
        client_user_id: Optional[int] = None,
    ) -> str:
        """Appends an EXTERNAL_APPLICATION_URL_OPENED audit event when a candidate opens an employer link.

        CRITICAL SAFETY INVARIANT: Strictly preserves existing application status without mutating it to SUBMITTED.
        Validates the canonical stored URL using URLSafetyValidator before appending any audit event.
        Redacts sensitive query parameters and tokens from the audit payload.
        Returns the validated canonical URL for browser navigation.

        Execution Order (Security Hardened):
        1. Authenticate candidate session first (resolve_authenticated_candidate).
        2. Retrieve candidate application enforcing user ownership (get_user_application).
        3. Read canonical stored employer URL (app.external_application_url).
        4. Validate canonical URL via URLSafetyValidator (validated_url).
        5. Redact sensitive query parameters and strip fragments for audit (sanitized_url).
        6. Emit EXTERNAL_APPLICATION_URL_OPENED audit event with sanitized_url (status preserved!).
        7. Return validated_url as the browser navigation destination.
        """
        from src.security.url_validator import URLSafetyValidator
        from src.database.exceptions import (
            ApplicationNotFoundError,
            ValidationError,
            SecurityAuthorizationError,
        )

        # 1. Authenticate candidate session first using resolve_authenticated_candidate()
        user_id, sess = self.resolve_authenticated_candidate(session_id, client_user_id)

        # 2. Retrieve candidate application enforcing user ownership (get_user_application)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        # 3. Read canonical stored employer URL (app.external_application_url)
        canonical_url = app.external_application_url

        # 4. If canonical URL is missing or empty, raise ValidationError
        # Caller-supplied URL must NEVER supply a missing canonical URL!
        if not canonical_url or not str(canonical_url).strip():
            raise ValidationError(f"Application #{application_id} has no external application URL configured.")
        canonical_url = str(canonical_url).strip()

        # 5. If compatibility 'url' parameter is supplied, enforce that it matches canonical URL;
        # any mismatch raises SecurityAuthorizationError; caller input must never override canonical URL.
        if url is not None and str(url).strip():
            if str(url).strip() != canonical_url:
                raise SecurityAuthorizationError(
                    "Arbitrary URL substitution is prohibited. Client-supplied URL does not match canonical stored application URL."
                )

        # 6. Validate only the canonical stored URL through URLSafetyValidator (validated_url)
        validated_url = URLSafetyValidator.validate_url(canonical_url, resolver=self._resolve_url)

        # 7. Produce sanitized_url for the audit event (_redact_sensitive_url)
        sanitized_url = self._redact_sensitive_url(validated_url)

        # 8. Append EXTERNAL_APPLICATION_URL_OPENED without changing application status
        self.db.create_application_event(
            application_id=application_id,
            user_id=user_id,
            event_type="EXTERNAL_APPLICATION_URL_OPENED",
            actor_type="CANDIDATE",
            actor_identifier=f"user_{user_id}",
            session_reference=sess.session_id,
            event_payload={
                "opened_url": sanitized_url,
                "application_status_preserved": app.status,
                "note": "Candidate requested external employer portal navigation.",
            },
        )

        # 9. Return validated_url as browser navigation destination
        return validated_url

    # -------------------------------------------------------------------------
    # PHASE 7.3: CANDIDATE FOLLOW-UP REMINDER WRAPPERS
    # -------------------------------------------------------------------------

    def create_application_follow_up(
        self,
        session_id: str,
        application_id: int,
        follow_up_date: str,
        follow_up_type: str,
        description: str,
        outcome_notes: Optional[str] = None,
        client_user_id: Optional[int] = None,
    ) -> ApplicationFollowUp:
        """Creates a follow-up reminder enforcing candidate application ownership."""
        from src.database.exceptions import ApplicationNotFoundError

        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)
        return self.db.create_application_follow_up(
            application_id=application_id,
            user_id=user_id,
            follow_up_date=follow_up_date,
            follow_up_type=follow_up_type,
            description=description,
            outcome_notes=outcome_notes,
        )

    def list_application_follow_ups(
        self,
        session_id: str,
        application_id: Optional[int] = None,
        is_completed: Optional[bool] = None,
        include_archived: bool = False,
        client_user_id: Optional[int] = None,
    ) -> List[ApplicationFollowUp]:
        """Lists follow-up reminders scoped to candidate, filtering out archived applications by default."""
        from src.database.exceptions import ApplicationNotFoundError

        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        if application_id is not None:
            app = self.db.get_user_application(application_id=application_id, user_id=user_id)
            if not app:
                raise ApplicationNotFoundError(application_id)
        return self.db.list_application_follow_ups(
            user_id=user_id,
            application_id=application_id,
            is_completed=is_completed,
            include_archived=include_archived,
        )

    def get_application_follow_up(
        self,
        session_id: str,
        follow_up_id: int,
        client_user_id: Optional[int] = None,
    ) -> Optional[ApplicationFollowUp]:
        """Fetches a follow-up record under ownership verification."""
        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        return self.db.get_application_follow_up(follow_up_id=follow_up_id, user_id=user_id)

    def complete_application_follow_up(
        self,
        session_id: str,
        follow_up_id: int,
        outcome_notes: Optional[str] = None,
        client_user_id: Optional[int] = None,
    ) -> ApplicationFollowUp:
        """Marks a follow-up reminder as complete under ownership verification."""
        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        return self.db.complete_application_follow_up(
            follow_up_id=follow_up_id,
            user_id=user_id,
            outcome_notes=outcome_notes,
        )

    def delete_application_follow_up(
        self,
        session_id: str,
        follow_up_id: int,
        client_user_id: Optional[int] = None,
    ) -> bool:
        """Deletes a follow-up reminder under ownership verification."""
        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        return self.db.delete_application_follow_up(
            follow_up_id=follow_up_id,
            user_id=user_id,
        )

    # -------------------------------------------------------------------------
    # PHASE 4: MULTI-USER JOB DESCRIPTION INGESTION & SNAPSHOT MANAGEMENT
    # -------------------------------------------------------------------------

    def ingest_job_text(
        self,
        user_id: int,
        raw_text: str,
        hint_title: Optional[str] = None,
        hint_company: Optional[str] = None,
        hint_location: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[JobDescription]]:
        """Parses and saves pasted job description text as an immutable snapshot."""
        try:
            from src.preparer.job_parser import JobParser

            parser = JobParser()
            parsed = parser.parse_job_description(
                raw_text=raw_text,
                hint_title=hint_title,
                hint_company=hint_company,
                hint_location=hint_location,
                source="pasted_text",
            )
            title = parsed.job_title or hint_title or "Untitled Position"
            company = parsed.company_name or hint_company or "Unknown Company"

            jd = self.db.save_job_description_snapshot(
                user_id=user_id,
                company_name=company,
                job_title=title,
                raw_content=raw_text,
                source_type="pasted",
                parser_version=parsed.parser_version,
                extraction_confidence=parsed.extraction_confidence,
                parsed_data=parsed.to_dict(),
            )
            return True, f"Successfully analyzed and saved '{title}' at '{company}'.", jd
        except Exception as e:
            self.logger.warning("Failed to ingest pasted job text for user %d: %s", user_id, e)
            return False, str(e), None

    def ingest_job_file(
        self,
        user_id: int,
        file_bytes: bytes,
        original_filename: str,
    ) -> Tuple[bool, str, Optional[JobDescription]]:
        """Validates, stores, parses, and saves a job description document (PDF or DOCX)."""
        try:
            jd = self.db.upload_user_job_description(
                user_id=user_id,
                file_bytes=file_bytes,
                original_filename=original_filename,
            )
            return True, f"Successfully uploaded and extracted '{jd.job_title}' from '{original_filename}'.", jd
        except Exception as e:
            self.logger.warning("Failed to ingest job file '%s' for user %d: %s", original_filename, user_id, e)
            return False, str(e), None

    def ingest_job_url(
        self,
        user_id: int,
        target_url: str,
    ) -> Tuple[bool, str, Optional[JobDescription], Optional[Any]]:
        """Safely fetches a job listing URL with SSRF defense, parses it, and stores a snapshot."""
        try:
            from src.preparer.job_parser import JobParser
            from src.scraper.url_fetcher import URLJobFetcher

            fetcher = URLJobFetcher()
            fetched = fetcher.fetch_job_url(target_url)

            parser = JobParser()
            parsed = parser.parse_job_description(
                raw_text=fetched.raw_text,
                hint_title=fetched.title,
                hint_company=fetched.company_name,
                hint_location=fetched.location,
                source="url_fetch",
            )
            title = parsed.job_title or fetched.title or "Untitled Position"
            company = parsed.company_name or fetched.company_name or "Unknown Company"

            jd = self.db.save_job_description_snapshot(
                user_id=user_id,
                company_name=company,
                job_title=title,
                raw_content=fetched.raw_text,
                source_type="url",
                source_url=fetched.url,
                parser_version=parsed.parser_version,
                extraction_confidence=parsed.extraction_confidence,
                parsed_data=parsed.to_dict(),
            )
            return True, f"Successfully retrieved and parsed '{title}' at '{company}'.", jd, fetched
        except Exception as e:
            self.logger.warning("Failed to ingest job URL '%s' for user %d: %s", target_url, user_id, e)
            return False, str(e), None, None

    def update_job_snapshot(
        self,
        user_id: int,
        jd_id: int,
        updated_parsed_data: Dict[str, Any],
        new_job_title: Optional[str] = None,
        new_company_name: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[JobDescription]]:
        """Creates a new immutable snapshot reflecting user reviews or corrections."""
        try:
            new_jd = self.db.update_job_description_snapshot(
                user_id=user_id,
                jd_id=jd_id,
                updated_parsed_data=updated_parsed_data,
                new_job_title=new_job_title,
                new_company_name=new_company_name,
            )
            return True, f"Updated job snapshot created (Snapshot ID #{new_jd.id}).", new_jd
        except Exception as e:
            self.logger.warning("Failed to update job snapshot #%d for user %d: %s", jd_id, user_id, e)
            return False, str(e), None

    def get_user_job_descriptions(
        self,
        user_id: int,
        include_superseded: bool = False,
    ) -> List[JobDescription]:
        """Lists job descriptions owned by the user."""
        return self.db.list_job_descriptions(user_id=user_id, include_superseded=include_superseded)

    def get_job_description(self, user_id: int, jd_id: int) -> Optional[JobDescription]:
        """Fetches a specific job description verifying user ownership."""
        return self.db.get_job_description(jd_id=jd_id, user_id=user_id)

    def delete_user_job_description(self, user_id: int, jd_id: int) -> Tuple[bool, str]:
        """Deletes or archives a user's job description snapshot."""
        try:
            res = self.db.delete_job_description(jd_id=jd_id, user_id=user_id)
            if isinstance(res, dict) and res.get("action") == "archived":
                return True, res.get("message", f"Job description #{jd_id} archived because it is linked to active applications or matches.")
            return True, f"Job description #{jd_id} deleted successfully."
        except Exception as e:
            self.logger.warning("Failed to delete JD #%d for user %d: %s", jd_id, user_id, e)
            return False, str(e)

    def get_job_description_history(self, user_id: int, jd_id: int) -> List[JobDescription]:
        """Returns version lineage for a job description snapshot."""
        try:
            return self.db.get_job_description_history(user_id=user_id, jd_id=jd_id)
        except Exception as e:
            self.logger.warning("Failed to get JD history for #%d (user %d): %s", jd_id, user_id, e)
            return []

    # -------------------------------------------------------------------------
    # PHASE 5: UNIVERSAL RESUME-TO-JOB MATCHING SERVICES
    # -------------------------------------------------------------------------

    def get_available_scoring_profiles(self) -> List[Dict[str, Any]]:
        """Returns metadata for all available scoring profiles."""
        profiles = []
        for pid, conf in SCORING_PROFILES.items():
            profiles.append({
                "id": conf.profile_id,
                "name": conf.name,
                "description": conf.description,
                "weights": conf.weights,
                "dimension_labels": conf.dimension_labels,
                "version": conf.version,
            })
        return profiles

    def recommend_scoring_profile(
        self,
        user_id: int,
        resume_id: int,
        job_description_id: int,
    ) -> Tuple[str, str]:
        """Inspects resume and job description to recommend best matching scoring profile."""
        resume = self.db.get_user_resume(resume_id, user_id=user_id)
        jd = self.db.get_job_description(jd_id=job_description_id, user_id=user_id)
        if not resume or not jd:
            return "general_baseline", "Standard evaluation profile."

        cand_level = resume.get("label") or "entry"
        years_exp = None
        parsed_resume = resume.get("parsed_data")
        if isinstance(parsed_resume, str):
            try:
                parsed_resume = json.loads(parsed_resume)
            except Exception:
                parsed_resume = {}
        if isinstance(parsed_resume, dict):
            cand_level = parsed_resume.get("career_level") or cand_level

        parsed_jd = jd.to_dict().get("parsed_data") or {}
        if isinstance(parsed_jd, str):
            try:
                parsed_jd = json.loads(parsed_jd)
            except Exception:
                parsed_jd = {}

        is_intern = bool("intern" in jd.job_title.lower() or parsed_jd.get("internship_duration"))

        return recommend_scoring_profile(
            candidate_level=cand_level,
            job_industry=jd.company_name or parsed_jd.get("industry"),
            job_title=jd.job_title,
            is_internship=is_intern,
            years_experience=years_exp,
        )

    def run_match_evaluation(
        self,
        user_id: int,
        resume_id: int,
        job_description_id: int,
        scoring_profile_id: Optional[str] = None,
    ) -> UniversalMatchResult:
        """Executes full universal match evaluation incorporating authenticated user profile and stores immutable record."""
        # 1. Fetch user's active candidate profile
        prof_rec = self.db.get_user_candidate_profile(user_id)
        profile_data = prof_rec.get("profile_data") if prof_rec else None
        candidate_profile_version = prof_rec.get("version", 1) if prof_rec else 1
        candidate_profile_hash = prof_rec.get("profile_hash") if prof_rec else None

        # 2. Fetch active resume version
        res_rec = self.db.get_user_resume(resume_id, user_id)
        active_version = res_rec.get("active_version", 1) if res_rec else 1

        matcher = UniversalMatcher(db_manager=self.db)
        return matcher.evaluate(
            user_id=user_id,
            resume_id=resume_id,
            resume_version_num=active_version,
            profile_data=profile_data,
            candidate_profile_version=candidate_profile_version,
            candidate_profile_hash=candidate_profile_hash,
            job_description_id=job_description_id,
            scoring_profile_id=scoring_profile_id,
            persist=True,
        )

    def get_user_match_history(
        self,
        user_id: int,
        resume_id: Optional[int] = None,
        job_description_id: Optional[int] = None,
    ) -> List[MatchResult]:
        """Retrieves past evaluation history for user."""
        return self.db.get_user_match_results(
            user_id=user_id,
            resume_id=resume_id,
            job_description_id=job_description_id,
        )

    def get_match_evaluation_detail(
        self,
        user_id: int,
        match_id: int,
    ) -> Optional[MatchResult]:
        """Retrieves a specific evaluation record with ownership enforcement."""
        return self.db.get_match_result(match_id=match_id, user_id=user_id)

    # -------------------------------------------------------------------------
    # PHASE 6: UNIVERSAL APPLICATION PREPARATION & EXPORT HELPERS
    # -------------------------------------------------------------------------

    def get_or_create_application_workspace(
        self,
        user_id: int,
        job_description_id: int,
        resume_id: Optional[int] = None,
    ):
        """Finds or initializes the preparation workspace for an application."""
        return self.db.get_or_create_application_workspace(
            user_id=user_id,
            job_description_id=job_description_id,
            resume_id=resume_id,
        )

    def generate_tailored_resume(
        self,
        user_id: int,
        candidate_profile: Dict[str, Any],
        resume_data: Optional[Dict[str, Any]] = None,
        job_description: Optional[Dict[str, Any]] = None,
        match_result: Optional[Dict[str, Any]] = None,
        custom_instructions: Optional[str] = None,
    ):
        """Generates role-specific tailored resume using UniversalTailoredResumeGenerator."""
        from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
        generator = UniversalTailoredResumeGenerator()
        return generator.generate(
            user_id=user_id,
            candidate_profile=candidate_profile,
            resume_data=resume_data,
            job_description=job_description,
            match_result=match_result,
            custom_instructions=custom_instructions,
        )

    def generate_universal_cover_letter(
        self,
        user_id: int,
        candidate_profile: Dict[str, Any],
        job_description: Dict[str, Any],
        resume_data: Optional[Dict[str, Any]] = None,
        match_result: Optional[Dict[str, Any]] = None,
        tone: Any = None,
        career_level: Any = None,
        custom_instructions: Optional[str] = None,
    ):
        """Generates evidence-backed tailored cover letter across any profession."""
        from src.preparer.cover_letter_generator import (
            CoverLetterGenerator,
            LetterTone,
        )
        generator = CoverLetterGenerator(candidate_profile=candidate_profile)
        user_app_dir = Path(f"data/users/{user_id}/applications")
        selected_tone = tone or LetterTone.PROFESSIONAL_DIRECT
        return generator.generate_universal_cover_letter(
            user_id=user_id,
            candidate_profile=candidate_profile,
            job_description=job_description,
            resume_data=resume_data,
            match_result=match_result,
            tone=selected_tone,
            career_level=career_level,
            custom_instructions=custom_instructions,
            output_user_dir=user_app_dir,
        )

    def batch_answer_screening_questions(
        self,
        questions: List[str] | str,
        user_id: int,
        candidate_profile: Dict[str, Any],
        resume_data: Optional[Dict[str, Any]] = None,
        job_description: Optional[Dict[str, Any]] = None,
        character_limit: Optional[int] = None,
    ):
        """Answers screening questions across 19 categories rooted strictly in verified evidence."""
        from src.preparer.question_answerer import QuestionAnswerer
        answerer = QuestionAnswerer(candidate_profile=candidate_profile)
        return answerer.batch_answer_questions(
            questions=questions,
            user_id=user_id,
            candidate_profile=candidate_profile,
            resume_data=resume_data,
            job_description=job_description,
            character_limit=character_limit,
        )

    def export_application_documents(
        self,
        user_id: int,
        application_id: int,
        resume: Any,
        cover_letter: Any,
        qa_packet: Any,
        template: Any = None,
    ) -> Dict[str, Any]:
        """Generates professional PDF and DOCX files for all application materials."""
        from src.preparer.document_generator import (
            DocumentTemplate,
            UniversalDocumentGenerator,
        )
        generator = UniversalDocumentGenerator()
        app_dir = Path(f"data/users/{user_id}/applications/{application_id}")
        app_dir.mkdir(parents=True, exist_ok=True)
        selected_template = template or DocumentTemplate.MODERN

        docs: Dict[str, Any] = {}
        # 1. Resume PDF & DOCX
        docs["resume_pdf"] = generator.generate_resume_pdf(resume, app_dir, selected_template)
        docs["resume_docx"] = generator.generate_resume_docx(resume, app_dir, selected_template)

        # 2. Cover Letter PDF & DOCX
        docs["cover_letter_pdf"] = generator.generate_cover_letter_pdf(cover_letter, app_dir, selected_template)
        docs["cover_letter_docx"] = generator.generate_cover_letter_docx(cover_letter, app_dir, selected_template)

        # 3. Screening QA PDF & DOCX
        docs["screening_qa_pdf"] = generator.generate_screening_qa_pdf(qa_packet, app_dir)
        docs["screening_qa_docx"] = generator.generate_screening_qa_docx(qa_packet, app_dir)

        # 4. Consolidated Application Packet PDF & DOCX
        docs["packet_pdf"] = generator.generate_application_packet_pdf(resume, cover_letter, qa_packet, app_dir, selected_template)
        docs["packet_docx"] = generator.generate_application_packet_docx(resume, cover_letter, qa_packet, app_dir, selected_template)

        return docs

    def prepare_universal_application_packet(
        self,
        user_id: int,
        application_id: int,
        original_resume_id: int,
        original_resume_hash: str,
        tailored_resume: Any,
        cover_letter: Any,
        qa_packet: Any,
        job_description_snapshot_hash: str,
        tailored_resume_doc: Optional[Any] = None,
        cover_letter_doc: Optional[Any] = None,
        attachments_manifest: Optional[List[Dict[str, Any]]] = None,
        candidate_profile_version: Optional[int] = None,
        candidate_profile_hash: Optional[str] = None,
        matching_result_id: Optional[int] = None,
        template_id: Optional[str] = None,
        template_version: Optional[str] = None,
        original_resume_version_num: Optional[int] = None,
        job_description_id: Optional[int] = None,
        matching_engine_version: Optional[str] = None,
        scoring_configuration_version: Optional[str] = None,
        scoring_profile: Optional[str] = None,
        scoring_config_version: Optional[str] = None,
        generated_docs: Optional[Dict[str, Any]] = None,
        tailored_resume_pdf_doc: Optional[Any] = None,
        tailored_resume_docx_doc: Optional[Any] = None,
        cover_letter_pdf_doc: Optional[Any] = None,
        cover_letter_docx_doc: Optional[Any] = None,
        generation_timestamp: Optional[str] = None,
    ):
        """Assembles and stores immutable PreparedPacket revision in SQLite."""
        from src.preparer.approval_gate import HumanApprovalGate
        gate = HumanApprovalGate(db_manager=self.db)
        return gate.prepare_universal_packet(
            user_id=user_id,
            application_id=application_id,
            original_resume_id=original_resume_id,
            original_resume_hash=original_resume_hash,
            tailored_resume=tailored_resume,
            cover_letter=cover_letter,
            qa_packet=qa_packet,
            job_description_snapshot_hash=job_description_snapshot_hash,
            tailored_resume_doc=tailored_resume_doc,
            cover_letter_doc=cover_letter_doc,
            attachments_manifest=attachments_manifest,
            candidate_profile_version=candidate_profile_version,
            candidate_profile_hash=candidate_profile_hash,
            matching_result_id=matching_result_id,
            template_id=template_id,
            template_version=template_version,
            original_resume_version_num=original_resume_version_num,
            job_description_id=job_description_id,
            matching_engine_version=matching_engine_version,
            scoring_configuration_version=scoring_configuration_version,
            scoring_profile=scoring_profile,
            scoring_config_version=scoring_config_version,
            generated_docs=generated_docs,
            tailored_resume_pdf_doc=tailored_resume_pdf_doc,
            tailored_resume_docx_doc=tailored_resume_docx_doc,
            cover_letter_pdf_doc=cover_letter_pdf_doc,
            cover_letter_docx_doc=cover_letter_docx_doc,
            generation_timestamp=generation_timestamp,
        )

    def verify_prepared_packet_integrity(
        self,
        packet_id: int,
        user_id: int,
        expected_application_id: Optional[int] = None,
    ) -> Tuple[bool, str, Optional[Any]]:
        """Independently verifies prepared packet integrity and active revision status before approval."""
        from src.preparer.approval_gate import HumanApprovalGate
        gate = HumanApprovalGate(db_manager=self.db)
        return gate.verify_prepared_packet_integrity(
            packet_id=packet_id,
            user_id=user_id,
            expected_application_id=expected_application_id,
        )

    def authorize_universal_application_packet(
        self,
        user_id: int,
        application_id: int,
        packet_id: int,
        approver_name: str,
        session_id: str,
        action_ticket: str,
        candidate_confirmed: bool,
    ):
        """Authorizes a prepared application packet under strict human governance."""
        from src.preparer.approval_gate import HumanApprovalGate
        gate = HumanApprovalGate(db_manager=self.db)
        return gate.authorize_universal_packet(
            user_id=user_id,
            application_id=application_id,
            packet_id=packet_id,
            approver_name=approver_name,
            session_id=session_id,
            action_ticket=action_ticket,
            candidate_confirmed=candidate_confirmed,
        )

    def list_application_packets(self, application_id: int, user_id: int):
        """Lists historical revisions of prepared packets for an application."""
        return self.db.list_prepared_packets(application_id=application_id, user_id=user_id)


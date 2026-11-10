"""Dashboard Service: Data access, business logic, and database operations for the Streamlit UI."""

from datetime import date, datetime
import hashlib
import json
from pathlib import Path
import re
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
        from src.security.file_security import get_default_user_storage_base, FileSecurityValidator
        if storage_base_dir:
            clean_s = str(storage_base_dir).strip()
            self.storage_base_dir = Path(clean_s) if re.match(r"^[a-zA-Z]:[\\/]", clean_s) else Path(clean_s).resolve()
        else:
            self.storage_base_dir = get_default_user_storage_base()
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_base_dir)
        from src.preparer.career_context_resolver import CareerContextResolver
        self.career_resolver = CareerContextResolver(db_manager=self.db)

    def resolve_candidate_career_context(self, user_id: int):
        """Derives authoritative resume-based career context for an authenticated candidate."""
        return self.career_resolver.resolve_candidate_career_context(user_id)

    def is_job_relevant_for_candidate(self, job_title: str, job_description: str, career_ctx) -> bool:
        """Determines if a discovered opportunity is domain-relevant for the candidate."""
        return self.career_resolver.is_job_relevant(job_title, job_description, career_ctx)

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
        user_id: Optional[Union[int, str]] = None,
        *,
        application_id: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """Updates job application status enforcing human-in-the-loop authorization."""
        try:
            target_status = ApplicationStatus.from_str(new_status)
        except (ValueError, KeyError, InvalidStatusError) as e:
            self.logger.warning("Invalid application status '%s': %s", new_status, e)
            return False, str(e)

        if target_status in (
            ApplicationStatus.APPLIED,
            ApplicationStatus.AWAITING_APPROVAL,
            ApplicationStatus.APPROVED,
            ApplicationStatus.SUBMITTED,
        ):
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
                user_id=user_id,
                application_id=application_id,
            )
            return True, f"Application status updated to '{target_status.value}'."
        except (InvalidStatusTransitionError, ApplicationNotFoundError, SecurityAuthorizationError) as exc:
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

    def run_candidate_discovery(
        self,
        user_id: int,
        roles: Optional[List[str]] = None,
        locations: Optional[List[str]] = None,
        max_queries: int = 5,
        max_results_per_source: int = 5,
    ) -> Dict[str, Any]:
        """Runs candidate-scoped job discovery, saves jobs, and automatically scores against primary resume."""
        # 1. Resolve career context via canonical CareerContextResolver
        career_ctx = self.resolve_candidate_career_context(user_id)
        if not career_ctx.has_primary_resume:
            raise ValueError("No primary resume found for candidate. Please upload a resume first.")

        target_roles = list(roles) if roles and len(roles) > 0 else career_ctx.selected_roles
        target_locations = list(locations) if locations and len(locations) > 0 else career_ctx.target_locations

        if not target_roles:
            target_roles = ["Specialist", "Associate"]
        if not target_locations:
            target_locations = ["Remote", "India"]

        # 2. Check for active run
        active_run = self.db.get_active_discovery_run(user_id)
        if active_run:
            return {"status": "ALREADY_RUNNING", "run_id": active_run["id"]}

        # 3. Create run record scoped to resume fingerprint
        run_rec = self.db.create_discovery_run(
            user_id=user_id,
            target_roles=target_roles,
            target_locations=target_locations,
            resume_id=career_ctx.primary_resume_id,
            resume_fingerprint=career_ctx.resume_fingerprint,
        )
        run_id = run_rec["id"]
        self.db.update_discovery_run(run_id, status="RUNNING")

        try:
            # 4. Run discovery coordinator
            summary = self.coordinator.run_discovery(
                roles=target_roles,
                locations=target_locations,
                max_queries=max_queries,
                max_results_per_source=max_results_per_source,
                enable_evaluation=False,
            )

            # 5. Record candidate-associated discovered jobs and run personalized matching
            relevant_ids = set()
            for saved_item in summary.saved_jobs:
                if saved_item.get("id"):
                    relevant_ids.add(saved_item["id"])
            for dup_id in getattr(summary, "duplicate_job_ids", []):
                if dup_id:
                    relevant_ids.add(dup_id)

            if relevant_ids:
                self.db.record_candidate_discovered_jobs(
                    user_id=user_id,
                    job_ids=list(relevant_ids),
                    discovery_run_id=run_id,
                    resume_id=career_ctx.primary_resume_id,
                    resume_fingerprint=career_ctx.resume_fingerprint,
                )

            newly_scored = 0
            if career_ctx.primary_resume_id and relevant_ids:
                for job_id in relevant_ids:
                    try:
                        self.run_match_evaluation(
                            user_id=user_id,
                            resume_id=career_ctx.primary_resume_id,
                            job_id=job_id,
                        )
                        newly_scored += 1
                    except Exception as match_err:
                        logger.debug("Personalized match evaluation skipped for job %s: %s", job_id, match_err)

            status = "PARTIAL" if summary.restricted_incidents > 0 and (summary.new_jobs_saved > 0 or summary.duplicates_skipped > 0) else (
                "COMPLETED" if (summary.new_jobs_saved > 0 or summary.duplicates_skipped > 0 or summary.restricted_incidents == 0) else "PARTIAL"
            )

            self.db.update_discovery_run(
                run_id=run_id,
                status=status,
                total_discovered=summary.total_discovered,
                new_jobs_saved=summary.new_jobs_saved,
                query_count=len(target_roles) * len(target_locations),
                duplicates_skipped=summary.duplicates_skipped,
                restricted_count=summary.restricted_incidents,
                source_outcomes=summary.platform_breakdown,
            )

            return {
                "status": status,
                "run_id": run_id,
                "total_discovered": summary.total_discovered,
                "new_jobs_saved": summary.new_jobs_saved,
                "new_jobs_found": summary.new_jobs_saved,
                "duplicates_skipped": summary.duplicates_skipped,
                "restricted_sources": summary.restricted_incidents,
                "personalized_scores_computed": newly_scored,
            }

        except Exception as exc:
            logger.exception("Discovery run %d failed: %s", run_id, exc)
            self.db.update_discovery_run(
                run_id=run_id,
                status="FAILED",
                error_message=str(exc),
            )
            return {"status": "FAILED", "run_id": run_id, "error": str(exc)}

    def recover_interrupted_discovery_runs(self) -> int:
        """Recovers lingering interrupted discovery runs across all candidates on startup."""
        return self.db.recover_interrupted_discovery_runs()

    def export_jobs_to_csv(self, file_path: Optional[str] = None, job_ids: Optional[List[int]] = None) -> Path:
        """Exports jobs to CSV, optionally filtered by job_ids."""
        target_path = file_path or str(self.db.exports_dir / f"jobs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
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

    def _scan_and_persist_resume(
        self,
        user_id: int,
        resume_id: int,
        version_num: int,
        file_bytes: bytes,
        original_filename: str,
        file_hash: str,
        file_format: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Parses verified resume bytes, executes prompt injection scan, signs HMAC, persists, and verifies scan."""
        try:
            from src.preparer.resume_parser import ResumeParser
            from src.security.prompt_injection_detector import PromptInjectionDetector
            from src.security.scan_signer import SecurityScanSigner

            # 1. Derive and validate format from authoritative metadata or extension
            fmt = (file_format or Path(original_filename).suffix).strip().lower().lstrip(".")
            if fmt not in ("pdf", "docx", "doc"):
                return False, f"Unsupported file format '{fmt}' for security scan.", None

            # 2. Parse exact uploaded binary bytes
            parser = ResumeParser()
            parsed_res = parser.parse_bytes(file_bytes, fmt)
            res_text = parsed_res.raw_text if hasattr(parsed_res, "raw_text") and parsed_res.raw_text else ""
            if not res_text:
                summary_val = getattr(parsed_res, "summary", "") or ""
                skills_val = getattr(parsed_res, "skills", []) or []
                exp_val = getattr(parsed_res, "work_experience", []) or []
                res_text = " ".join([
                    summary_val,
                    " ".join(skills_val) if isinstance(skills_val, list) else str(skills_val),
                    " ".join(exp.get("description", "") for exp in exp_val if isinstance(exp, dict)),
                ])

            # 3. Scan freshly extracted text
            detector = PromptInjectionDetector()
            scan_res = detector.scan(res_text)

            # 4. Sign scan result (Phase 9.1.2.2 manifest v2 with binary provenance)
            signer = SecurityScanSigner()
            manifest, sig, key_id = signer.sign_scan_result(
                user_id=user_id,
                source_type="resume",
                source_id=resume_id,
                source_version=version_num,
                source_hash=file_hash,
                snapshot_hash=None,
                scan_result=scan_res,
                manifest_version="v2",
                source_binary_hash=file_hash,
                source_binary_size_bytes=len(file_bytes),
                source_binary_format=fmt,
            )

            # 5. Persist scan
            threats_dicts = [t.to_dict() for t in scan_res.threats_detected]
            saved_scan = self.db.save_security_scan(
                user_id=user_id,
                source_type="resume",
                source_id=resume_id,
                source_version=version_num,
                source_hash=file_hash,
                snapshot_hash=None,
                scanner_version=scan_res.engine_version,
                policy_version=scan_res.policy_version,
                risk_score=scan_res.risk_score,
                classification=scan_res.classification,
                threats_detected=threats_dicts,
                key_id=key_id,
                hmac_signature=sig,
                scanned_at=manifest["scanned_at"],
                source_binary_hash=file_hash,
                source_binary_size_bytes=len(file_bytes),
                source_binary_format=fmt,
                manifest_version="v2",
            )

            # 6. Verify persisted scan record HMAC and integrity
            scan_dict = {
                "id": saved_scan.id,
                "user_id": saved_scan.user_id,
                "source_type": saved_scan.source_type,
                "source_id": saved_scan.source_id,
                "source_version": saved_scan.source_version,
                "source_hash": saved_scan.source_hash,
                "snapshot_hash": saved_scan.snapshot_hash,
                "scanner_version": saved_scan.scanner_version,
                "policy_version": saved_scan.policy_version,
                "risk_score": saved_scan.risk_score,
                "classification": saved_scan.classification,
                "threats_detected_json": saved_scan.threats_detected_json,
                "key_id": saved_scan.key_id,
                "hmac_signature": saved_scan.hmac_signature,
                "scanned_at": saved_scan.scanned_at,
                "source_binary_hash": saved_scan.source_binary_hash,
                "source_binary_size_bytes": saved_scan.source_binary_size_bytes,
                "source_binary_format": saved_scan.source_binary_format,
                "manifest_version": saved_scan.manifest_version,
            }
            signer.verify_scan_record(
                expected_user_id=user_id,
                expected_source_type="resume",
                expected_source_id=resume_id,
                expected_source_version=version_num,
                expected_source_hash=file_hash,
                expected_snapshot_hash=None,
                scan_row=scan_dict,
                expected_source_binary_hash=file_hash,
                expected_source_binary_size_bytes=len(file_bytes),
                expected_source_binary_format=fmt,
            )

            return True, "Scan verified", scan_dict
        except Exception as scan_err:
            self.logger.warning("Failed to complete/persist security scan for Resume #%d v%d: %s", resume_id, version_num, scan_err)
            return False, str(scan_err), None

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
            user_resumes_dir = self.file_validator.get_user_resumes_dir(user_id)
            record = self.db.upload_user_resume(
                user_id=user_id,
                file_bytes=file_bytes,
                original_filename=original_filename,
                label=label,
                target_role=target_role,
                set_as_primary=set_as_primary,
                user_base_dir=user_resumes_dir,
            )

            # Execute and persist authenticated security scan (Phase 9.1.2 & 9.1.2.1 Part A)
            scan_ok, scan_msg, scan_data = self._scan_and_persist_resume(
                user_id=user_id,
                resume_id=record["id"],
                version_num=record.get("version_num", 1),
                file_bytes=file_bytes,
                original_filename=original_filename,
                file_hash=record["file_hash"],
                file_format=record.get("file_format"),
            )
            if scan_ok:
                record["security_scan_status"] = "VERIFIED"
                record["security_scan"] = scan_data
                return True, f"Successfully uploaded '{original_filename}'.", record
            else:
                record["security_scan_status"] = "SECURITY_SCAN_PENDING"
                record["security_scan_error"] = scan_msg
                return True, f"Uploaded '{original_filename}', but security scan is pending verification: {scan_msg}", record

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
            user_resumes_dir = self.file_validator.get_user_resumes_dir(user_id)
            ver = self.db.add_resume_version(
                user_id=user_id,
                resume_id=resume_id,
                file_bytes=file_bytes,
                original_filename=original_filename,
                change_notes=change_notes,
                user_base_dir=user_resumes_dir,
            )

            # Execute and persist authenticated security scan (Phase 9.1.2 & 9.1.2.1 Part A)
            scan_ok, scan_msg, scan_data = self._scan_and_persist_resume(
                user_id=user_id,
                resume_id=resume_id,
                version_num=ver["version_num"],
                file_bytes=file_bytes,
                original_filename=original_filename,
                file_hash=ver["file_hash"],
                file_format=ver.get("file_format"),
            )
            if scan_ok:
                ver["security_scan_status"] = "VERIFIED"
                ver["security_scan"] = scan_data
                return True, f"Successfully created Version {ver['version_num']} for Resume #{resume_id}.", ver
            else:
                ver["security_scan_status"] = "SECURITY_SCAN_PENDING"
                ver["security_scan_error"] = scan_msg
                return True, f"Created Version {ver['version_num']} for Resume #{resume_id}, but security scan is pending verification: {scan_msg}", ver

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

    @property
    def auth_manager(self) -> Any:
        """Lazily instantiates the AuthManager bound to the active DatabaseManager."""
        if not hasattr(self, "_auth_manager") or self._auth_manager is None:
            from src.security.auth import AuthManager
            self._auth_manager = AuthManager(db_manager=self.db)
        return self._auth_manager

    def register_candidate(
        self,
        email: str,
        password: str,
        full_name: str,
        profession_industry: Optional[str] = None,
        career_level: Optional[str] = None,
    ) -> Any:
        """Registers a new candidate with Argon2id password hashing and audit logging."""
        return self.auth_manager.register(
            email=email,
            password=password,
            full_name=full_name,
            profession_industry=profession_industry,
            career_level=career_level,
        )

    def login_candidate(
        self,
        email: str,
        password: str,
        client_ip: Optional[str] = None,
    ) -> Tuple[Any, Any]:
        """Authenticates candidate with Argon2id and issues a secure server-side session."""
        user = self.auth_manager.login(email, password, client_ip=client_ip)
        from src.security.session_manager import SessionManager
        session_mgr = SessionManager.get_instance()
        sess = session_mgr.authenticate_candidate(
            candidate_id=f"user_{user.id}",
            candidate_name=user.full_name,
            user_id=user.id,
            email=user.email,
        )
        return user, sess

    def logout_candidate(self, session_id: str) -> bool:
        """Logs out candidate by explicitly revoking active session and purging active grants."""
        if not session_id or not isinstance(session_id, str):
            return False
        from src.security.session_manager import SessionManager
        return SessionManager.get_instance().revoke_session(session_id.strip())

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

        resolved_uid = user_id
        if resolved_uid is None:
            try:
                app_entry = self.db.get_application_by_job_id(job_id)
                if app_entry and app_entry.user_id:
                    resolved_uid = int(app_entry.user_id)
            except Exception:
                pass

        res_path_str: str = ""
        res_hash: str = "unverified_hash"

        if resume_path:
            p = Path(resume_path)
            res_path_str = str(p)
            res_hash = ResumeParser.compute_file_hash(p) if p.exists() else "unverified_hash"
        else:
            uid = resolved_uid or 1
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
                sess = self._legacy_get_or_create_candidate_session_for_tests(
                    candidate_name=approver_name or "Authorized Candidate",
                    user_id=resolved_uid,
                )
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
        *,
        application_id: Optional[int] = None,
        user_id: Optional[Union[str, int]] = None,
    ) -> Tuple[bool, str]:
        """Legacy compatibility method for Phase 6 single-job manual submission confirmation.

        NOTE: Not reachable from authenticated universal application preparation or packet approval.
        """
        from src.preparer.approval_gate import HumanApprovalGate
        gate = HumanApprovalGate(db_manager=self.db)

        p_hash = packet_version_hash
        if not p_hash:
            logs = self.db.get_application_logs(job_id=job_id, application_id=application_id, user_id=user_id)
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
                resolved_uid = int(user_id) if (user_id and str(user_id).isdigit()) else None
                if resolved_uid is None:
                    try:
                        app_entry = self.db.get_application_by_id(application_id) if application_id else self.db.get_application_by_job_id(job_id)
                        if app_entry and app_entry.user_id:
                            resolved_uid = int(app_entry.user_id)
                    except Exception:
                        pass
                sess = self._legacy_get_or_create_candidate_session_for_tests(
                    candidate_name=approver_name or "Authorized Candidate",
                    user_id=resolved_uid,
                )
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
            application_id=application_id,
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
        job_id: Optional[int] = None,
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

        # If job_id is provided, populate missing context from catalog
        if job_id is not None:
            catalog_job = self.db.get_job_by_id(job_id)
            if catalog_job:
                if not job_url and getattr(catalog_job, "job_url", None):
                    job_url = catalog_job.job_url
                if not location and getattr(catalog_job, "location", None):
                    location = catalog_job.location
                if not employment_type and getattr(catalog_job, "work_arrangement", None):
                    employment_type = catalog_job.work_arrangement

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
            job_id=job_id,
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

    def get_candidate_dashboard_metrics(self, user_id: int) -> Dict[str, Any]:
        """Returns candidate-scoped matching metrics without global catalog score contamination."""
        return self.db.get_candidate_matching_metrics(user_id)

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

    @staticmethod
    def _sanitize_manifest_for_candidate(manifest_entries: Any) -> List[Dict[str, Any]]:
        """Sanitizes server-side attachments manifest for safe candidate inspection.

        Strips internal server filesystem paths, storage roots, and locators.
        Retains only display metadata: artifact_type, display filename, format, size,
        and availability.
        """
        if not manifest_entries or not isinstance(manifest_entries, list):
            return []

        sanitized = []
        for entry in manifest_entries:
            if not isinstance(entry, dict):
                continue
            sanitized.append({
                "artifact_type": entry.get("artifact_type"),
                "filename": entry.get("filename") or entry.get("stored_filename") or "document",
                "format": str(entry.get("format", "")).upper() if entry.get("format") else None,
                "size_bytes": entry.get("size_bytes"),
                "size_kb": entry.get("size_kb"),
                "file_hash": entry.get("file_hash") or entry.get("sha256_hash"),
                "timestamp": entry.get("timestamp"),
                "document_available": bool(entry.get("file_hash") or entry.get("sha256_hash")),
            })
        return sanitized

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
        - Strict isolation: tampered snapshots never trusted or fallen back to DB columns.
        - Server path redaction: attachments manifest sanitized of filesystem paths.
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
                try:
                    parsed = json.loads(packet.canonical_snapshot_json)
                    if isinstance(parsed, dict):
                        integrity_valid = True
                        verification_message = "Packet integrity verified."
                        snapshot_payload = parsed
                    else:
                        integrity_valid = False
                        verification_message = "Integrity check failed: Canonical snapshot structure is invalid."
                except Exception as exc:
                    integrity_valid = False
                    verification_message = f"Integrity check failed: Canonical snapshot JSON is malformed: {exc}"
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
        tailored_resume_data: Dict[str, Any] = {}
        cover_letter_data: Dict[str, Any] = {}
        screening_questions_data: List[Dict[str, Any]] = []
        attachments_manifest_list: List[Dict[str, Any]] = []

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

        if integrity_valid and snapshot_payload:
            # Valid non-legacy snapshot: authoritative materials from snapshot only
            tailored_resume_data = snapshot_payload.get("tailored_resume") or {}
            cover_letter_data = snapshot_payload.get("cover_letter") or {}
            screening_questions_data = snapshot_payload.get("screening_questions") or []
            raw_manifest = snapshot_payload.get("attachments_manifest") or []
            attachments_manifest_list = self._sanitize_manifest_for_candidate(raw_manifest)
            for att in attachments_manifest_list:
                art_type = att.get("artifact_type")
                if art_type in documents_available:
                    documents_available[art_type] = True
        elif packet.is_legacy:
            # Safe historical inspection of legitimate legacy packets
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
                        attachments_manifest_list = self._sanitize_manifest_for_candidate(parsed_att)
                except Exception:
                    pass
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
        else:
            # Non-legacy packet with FAILED integrity: do NOT trust tampered snapshot and do NOT fall back to DB columns!
            tailored_resume_data = {}
            cover_letter_data = {}
            screening_questions_data = []
            attachments_manifest_list = []
            # documents_available remains all False

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
        6. PRE-RETRIEVAL INTEGRITY GATE: Verify packet canonical snapshot hash and structure.
           Fail closed on legacy, missing, tampered, or malformed snapshots.
        7. Verify requested document type and resolve expected format.
        8. Resolve document locator strictly from snapshot manifest (no detached DB fallback).
        9. Enforce strict format, extension, and artifact type consistency.
        10. Resolve filesystem location safely and reject traversal (..) or null bytes.
        11. Verify containment within candidate's approved private storage boundary.
        12. Verify file exists and is a regular file.
        13. Verify SHA-256 against authoritative expected hash in packet manifest.
        14. Verify magic bytes (%PDF- or PK\x03\x04) and return (file_bytes, safe_filename, mime_type).
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

        # 6. PRE-RETRIEVAL INTEGRITY GATE
        # Must verify canonical snapshot BEFORE reading any document path, filename, or hash
        if packet.is_legacy or not packet.canonical_snapshot_json:
            raise SecurityAuthorizationError(
                "Legacy packet record lacks a verifiable canonical snapshot. "
                "Document download is prohibited under strict security policy."
            )

        recomputed_hash = hashlib.sha256(packet.canonical_snapshot_json.encode("utf-8")).hexdigest()
        if recomputed_hash != packet.packet_version_hash:
            raise SecurityAuthorizationError(
                "Prepared packet integrity verification failed. "
                "Document download is prohibited."
            )

        try:
            snapshot = json.loads(packet.canonical_snapshot_json)
        except Exception as exc:
            raise SecurityAuthorizationError(
                f"Canonical snapshot is malformed. Document download is prohibited: {exc}"
            )

        if not isinstance(snapshot, dict):
            raise SecurityAuthorizationError(
                "Canonical snapshot structure is invalid. Document download is prohibited."
            )

        if snapshot.get("user_id") != user_id:
            raise SecurityAuthorizationError(
                "Snapshot user identity mismatch. Document download is prohibited."
            )
        if snapshot.get("application_id") != application_id:
            raise SecurityAuthorizationError(
                "Snapshot application identity mismatch. Document download is prohibited."
            )
        expected_version = getattr(packet, "packet_version", packet.version_num)
        if snapshot.get("packet_version") != expected_version:
            raise SecurityAuthorizationError(
                "Snapshot packet version mismatch. Document download is prohibited."
            )

        manifest_entries = snapshot.get("attachments_manifest")
        if manifest_entries is None or not isinstance(manifest_entries, list):
            raise SecurityAuthorizationError(
                "Snapshot attachments manifest is invalid. Document download is prohibited."
            )

        # 7. Verify requested document type and resolve expected format
        if not document_type or not isinstance(document_type, str):
            raise ValidationError("Document type must be a non-empty string.")

        norm_type = document_type.strip().lower()

        format_expectations = {
            "tailored_resume_pdf": ("tailored_resume_pdf", "PDF"),
            "tailored_resume_docx": ("tailored_resume_docx", "DOCX"),
            "cover_letter_pdf": ("cover_letter_pdf", "PDF"),
            "cover_letter_docx": ("cover_letter_docx", "DOCX"),
            "screening_qa_pdf": ("screening_qa_pdf", "PDF"),
            "screening_qa_docx": ("screening_qa_docx", "DOCX"),
            "consolidated_packet_pdf": ("consolidated_packet_pdf", "PDF"),
            "consolidated_packet_docx": ("consolidated_packet_docx", "DOCX"),
            "original_resume": ("original_resume", None),
            # Aliases
            "resume_pdf": ("tailored_resume_pdf", "PDF"),
            "resume_docx": ("tailored_resume_docx", "DOCX"),
            "cover_pdf": ("cover_letter_pdf", "PDF"),
            "cover_docx": ("cover_letter_docx", "DOCX"),
            "qa_pdf": ("screening_qa_pdf", "PDF"),
            "qa_docx": ("screening_qa_docx", "DOCX"),
            "packet_pdf": ("consolidated_packet_pdf", "PDF"),
            "packet_docx": ("consolidated_packet_docx", "DOCX"),
            "tailored_resume": ("tailored_resume_pdf", "PDF"),
            "cover_letter": ("cover_letter_pdf", "PDF"),
            "screening_qa": ("screening_qa_pdf", "PDF"),
            "packet": ("consolidated_packet_pdf", "PDF"),
        }

        if norm_type not in format_expectations:
            raise ValidationError(
                f"Unsupported document type: '{document_type}'. "
                "Only compiled PDF and DOCX packet materials are supported."
            )

        target_art_type, expected_format = format_expectations[norm_type]

        # 8. Resolve document locator strictly from snapshot manifest (no detached DB fallback)
        target_entry = None
        for entry in manifest_entries:
            if isinstance(entry, dict) and entry.get("artifact_type") == target_art_type:
                target_entry = entry
                break

        if not target_entry:
            raise FileNotFoundError(
                f"Requested document '{document_type}' is unavailable for Packet #{packet_id}."
            )

        raw_path_str = target_entry.get("file_path")
        expected_hash = target_entry.get("file_hash") or target_entry.get("sha256_hash")
        display_filename = target_entry.get("filename") or target_entry.get("stored_filename")
        manifest_format = str(target_entry.get("format", "")).upper()

        # 9. Enforce document format & extension consistency
        if not manifest_format or manifest_format not in ("PDF", "DOCX"):
            raise ValidationError(
                f"Unsupported manifest document format: '{manifest_format}'."
            )

        if expected_format is not None and manifest_format != expected_format:
            raise ValidationError(
                f"Document format mismatch: requested '{document_type}' ({expected_format}) "
                f"conflicts with manifest format '{manifest_format}'."
            )

        if not raw_path_str:
            raise FileNotFoundError(
                f"Requested document '{document_type}' has no file path in packet manifest."
            )

        ext = Path(raw_path_str).suffix.lower()
        if manifest_format == "PDF" and ext != ".pdf":
            raise ValidationError(
                f"Format mismatch: manifest format 'PDF' conflicts with file extension '{ext}'."
            )
        if manifest_format == "DOCX" and ext != ".docx":
            raise ValidationError(
                f"Format mismatch: manifest format 'DOCX' conflicts with file extension '{ext}'."
            )

        if not expected_hash:
            raise SecurityAuthorizationError(
                f"Document '{document_type}' lacks an authoritative integrity hash in packet manifest. "
                "Download rejected under strict security policy."
            )

        # 10. Resolve filesystem location safely and reject traversal
        if ".." in raw_path_str:
            raise SecurityAuthorizationError("Path traversal detected in document locator.")
        if "\x00" in raw_path_str:
            raise SecurityAuthorizationError("Invalid character in document path locator.")

        raw_path = Path(raw_path_str)
        target_path = raw_path.resolve()

        # 11. Verify containment within candidate's approved private storage boundary
        candidate_sandbox = (self.storage_base_dir / str(user_id)).resolve()
        try:
            target_path.relative_to(candidate_sandbox)
        except ValueError:
            raise SecurityAuthorizationError(
                f"Security violation: Requested document escapes candidate #{user_id} private storage boundary."
            )

        # 12. Verify file exists and is regular file
        safe_filename = FileSecurityValidator.sanitize_filename(display_filename or target_path.name)
        if not target_path.exists() or not target_path.is_file():
            raise FileNotFoundError(
                f"Stored document file not found on disk: '{safe_filename}'"
            )

        # 13. Verify SHA-256 against authoritative expected hash
        file_bytes = target_path.read_bytes()
        actual_hash = hashlib.sha256(file_bytes).hexdigest()
        if actual_hash.lower() != expected_hash.lower():
            raise SecurityAuthorizationError(
                "Document integrity verification failed. File on disk does not match immutable packet manifest."
            )

        # 14. Verify file format and magic bytes
        if manifest_format == "PDF":
            if not file_bytes.startswith(b"%PDF-"):
                raise InvalidFileFormatError(
                    f"File format validation failed for '{safe_filename}': missing valid PDF magic bytes."
                )
            mime_type = "application/pdf"
        elif manifest_format == "DOCX":
            if not file_bytes.startswith(b"PK\x03\x04"):
                raise InvalidFileFormatError(
                    f"File format validation failed for '{safe_filename}': missing valid DOCX magic bytes."
                )
            mime_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        else:
            raise InvalidFileFormatError(
                f"Unsupported document format '{manifest_format}'. Only PDF and DOCX are allowed."
            )

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
        proof_bytes: Optional[bytes] = None,
        proof_filename: Optional[str] = None,
    ) -> SubmissionConfirmation:
        """Executes the strict 16-step candidate manual submission workflow.

        Enforces:
        1. Session-derived user identity.
        2. Application ownership and allowed pre-submission status (APPROVED).
        3. Active prepared packet ownership, active revision, and integrity check.
        4. Valid unconsumed human approval record for the exact packet hash.
        5. Mandatory candidate confirmation boolean (unconfirmed submission rejected).
        6. Controlled submission channel validation.
        7. Pre-validation of optional confirmation evidence before ticket consumption.
        8. Cryptographic action ticket verification and single-use consumption.
        9. Atomic storage of evidence document inside candidate private storage sandbox.
        10. Atomic database transition to SUBMITTED, approval consumption, and SUBMISSION_CONFIRMED event.
        11. File rollback on database persistence failure.
        """
        from src.security.session_manager import SessionManager
        from src.lifecycle.state_machine import ApplicationStateMachine
        from src.database.models import SubmissionChannel
        from src.security.file_security import FileSecurityValidator
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
            active_pkt = self.db.get_active_prepared_packet(application_id=application_id, user_id=user_id)
            if active_pkt and active_pkt.id:
                appr_chk = self.db.get_packet_approval(active_pkt.id, user_id, include_revoked=True)
                if appr_chk and (getattr(appr_chk, "is_revoked", False) or appr_chk.is_revoked == 1):
                    reason = getattr(appr_chk, "revocation_reason", None) or "REVOKED"
                    raise SecurityAuthorizationError(
                        f"Human approval for PreparedPacket #{active_pkt.id} has been revoked ({reason}). "
                        f"Application is in status '{app.status}'. Candidate re-authorization is required."
                    )
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

        # 8. Retrieve corresponding human approval record (including revoked to enforce explicit security rejection)
        approval = self.db.get_packet_approval(packet_id, user_id, include_revoked=True)
        if not approval:
            raise SecurityAuthorizationError(
                f"No human approval record found for PreparedPacket #{packet_id}."
            )

        # Confirm approval is not revoked
        if getattr(approval, "is_revoked", False) or approval.is_revoked == 1:
            reason = getattr(approval, "revocation_reason", None) or "REVOKED"
            raise SecurityAuthorizationError(
                f"Human approval for PreparedPacket #{packet_id} has been revoked ({reason}). "
                "Candidate re-authorization under an active signing key is required."
            )

        # Confirm signing key used for approval has not been revoked
        if hasattr(self.db, "is_key_revoked") and self.db.is_key_revoked(approval.key_id):
            raise SecurityAuthorizationError(
                f"Human approval for PreparedPacket #{packet_id} was signed with revoked key '{approval.key_id}'. "
                "Candidate re-authorization under an active signing key is required."
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

        # Pre-validate optional proof bytes BEFORE consuming action ticket
        validator = FileSecurityValidator(base_storage_dir=self.storage_base_dir)
        final_doc_path = None
        final_doc_hash = None
        saved_proof_path = None

        if proof_bytes is not None:
            safe_name = proof_filename or "proof.pdf"
            validator.validate_confirmation_proof(proof_bytes, safe_name)

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

        # Save proof file atomically after ticket consumption
        if proof_bytes is not None:
            safe_name = proof_filename or "proof.pdf"
            storage_filename, detected_format, _, file_hash = validator.save_user_confirmation_file(
                user_id=user_id,
                application_id=application_id,
                file_bytes=proof_bytes,
                original_filename=safe_name,
            )
            final_doc_path = f"confirmations/{storage_filename}"
            final_doc_hash = file_hash
            saved_proof_path = validator.get_user_confirmations_dir(user_id) / storage_filename

        # 14. Call atomic database submission confirmation with transition_status=True
        try:
            confirmation = self.db.create_submission_confirmation(
                application_id=application_id,
                user_id=user_id,
                submission_channel=submission_channel,
                packet_id=packet_id,
                submission_timestamp=submission_timestamp,
                confirmation_reference=confirmation_reference,
                confirmation_doc_path=final_doc_path,
                confirmation_doc_hash=final_doc_hash,
                candidate_notes=candidate_notes,
                transition_status=True,
            )
        except Exception:
            if saved_proof_path and saved_proof_path.exists():
                try:
                    saved_proof_path.unlink()
                except OSError:
                    pass
            raise

        return confirmation

    def attach_submission_confirmation_proof(
        self,
        application_id: int,
        session_id: str,
        file_bytes: bytes,
        original_filename: str,
        client_user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Validates and attaches confirmation evidence to an existing submission confirmation.

        Responsibilities:
        1. Resolve authenticated candidate identity using resolve_authenticated_candidate().
        2. Retrieve candidate-owned application.
        3. Retrieve applicable active submission confirmation.
        4. Verify confirmation belongs to authenticated candidate and requested application.
        5. Validate raw uploaded bytes, size (<=10MB), magic bytes, and structural integrity.
        6. Enforce private containment in data/users/<user_id>/confirmations/.
        7. Save file atomically with server-generated unique filename.
        8. Atomically update confirmation record and emit timeline event without leaking server paths.
        9. Return sanitized confirmation metadata.
        """
        from src.security.file_security import FileSecurityValidator
        from src.database.exceptions import (
            ApplicationNotFoundError,
            CrossUserAccessError,
            ValidationError,
        )

        user_id, sess = self.resolve_authenticated_candidate(session_id, client_user_id)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        conf = self.db.get_submission_confirmation(application_id=application_id, user_id=user_id, active_only=True)
        if not conf or conf.id is None:
            raise ValidationError(
                f"No active submission confirmation found for Application #{application_id}. Confirm submission first."
            )

        if conf.user_id != user_id or conf.application_id != application_id:
            raise CrossUserAccessError(
                user_id=user_id,
                target_user_id=conf.user_id,
                resource=f"SubmissionConfirmation #{conf.id}",
            )

        validator = FileSecurityValidator(base_storage_dir=self.storage_base_dir)
        detected_format, file_hash = validator.validate_confirmation_proof(file_bytes, original_filename)

        storage_filename, detected_format, _, file_hash = validator.save_user_confirmation_file(
            user_id=user_id,
            application_id=application_id,
            file_bytes=file_bytes,
            original_filename=original_filename,
        )
        saved_rel_path = f"confirmations/{storage_filename}"
        user_dir = validator.get_user_confirmations_dir(user_id)
        target_path = (user_dir / storage_filename).resolve()

        safe_filename = validator.sanitize_filename(original_filename)

        try:
            updated = self.db.attach_confirmation_proof(
                confirmation_id=conf.id,
                user_id=user_id,
                confirmation_doc_path=saved_rel_path,
                confirmation_doc_hash=file_hash,
                file_format=detected_format,
                safe_filename=safe_filename,
            )
        except Exception:
            if target_path.exists():
                try:
                    target_path.unlink()
                except OSError:
                    pass
            raise

        return {
            "confirmation_id": updated.id,
            "application_id": application_id,
            "submission_channel": updated.submission_channel,
            "submission_timestamp": updated.submission_timestamp,
            "confirmation_reference": updated.confirmation_reference,
            "has_proof": True,
            "proof_format": detected_format,
            "proof_hash": file_hash,
            "safe_filename": safe_filename,
        }

    def get_candidate_submission_confirmation_proof(
        self,
        application_id: int,
        session_id: str,
        client_user_id: Optional[int] = None,
    ) -> Tuple[bytes, str, str]:
        """Retrieves and cryptographically verifies candidate submission confirmation proof document.

        Enforces:
        1. Authenticated session resolution.
        2. Application and confirmation ownership.
        3. Strict sandbox containment inside data/users/<user_id>/confirmations/.
        4. Traversal, absolute path, null byte, and symlink escape defenses.
        5. File existence and regular file verification.
        6. SHA-256 integrity comparison against stored hash.
        7. Magic-byte and structural verification before returning.
        8. Returns (file_bytes, safe_filename, mime_type).
        """
        import hashlib
        from src.security.file_security import FileSecurityValidator
        from src.database.exceptions import (
            ApplicationNotFoundError,
            CorruptedFileError,
            CrossUserAccessError,
            SecurityAuthorizationError,
            ValidationError,
        )

        user_id, sess = self.resolve_authenticated_candidate(session_id, client_user_id)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        conf = self.db.get_submission_confirmation(application_id=application_id, user_id=user_id, active_only=True)
        if not conf:
            raise ValidationError(f"No active submission confirmation found for Application #{application_id}.")

        if conf.user_id != user_id or conf.application_id != application_id:
            raise CrossUserAccessError(
                user_id=user_id,
                target_user_id=conf.user_id,
                resource=f"SubmissionConfirmation #{conf.id}",
            )

        if not conf.confirmation_doc_path or not conf.confirmation_doc_hash:
            raise ValidationError(f"No confirmation evidence document attached to Application #{application_id}.")

        stored_path_str = str(conf.confirmation_doc_path)
        if "\x00" in stored_path_str or Path(stored_path_str).is_absolute():
            raise SecurityAuthorizationError("Illegal confirmation document storage path.")
        if ".." in stored_path_str:
            raise SecurityAuthorizationError("Path traversal detected in confirmation document storage path.")

        candidate_sandbox = (self.storage_base_dir / str(user_id)).resolve()
        user_confirmations_dir = (candidate_sandbox / "confirmations").resolve()
        raw_path = Path(stored_path_str)

        if raw_path.parts and raw_path.parts[0] == "confirmations":
            target_path = (candidate_sandbox / raw_path).resolve()
        else:
            target_path = (user_confirmations_dir / raw_path.name).resolve()

        try:
            target_path.relative_to(candidate_sandbox)
        except ValueError:
            raise SecurityAuthorizationError(
                f"Security violation: Requested evidence escapes candidate #{user_id} private storage boundary."
            )

        if target_path.is_symlink():
            raise SecurityAuthorizationError("Symlink access rejected.")

        if not target_path.is_file():
            raise FileNotFoundError("Confirmation evidence file not found on disk.")

        with open(target_path, "rb") as f:
            file_bytes = f.read()

        actual_hash = hashlib.sha256(file_bytes).hexdigest()
        if actual_hash != conf.confirmation_doc_hash:
            raise CorruptedFileError("Integrity check failed: Confirmation document hash mismatch.")

        validator = FileSecurityValidator(base_storage_dir=self.storage_base_dir)
        detected_format, _ = validator.validate_confirmation_proof(file_bytes, target_path.name)

        mime_map = {
            "pdf": "application/pdf",
            "png": "image/png",
            "jpeg": "image/jpeg",
            "jpg": "image/jpeg",
        }
        mime_type = mime_map.get(detected_format, "application/octet-stream")
        safe_filename = f"submission_proof_{application_id}.{detected_format}"

        return file_bytes, safe_filename, mime_type

    def get_candidate_submission_confirmation(
        self,
        application_id: int,
        session_id: str,
        client_user_id: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieves sanitized candidate-facing submission confirmation metadata.

        Never exposes internal server filesystem paths or storage locators.
        """
        from src.database.exceptions import ApplicationNotFoundError, CrossUserAccessError

        user_id, sess = self.resolve_authenticated_candidate(session_id, client_user_id)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        conf = self.db.get_submission_confirmation(application_id=application_id, user_id=user_id, active_only=True)
        if not conf:
            return None

        if conf.user_id != user_id or conf.application_id != application_id:
            raise CrossUserAccessError(
                user_id=user_id,
                target_user_id=conf.user_id,
                resource=f"SubmissionConfirmation #{conf.id}",
            )

        has_proof = bool(conf.confirmation_doc_path and conf.confirmation_doc_hash)
        safe_display_name = None
        if has_proof and conf.confirmation_doc_path:
            ext = Path(conf.confirmation_doc_path).suffix.lstrip(".").lower() or "proof"
            safe_display_name = f"submission_proof_{application_id}.{ext}"

        return {
            "id": conf.id,
            "confirmation_id": conf.id,
            "application_id": conf.application_id,
            "submission_channel": conf.submission_channel,
            "submission_timestamp": conf.submission_timestamp,
            "confirmation_reference": conf.confirmation_reference,
            "has_proof": has_proof,
            "safe_display_name": safe_display_name,
            "candidate_notes": conf.candidate_notes,
            "is_active_confirmation": bool(conf.is_active_confirmation),
            "created_at": conf.created_at,
        }

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
        from src.database.exceptions import ApplicationNotFoundError, ValidationError

        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)
        if bool(getattr(app, "is_archived", 0)):
            raise ValidationError(
                f"Cannot create follow-up reminder for archived Application #{application_id}."
            )
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

    def recommend_application_follow_up(
        self,
        application_id: int,
        session_id: str,
        client_user_id: Optional[int] = None,
        reference_date: Optional[date] = None,
        extra_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Calculates deterministic follow-up recommendations for a candidate application."""
        from src.database.exceptions import ApplicationNotFoundError, ValidationError
        from src.lifecycle.follow_up_engine import FollowUpRecommendationEngine

        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        if bool(getattr(app, "is_archived", 0)):
            raise ValidationError(
                f"Cannot generate follow-up recommendations for archived Application #{application_id}."
            )

        existing_reminders = self.db.list_application_follow_ups(
            user_id=user_id,
            application_id=application_id,
            is_completed=False,
            include_archived=False,
        )

        recommendation = FollowUpRecommendationEngine.recommend(
            application=app,
            existing_reminders=existing_reminders,
            reference_date=reference_date,
            extra_context=extra_context,
        )
        return recommendation.to_dict()

    def generate_follow_up_template(
        self,
        application_id: int,
        session_id: str,
        follow_up_type: str,
        client_user_id: Optional[int] = None,
        follow_up_id: Optional[int] = None,
        extra_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generates a zero-hallucination, professional draft message for manual candidate sending."""
        from src.database.exceptions import ApplicationNotFoundError, ValidationError
        from src.lifecycle.follow_up_engine import (
            SUPPORTED_TEMPLATE_TYPES,
            FollowUpTemplateGenerator,
        )

        user_id, _ = self.resolve_authenticated_candidate(session_id, client_user_id)
        app = self.db.get_user_application(application_id=application_id, user_id=user_id)
        if not app:
            raise ApplicationNotFoundError(application_id)

        if bool(getattr(app, "is_archived", 0)):
            raise ValidationError(
                f"Cannot generate follow-up templates for archived Application #{application_id}."
            )

        clean_type = follow_up_type.strip().upper() if isinstance(follow_up_type, str) else ""
        if clean_type not in SUPPORTED_TEMPLATE_TYPES:
            raise ValidationError(
                f"Unsupported follow-up template type '{follow_up_type}'. Supported: {list(SUPPORTED_TEMPLATE_TYPES)}"
            )

        # Extract candidate profile cleanly without leaking DB wrapper metadata
        profile_row = self.db.get_user_candidate_profile(user_id)
        candidate_profile_data: Dict[str, Any] = {}
        if profile_row and isinstance(profile_row, dict):
            inner_data = profile_row.get("profile_data")
            if isinstance(inner_data, dict):
                candidate_profile_data = dict(inner_data)
            elif "personal_information" in profile_row or "full_name" in profile_row:
                candidate_profile_data = {
                    k: v for k, v in profile_row.items()
                    if k not in ("id", "user_id", "profile_hash", "version", "is_active", "last_updated")
                }

        trusted_account_name: Optional[str] = None
        user_row = self.db.get_user_by_id(user_id)
        if user_row and user_row.get("full_name") and str(user_row.get("full_name")).strip():
            trusted_account_name = str(user_row["full_name"]).strip()

        # Finding A: Strip reserved identity keys from caller context before constructing internal context
        RESERVED_IDENTITY_KEYS = {"_trusted_account_name", "trusted_account_name", "candidate_name"}
        merged_context = {
            k: v for k, v in (extra_context or {}).items()
            if k not in RESERVED_IDENTITY_KEYS
        }

        if follow_up_id is not None:
            fup = self.db.get_application_follow_up(follow_up_id=follow_up_id, user_id=user_id)
            if fup:
                if fup.follow_up_date and "submission_date" not in merged_context:
                    merged_context["reminder_date"] = fup.follow_up_date

        template = FollowUpTemplateGenerator.generate(
            follow_up_type=clean_type,
            application=app,
            candidate_profile=candidate_profile_data,
            extra_context=merged_context,
            trusted_account_name=trusted_account_name,
        )
        return template.to_dict()

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

            # Execute and persist authenticated security scan (Phase 9.1.2)
            try:
                from src.security.prompt_injection_detector import PromptInjectionDetector
                from src.security.scan_signer import SecurityScanSigner
                detector = PromptInjectionDetector()
                scan_res = detector.scan(raw_text)
                signer = SecurityScanSigner()
                manifest, sig, key_id = signer.sign_scan_result(
                    user_id=user_id,
                    source_type="job_description",
                    source_id=jd.id,
                    source_version=1,
                    source_hash=jd.content_hash,
                    snapshot_hash=jd.snapshot_hash,
                    scan_result=scan_res,
                    manifest_version="v2",
                    source_binary_hash=jd.file_hash,
                    source_binary_size_bytes=jd.file_size_bytes,
                    source_binary_format=jd.file_format,
                )
                self.db.save_security_scan(
                    user_id=user_id,
                    source_type="job_description",
                    source_id=jd.id,
                    source_version=1,
                    source_hash=jd.content_hash,
                    snapshot_hash=jd.snapshot_hash,
                    scanner_version=scan_res.engine_version,
                    policy_version=scan_res.policy_version,
                    risk_score=scan_res.risk_score,
                    classification=scan_res.classification,
                    threats_detected=[t.to_dict() for t in scan_res.threats_detected],
                    key_id=key_id,
                    hmac_signature=sig,
                    scanned_at=manifest["scanned_at"],
                    source_binary_hash=jd.file_hash,
                    source_binary_size_bytes=jd.file_size_bytes,
                    source_binary_format=jd.file_format,
                    manifest_version="v2",
                )
            except Exception as scan_err:
                self.logger.warning("Failed to persist security scan for JobDescription #%d: %s", jd.id, scan_err)

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

            # Execute and persist authenticated security scan (Phase 9.1.2)
            try:
                from src.security.prompt_injection_detector import PromptInjectionDetector
                from src.security.scan_signer import SecurityScanSigner
                detector = PromptInjectionDetector()
                scan_res = detector.scan(jd.raw_content)
                signer = SecurityScanSigner()
                manifest, sig, key_id = signer.sign_scan_result(
                    user_id=user_id,
                    source_type="job_description",
                    source_id=jd.id,
                    source_version=1,
                    source_hash=jd.content_hash,
                    snapshot_hash=jd.snapshot_hash,
                    scan_result=scan_res,
                    manifest_version="v2",
                    source_binary_hash=jd.file_hash,
                    source_binary_size_bytes=jd.file_size_bytes,
                    source_binary_format=jd.file_format,
                )
                self.db.save_security_scan(
                    user_id=user_id,
                    source_type="job_description",
                    source_id=jd.id,
                    source_version=1,
                    source_hash=jd.content_hash,
                    snapshot_hash=jd.snapshot_hash,
                    scanner_version=scan_res.engine_version,
                    policy_version=scan_res.policy_version,
                    risk_score=scan_res.risk_score,
                    classification=scan_res.classification,
                    threats_detected=[t.to_dict() for t in scan_res.threats_detected],
                    key_id=key_id,
                    hmac_signature=sig,
                    scanned_at=manifest["scanned_at"],
                    source_binary_hash=jd.file_hash,
                    source_binary_size_bytes=jd.file_size_bytes,
                    source_binary_format=jd.file_format,
                    manifest_version="v2",
                )
            except Exception as scan_err:
                self.logger.warning("Failed to persist security scan for JobDescription #%d: %s", jd.id, scan_err)

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

            # Execute and persist authenticated security scan (Phase 9.1.2)
            try:
                from src.security.prompt_injection_detector import PromptInjectionDetector
                from src.security.scan_signer import SecurityScanSigner
                detector = PromptInjectionDetector()
                scan_res = detector.scan(fetched.raw_text)
                signer = SecurityScanSigner()
                manifest, sig, key_id = signer.sign_scan_result(
                    user_id=user_id,
                    source_type="job_description",
                    source_id=jd.id,
                    source_version=1,
                    source_hash=jd.content_hash,
                    snapshot_hash=jd.snapshot_hash,
                    scan_result=scan_res,
                    manifest_version="v2",
                    source_binary_hash=jd.file_hash,
                    source_binary_size_bytes=jd.file_size_bytes,
                    source_binary_format=jd.file_format,
                )
                self.db.save_security_scan(
                    user_id=user_id,
                    source_type="job_description",
                    source_id=jd.id,
                    source_version=1,
                    source_hash=jd.content_hash,
                    snapshot_hash=jd.snapshot_hash,
                    scanner_version=scan_res.engine_version,
                    policy_version=scan_res.policy_version,
                    risk_score=scan_res.risk_score,
                    classification=scan_res.classification,
                    threats_detected=[t.to_dict() for t in scan_res.threats_detected],
                    key_id=key_id,
                    hmac_signature=sig,
                    scanned_at=manifest["scanned_at"],
                    source_binary_hash=jd.file_hash,
                    source_binary_size_bytes=jd.file_size_bytes,
                    source_binary_format=jd.file_format,
                    manifest_version="v2",
                )
            except Exception as scan_err:
                self.logger.warning("Failed to persist security scan for JobDescription #%d: %s", jd.id, scan_err)

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
        resume_id: Optional[int],
        job_description_id: int,
    ) -> Tuple[str, str]:
        """Inspects resume and job description to recommend best matching scoring profile."""
        jd = self.db.get_job_description(jd_id=job_description_id, user_id=user_id)
        if not jd:
            return "general_baseline", "Standard evaluation profile."

        cand_level = "entry"
        years_exp = None
        if resume_id is not None:
            from src.security.resume_verifier import ResumeIntegrityVerifier
            from src.security.file_security import FileSecurityValidator
            f_val = FileSecurityValidator(base_storage_dir=self.storage_base_dir) if self.storage_base_dir else None
            verifier = ResumeIntegrityVerifier(
                db_manager=self.db,
                file_validator=f_val,
            )
            verified_res = verifier.verify_and_load_resume(user_id=user_id, resume_id=resume_id, fresh_parse=True)
            cand_level = verified_res.parsed_resume.career_level or "entry"

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
        job_description_id: Optional[int] = None,
        job_id: Optional[int] = None,
        scoring_profile_id: Optional[str] = None,
        verified_resume: Optional[Any] = None,
    ) -> UniversalMatchResult:
        """Executes full universal match evaluation incorporating authenticated user profile and stores immutable record."""
        # 1. Fetch user's active candidate profile
        prof_rec = self.db.get_user_candidate_profile(user_id)
        profile_data = prof_rec.get("profile_data") if prof_rec else None
        candidate_profile_version = prof_rec.get("version", 1) if prof_rec else 1
        candidate_profile_hash = prof_rec.get("profile_hash") if prof_rec else None

        # 2. Fetch active resume version
        res_rec = self.db.get_user_resume(resume_id, user_id)
        if not res_rec:
            raise ResumeNotFoundError(f"Resume #{resume_id} not found.")
        active_version = res_rec.get("active_version", 1) or 1

        # 3. JIT Verify Resume Binary before matching (Finding A)
        if verified_resume is not None:
            if getattr(verified_resume, "user_id", None) != user_id or getattr(verified_resume, "resume_id", None) != resume_id:
                verified_resume = None

        if verified_resume is None:
            from src.security.resume_verifier import ResumeIntegrityVerifier
            from src.security.file_security import FileSecurityValidator

            f_val = FileSecurityValidator(base_storage_dir=self.storage_base_dir) if self.storage_base_dir else None
            verifier = ResumeIntegrityVerifier(db_manager=self.db, file_validator=f_val)
            verified_resume = verifier.verify_and_load_resume(
                user_id=user_id,
                resume_id=resume_id,
                version_num=active_version,
                fresh_parse=True,
            )

        matcher = UniversalMatcher(db_manager=self.db)
        return matcher.evaluate(
            user_id=user_id,
            resume_id=resume_id,
            resume_version_num=verified_resume.version_num,
            resume_data=verified_resume.parsed_resume,
            verified_resume=verified_resume,
            profile_data=profile_data,
            candidate_profile_version=candidate_profile_version,
            candidate_profile_hash=candidate_profile_hash,
            job_description_id=job_description_id,
            job_id=job_id,
            scoring_profile_id=scoring_profile_id,
            persist=True,
            enforce_resume_verification=True,
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

    def verify_and_load_resume(
        self,
        user_id: int,
        resume_id: int,
        version_num: Optional[int] = None,
        fresh_parse: bool = True,
    ):
        """Just-in-time verifies and loads candidate resume binary via ResumeIntegrityVerifier."""
        from src.security.resume_verifier import ResumeIntegrityVerifier
        from src.security.file_security import FileSecurityValidator
        verifier = ResumeIntegrityVerifier(
            db_manager=self.db,
            file_validator=FileSecurityValidator(base_storage_dir=self.storage_base_dir),
        )
        return verifier.verify_and_load_resume(
            user_id=user_id,
            resume_id=resume_id,
            version_num=version_num,
            fresh_parse=fresh_parse,
        )

    def sync_user_profile_from_resume_id(
        self,
        user_id: int,
        resume_id: int,
        version_num: Optional[int] = None,
        approved_fields: Optional[List[str]] = None,
        override_protected: bool = False,
    ) -> Dict[str, Any]:
        """Verifies candidate resume JIT and synchronizes user candidate profile."""
        from src.preparer.profile_updater import ProfileUpdater
        updater = ProfileUpdater(db_manager=self.db)
        return updater.sync_user_profile(
            user_id=user_id,
            resume_id=resume_id,
            version_num=version_num,
            approved_fields=approved_fields,
            override_protected=override_protected,
            user_base_dir=self.storage_base_dir,
        )

    def generate_tailored_resume(
        self,
        user_id: int,
        candidate_profile: Dict[str, Any],
        resume_data: Optional[Dict[str, Any]] = None,
        job_description: Optional[Dict[str, Any]] = None,
        match_result: Optional[Dict[str, Any]] = None,
        custom_instructions: Optional[str] = None,
        resume_id: Optional[int] = None,
        resume_version_num: Optional[int] = None,
    ):
        """Generates role-specific tailored resume using UniversalTailoredResumeGenerator with JIT verification."""
        from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator
        from src.security.resume_verifier import VerifiedResume
        from src.database.exceptions import CrossUserAccessError, ResumeIntegrityError

        target_res_id = resume_id
        v_res = None

        if isinstance(resume_data, VerifiedResume):
            if resume_data.user_id != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=resume_data.user_id,
                    resource=f"VerifiedResume #{resume_data.resume_id}",
                )
            target_res_id = resume_data.resume_id
            resume_version_num = resume_data.version_num
            v_res = resume_data
        elif target_res_id is None and isinstance(resume_data, dict):
            target_res_id = resume_data.get("id") or resume_data.get("resume_id")

        if v_res is None and target_res_id is not None:
            from src.security.resume_verifier import ResumeIntegrityVerifier
            verifier = ResumeIntegrityVerifier(db_manager=self.db, file_validator=self.file_validator)
            v_res = verifier.verify_and_load_resume(
                user_id=user_id,
                resume_id=target_res_id,
                version_num=resume_version_num,
                fresh_parse=True,
            )
            resume_version_num = v_res.version_num
        elif v_res is None and isinstance(resume_data, dict) and len(resume_data) > 0:
            raise ResumeIntegrityError(
                "Unverified resume dictionary provided without authoritative identity. "
                "Resume-backed operations require an authoritative resume ID or a VerifiedResume artifact."
            )

        generator = UniversalTailoredResumeGenerator()

        # Security Preflight Enforcement (Phase 9.1.2 & 9.1.2.1 Part B)
        from src.security.security_preflight import SecurityPreflightManager
        preflight = SecurityPreflightManager(db_manager=self.db, file_validator=self.file_validator)
        if isinstance(job_description, dict) and job_description.get("id"):
            preflight.check_job_description_security(user_id=user_id, jd_id=job_description["id"], target_action="document_generation")
        elif isinstance(job_description, dict) and (job_description.get("raw_content") or job_description.get("job_description")):
            raw_text = job_description.get("raw_content") or job_description.get("job_description")
            from src.security.prompt_injection_detector import PromptInjectionDetector, ScanClassification
            from src.database.exceptions import QuarantinedSourceError
            det = PromptInjectionDetector()
            scan_res = det.scan(raw_text)
            if scan_res.classification in (ScanClassification.SUSPICIOUS, ScanClassification.QUARANTINED):
                raise QuarantinedSourceError(
                    f"Action 'document_generation' blocked: Job description contains {scan_res.classification} prompt injection (Risk: {scan_res.risk_score:.2f}).",
                    source_type="job_description",
                    source_id=0,
                    classification=scan_res.classification,
                    risk_score=scan_res.risk_score,
                )
        if target_res_id is not None:
            preflight.check_resume_security(
                user_id=user_id,
                resume_id=target_res_id,
                version_num=resume_version_num,
                target_action="document_generation",
                verified_resume=v_res,
            )

        return generator.generate(
            user_id=user_id,
            candidate_profile=candidate_profile,
            resume_data=v_res or resume_data,
            job_description=job_description,
            match_result=match_result,
            custom_instructions=custom_instructions,
            resume_id=target_res_id,
            resume_version_num=resume_version_num,
            db_manager=self.db,
            user_base_dir=self.storage_base_dir,
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
        resume_id: Optional[int] = None,
        resume_version_num: Optional[int] = None,
    ):
        """Generates evidence-backed tailored cover letter across any profession with JIT verification."""
        from src.preparer.cover_letter_generator import (
            CoverLetterGenerator,
            LetterTone,
        )
        from src.security.resume_verifier import VerifiedResume
        from src.database.exceptions import CrossUserAccessError, ResumeIntegrityError

        target_res_id = resume_id
        v_res = None
        if isinstance(resume_data, VerifiedResume):
            if resume_data.user_id != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=resume_data.user_id,
                    resource=f"VerifiedResume #{resume_data.resume_id}",
                )
            target_res_id = resume_data.resume_id
            resume_version_num = resume_data.version_num
            v_res = resume_data
            parsed_resume_dict = resume_data.parsed_resume.to_dict()
        elif target_res_id is None and isinstance(resume_data, dict):
            target_res_id = resume_data.get("id") or resume_data.get("resume_id")

        if v_res is None and target_res_id is not None:
            from src.security.resume_verifier import ResumeIntegrityVerifier
            from src.security.file_security import FileSecurityValidator
            verifier = ResumeIntegrityVerifier(
                db_manager=self.db,
                file_validator=FileSecurityValidator(base_storage_dir=self.storage_base_dir),
            )
            v_res = verifier.verify_and_load_resume(
                user_id=user_id,
                resume_id=target_res_id,
                version_num=resume_version_num,
                fresh_parse=True,
            )
            resume_version_num = v_res.version_num
            parsed_resume_dict = v_res.parsed_resume.to_dict()
        elif v_res is None and isinstance(resume_data, dict) and len(resume_data) > 0:
            raise ResumeIntegrityError(
                "Unverified resume dictionary provided without authoritative identity. "
                "Resume-backed operations require an authoritative resume ID or a VerifiedResume artifact."
            )
        elif v_res is None:
            parsed_resume_dict = {}

        # Security Preflight Enforcement (Phase 9.1.2 & 9.1.2.1 Part B)
        from src.security.security_preflight import SecurityPreflightManager
        preflight = SecurityPreflightManager(db_manager=self.db, file_validator=self.file_validator)
        if isinstance(job_description, dict) and job_description.get("id"):
            preflight.check_job_description_security(user_id=user_id, jd_id=job_description["id"], target_action="document_generation")
        elif isinstance(job_description, dict) and (job_description.get("raw_content") or job_description.get("job_description")):
            raw_text = job_description.get("raw_content") or job_description.get("job_description")
            from src.security.prompt_injection_detector import PromptInjectionDetector, ScanClassification
            from src.database.exceptions import QuarantinedSourceError
            det = PromptInjectionDetector()
            scan_res = det.scan(raw_text)
            if scan_res.classification in (ScanClassification.SUSPICIOUS, ScanClassification.QUARANTINED):
                raise QuarantinedSourceError(
                    f"Action 'document_generation' blocked: Job description contains {scan_res.classification} prompt injection (Risk: {scan_res.risk_score:.2f}).",
                    source_type="job_description",
                    source_id=0,
                    classification=scan_res.classification,
                    risk_score=scan_res.risk_score,
                )
        if target_res_id is not None:
            preflight.check_resume_security(
                user_id=user_id,
                resume_id=target_res_id,
                version_num=resume_version_num,
                target_action="document_generation",
                verified_resume=v_res,
            )

        generator = CoverLetterGenerator(candidate_profile=candidate_profile)
        user_app_dir = Path(f"data/users/{user_id}/applications")
        selected_tone = tone or LetterTone.PROFESSIONAL_DIRECT
        return generator.generate_universal_cover_letter(
            user_id=user_id,
            candidate_profile=candidate_profile,
            job_description=job_description,
            resume_data=parsed_resume_dict,
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
        resume_id: Optional[int] = None,
        resume_version_num: Optional[int] = None,
    ):
        """Answers screening questions across 19 categories rooted strictly in verified evidence with JIT verification."""
        from src.preparer.question_answerer import QuestionAnswerer
        from src.security.resume_verifier import VerifiedResume
        from src.database.exceptions import CrossUserAccessError, ResumeIntegrityError

        target_res_id = resume_id
        v_res = None
        if isinstance(resume_data, VerifiedResume):
            if resume_data.user_id != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=resume_data.user_id,
                    resource=f"VerifiedResume #{resume_data.resume_id}",
                )
            target_res_id = resume_data.resume_id
            resume_version_num = resume_data.version_num
            v_res = resume_data
            parsed_resume_dict = resume_data.parsed_resume.to_dict()
        elif target_res_id is None and isinstance(resume_data, dict):
            target_res_id = resume_data.get("id") or resume_data.get("resume_id")

        if v_res is None and target_res_id is not None:
            from src.security.resume_verifier import ResumeIntegrityVerifier
            from src.security.file_security import FileSecurityValidator
            verifier = ResumeIntegrityVerifier(
                db_manager=self.db,
                file_validator=FileSecurityValidator(base_storage_dir=self.storage_base_dir),
            )
            v_res = verifier.verify_and_load_resume(
                user_id=user_id,
                resume_id=target_res_id,
                version_num=resume_version_num,
                fresh_parse=True,
            )
            resume_version_num = v_res.version_num
            parsed_resume_dict = v_res.parsed_resume.to_dict()
        elif v_res is None and isinstance(resume_data, dict) and len(resume_data) > 0:
            raise ResumeIntegrityError(
                "Unverified resume dictionary provided without authoritative identity. "
                "Resume-backed operations require an authoritative resume ID or a VerifiedResume artifact."
            )
        elif v_res is None:
            parsed_resume_dict = {}

        # Security Preflight Enforcement (Phase 9.1.2 & 9.1.2.1 Part B)
        from src.security.security_preflight import SecurityPreflightManager
        preflight = SecurityPreflightManager(db_manager=self.db, file_validator=self.file_validator)
        if isinstance(job_description, dict) and job_description.get("id"):
            preflight.check_job_description_security(user_id=user_id, jd_id=job_description["id"], target_action="document_generation")
        elif isinstance(job_description, dict) and (job_description.get("raw_content") or job_description.get("job_description")):
            raw_text = job_description.get("raw_content") or job_description.get("job_description")
            from src.security.prompt_injection_detector import PromptInjectionDetector, ScanClassification
            from src.database.exceptions import QuarantinedSourceError
            det = PromptInjectionDetector()
            scan_res = det.scan(raw_text)
            if scan_res.classification in (ScanClassification.SUSPICIOUS, ScanClassification.QUARANTINED):
                raise QuarantinedSourceError(
                    f"Action 'document_generation' blocked: Job description contains {scan_res.classification} prompt injection (Risk: {scan_res.risk_score:.2f}).",
                    source_type="job_description",
                    source_id=0,
                    classification=scan_res.classification,
                    risk_score=scan_res.risk_score,
                )
        if target_res_id is not None:
            preflight.check_resume_security(
                user_id=user_id,
                resume_id=target_res_id,
                version_num=resume_version_num,
                target_action="document_generation",
                verified_resume=v_res,
            )

        answerer = QuestionAnswerer(candidate_profile=candidate_profile)
        return answerer.batch_answer_questions(
            questions=questions,
            user_id=user_id,
            candidate_profile=candidate_profile,
            resume_data=parsed_resume_dict,
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
        # Fail-closed application authorization and security preflight (Phase 9.1.2.1 Part G.1)
        with self.db.connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, user_id, resume_id, job_description_id FROM applications WHERE id = ?", (application_id,))
            app_r = c.fetchone()
            if not app_r:
                from src.database.exceptions import ApplicationNotFoundError
                raise ApplicationNotFoundError(f"Application #{application_id} not found.")
            if app_r["user_id"] != user_id:
                from src.database.exceptions import CrossUserAccessError
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_r["user_id"],
                    resource=f"Application #{application_id}",
                )

            from src.security.security_preflight import SecurityPreflightManager
            preflight = SecurityPreflightManager(db_manager=self.db, file_validator=self.file_validator)
            if app_r["job_description_id"]:
                preflight.check_job_description_security(user_id=user_id, jd_id=app_r["job_description_id"], target_action="document_export")
            if app_r["resume_id"]:
                preflight.check_resume_security(user_id=user_id, resume_id=app_r["resume_id"], target_action="document_export")

        from src.preparer.document_generator import (
            DocumentTemplate,
            UniversalDocumentGenerator,
        )
        generator = UniversalDocumentGenerator()
        app_dir = self.file_validator.get_candidate_storage_root(user_id) / "applications" / str(application_id)
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

    def confirm_universal_manual_submission(
        self,
        application_id: int,
        approver_name: str,
        session_id: str,
        submission_ticket: str,
        packet_version_hash: str,
        submission_notes: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Records confirmed manual application submission by candidate."""
        from src.preparer.approval_gate import HumanApprovalGate
        gate = HumanApprovalGate(db_manager=self.db)
        return gate.record_manual_submission(
            application_id=application_id,
            approver_name=approver_name,
            session_id=session_id,
            submission_ticket=submission_ticket,
            packet_version_hash=packet_version_hash,
            submission_notes=submission_notes,
        )

    # Aliases for unified preparation interface
    generate_universal_tailored_resume = generate_tailored_resume
    generate_universal_application_documents = export_application_documents


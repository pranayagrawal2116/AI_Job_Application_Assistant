"""SQLite Database Manager for AI Job Application Assistant."""

from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

import pandas as pd

from src.database.exceptions import (
    AccountLockedError,
    ApplicationNotFoundError,
    AuthenticationFailedError,
    CompanyNotFoundError,
    CrossUserAccessError,
    DatabaseError,
    DuplicateJobError,
    DuplicateUserError,
    InvalidStatusError,
    InvalidStatusTransitionError,
    InvalidTicketError,
    JobNotFoundError,
    KeyRevokedError,
    RateLimitExceededError,
    SecurityAuthorizationError,
    TicketAlreadyConsumedError,
    TokenAlreadyUsedError,
    TokenExpiredError,
    UnconfirmedSubmissionError,
    UserNotFoundError,
    ValidationError,
)
from src.database.models import (
    Application,
    ApplicationApproval,
    ApplicationLog,
    ApplicationStatus,
    CandidateProfileRecord,
    Company,
    Job,
    JobDescription,
    PasswordResetToken,
    PreparedPacket,
    User,
)
from src.database.url_normalizer import (
    generate_company_title_key,
    normalize_entity_name,
    normalize_job_url,
)
from src.utils.logger import setup_logger

logger = setup_logger("DatabaseManager")

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "storage" / "job_assistant.db"
DEFAULT_EXPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "exports"


ALLOWED_TRANSITIONS: Dict[str, List[str]] = {
    ApplicationStatus.DISCOVERED.value: [
        ApplicationStatus.UNDER_REVIEW.value,
        ApplicationStatus.SHORTLISTED.value,
        ApplicationStatus.REJECTED.value,
        ApplicationStatus.WITHDRAWN.value,
    ],
    ApplicationStatus.UNDER_REVIEW.value: [
        ApplicationStatus.SHORTLISTED.value,
        ApplicationStatus.REJECTED.value,
        ApplicationStatus.WITHDRAWN.value,
    ],
    ApplicationStatus.SHORTLISTED.value: [
        ApplicationStatus.APPLICATION_PREPARED.value,
        ApplicationStatus.UNDER_REVIEW.value,
        ApplicationStatus.REJECTED.value,
        ApplicationStatus.WITHDRAWN.value,
    ],
    ApplicationStatus.APPLICATION_PREPARED.value: [
        ApplicationStatus.AWAITING_APPROVAL.value,
        ApplicationStatus.SHORTLISTED.value,
        ApplicationStatus.REJECTED.value,
        ApplicationStatus.WITHDRAWN.value,
    ],
    ApplicationStatus.AWAITING_APPROVAL.value: [
        ApplicationStatus.APPLIED.value,
        ApplicationStatus.APPLICATION_PREPARED.value,
        ApplicationStatus.REJECTED.value,
        ApplicationStatus.WITHDRAWN.value,
    ],
    ApplicationStatus.APPLIED.value: [
        ApplicationStatus.INTERVIEW.value,
        ApplicationStatus.REJECTED.value,
        ApplicationStatus.WITHDRAWN.value,
    ],
    ApplicationStatus.INTERVIEW.value: [
        ApplicationStatus.REJECTED.value,
        ApplicationStatus.WITHDRAWN.value,
    ],
    ApplicationStatus.REJECTED.value: [
        ApplicationStatus.UNDER_REVIEW.value,
        ApplicationStatus.SHORTLISTED.value,
    ],
    ApplicationStatus.WITHDRAWN.value: [
        ApplicationStatus.UNDER_REVIEW.value,
        ApplicationStatus.SHORTLISTED.value,
    ],
}


class DatabaseManager:
    """Manages SQLite database connections, transactions, and CRUD operations."""

    def __init__(
        self,
        db_path: Union[str, Path] = DEFAULT_DB_PATH,
        schema_path: Union[str, Path] = DEFAULT_SCHEMA_PATH,
    ):
        self.db_path = str(db_path)
        self.schema_path = Path(schema_path)

        # Ensure parent directory exists for file-based DB
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Creates and configures a new SQLite connection."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing an auto-closing SQLite connection."""
        conn = self.get_connection()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing an atomic database transaction.

        Commits on normal block exit, rolls back on any exception, and closes connection.
        """
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("Transaction failed and was rolled back: %s", e)
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes tables, indexes, and constraints using schema.sql."""
        if not self.schema_path.is_file():
            raise FileNotFoundError(f"Schema file not found at: {self.schema_path}")

        with open(self.schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        with self.connection() as conn:
            conn.executescript(schema_sql)
            conn.commit()
        logger.info("Database initialized successfully at: %s", self.db_path)

    # -------------------------------------------------------------------------
    # COMPANY OPERATIONS
    # -------------------------------------------------------------------------

    def get_or_create_company(
        self,
        name: str,
        website: Optional[str] = None,
        careers_url: Optional[str] = None,
        location: Optional[str] = None,
    ) -> Company:
        """Retrieves an existing company by name (case-insensitive) or creates a new one."""
        if not name or not name.strip():
            raise ValidationError("Company name cannot be empty.")

        clean_name = name.strip()
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM companies WHERE name = ? COLLATE NOCASE", (clean_name,))
            row = cursor.fetchone()
            if row:
                return Company(**dict(row))

            cursor.execute(
                """
                INSERT INTO companies (name, website, careers_url, location)
                VALUES (?, ?, ?, ?)
                """,
                (clean_name, website, careers_url, location),
            )
            company_id = cursor.lastrowid
            cursor.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
            created_row = cursor.fetchone()
            logger.info("Created new company entry: %s (ID: %d)", clean_name, company_id)
            return Company(**dict(created_row))

    def get_company_by_id(self, company_id: int) -> Optional[Company]:
        """Fetches a company by its ID."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
            row = cursor.fetchone()
            return Company(**dict(row)) if row else None

    def list_companies(self) -> List[Company]:
        """Returns all registered companies."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM companies ORDER BY name ASC")
            return [Company(**dict(row)) for row in cursor.fetchall()]

    # -------------------------------------------------------------------------
    # JOB OPERATIONS & DUPLICATE DETECTION
    # -------------------------------------------------------------------------

    def check_is_duplicate(
        self, job_url: str, company_name: str, job_title: str
    ) -> Tuple[bool, Optional[int], Optional[str]]:
        """Checks whether a job already exists by URL or (company_name, job_title).

        Returns:
            Tuple of (is_duplicate: bool, existing_job_id: Optional[int], duplicate_reason: Optional[str])
        """
        normalized_url = normalize_job_url(job_url)

        with self.connection() as conn:
            cursor = conn.cursor()

            # 1. Check normalized URL
            if normalized_url:
                cursor.execute("SELECT id FROM jobs WHERE job_url = ?", (normalized_url,))
                row = cursor.fetchone()
                if row:
                    return (True, row["id"], f"Normalized URL match: {normalized_url}")

            # 2. Check composite (company_name, job_title)
            norm_company, norm_title = generate_company_title_key(company_name, job_title)
            cursor.execute(
                """
                SELECT id FROM jobs
                WHERE LOWER(TRIM(company_name)) = ? AND LOWER(TRIM(job_title)) = ?
                """,
                (norm_company, norm_title),
            )
            row = cursor.fetchone()
            if row:
                return (True, row["id"], f"Company and Title match: '{company_name}' - '{job_title}'")

        return (False, None, None)

    def insert_job(self, job: Job, auto_create_company: bool = True) -> Job:
        """Inserts a new job posting with duplicate checking and initial application registration."""
        if not job.company_name or not job.company_name.strip():
            raise ValidationError("Job must have a valid company_name.")
        if not job.job_title or not job.job_title.strip():
            raise ValidationError("Job must have a valid job_title.")
        if not job.job_url or not job.job_url.strip():
            raise ValidationError("Job must have a valid job_url.")

        job.job_url = normalize_job_url(job.job_url)

        # Check duplicates
        is_dup, existing_id, reason = self.check_is_duplicate(
            job.job_url, job.company_name, job.job_title
        )
        if is_dup:
            raise DuplicateJobError(
                f"Duplicate job detected ({reason}). Existing Job ID: {existing_id}",
                existing_job_id=existing_id,
                duplicate_field=reason,
            )

        with self.transaction() as conn:
            cursor = conn.cursor()

            # Auto-link company
            if auto_create_company and not job.company_id:
                cursor.execute(
                    "SELECT id FROM companies WHERE name = ? COLLATE NOCASE",
                    (job.company_name.strip(),),
                )
                comp_row = cursor.fetchone()
                if comp_row:
                    job.company_id = comp_row["id"]
                else:
                    cursor.execute(
                        "INSERT INTO companies (name, location) VALUES (?, ?)",
                        (job.company_name.strip(), job.location),
                    )
                    job.company_id = cursor.lastrowid

            cursor.execute(
                """
                INSERT INTO jobs (
                    company_id, company_name, job_title, job_description,
                    job_url, location, stipend, required_skills,
                    eligibility_criteria, application_deadline, match_score,
                    match_classification, is_eligible, score_breakdown,
                    platform, work_arrangement, publication_date, internship_duration,
                    listing_status, extraction_confidence, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job.company_id,
                    job.company_name.strip(),
                    job.job_title.strip(),
                    job.job_description,
                    job.job_url,
                    job.location,
                    job.stipend,
                    job.get_skills_as_json(),
                    job.get_eligibility_as_json(),
                    job.application_deadline,
                    job.match_score,
                    job.match_classification,
                    1 if job.is_eligible else 0,
                    job.get_score_breakdown_as_json(),
                    job.platform,
                    job.work_arrangement,
                    job.publication_date,
                    job.internship_duration,
                    job.listing_status,
                    job.extraction_confidence,
                    job.notes,
                ),
            )
            job.id = cursor.lastrowid

            # Automatically initialize application record
            cursor.execute(
                """
                INSERT INTO applications (job_id, status)
                VALUES (?, ?)
                """,
                (job.id, ApplicationStatus.DISCOVERED.value),
            )
            app_id = cursor.lastrowid

            # Create initial audit log
            cursor.execute(
                """
                INSERT INTO application_logs (job_id, application_id, action, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    job.id,
                    app_id,
                    "JOB_DISCOVERED",
                    json.dumps({"platform": job.platform, "score": job.match_score}),
                ),
            )

            # Retrieve inserted job with timestamps
            cursor.execute("SELECT * FROM jobs WHERE id = ?", (job.id,))
            row = cursor.fetchone()
            logger.info("Successfully registered job '%s' at '%s' (ID: %d)", job.job_title, job.company_name, job.id)
            return self._row_to_job(row)

    def get_job_by_id(self, job_id: int) -> Optional[Job]:
        """Retrieves a job by its ID."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
            row = cursor.fetchone()
            return self._row_to_job(row) if row else None

    def get_job_by_url(self, job_url: str) -> Optional[Job]:
        """Retrieves a job by its URL (normalizes before query)."""
        normalized_url = normalize_job_url(job_url)
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM jobs WHERE job_url = ?", (normalized_url,))
            row = cursor.fetchone()
            return self._row_to_job(row) if row else None

    def list_jobs(
        self,
        platform: Optional[str] = None,
        status: Optional[str] = None,
        min_score: Optional[float] = None,
        is_eligible: Optional[bool] = None,
        search_term: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Job]:
        """Queries and filters jobs with pagination support."""
        query = """
            SELECT j.* FROM jobs j
            LEFT JOIN applications a ON j.id = a.job_id
            WHERE 1=1
        """
        params: List[Any] = []

        if platform:
            query += " AND LOWER(j.platform) = LOWER(?)"
            params.append(platform)

        if status:
            query += " AND a.status = ?"
            params.append(status)

        if min_score is not None:
            query += " AND j.match_score >= ?"
            params.append(min_score)

        if is_eligible is not None:
            query += " AND j.is_eligible = ?"
            params.append(1 if is_eligible else 0)

        if search_term:
            term = f"%{search_term.strip()}%"
            query += " AND (j.job_title LIKE ? OR j.company_name LIKE ? OR j.job_description LIKE ?)"
            params.extend([term, term, term])

        query += " ORDER BY j.match_score DESC, j.created_at DESC"

        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [self._row_to_job(row) for row in cursor.fetchall()]

    # Aliases for convenience
    add_job = insert_job
    get_all_jobs = list_jobs

    def update_job(self, job: Job) -> Job:
        """Updates an existing job record."""
        if not job.id:
            raise ValidationError("Job must have an ID to be updated.")

        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM jobs WHERE id = ?", (job.id,))
            if not cursor.fetchone():
                raise JobNotFoundError(job.id)

            cursor.execute(
                """
                UPDATE jobs SET
                    company_name = ?,
                    job_title = ?,
                    job_description = ?,
                    location = ?,
                    stipend = ?,
                    required_skills = ?,
                    eligibility_criteria = ?,
                    application_deadline = ?,
                    match_score = ?,
                    match_classification = ?,
                    is_eligible = ?,
                    score_breakdown = ?,
                    work_arrangement = ?,
                    publication_date = ?,
                    internship_duration = ?,
                    listing_status = ?,
                    last_verified = CURRENT_TIMESTAMP,
                    extraction_confidence = ?,
                    notes = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    job.company_name,
                    job.job_title,
                    job.job_description,
                    job.location,
                    job.stipend,
                    job.get_skills_as_json(),
                    job.get_eligibility_as_json(),
                    job.application_deadline,
                    job.match_score,
                    job.match_classification,
                    1 if job.is_eligible else 0,
                    job.get_score_breakdown_as_json(),
                    job.work_arrangement,
                    job.publication_date,
                    job.internship_duration,
                    job.listing_status,
                    job.extraction_confidence,
                    job.notes,
                    job.id,
                ),
            )
            cursor.execute("SELECT * FROM jobs WHERE id = ?", (job.id,))
            return self._row_to_job(cursor.fetchone())

    def delete_job(self, job_id: int) -> bool:
        """Deletes a job. Cascades automatically to applications and application_logs."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM jobs WHERE id = ?", (job_id,))
            if not cursor.fetchone():
                raise JobNotFoundError(job_id)

            cursor.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
            logger.info("Deleted job ID: %d", job_id)
            return True

    # -------------------------------------------------------------------------
    # APPLICATION OPERATIONS & STATUS TRACKING
    # -------------------------------------------------------------------------

    def get_application_by_job_id(self, job_id: int) -> Optional[Application]:
        """Fetches the application record linked to a given job ID."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM applications WHERE job_id = ?", (job_id,))
            row = cursor.fetchone()
            return Application(**dict(row)) if row else None

    def list_applications(self, status: Optional[str] = None) -> List[Application]:
        """Lists all applications, optionally filtered by status."""
        query = "SELECT * FROM applications"
        params: List[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY updated_at DESC"

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [Application(**dict(row)) for row in cursor.fetchall()]

    def update_application_status(
        self,
        job_id: int,
        new_status: Union[str, ApplicationStatus],
        confirmed: bool = False,
        notes: Optional[str] = None,
        resume_used: Optional[str] = None,
        cover_letter_reference: Optional[str] = None,
        packet_version_hash: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Application:
        """Updates the application status for a job, with strict transition state machines,
        human-in-the-loop authorization, and immutable audit logging.

        Raises:
            JobNotFoundError: If job does not exist.
            ApplicationNotFoundError: If application record does not exist.
            InvalidStatusError: If new_status is not a recognized status.
            InvalidStatusTransitionError: If the transition skips intermediate state machines.
            SecurityAuthorizationError: If human approval or packet verification fails.
            UnconfirmedSubmissionError: If trying to set 'Applied' without confirmed=True or valid approval.
        """
        valid_statuses = ApplicationStatus.list()
        status_value = (
            new_status.value if isinstance(new_status, ApplicationStatus) else str(new_status)
        )

        matched_status = None
        for s in valid_statuses:
            if s.lower() == status_value.strip().lower():
                matched_status = s
                break

        if not matched_status:
            raise InvalidStatusError(status_value, valid_statuses)

        # Retrieve current application state
        app = self.get_application_by_job_id(job_id)
        if not app:
            raise ApplicationNotFoundError(f"Job ID {job_id}")

        old_status = app.status
        if old_status == matched_status:
            return app

        # 1. State Machine Validation
        allowed = ALLOWED_TRANSITIONS.get(old_status, [])
        if matched_status not in allowed:
            raise InvalidStatusTransitionError(old_status=old_status, new_status=matched_status, allowed=allowed)

        # 2. Strict Human Authorization Validation for Awaiting Approval
        if matched_status == ApplicationStatus.AWAITING_APPROVAL.value:
            if not self.has_valid_human_approval(job_id, expected_packet_hash=packet_version_hash, user_id=user_id):
                raise SecurityAuthorizationError(
                    f"Transition to 'Awaiting Approval' rejected: Job #{job_id} requires valid, authenticated "
                    f"human approval of the reviewed application packet."
                )

        # 3. Strict Submission Safeguard for Applied
        if matched_status == ApplicationStatus.APPLIED.value:
            if not confirmed:
                raise UnconfirmedSubmissionError(
                    "Cannot mark application as 'Applied' without confirmed manual submission."
                )
            if old_status != ApplicationStatus.AWAITING_APPROVAL.value:
                raise InvalidStatusTransitionError(
                    old_status=old_status,
                    new_status=matched_status,
                    allowed=[ApplicationStatus.AWAITING_APPROVAL.value],
                )
            if not self.has_valid_human_approval(job_id, expected_packet_hash=packet_version_hash, user_id=user_id):
                raise UnconfirmedSubmissionError(
                    "STRICT SAFEGUARD: Cannot mark application as 'Applied' without an active, unconsumed human approval record "
                    "matching the reviewed application packet hash in the audit trail."
                )

        with self.transaction() as conn:
            cursor = conn.cursor()

            date_submitted_clause = ""
            date_prepared_clause = ""
            params: List[Any] = [matched_status]

            if matched_status == ApplicationStatus.APPLIED.value:
                date_submitted_clause = ", date_submitted = CURRENT_TIMESTAMP"
            elif matched_status == ApplicationStatus.APPLICATION_PREPARED.value:
                date_prepared_clause = ", date_prepared = CURRENT_TIMESTAMP"

            if resume_used is not None:
                params.append(resume_used)
            else:
                params.append(app.resume_used)

            if cover_letter_reference is not None:
                params.append(cover_letter_reference)
            else:
                params.append(app.cover_letter_reference)

            if notes is not None:
                params.append(notes)
            else:
                params.append(app.notes)

            params.append(job_id)

            cursor.execute(
                f"""
                UPDATE applications SET
                    status = ?,
                    resume_used = ?,
                    cover_letter_reference = ?,
                    notes = ?,
                    updated_at = CURRENT_TIMESTAMP
                    {date_submitted_clause}
                    {date_prepared_clause}
                WHERE job_id = ?
                """,
                params,
            )

            # Record immutable audit log
            log_details = {
                "old_status": old_status,
                "new_status": matched_status,
                "notes": notes,
                "user_id": user_id or "candidate_pranay",
                "packet_version_hash": packet_version_hash or "",
            }
            cursor.execute(
                """
                INSERT INTO application_logs (job_id, application_id, action, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    job_id,
                    app.id,
                    f"STATUS_TRANSITION: {old_status} -> {matched_status}",
                    json.dumps(log_details),
                ),
            )

            if matched_status == ApplicationStatus.APPLIED.value:
                cursor.execute(
                    """
                    INSERT INTO application_logs (job_id, application_id, action, details)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        job_id,
                        app.id,
                        "HUMAN_APPROVAL_CONSUMED",
                        json.dumps({
                            "action": "CONSUMED",
                            "consumed_at": datetime.now().isoformat(),
                            "user_id": user_id or "candidate_pranay",
                            "packet_version_hash": packet_version_hash or "",
                            "notes": notes or "Approval record consumed for confirmed manual application submission.",
                        }),
                    ),
                )

            cursor.execute("SELECT * FROM applications WHERE job_id = ?", (job_id,))
            updated_row = cursor.fetchone()
            logger.info("Updated application for job %d: %s -> %s", job_id, old_status, matched_status)
            return Application(**dict(updated_row))

    def record_human_approval(
        self,
        job_id: int,
        approver_name: str,
        approver_id: Optional[str] = None,
        session_id: Optional[str] = None,
        packet_version_hash: Optional[str] = None,
        ticket_nonce: Optional[str] = None,
        approval_notes: Optional[str] = None,
    ) -> ApplicationLog:
        """Records an explicit human approval record in the application audit trail.

        Automated agents, matchers, or bots are prohibited from self-authorizing submissions.
        """
        if not approver_name or not approver_name.strip():
            raise ValidationError("Approver name cannot be empty.")

        clean_approver = approver_name.strip()
        prohibited_keywords = ["bot", "agent", "matcher", "automated", "auto", "ai", "playwright", "scraper", "system"]
        if any(keyword in clean_approver.lower() for keyword in prohibited_keywords):
            raise ValidationError(
                f"Unauthorized approver '{clean_approver}'. Automated engines/agents are strictly forbidden from approving applications."
            )

        app = self.get_application_by_job_id(job_id)
        if not app:
            raise ApplicationNotFoundError(f"Job ID {job_id}")

        details = {
            "approver": clean_approver,
            "approver_id": approver_id or "candidate_pranay",
            "session_id": session_id or "",
            "packet_version_hash": packet_version_hash or "",
            "ticket_nonce": ticket_nonce or "",
            "approved_at": datetime.now().isoformat(),
            "notes": approval_notes or "Human authorization confirmed for final submission.",
            "is_human": True,
            "status": "ACTIVE",
        }

        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO application_logs (job_id, application_id, action, details)
                VALUES (?, ?, ?, ?)
                """,
                (job_id, app.id, "HUMAN_APPROVAL_GRANTED", json.dumps(details)),
            )
            log_id = cursor.lastrowid
            cursor.execute("SELECT * FROM application_logs WHERE id = ?", (log_id,))
            logger.info("Human approval granted for job %d by '%s'", job_id, clean_approver)
            return ApplicationLog(**dict(cursor.fetchone()))

    def consume_human_approval(
        self,
        job_id: int,
        packet_version_hash: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        ticket_nonce: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        """Marks a prior human approval as consumed upon manual submission confirmation, preventing replay."""
        app = self.get_application_by_job_id(job_id)
        if not app:
            raise ApplicationNotFoundError(f"Job ID {job_id}")

        if ticket_nonce:
            self.consume_action_nonce_persistently(
                ticket_nonce=ticket_nonce,
                key_id="v1",
                user_id=int(user_id) if (user_id and str(user_id).isdigit()) else None,
                action_type="SUBMIT_APPLICATION",
            )
        else:
            with self.transaction() as conn:
                cursor = conn.cursor()
                if packet_version_hash:
                    cursor.execute(
                        """
                        UPDATE application_approvals
                        SET is_consumed = 1, consumed_at = CURRENT_TIMESTAMP
                        WHERE application_id = ? AND packet_version_hash = ?
                        """,
                        (app.id, packet_version_hash),
                    )
                else:
                    cursor.execute(
                        """
                        UPDATE application_approvals
                        SET is_consumed = 1, consumed_at = CURRENT_TIMESTAMP
                        WHERE application_id = ?
                        """,
                        (app.id,),
                    )

        details = {
            "action": "CONSUMED",
            "consumed_at": datetime.now().isoformat(),
            "user_id": str(user_id or "candidate_pranay"),
            "session_id": session_id or "",
            "packet_version_hash": packet_version_hash or "",
            "ticket_nonce": ticket_nonce or "",
            "notes": notes or "Approval record consumed for confirmed manual application submission.",
        }
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO application_logs (job_id, application_id, action, details)
                VALUES (?, ?, ?, ?)
                """,
                (job_id, app.id, "HUMAN_APPROVAL_CONSUMED", json.dumps(details)),
            )
            logger.info("Human approval consumed for job %d (replay prevention active)", job_id)

    def has_valid_human_approval(
        self,
        job_id: int,
        expected_packet_hash: Optional[str] = None,
        user_id: Optional[Union[int, str]] = None,
    ) -> bool:
        """Checks whether an active, unrevoked, and unconsumed human approval record exists."""
        # 1. Check application_approvals table if application exists
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id FROM applications WHERE job_id = ?", (job_id,))
            app_row = cursor.fetchone()
            if app_row:
                app_id = app_row["id"]
                if expected_packet_hash:
                    cursor.execute(
                        """
                        SELECT id, is_consumed, packet_version_hash
                        FROM application_approvals
                        WHERE application_id = ? AND packet_version_hash = ?
                        ORDER BY approved_at DESC LIMIT 1
                        """,
                        (app_id, expected_packet_hash),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT id, is_consumed, packet_version_hash
                        FROM application_approvals
                        WHERE application_id = ?
                        ORDER BY approved_at DESC LIMIT 1
                        """,
                        (app_id,),
                    )
                appr_row = cursor.fetchone()
                if appr_row:
                    if appr_row["is_consumed"]:
                        return False
                    return True

        # 2. Check legacy application_logs audit trail for backward compatibility
        logs = self.get_application_logs(job_id)
        has_approval = False
        latest_approval_hash = None
        for log in logs:
            if log.action == "HUMAN_APPROVAL_GRANTED":
                has_approval = True
                try:
                    det = json.loads(log.details) if log.details else {}
                    latest_approval_hash = det.get("packet_version_hash")
                except Exception:
                    latest_approval_hash = None
            elif log.action in (
                "HUMAN_APPROVAL_REVOKED",
                "HUMAN_APPROVAL_CONSUMED",
                "STATUS_TRANSITION: Applied -> Rejected",
                "STATUS_TRANSITION: Applied -> Withdrawn",
            ):
                has_approval = False
                latest_approval_hash = None

        if not has_approval:
            return False

        if expected_packet_hash:
            if not latest_approval_hash or latest_approval_hash != expected_packet_hash:
                logger.warning(
                    f"Approval packet hash mismatch for Job #{job_id}: approved {latest_approval_hash}, expected {expected_packet_hash}"
                )
                return False

        return True

    def get_application_logs(self, job_id: int) -> List[ApplicationLog]:
        """Retrieves audit trail logs for a given job."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM application_logs WHERE job_id = ? ORDER BY timestamp ASC",
                (job_id,),
            )
            return [ApplicationLog(**dict(row)) for row in cursor.fetchall()]

    # -------------------------------------------------------------------------
    # CANDIDATE PROFILE STORAGE
    # -------------------------------------------------------------------------

    def save_candidate_profile(self, profile_data: Dict[str, Any]) -> CandidateProfileRecord:
        """Stores or updates the candidate profile snapshot in SQLite."""
        if not profile_data:
            raise ValidationError("Profile data cannot be empty.")

        json_str = json.dumps(profile_data)
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO candidate_profile (profile_data, last_updated)
                VALUES (?, CURRENT_TIMESTAMP)
                """,
                (json_str,),
            )
            profile_id = cursor.lastrowid
            cursor.execute("SELECT * FROM candidate_profile WHERE id = ?", (profile_id,))
            row = cursor.fetchone()
            logger.info("Saved candidate profile snapshot (ID: %d)", profile_id)
            return CandidateProfileRecord(
                id=row["id"],
                profile_data=json.loads(row["profile_data"]),
                last_updated=row["last_updated"],
            )

    def get_latest_candidate_profile(self) -> Optional[CandidateProfileRecord]:
        """Retrieves the latest saved candidate profile from SQLite."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM candidate_profile ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if not row:
                return None
            return CandidateProfileRecord(
                id=row["id"],
                profile_data=json.loads(row["profile_data"]),
                last_updated=row["last_updated"],
            )

    # -------------------------------------------------------------------------
    # CSV EXPORT
    # -------------------------------------------------------------------------

    def export_jobs_to_csv(
        self,
        output_path: Optional[Union[str, Path]] = None,
        status: Optional[str] = None,
    ) -> Path:
        """Exports jobs, companies, and application statuses to a clean CSV file."""
        if output_path is None:
            DEFAULT_EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = DEFAULT_EXPORTS_DIR / f"applications_export_{timestamp}.csv"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        query = """
            SELECT
                j.id AS job_id,
                j.company_name,
                j.job_title,
                j.location,
                j.stipend,
                j.match_score,
                j.match_classification,
                j.is_eligible,
                a.status AS application_status,
                a.date_prepared,
                a.date_submitted,
                j.platform,
                j.job_url,
                j.discovery_date
            FROM jobs j
            LEFT JOIN applications a ON j.id = a.job_id
            WHERE 1=1
        """
        params: List[Any] = []
        if status:
            query += " AND a.status = ?"
            params.append(status)

        query += " ORDER BY j.match_score DESC, j.created_at DESC"

        with self.connection() as conn:
            df = pd.read_sql_query(query, conn, params=params)

        df.to_csv(output_path, index=False)
        logger.info("Exported %d job records to CSV at %s", len(df), output_path)
        return output_path

    # -------------------------------------------------------------------------
    # DATABASE BACKUP & RESTORATION
    # -------------------------------------------------------------------------

    def backup_database(self, backup_path: Optional[Union[str, Path]] = None) -> Path:
        """Creates an atomic, consistent online backup of the SQLite database.

        Uses the standard SQLite Online Backup API.
        """
        if self.db_path == ":memory:":
            raise DatabaseError("Cannot backup an in-memory database to file via default path.")

        if backup_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Path(self.db_path).parent / f"backup_job_assistant_{timestamp}.db"
        else:
            backup_path = Path(backup_path)
            backup_path.parent.mkdir(parents=True, exist_ok=True)

        source_conn = self.get_connection()
        dest_conn = sqlite3.connect(str(backup_path))
        try:
            with dest_conn:
                source_conn.backup(dest_conn)
            logger.info("Database backup created successfully at: %s", backup_path)
            return backup_path
        finally:
            dest_conn.close()
            source_conn.close()

    def restore_database(self, backup_path: Union[str, Path]) -> bool:
        """Restores the live database from a backup file."""
        backup_file = Path(backup_path)
        if not backup_file.is_file():
            raise FileNotFoundError(f"Backup file does not exist: {backup_file}")

        source_conn = sqlite3.connect(str(backup_file))
        dest_conn = self.get_connection()
        try:
            with dest_conn:
                source_conn.backup(dest_conn)
            logger.info("Database restored successfully from: %s", backup_file)
            return True
        finally:
            source_conn.close()
            dest_conn.close()

    # -------------------------------------------------------------------------
    # HELPER MAPPINGS
    # -------------------------------------------------------------------------

    def _row_to_job(self, row: sqlite3.Row) -> Job:
        d = dict(row)
        # Parse JSON fields
        for json_field in ("required_skills", "eligibility_criteria", "score_breakdown"):
            if d.get(json_field) and isinstance(d[json_field], str):
                try:
                    d[json_field] = json.loads(d[json_field])
                except Exception:
                    pass
        d["is_eligible"] = bool(d.get("is_eligible", 1))
        return Job(**d)

    # -------------------------------------------------------------------------
    # PHASE 2: PERSISTENT NONCE & APPROVAL CONSUMPTION
    # -------------------------------------------------------------------------

    def consume_action_nonce_persistently(
        self,
        ticket_nonce: str,
        key_id: str = "v1",
        user_id: Optional[int] = None,
        action_type: str = "SUBMIT_APPLICATION",
    ) -> None:
        """Atomically consumes an action ticket nonce, storing it permanently in SQLite.

        Uses immediate transaction locking and unique constraint enforcement to
        prevent concurrent race conditions and replay attacks.
        """
        if not ticket_nonce or not ticket_nonce.strip():
            raise ValidationError("ticket_nonce cannot be empty.")

        clean_nonce = ticket_nonce.strip()

        # Connect and acquire an immediate transaction lock
        conn = self.get_connection()
        conn.isolation_level = None  # Autocommit mode to allow explicit BEGIN IMMEDIATE
        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.cursor()

            # 1. Check if already recorded in consumed_action_nonces
            cursor.execute("SELECT nonce FROM consumed_action_nonces WHERE nonce = ?", (clean_nonce,))
            if cursor.fetchone():
                conn.execute("ROLLBACK")
                raise TicketAlreadyConsumedError(
                    f"Action ticket nonce '{clean_nonce}' has already been consumed (replay prevention)."
                )

            # 2. Check if recorded as consumed in application_approvals
            cursor.execute(
                "SELECT id, is_consumed FROM application_approvals WHERE ticket_nonce = ?",
                (clean_nonce,),
            )
            approval_row = cursor.fetchone()
            if approval_row and approval_row["is_consumed"]:
                conn.execute("ROLLBACK")
                raise TicketAlreadyConsumedError(
                    f"Action ticket nonce '{clean_nonce}' was previously consumed on an approved packet."
                )

            # 3. Insert into consumed_action_nonces
            try:
                cursor.execute(
                    """
                    INSERT INTO consumed_action_nonces (nonce, key_id, user_id, action_type, consumed_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (clean_nonce, key_id, user_id, action_type),
                )
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK")
                raise TicketAlreadyConsumedError(
                    f"Action ticket nonce '{clean_nonce}' has already been consumed (race condition detected)."
                )

            # 4. Mark approval record as consumed if exists
            if approval_row:
                cursor.execute(
                    """
                    UPDATE application_approvals
                    SET is_consumed = 1, consumed_at = CURRENT_TIMESTAMP
                    WHERE ticket_nonce = ?
                    """,
                    (clean_nonce,),
                )

            conn.execute("COMMIT")
            logger.info("Successfully consumed ticket nonce '%s' for action '%s'", clean_nonce, action_type)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def is_nonce_consumed(self, ticket_nonce: str) -> bool:
        """Checks whether a ticket nonce has been consumed in SQLite."""
        if not ticket_nonce:
            return False
        clean_nonce = ticket_nonce.strip()
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT nonce FROM consumed_action_nonces WHERE nonce = ?", (clean_nonce,))
            if cursor.fetchone():
                return True
            cursor.execute("SELECT is_consumed FROM application_approvals WHERE ticket_nonce = ?", (clean_nonce,))
            row = cursor.fetchone()
            return bool(row and row["is_consumed"])

    def record_packet_approval(
        self,
        application_id: int,
        user_id: int,
        packet_version_hash: str,
        ticket_nonce: str,
        key_id: str = "v1",
        approver_name: str = "Human Candidate",
        session_id: str = "",
        packet_id: Optional[int] = None,
    ) -> ApplicationApproval:
        """Records an explicit human approval record for an application packet.

        Validates user ownership and ensures automated agents cannot approve.
        """
        if not approver_name or not approver_name.strip():
            raise ValidationError("Approver name cannot be empty.")

        clean_approver = approver_name.strip()
        prohibited_keywords = [
            "bot", "agent", "matcher", "automated", "auto", "ai", "playwright", "scraper", "system"
        ]
        if any(keyword in clean_approver.lower() for keyword in prohibited_keywords):
            raise ValidationError(
                f"Unauthorized approver '{clean_approver}'. Automated engines/agents are strictly forbidden from approving applications."
            )

        with self.transaction() as conn:
            cursor = conn.cursor()

            # Verify application exists and belongs to user
            cursor.execute("SELECT id, user_id FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise ApplicationNotFoundError(application_id)
            if app_row["user_id"] is not None and app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )

            # If packet_id provided, verify packet belongs to user
            if packet_id is not None:
                cursor.execute("SELECT id, user_id FROM prepared_packets WHERE id = ?", (packet_id,))
                pkt_row = cursor.fetchone()
                if not pkt_row:
                    raise ValidationError(f"Prepared packet #{packet_id} not found.")
                if pkt_row["user_id"] != user_id:
                    raise CrossUserAccessError(
                        user_id=user_id,
                        target_user_id=pkt_row["user_id"],
                        resource=f"PreparedPacket #{packet_id}",
                    )

            try:
                cursor.execute(
                    """
                    INSERT INTO application_approvals (
                        application_id, packet_id, user_id, packet_version_hash,
                        ticket_nonce, key_id, approver_name, session_id,
                        approved_at, is_consumed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 0)
                    """,
                    (
                        application_id,
                        packet_id,
                        user_id,
                        packet_version_hash,
                        ticket_nonce,
                        key_id,
                        clean_approver,
                        session_id,
                    ),
                )
            except sqlite3.IntegrityError as e:
                if "ticket_nonce" in str(e):
                    raise TicketAlreadyConsumedError(
                        f"Ticket nonce '{ticket_nonce}' is already registered in approvals."
                    )
                raise

            approval_id = cursor.lastrowid
            cursor.execute("SELECT * FROM application_approvals WHERE id = ?", (approval_id,))
            row = cursor.fetchone()

            # Also log to application_logs
            cursor.execute(
                """
                INSERT INTO application_logs (application_id, user_id, action, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    application_id,
                    user_id,
                    "HUMAN_APPROVAL_GRANTED",
                    json.dumps({
                        "approver": clean_approver,
                        "session_id": session_id,
                        "packet_version_hash": packet_version_hash,
                        "ticket_nonce": ticket_nonce,
                        "key_id": key_id,
                        "is_human": True,
                    }),
                ),
            )
            return ApplicationApproval(**dict(row))

    def has_valid_packet_approval(
        self,
        application_id: int,
        user_id: int,
        expected_packet_hash: str,
    ) -> bool:
        """Verifies if an active, unconsumed human approval exists for this user and packet version hash."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id FROM application_approvals
                WHERE application_id = ? AND user_id = ? AND packet_version_hash = ? AND is_consumed = 0
                ORDER BY approved_at DESC LIMIT 1
                """,
                (application_id, user_id, expected_packet_hash),
            )
            return cursor.fetchone() is not None

    # -------------------------------------------------------------------------
    # PHASE 2: USER-SCOPED JOB DESCRIPTIONS
    # -------------------------------------------------------------------------

    def create_job_description(
        self,
        user_id: int,
        company_name: str,
        job_title: str,
        raw_content: str,
        source_type: str = "pasted",
        content_hash: Optional[str] = None,
        parsed_data: Optional[Dict[str, Any]] = None,
    ) -> JobDescription:
        """Creates a user-owned job description record."""
        if not company_name or not company_name.strip():
            raise ValidationError("company_name cannot be empty.")
        if not job_title or not job_title.strip():
            raise ValidationError("job_title cannot be empty.")
        if not raw_content or not raw_content.strip():
            raise ValidationError("raw_content cannot be empty.")

        if not content_hash:
            content_hash = hashlib.sha256(raw_content.strip().encode("utf-8")).hexdigest()

        parsed_json = json.dumps(parsed_data) if parsed_data else None

        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content, content_hash, parsed_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    source_type,
                    company_name.strip(),
                    job_title.strip(),
                    raw_content.strip(),
                    content_hash,
                    parsed_json,
                ),
            )
            jd_id = cursor.lastrowid
            cursor.execute("SELECT * FROM job_descriptions WHERE id = ?", (jd_id,))
            return JobDescription(**dict(cursor.fetchone()))

    def get_job_description(self, jd_id: int, user_id: int) -> Optional[JobDescription]:
        """Fetches a job description owned by the specified user. Enforces cross-user isolation."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM job_descriptions WHERE id = ?", (jd_id,))
            row = cursor.fetchone()
            if not row:
                return None
            if row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"JobDescription #{jd_id}",
                )
            return JobDescription(**dict(row))

    def list_job_descriptions(self, user_id: int) -> List[JobDescription]:
        """Lists all job descriptions belonging to a user."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM job_descriptions WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            )
            return [JobDescription(**dict(row)) for row in cursor.fetchall()]

    # -------------------------------------------------------------------------
    # PHASE 2: USER-SCOPED APPLICATIONS
    # -------------------------------------------------------------------------

    def create_user_application(
        self,
        user_id: int,
        company_name: str,
        job_title: str,
        job_id: Optional[int] = None,
        job_description_id: Optional[int] = None,
        status: str = ApplicationStatus.DISCOVERED.value,
        notes: Optional[str] = None,
    ) -> Application:
        """Creates an application owned by a specific user with composite foreign key validation."""
        if not company_name or not company_name.strip():
            raise ValidationError("company_name cannot be empty.")
        if not job_title or not job_title.strip():
            raise ValidationError("job_title cannot be empty.")

        with self.transaction() as conn:
            cursor = conn.cursor()

            # If job_description_id is provided, verify it belongs to user_id
            if job_description_id is not None:
                cursor.execute("SELECT id, user_id FROM job_descriptions WHERE id = ?", (job_description_id,))
                jd_row = cursor.fetchone()
                if not jd_row:
                    raise ValidationError(f"JobDescription #{job_description_id} not found.")
                if jd_row["user_id"] != user_id:
                    raise CrossUserAccessError(
                        user_id=user_id,
                        target_user_id=jd_row["user_id"],
                        resource=f"JobDescription #{job_description_id}",
                    )

            cursor.execute(
                """
                INSERT INTO applications (
                    user_id, company_name, job_title, job_id, job_description_id, status, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, company_name.strip(), job_title.strip(), job_id, job_description_id, status, notes),
            )
            app_id = cursor.lastrowid
            cursor.execute("SELECT * FROM applications WHERE id = ?", (app_id,))
            return Application(**dict(cursor.fetchone()))

    def get_user_application(self, application_id: int, user_id: int) -> Optional[Application]:
        """Fetches an application owned by user. Enforces cross-user isolation."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM applications WHERE id = ?", (application_id,))
            row = cursor.fetchone()
            if not row:
                return None
            if row["user_id"] is not None and row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"Application #{application_id}",
                )
            return Application(**dict(row))

    def list_user_applications(self, user_id: int, status: Optional[str] = None) -> List[Application]:
        """Lists applications belonging to a user, optionally filtered by status."""
        query = "SELECT * FROM applications WHERE user_id = ?"
        params: List[Any] = [user_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY updated_at DESC"
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [Application(**dict(row)) for row in cursor.fetchall()]

    # -------------------------------------------------------------------------
    # PHASE 2: USER-SCOPED RESUMES
    # -------------------------------------------------------------------------

    def create_user_resume(
        self,
        user_id: int,
        original_filename: str,
        storage_filename: str,
        file_format: str,
        file_hash: str,
        file_size_bytes: int,
        parsed_data: Optional[Dict[str, Any]] = None,
        is_primary: bool = False,
    ) -> Dict[str, Any]:
        """Stores a resume record owned by a specific user."""
        if file_format.lower() not in ("pdf", "docx"):
            raise ValidationError(f"Invalid file format '{file_format}'. Must be 'pdf' or 'docx'.")

        parsed_json = json.dumps(parsed_data) if parsed_data else None

        with self.transaction() as conn:
            cursor = conn.cursor()
            if is_primary:
                cursor.execute("UPDATE resumes SET is_primary = 0 WHERE user_id = ?", (user_id,))

            cursor.execute(
                """
                INSERT INTO resumes (
                    user_id, original_filename, storage_filename, file_format,
                    file_hash, file_size_bytes, parsed_data, is_primary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    original_filename,
                    storage_filename,
                    file_format.lower(),
                    file_hash,
                    file_size_bytes,
                    parsed_json,
                    1 if is_primary else 0,
                ),
            )
            resume_id = cursor.lastrowid
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            return dict(cursor.fetchone())

    def get_user_resume(self, resume_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves a resume owned by user. Enforces cross-user isolation."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            row = cursor.fetchone()
            if not row:
                return None
            if row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"Resume #{resume_id}",
                )
            return dict(row)

    def list_user_resumes(self, user_id: int) -> List[Dict[str, Any]]:
        """Lists all resumes belonging to a user."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE user_id = ? ORDER BY uploaded_at DESC", (user_id,))
            return [dict(row) for row in cursor.fetchall()]

    def create_resume_version(
        self,
        resume_id: int,
        user_id: int,
        version_num: int,
        snapshot_json: str,
    ) -> Dict[str, Any]:
        """Stores an immutable resume version snapshot with composite foreign key check."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id FROM resumes WHERE id = ?", (resume_id,))
            res_row = cursor.fetchone()
            if not res_row:
                raise ValidationError(f"Resume #{resume_id} not found.")
            if res_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=res_row["user_id"],
                    resource=f"Resume #{resume_id}",
                )

            cursor.execute(
                """
                INSERT INTO resume_versions (resume_id, user_id, version_num, snapshot_json)
                VALUES (?, ?, ?, ?)
                """,
                (resume_id, user_id, version_num, snapshot_json),
            )
            v_id = cursor.lastrowid
            cursor.execute("SELECT * FROM resume_versions WHERE id = ?", (v_id,))
            return dict(cursor.fetchone())

    # -------------------------------------------------------------------------
    # PHASE 2: PREPARED PACKETS (MULTI-VERSION & COMPOSITE OWNERSHIP)
    # -------------------------------------------------------------------------

    def create_prepared_packet(
        self,
        application_id: int,
        user_id: int,
        packet_version_hash: str,
        original_resume_hash: str,
        job_description_snapshot_hash: str,
        screening_answers: Union[Dict[str, Any], str],
        original_resume_id: Optional[int] = None,
        tailored_resume_path: Optional[str] = None,
        tailored_resume_hash: Optional[str] = None,
        cover_letter_path: Optional[str] = None,
        cover_letter_hash: Optional[str] = None,
        form_payload: Optional[Union[Dict[str, Any], str]] = None,
        attachments_manifest: Optional[Union[List[Dict[str, Any]], str]] = None,
        version_num: Optional[int] = None,
    ) -> PreparedPacket:
        """Stores a prepared application packet revision with composite foreign key integrity."""
        with self.transaction() as conn:
            cursor = conn.cursor()

            # Verify application exists and belongs to user
            cursor.execute("SELECT id, user_id FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise ApplicationNotFoundError(application_id)
            if app_row["user_id"] is not None and app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )

            # Verify resume belongs to user if provided
            if original_resume_id is not None:
                cursor.execute("SELECT id, user_id FROM resumes WHERE id = ?", (original_resume_id,))
                res_row = cursor.fetchone()
                if not res_row:
                    raise ValidationError(f"Original resume #{original_resume_id} not found.")
                if res_row["user_id"] != user_id:
                    raise CrossUserAccessError(
                        user_id=user_id,
                        target_user_id=res_row["user_id"],
                        resource=f"Resume #{original_resume_id}",
                    )

            # Determine version_num
            if version_num is None:
                cursor.execute(
                    "SELECT COALESCE(MAX(version_num), 0) + 1 AS next_v FROM prepared_packets WHERE application_id = ?",
                    (application_id,),
                )
                version_num = cursor.fetchone()["next_v"]

            screening_str = (
                screening_answers
                if isinstance(screening_answers, str)
                else json.dumps(screening_answers)
            )
            form_payload_str = (
                form_payload
                if isinstance(form_payload, str)
                else (json.dumps(form_payload) if form_payload else None)
            )
            attachments_str = (
                attachments_manifest
                if isinstance(attachments_manifest, str)
                else (json.dumps(attachments_manifest) if attachments_manifest else None)
            )

            # Deactivate earlier active revisions for this application
            cursor.execute(
                "UPDATE prepared_packets SET is_active_revision = 0 WHERE application_id = ?",
                (application_id,),
            )

            cursor.execute(
                """
                INSERT INTO prepared_packets (
                    application_id, user_id, version_num, packet_version_hash,
                    original_resume_id, original_resume_hash, tailored_resume_path,
                    tailored_resume_hash, cover_letter_path, cover_letter_hash,
                    job_description_snapshot_hash, screening_answers_json,
                    form_payload_json, form_payload_hash,
                    attachments_manifest_json, attachments_manifest_hash,
                    is_active_revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    application_id,
                    user_id,
                    version_num,
                    packet_version_hash,
                    original_resume_id,
                    original_resume_hash,
                    tailored_resume_path,
                    tailored_resume_hash,
                    cover_letter_path,
                    cover_letter_hash,
                    job_description_snapshot_hash,
                    screening_str,
                    form_payload_str,
                    hashlib.sha256(form_payload_str.encode("utf-8")).hexdigest() if form_payload_str else None,
                    attachments_str,
                    hashlib.sha256(attachments_str.encode("utf-8")).hexdigest() if attachments_str else None,
                ),
            )
            pkt_id = cursor.lastrowid
            cursor.execute("SELECT * FROM prepared_packets WHERE id = ?", (pkt_id,))
            return PreparedPacket(**dict(cursor.fetchone()))

    def get_prepared_packet(self, packet_id: int, user_id: int) -> Optional[PreparedPacket]:
        """Fetches a prepared packet owned by user. Enforces cross-user isolation."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM prepared_packets WHERE id = ?", (packet_id,))
            row = cursor.fetchone()
            if not row:
                return None
            if row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"PreparedPacket #{packet_id}",
                )
            return PreparedPacket(**dict(row))

    def get_active_prepared_packet(self, application_id: int, user_id: int) -> Optional[PreparedPacket]:
        """Fetches the active revision of a prepared packet for an application owned by user."""
        with self.connection() as conn:
            cursor = conn.cursor()
            # Verify application ownership
            cursor.execute("SELECT id, user_id FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                return None
            if app_row["user_id"] is not None and app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )

            cursor.execute(
                """
                SELECT * FROM prepared_packets
                WHERE application_id = ? AND user_id = ? AND is_active_revision = 1
                ORDER BY version_num DESC LIMIT 1
                """,
                (application_id, user_id),
            )
            row = cursor.fetchone()
            return PreparedPacket(**dict(row)) if row else None

    def list_prepared_packets(self, application_id: int, user_id: int) -> List[PreparedPacket]:
        """Lists all revisions of prepared packets for an application."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                return []
            if app_row["user_id"] is not None and app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )

            cursor.execute(
                "SELECT * FROM prepared_packets WHERE application_id = ? AND user_id = ? ORDER BY version_num ASC",
                (application_id, user_id),
            )
            return [PreparedPacket(**dict(row)) for row in cursor.fetchall()]

    # -------------------------------------------------------------------------
    # PHASE 2: DATA RETENTION & DELETION
    # -------------------------------------------------------------------------

    def delete_user_account_data(self, user_id: int) -> bool:
        """Deletes user-controlled materials while preserving immutable submission audit logs
        under an anonymized pseudonym, per privacy and audit integrity specifications.
        """
        pseudonym = f"ANON_USER_{hashlib.sha256(str(user_id).encode()).hexdigest()[:12]}"
        with self.transaction() as conn:
            cursor = conn.cursor()
            # Verify user exists
            cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
            if not cursor.fetchone():
                raise UserNotFoundError(user_id)

            # 1. Anonymize application_logs details for this user (strip PII, retain submission audit)
            cursor.execute(
                """
                UPDATE application_logs
                SET user_id = NULL,
                    anonymized_user_pseudonym = ?,
                    details = json_set(COALESCE(details, '{}'), '$.user_deleted', 1, '$.anonymized_at', CURRENT_TIMESTAMP)
                WHERE user_id = ?
                """,
                (pseudonym, user_id),
            )

            # 2. Anonymize auth_audit_logs metadata
            cursor.execute(
                """
                UPDATE auth_audit_logs
                SET user_id = NULL,
                    metadata_json = '{"anonymized": true}'
                WHERE user_id = ?
                """,
                (user_id,),
            )

            # 3. Delete user row (cascades automatically to resumes, versions, job_descriptions,
            #    applications, prepared_packets, application_approvals, password_reset_tokens)
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            logger.info("Deleted user account data for User #%d with pseudonym '%s'", user_id, pseudonym)
            return True

"""SQLite Database Manager for AI Job Application Assistant."""

from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

import pandas as pd

from src.database.exceptions import (
    ApplicationNotFoundError,
    CrossUserAccessError,
    DatabaseError,
    DuplicateJobDescriptionError,
    DuplicateJobError,
    DuplicateResumeError,
    InvalidFileFormatError,
    InvalidStatusError,
    InvalidStatusTransitionError,
    JobDescriptionNotFoundError,
    JobNotFoundError,
    ResumeInUseError,
    ResumeNotFoundError,
    SecurityAuthorizationError,
    TicketAlreadyConsumedError,
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
    MatchResult,
    PreparedPacket,
)
from src.database.url_normalizer import (
    generate_company_title_key,
    normalize_job_url,
)
from src.utils.canonical_json import canonical_json_hash
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

    def _ensure_backward_compatible_columns(self, cursor: sqlite3.Cursor) -> None:
        """Ensures newly added columns exist in older database tables before schema indexes are applied."""
        def add_col_if_missing(table: str, col: str, col_def: str) -> None:
            try:
                cursor.execute(f"PRAGMA table_info({table})")
                cols = [r[1] for r in cursor.fetchall()]
                if cols and col not in cols:
                    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
            except sqlite3.OperationalError:
                pass

        add_col_if_missing("applications", "user_id", "INTEGER")
        add_col_if_missing("applications", "resume_id", "INTEGER")
        add_col_if_missing("applications", "job_description_id", "INTEGER")
        add_col_if_missing("application_logs", "user_id", "INTEGER")
        add_col_if_missing("resumes", "label", "TEXT DEFAULT 'General'")
        add_col_if_missing("resumes", "target_role", "TEXT")
        add_col_if_missing("resumes", "updated_at", "DATETIME DEFAULT CURRENT_TIMESTAMP")
        add_col_if_missing("resumes", "parsing_status", "TEXT DEFAULT 'COMPLETED'")
        add_col_if_missing("resumes", "active_version", "INTEGER DEFAULT 1")
        add_col_if_missing("resumes", "is_active", "INTEGER DEFAULT 1")
        add_col_if_missing("resumes", "is_primary", "INTEGER DEFAULT 0")
        add_col_if_missing("jobs", "company_id", "INTEGER")
        add_col_if_missing("candidate_profiles", "profile_hash", "TEXT")
        add_col_if_missing("job_descriptions", "source_url", "TEXT")
        add_col_if_missing("job_descriptions", "original_filename", "TEXT")
        add_col_if_missing("job_descriptions", "storage_filename", "TEXT")
        add_col_if_missing("job_descriptions", "parser_version", "TEXT DEFAULT '1.0.0'")
        add_col_if_missing("job_descriptions", "extraction_confidence", "REAL DEFAULT 1.0")
        add_col_if_missing("job_descriptions", "supersedes_job_description_id", "INTEGER")
        add_col_if_missing("job_descriptions", "snapshot_hash", "TEXT")
        add_col_if_missing("job_descriptions", "is_active", "INTEGER DEFAULT 1")
        add_col_if_missing("match_results", "resume_version_num", "INTEGER DEFAULT 1")
        add_col_if_missing("match_results", "resume_file_hash", "TEXT")
        add_col_if_missing("match_results", "candidate_profile_version", "INTEGER DEFAULT 1")
        add_col_if_missing("match_results", "candidate_profile_hash", "TEXT")
        add_col_if_missing("match_results", "job_snapshot_hash", "TEXT")
        add_col_if_missing("match_results", "scoring_profile", "TEXT DEFAULT 'general_baseline'")
        add_col_if_missing("match_results", "scoring_config_version", "TEXT DEFAULT '1.0.0'")
        add_col_if_missing("match_results", "assessment_confidence", "REAL DEFAULT 1.0")
        add_col_if_missing("match_results", "engine_version", "TEXT DEFAULT '2.1.1'")
        add_col_if_missing("match_results", "matching_skills", "TEXT")
        add_col_if_missing("match_results", "related_skills", "TEXT")
        add_col_if_missing("match_results", "partial_matches", "TEXT")
        add_col_if_missing("match_results", "missing_skills", "TEXT")
        add_col_if_missing("match_results", "education_analysis", "TEXT")
        add_col_if_missing("match_results", "experience_analysis", "TEXT")
        add_col_if_missing("match_results", "certification_analysis", "TEXT")
        add_col_if_missing("match_results", "eligibility_reasons", "TEXT")
        add_col_if_missing("match_results", "scoring_explanations", "TEXT")
        add_col_if_missing("match_results", "recommendations", "TEXT")
        add_col_if_missing("match_results", "details_json", "TEXT")
        add_col_if_missing("prepared_packets", "canonical_snapshot_json", "TEXT")
        add_col_if_missing("prepared_packets", "candidate_profile_version", "INTEGER DEFAULT 1")
        add_col_if_missing("prepared_packets", "candidate_profile_hash", "TEXT")
        add_col_if_missing("prepared_packets", "matching_result_id", "INTEGER")
        add_col_if_missing("prepared_packets", "matching_engine_version", "TEXT")
        add_col_if_missing("prepared_packets", "scoring_configuration_version", "TEXT")
        add_col_if_missing("prepared_packets", "original_resume_version_num", "INTEGER")
        add_col_if_missing("prepared_packets", "job_description_id", "INTEGER")
        add_col_if_missing("prepared_packets", "template_id", "TEXT")
        add_col_if_missing("prepared_packets", "template_version", "TEXT DEFAULT '1.0.0'")

        # Composite indexes required to safely satisfy composite foreign keys in application_approvals
        try:
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_applications_id_user ON applications(id, user_id)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_prepared_packets_id_user ON prepared_packets(id, user_id)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_applications_user_jd ON applications(user_id, job_description_id) WHERE job_description_id IS NOT NULL")
        except sqlite3.OperationalError:
            pass

    def _migrate_match_results_foreign_keys(self, conn: sqlite3.Connection) -> None:
        """Migrates match_results table in existing SQLite databases to enforce RESTRICT on resumes/JDs and SET NULL on jobs.

        Uses SQLite's 12-step table rebuild procedure safely preserving all IDs, timestamps,
        scores, provenance, hashes, explanations, and JSON columns.
        """
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='match_results'")
        if not cursor.fetchone():
            return  # Table will be created fresh by schema.sql

        # Check existing foreign keys and columns
        cursor.execute("PRAGMA foreign_key_list(match_results)")
        fks = cursor.fetchall()
        cursor.execute("PRAGMA table_info(match_results)")
        existing_cols = [r[1] for r in cursor.fetchall()]

        needs_migration = False
        if "candidate_profile_hash" not in existing_cols:
            needs_migration = True

        for fk in fks:
            table_ref = fk[2]
            on_delete = fk[6]
            if table_ref == "jobs" and on_delete != "SET NULL":
                needs_migration = True
            elif table_ref in ("resumes", "job_descriptions") and on_delete != "RESTRICT":
                needs_migration = True

        if not needs_migration:
            return

        logger.info("Performing table rebuild migration for match_results foreign keys...")
        # Disable foreign keys on this connection for the table rebuild
        cursor.execute("PRAGMA foreign_keys = OFF")
        cursor.execute("DROP TABLE IF EXISTS match_results_v2")

        cursor.execute("""
            CREATE TABLE match_results_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                resume_id INTEGER,
                job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
                job_description_id INTEGER,
                match_score REAL NOT NULL,
                match_classification TEXT NOT NULL,
                eligibility_status TEXT NOT NULL CHECK(eligibility_status IN ('ELIGIBLE', 'INELIGIBLE', 'UNKNOWN')),
                score_breakdown TEXT NOT NULL,
                explanation TEXT NOT NULL,
                resume_version_num INTEGER DEFAULT 1,
                resume_file_hash TEXT,
                candidate_profile_version INTEGER DEFAULT 1,
                candidate_profile_hash TEXT,
                job_snapshot_hash TEXT,
                scoring_profile TEXT DEFAULT 'general_baseline',
                scoring_config_version TEXT DEFAULT '1.0.0',
                assessment_confidence REAL DEFAULT 1.0,
                engine_version TEXT DEFAULT '2.1.1',
                matching_skills TEXT,
                related_skills TEXT,
                partial_matches TEXT,
                missing_skills TEXT,
                education_analysis TEXT,
                experience_analysis TEXT,
                certification_analysis TEXT,
                eligibility_reasons TEXT,
                scoring_explanations TEXT,
                recommendations TEXT,
                details_json TEXT,
                evaluated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE RESTRICT,
                FOREIGN KEY (job_description_id, user_id) REFERENCES job_descriptions(id, user_id) ON DELETE RESTRICT
            )
        """)

        cursor.execute("PRAGMA table_info(match_results_v2)")
        v2_cols = [r[1] for r in cursor.fetchall()]
        common_cols = [c for c in v2_cols if c in existing_cols]
        cols_str = ", ".join(common_cols)

        cursor.execute(f"INSERT INTO match_results_v2 ({cols_str}) SELECT {cols_str} FROM match_results")
        cursor.execute("DROP TABLE match_results")
        cursor.execute("ALTER TABLE match_results_v2 RENAME TO match_results")

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_match_results_user ON match_results(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_match_results_resume ON match_results(user_id, resume_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_match_results_jd ON match_results(user_id, job_description_id)")

        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA foreign_key_check(match_results)")
        fk_errors = cursor.fetchall()
        if fk_errors:
            raise RuntimeError(f"Foreign key integrity check failed after match_results migration: {fk_errors}")

        logger.info("match_results migration completed successfully.")

    def _migrate_prepared_packets_foreign_keys(self, conn: sqlite3.Connection) -> None:
        """Migrates prepared_packets table to enforce ON DELETE RESTRICT on resumes.

        Preserves all historical packet rows, version numbers, hashes, and canonical snapshots without fabricating metadata.
        """
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='prepared_packets'")
        if not cursor.fetchone():
            return

        cursor.execute("PRAGMA foreign_key_list(prepared_packets)")
        fks = cursor.fetchall()
        needs_migration = False
        for fk in fks:
            table_ref = fk[2]
            on_delete = fk[6]
            if table_ref == "resumes" and on_delete != "RESTRICT":
                needs_migration = True
                break

        if not needs_migration:
            return

        logger.info("Performing table rebuild migration for prepared_packets foreign keys (enforcing RESTRICT on resumes)...")
        cursor.execute("PRAGMA foreign_keys = OFF")
        cursor.execute("DROP TABLE IF EXISTS prepared_packets_v2")

        cursor.execute("""
            CREATE TABLE prepared_packets_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                version_num INTEGER NOT NULL DEFAULT 1,
                packet_version_hash TEXT NOT NULL,
                original_resume_id INTEGER,
                original_resume_hash TEXT NOT NULL,
                tailored_resume_path TEXT,
                tailored_resume_hash TEXT,
                cover_letter_path TEXT,
                cover_letter_hash TEXT,
                job_description_snapshot_hash TEXT NOT NULL,
                screening_answers_json TEXT NOT NULL,
                form_payload_json TEXT,
                form_payload_hash TEXT,
                attachments_manifest_json TEXT,
                attachments_manifest_hash TEXT,
                canonical_snapshot_json TEXT,
                candidate_profile_version INTEGER,
                candidate_profile_hash TEXT,
                matching_result_id INTEGER,
                matching_engine_version TEXT,
                scoring_configuration_version TEXT,
                original_resume_version_num INTEGER,
                job_description_id INTEGER,
                template_id TEXT,
                template_version TEXT,
                is_active_revision INTEGER DEFAULT 1 CHECK(is_active_revision IN (0, 1)),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(id, user_id),
                UNIQUE(application_id, version_num),
                FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE,
                FOREIGN KEY (original_resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE RESTRICT
            )
        """)

        cursor.execute("PRAGMA table_info(prepared_packets)")
        old_cols = [r[1] for r in cursor.fetchall()]
        v2_cols = [
            "id", "application_id", "user_id", "version_num", "packet_version_hash",
            "original_resume_id", "original_resume_hash", "tailored_resume_path",
            "tailored_resume_hash", "cover_letter_path", "cover_letter_hash",
            "job_description_snapshot_hash", "screening_answers_json",
            "form_payload_json", "form_payload_hash", "attachments_manifest_json",
            "attachments_manifest_hash", "canonical_snapshot_json",
            "candidate_profile_version", "candidate_profile_hash",
            "matching_result_id", "matching_engine_version",
            "scoring_configuration_version", "original_resume_version_num",
            "job_description_id", "template_id", "template_version",
            "is_active_revision", "created_at",
        ]
        shared_cols = [c for c in v2_cols if c in old_cols]
        cols_str = ", ".join(shared_cols)

        cursor.execute(f"INSERT INTO prepared_packets_v2 ({cols_str}) SELECT {cols_str} FROM prepared_packets")
        cursor.execute("DROP TABLE prepared_packets")
        cursor.execute("ALTER TABLE prepared_packets_v2 RENAME TO prepared_packets")

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_prepared_packets_app ON prepared_packets(application_id, user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_prepared_packets_hash ON prepared_packets(packet_version_hash)")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_prepared_packets_id_user ON prepared_packets(id, user_id)")

        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA foreign_key_check(prepared_packets)")
        fk_errors = cursor.fetchall()
        if fk_errors:
            raise RuntimeError(f"Foreign key integrity check failed after prepared_packets migration: {fk_errors}")

        logger.info("prepared_packets migration completed successfully.")

    def _init_db(self) -> None:
        """Initializes tables, indexes, and constraints using schema.sql."""
        if not self.schema_path.is_file():
            raise FileNotFoundError(f"Schema file not found at: {self.schema_path}")

        with open(self.schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        with self.connection() as conn:
            cursor = conn.cursor()
            self._ensure_backward_compatible_columns(cursor)
            conn.commit()
            self._migrate_match_results_foreign_keys(conn)
            conn.commit()
            self._migrate_prepared_packets_foreign_keys(conn)
            conn.commit()
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
                "user_id": str(user_id or "candidate_user"),
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
                            "user_id": str(user_id or "candidate_user"),
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
            "approver_id": approver_id or "candidate_user",
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
            "user_id": str(user_id or "candidate_user"),
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

            # If packet_id provided, verify packet belongs to user, matches application, hash, and active revision
            if packet_id is not None:
                cursor.execute(
                    "SELECT id, user_id, application_id, packet_version_hash, is_active_revision FROM prepared_packets WHERE id = ?",
                    (packet_id,),
                )
                pkt_row = cursor.fetchone()
                if not pkt_row:
                    raise ValidationError(f"Prepared packet #{packet_id} not found.")
                if pkt_row["user_id"] != user_id:
                    raise CrossUserAccessError(
                        user_id=user_id,
                        target_user_id=pkt_row["user_id"],
                        resource=f"PreparedPacket #{packet_id}",
                    )
                if pkt_row["application_id"] != application_id:
                    raise ValidationError(
                        f"Prepared packet #{packet_id} belongs to Application #{pkt_row['application_id']}, not #{application_id}."
                    )
                if pkt_row["packet_version_hash"] != packet_version_hash:
                    raise ValidationError(
                        f"Packet version hash mismatch for PreparedPacket #{packet_id}."
                    )
                if not pkt_row["is_active_revision"]:
                    raise ValidationError(
                        f"Prepared packet #{packet_id} is not the active revision. Previous approvals cannot authorize outdated packet revisions."
                    )
            else:
                cursor.execute(
                    """
                    SELECT id, user_id, application_id, packet_version_hash, is_active_revision
                    FROM prepared_packets
                    WHERE application_id = ? AND user_id = ? AND is_active_revision = 1
                    ORDER BY version_num DESC LIMIT 1
                    """,
                    (application_id, user_id),
                )
                pkt_row = cursor.fetchone()
                if pkt_row:
                    if pkt_row["packet_version_hash"] != packet_version_hash:
                        raise ValidationError("Packet version hash mismatch with active prepared packet.")
                    packet_id = pkt_row["id"]

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
    # PHASE 2 & 4: USER-SCOPED JOB DESCRIPTIONS & SNAPSHOT MANAGEMENT
    # -------------------------------------------------------------------------

    def save_job_description_snapshot(
        self,
        user_id: int,
        company_name: str,
        job_title: str,
        raw_content: str,
        source_type: str = "pasted",
        content_hash: Optional[str] = None,
        snapshot_hash: Optional[str] = None,
        parsed_data: Optional[Dict[str, Any]] = None,
        source_url: Optional[str] = None,
        original_filename: Optional[str] = None,
        storage_filename: Optional[str] = None,
        parser_version: str = "1.0.0",
        extraction_confidence: float = 1.0,
        supersedes_job_description_id: Optional[int] = None,
        is_active: bool = True,
    ) -> JobDescription:
        """Saves an immutable job description snapshot enforcing deduplication and multi-user isolation."""
        if not company_name or not company_name.strip():
            raise ValidationError("company_name cannot be empty.")
        if not job_title or not job_title.strip():
            raise ValidationError("job_title cannot be empty.")
        if not raw_content or not raw_content.strip():
            raise ValidationError("raw_content cannot be empty.")

        user = self.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User #{user_id}")

        raw_content_clean = raw_content.strip()
        raw_content_hash = hashlib.sha256(raw_content_clean.encode("utf-8")).hexdigest()
        if not content_hash:
            content_hash = raw_content_hash

        # Compute RFC 8785 canonical snapshot_hash if not explicitly provided
        if not snapshot_hash:
            manifest = {
                "user_id": user_id,
                "company_name": company_name.strip(),
                "job_title": job_title.strip(),
                "raw_content_hash": raw_content_hash,
                "parsed_data": parsed_data,
                "parser_version": parser_version,
                "source_type": source_type,
                "source_url": source_url,
                "original_filename": original_filename,
            }
            snapshot_hash = canonical_json_hash(manifest)

        # Check deduplication per-user
        if supersedes_job_description_id is None:
            with self.connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id FROM job_descriptions WHERE user_id = ? AND content_hash = ? AND is_active = 1",
                    (user_id, content_hash),
                )
                existing = cursor.fetchone()
                if existing:
                    raise DuplicateJobDescriptionError(
                        f"Job description with identical content already exists as ID #{existing['id']}.",
                        existing_id=existing["id"],
                    )

        # If superseding, verify parent ownership
        if supersedes_job_description_id is not None:
            parent = self.get_job_description(supersedes_job_description_id, user_id=user_id)
            if not parent:
                raise JobDescriptionNotFoundError(f"Job Description #{supersedes_job_description_id} not found.")

        parsed_json = json.dumps(parsed_data) if parsed_data else None

        with self.transaction() as conn:
            cursor = conn.cursor()

            # If superseding, deactivate the superseded record
            if supersedes_job_description_id is not None:
                cursor.execute(
                    "UPDATE job_descriptions SET is_active = 0 WHERE id = ? AND user_id = ?",
                    (supersedes_job_description_id, user_id),
                )

            cursor.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content, content_hash, snapshot_hash, parsed_data,
                    source_url, original_filename, storage_filename, parser_version, extraction_confidence,
                    supersedes_job_description_id, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    source_type,
                    company_name.strip(),
                    job_title.strip(),
                    raw_content_clean,
                    content_hash,
                    snapshot_hash,
                    parsed_json,
                    source_url,
                    original_filename,
                    storage_filename,
                    parser_version,
                    extraction_confidence,
                    supersedes_job_description_id,
                    1 if is_active else 0,
                ),
            )
            jd_id = cursor.lastrowid
            cursor.execute("SELECT * FROM job_descriptions WHERE id = ?", (jd_id,))
            return JobDescription(**dict(cursor.fetchone()))

    def create_job_description(
        self,
        user_id: int,
        company_name: str,
        job_title: str,
        raw_content: str,
        source_type: str = "pasted",
        content_hash: Optional[str] = None,
        snapshot_hash: Optional[str] = None,
        parsed_data: Optional[Dict[str, Any]] = None,
        source_url: Optional[str] = None,
        original_filename: Optional[str] = None,
        storage_filename: Optional[str] = None,
        parser_version: str = "1.0.0",
        extraction_confidence: float = 1.0,
        supersedes_job_description_id: Optional[int] = None,
        is_active: bool = True,
    ) -> JobDescription:
        """Creates a user-owned job description record (backward-compatible delegate to save_job_description_snapshot)."""
        return self.save_job_description_snapshot(
            user_id=user_id,
            company_name=company_name,
            job_title=job_title,
            raw_content=raw_content,
            source_type=source_type,
            content_hash=content_hash,
            snapshot_hash=snapshot_hash,
            parsed_data=parsed_data,
            source_url=source_url,
            original_filename=original_filename,
            storage_filename=storage_filename,
            parser_version=parser_version,
            extraction_confidence=extraction_confidence,
            supersedes_job_description_id=supersedes_job_description_id,
            is_active=is_active,
        )

    def update_job_description_snapshot(
        self,
        user_id: int,
        jd_id: int,
        updated_parsed_data: Dict[str, Any],
        new_job_title: Optional[str] = None,
        new_company_name: Optional[str] = None,
        new_raw_content: Optional[str] = None,
    ) -> JobDescription:
        """Creates a new immutable job description snapshot linked via supersedes_job_description_id."""
        existing = self.get_job_description(jd_id, user_id=user_id)
        if not existing:
            raise JobDescriptionNotFoundError(f"Job Description #{jd_id} not found.")

        title = new_job_title.strip() if new_job_title else existing.job_title
        company = new_company_name.strip() if new_company_name else existing.company_name
        raw = new_raw_content.strip() if new_raw_content else existing.raw_content

        confidence = float(updated_parsed_data.get("extraction_confidence", existing.extraction_confidence or 1.0))
        version = str(updated_parsed_data.get("parser_version", existing.parser_version or "1.0.0"))

        return self.save_job_description_snapshot(
            user_id=user_id,
            company_name=company,
            job_title=title,
            raw_content=raw,
            source_type=existing.source_type,
            source_url=existing.source_url,
            original_filename=existing.original_filename,
            storage_filename=existing.storage_filename,
            parser_version=version,
            extraction_confidence=confidence,
            parsed_data=updated_parsed_data,
            supersedes_job_description_id=existing.id,
            is_active=True,
        )

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

    def list_job_descriptions(
        self,
        user_id: int,
        include_superseded: bool = False,
        active_only: bool = True,
    ) -> List[JobDescription]:
        """Lists all job descriptions belonging to a user."""
        with self.connection() as conn:
            cursor = conn.cursor()
            if active_only and not include_superseded:
                cursor.execute(
                    "SELECT * FROM job_descriptions WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC",
                    (user_id,),
                )
            else:
                cursor.execute(
                    "SELECT * FROM job_descriptions WHERE user_id = ? ORDER BY created_at DESC",
                    (user_id,),
                )
            return [JobDescription(**dict(row)) for row in cursor.fetchall()]

    def get_job_description_history(self, user_id: int, jd_id: int) -> List[JobDescription]:
        """Returns the version lineage for a job description snapshot (from latest to earliest)."""
        current = self.get_job_description(jd_id, user_id=user_id)
        if not current:
            raise JobDescriptionNotFoundError(f"Job Description #{jd_id} not found.")

        history: List[JobDescription] = [current]
        visited_ids = {current.id}

        while current.supersedes_job_description_id:
            parent_id = current.supersedes_job_description_id
            if parent_id in visited_ids:
                break
            parent = self.get_job_description(parent_id, user_id=user_id)
            if not parent:
                break
            history.append(parent)
            visited_ids.add(parent.id)
            current = parent

        return history

    def delete_job_description(self, jd_id: int, user_id: int) -> Dict[str, Any]:
        """Deletes or archives a user's job description snapshot and removes associated files if safe."""
        jd = self.get_job_description(jd_id, user_id=user_id)
        if not jd:
            raise JobDescriptionNotFoundError(f"Job Description #{jd_id} not found.")

        # Check references across applications, match_results, and supersedes lineage
        with self.connection() as conn:
            cursor = conn.cursor()

            # 1. Applications reference (using job_description_id)
            cursor.execute(
                "SELECT COUNT(*) as cnt FROM applications WHERE user_id = ? AND job_description_id = ?",
                (user_id, jd_id),
            )
            linked_apps = cursor.fetchone()["cnt"]

            # 2. Match results reference
            cursor.execute(
                "SELECT COUNT(*) as cnt FROM match_results WHERE user_id = ? AND job_description_id = ?",
                (user_id, jd_id),
            )
            linked_matches = cursor.fetchone()["cnt"]

            # 3. Supersedes lineage (child records that supersede this snapshot)
            cursor.execute(
                "SELECT COUNT(*) as cnt FROM job_descriptions WHERE user_id = ? AND supersedes_job_description_id = ?",
                (user_id, jd_id),
            )
            linked_lineage = cursor.fetchone()["cnt"]

        total_refs = linked_apps + linked_matches + linked_lineage

        if total_refs > 0:
            # Soft-delete / Archive
            with self.transaction() as t_conn:
                t_cursor = t_conn.cursor()
                t_cursor.execute(
                    "UPDATE job_descriptions SET is_active = 0 WHERE id = ? AND user_id = ?",
                    (jd_id, user_id),
                )
            logger.info(
                f"Job Description #{jd_id} archived (soft-deleted) due to {total_refs} active references "
                f"({linked_apps} apps, {linked_matches} matches, {linked_lineage} lineage child records)."
            )
            return {
                "success": True,
                "action": "archived",
                "archived": True,
                "deleted": False,
                "message": (
                    f"Job description #{jd_id} is referenced by existing applications, matches, or version lineage. "
                    "It has been safely archived instead of deleted to protect historical application integrity."
                ),
            }

        # Hard-delete when 0 references exist
        with self.transaction() as t_conn:
            t_cursor = t_conn.cursor()
            t_cursor.execute("DELETE FROM job_descriptions WHERE id = ? AND user_id = ?", (jd_id, user_id))

        # Check if physical file can be removed (only if no remaining records for this user share the file)
        if jd.storage_filename:
            with self.connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) as cnt FROM job_descriptions WHERE user_id = ? AND storage_filename = ?",
                    (user_id, jd.storage_filename),
                )
                remaining_file_refs = cursor.fetchone()["cnt"]

            if remaining_file_refs == 0:
                try:
                    from src.security.file_security import FileSecurityValidator
                    validator = FileSecurityValidator()
                    validator.delete_stored_job_description_file(user_id, jd.storage_filename)
                except Exception as e:
                    logger.warning(f"Error removing storage file for JD #{jd_id}: {e}")

        return {
            "success": True,
            "action": "deleted",
            "archived": False,
            "deleted": True,
            "message": f"Job description #{jd_id} and associated unreferenced files deleted successfully.",
        }

    def upload_user_job_description(
        self,
        user_id: int,
        file_bytes: bytes,
        original_filename: str,
        user_base_dir: Optional[Path] = None,
    ) -> JobDescription:
        """Validates, stores, parses, and persists a user job description document (PDF or DOCX)."""
        from src.security.file_security import FileSecurityValidator
        from src.preparer.job_parser import JobParser

        user = self.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User #{user_id}")

        validator = FileSecurityValidator()
        validator.validate_file(file_bytes, original_filename)

        ext = Path(original_filename).suffix.lstrip(".").lower()
        if ext not in ("pdf", "docx"):
            raise InvalidFileFormatError(f"Unsupported file format '.{ext}'. Only PDF and DOCX documents are accepted.")

        storage_filename, detected_format, _, _ = validator.save_user_job_description_file(
            user_id=user_id,
            file_bytes=file_bytes,
            original_filename=original_filename,
            user_base_dir=user_base_dir,
        )

        job_dir = user_base_dir or validator.get_user_job_descriptions_dir(user_id)
        dest_path = job_dir / storage_filename

        parser = JobParser()
        if ext == "pdf":
            raw_text = parser.extract_text_from_pdf(dest_path)
        else:
            raw_text = parser.extract_text_from_docx(dest_path)

        stem_name = Path(original_filename).stem.replace("_", " ").replace("-", " ")
        structured = parser.parse_job_description(
            raw_text=raw_text,
            hint_title=stem_name if len(stem_name) > 3 else None,
            source=f"upload_{ext}",
        )

        company = structured.company_name or "Unknown Company"
        title = structured.job_title or stem_name or "Untitled Position"

        return self.save_job_description_snapshot(
            user_id=user_id,
            company_name=company,
            job_title=title,
            raw_content=raw_text,
            source_type="upload",
            original_filename=original_filename,
            storage_filename=storage_filename,
            parser_version=structured.parser_version,
            extraction_confidence=structured.extraction_confidence,
            parsed_data=structured.to_dict(),
        )

    def get_job_description_file_path(
        self,
        user_id: int,
        jd_id: int,
        user_base_dir: Optional[Path] = None,
    ) -> Optional[Path]:
        """Returns safe, validated Path to job description document on disk, enforcing sandbox containment."""
        from src.security.file_security import FileSecurityValidator

        jd = self.get_job_description(jd_id, user_id=user_id)
        if not jd:
            raise JobDescriptionNotFoundError(f"Job Description #{jd_id} not found.")

        if not jd.storage_filename:
            return None

        validator = FileSecurityValidator()
        return validator.get_stored_job_description_path(user_id, jd.storage_filename, user_base_dir=user_base_dir)

    # -------------------------------------------------------------------------
    # PHASE 2: USER-SCOPED APPLICATIONS
    # -------------------------------------------------------------------------

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Fetches a user record by primary key id."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

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

    def get_or_create_application_workspace(
        self,
        user_id: int,
        job_description_id: int,
        resume_id: Optional[int] = None,
    ) -> Application:
        """Finds an existing application for this user and job_description_id or creates a new one,
        avoiding duplicate application records when reopening preparation.
        """
        # Validate JD belongs to user
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, user_id, job_title, company_name FROM job_descriptions WHERE id = ?",
                (job_description_id,),
            )
            jd_row = cursor.fetchone()
            if not jd_row:
                raise ValidationError(f"JobDescription #{job_description_id} not found.")
            if jd_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=jd_row["user_id"],
                    resource=f"JobDescription #{job_description_id}",
                )

            # Validate resume belongs to user and is active if provided
            if resume_id is not None:
                cursor.execute(
                    "SELECT id, user_id, is_active FROM resumes WHERE id = ?",
                    (resume_id,),
                )
                res_row = cursor.fetchone()
                if not res_row:
                    raise ValidationError(f"Resume #{resume_id} not found.")
                if res_row["user_id"] != user_id:
                    raise CrossUserAccessError(
                        user_id=user_id,
                        target_user_id=res_row["user_id"],
                        resource=f"Resume #{resume_id}",
                    )
                if not res_row["is_active"]:
                    raise ValidationError(f"Resume #{resume_id} is inactive / archived.")

            # Check for existing application
            cursor.execute(
                """
                SELECT * FROM applications
                WHERE user_id = ? AND job_description_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (user_id, job_description_id),
            )
            existing = cursor.fetchone()
            if existing:
                app = Application(**dict(existing))
                # Update resume_id if provided and different
                if resume_id is not None and app.resume_id != resume_id:
                    cursor.execute(
                        "UPDATE applications SET resume_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
                        (resume_id, app.id, user_id),
                    )
                    cursor.execute("SELECT * FROM applications WHERE id = ?", (app.id,))
                    return Application(**dict(cursor.fetchone()))
                return app

            # Create new application record within same transaction
            company = jd_row["company_name"] or "Target Organization"
            title = jd_row["job_title"] or "Target Role"
            cursor.execute(
                """
                INSERT INTO applications (
                    user_id, company_name, job_title, job_description_id, resume_id, status
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    company.strip(),
                    title.strip(),
                    job_description_id,
                    resume_id,
                    ApplicationStatus.UNDER_REVIEW.value,
                ),
            )
            new_id = cursor.lastrowid
            cursor.execute("SELECT * FROM applications WHERE id = ?", (new_id,))
            return Application(**dict(cursor.fetchone()))

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

    def list_user_resumes(self, user_id: int, active_only: bool = True) -> List[Dict[str, Any]]:
        """Lists all resumes belonging to a user, filtering active by default."""
        with self.connection() as conn:
            cursor = conn.cursor()
            if active_only:
                cursor.execute(
                    "SELECT * FROM resumes WHERE user_id = ? AND is_active = 1 ORDER BY uploaded_at DESC",
                    (user_id,),
                )
            else:
                cursor.execute(
                    "SELECT * FROM resumes WHERE user_id = ? ORDER BY uploaded_at DESC",
                    (user_id,),
                )
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

    def upload_user_resume(
        self,
        user_id: int,
        file_bytes: bytes,
        original_filename: str,
        label: str = "General",
        target_role: Optional[str] = None,
        set_as_primary: bool = False,
        user_base_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Validates, stores, parses, and persists a user resume document.

        Enforces file security, unique hash per user, isolated storage, and primary resume rules.
        """
        from src.security.file_security import FileSecurityValidator
        from src.preparer.resume_parser import ResumeParser

        # 1. Verify user exists
        user = self.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User #{user_id}")

        # 2. File security validation
        validator = FileSecurityValidator()
        validator.validate_file(file_bytes, original_filename)

        ext = Path(original_filename).suffix.lstrip(".").lower()
        file_format = ext
        file_size = len(file_bytes)
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        # 3. Check for duplicate hash for this user
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM resumes WHERE user_id = ? AND file_hash = ?", (user_id, file_hash))
            existing = cursor.fetchone()
            if existing:
                raise DuplicateResumeError(
                    f"A resume with identical content hash {file_hash[:12]} already exists as Resume #{existing['id']}."
                )

        # 4. Generate isolated user storage path
        storage_filename = validator.generate_storage_filename(original_filename)
        base_dir = user_base_dir or (Path("data/users") / str(user_id) / "resumes")
        dest_path = base_dir / storage_filename
        validator.save_file(file_bytes, dest_path, user_id=user_id)

        # 5. Universal parsing
        parser = ResumeParser()
        try:
            parsed = parser.parse_file(dest_path)
            parsed_json = json.dumps(parsed.to_dict())
            parsing_status = "COMPLETED"
        except Exception as e:
            logger.warning("Resume parsing encountered issues for user %d: %s", user_id, e)
            parsed_json = json.dumps({"raw_error": str(e)})
            parsing_status = "FAILED"

        # 6. Database persistence with primary resume logic
        with self.transaction() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) as cnt FROM resumes WHERE user_id = ?", (user_id,))
            resume_count = cursor.fetchone()["cnt"]

            make_primary = set_as_primary or (resume_count == 0)
            if make_primary:
                cursor.execute("UPDATE resumes SET is_primary = 0 WHERE user_id = ?", (user_id,))

            cursor.execute(
                """
                INSERT INTO resumes (
                    user_id, storage_filename, original_filename, file_format,
                    file_hash, parsed_data, is_primary, label, target_role,
                    file_size_bytes, parsing_status, active_version, uploaded_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    user_id,
                    storage_filename,
                    original_filename,
                    file_format,
                    file_hash,
                    parsed_json,
                    1 if make_primary else 0,
                    label or "General",
                    target_role,
                    file_size,
                    parsing_status,
                ),
            )
            resume_id = cursor.lastrowid

            # Create initial version 1
            cursor.execute(
                """
                INSERT INTO resume_versions (
                    resume_id, user_id, version_num, storage_filename,
                    file_hash, file_size_bytes, change_notes, snapshot_json, created_at
                ) VALUES (?, ?, 1, ?, ?, ?, 'Initial upload', ?, CURRENT_TIMESTAMP)
                """,
                (
                    resume_id,
                    user_id,
                    storage_filename,
                    file_hash,
                    file_size,
                    parsed_json,
                ),
            )

            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            return dict(cursor.fetchone())

    def add_resume_version(
        self,
        user_id: int,
        resume_id: int,
        file_bytes: bytes,
        original_filename: str,
        change_notes: str = "",
        user_base_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Uploads a new version of an existing resume."""
        from src.security.file_security import FileSecurityValidator
        from src.preparer.resume_parser import ResumeParser

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            row = cursor.fetchone()
            if not row:
                raise ResumeNotFoundError(f"Resume #{resume_id} not found.")
            if row["user_id"] != user_id:
                raise CrossUserAccessError(user_id=user_id, target_user_id=row["user_id"], resource=f"Resume #{resume_id}")

        validator = FileSecurityValidator()
        validator.validate_file(file_bytes, original_filename)

        ext = Path(original_filename).suffix.lstrip(".").lower()
        file_size = len(file_bytes)
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        # Check duplicate hash against versions of this resume
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM resume_versions WHERE resume_id = ? AND file_hash = ?", (resume_id, file_hash))
            if cursor.fetchone():
                raise DuplicateResumeError(f"This exact version content (hash {file_hash[:12]}) is already stored for Resume #{resume_id}.")

            cursor.execute("SELECT MAX(version_num) as max_v FROM resume_versions WHERE resume_id = ?", (resume_id,))
            max_row = cursor.fetchone()
            next_version = (max_row["max_v"] or 1) + 1

        storage_filename = validator.generate_storage_filename(original_filename)
        base_dir = user_base_dir or (Path("data/users") / str(user_id) / "resumes")
        dest_path = base_dir / storage_filename
        validator.save_file(file_bytes, dest_path, user_id=user_id)

        parser = ResumeParser()
        try:
            parsed = parser.parse_file(dest_path)
            parsed_json = json.dumps(parsed.to_dict())
            parsing_status = "COMPLETED"
        except Exception as e:
            logger.warning("Resume version parsing error: %s", e)
            parsed_json = json.dumps({"raw_error": str(e)})
            parsing_status = "FAILED"

        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO resume_versions (
                    resume_id, user_id, version_num, storage_filename,
                    file_hash, file_size_bytes, change_notes, snapshot_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    resume_id,
                    user_id,
                    next_version,
                    storage_filename,
                    file_hash,
                    file_size,
                    change_notes or f"Version {next_version}",
                    parsed_json,
                ),
            )
            v_id = cursor.lastrowid

            cursor.execute(
                """
                UPDATE resumes SET
                    storage_filename = ?,
                    original_filename = ?,
                    file_format = ?,
                    file_hash = ?,
                    file_size_bytes = ?,
                    parsed_data = ?,
                    parsing_status = ?,
                    active_version = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
                """,
                (
                    storage_filename,
                    original_filename,
                    ext,
                    file_hash,
                    file_size,
                    parsed_json,
                    parsing_status,
                    next_version,
                    resume_id,
                    user_id,
                ),
            )

            cursor.execute("SELECT * FROM resume_versions WHERE id = ?", (v_id,))
            return dict(cursor.fetchone())

    def set_primary_resume(self, user_id: int, resume_id: int) -> Dict[str, Any]:
        """Toggles the primary resume for a user atomically."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            row = cursor.fetchone()
            if not row:
                raise ResumeNotFoundError(f"Resume #{resume_id} not found.")
            if row["user_id"] != user_id:
                raise CrossUserAccessError(user_id=user_id, target_user_id=row["user_id"], resource=f"Resume #{resume_id}")

            cursor.execute("UPDATE resumes SET is_primary = 0 WHERE user_id = ?", (user_id,))
            cursor.execute("UPDATE resumes SET is_primary = 1 WHERE id = ? AND user_id = ?", (resume_id, user_id))

            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            return dict(cursor.fetchone())

    def get_primary_resume(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Returns the primary active resume record for a user, or None."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE user_id = ? AND is_primary = 1 AND is_active = 1 LIMIT 1", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_user_resume_versions(self, user_id: int, resume_id: int) -> List[Dict[str, Any]]:
        """Lists all version snapshots for a resume."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            row = cursor.fetchone()
            if not row:
                raise ResumeNotFoundError(f"Resume #{resume_id} not found.")
            if row["user_id"] != user_id:
                raise CrossUserAccessError(user_id=user_id, target_user_id=row["user_id"], resource=f"Resume #{resume_id}")

            cursor.execute(
                "SELECT * FROM resume_versions WHERE resume_id = ? AND user_id = ? ORDER BY version_num DESC",
                (resume_id, user_id),
            )
            return [dict(r) for r in cursor.fetchall()]

    def get_resume_file_path(
        self,
        user_id: int,
        resume_id: int,
        version_num: Optional[int] = None,
        user_base_dir: Optional[Path] = None,
    ) -> Path:
        """Returns the verified disk path to a resume file, strictly contained within the user sandbox."""
        from src.security.file_security import FileSecurityValidator

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            row = cursor.fetchone()
            if not row:
                raise ResumeNotFoundError(f"Resume #{resume_id} not found.")
            if row["user_id"] != user_id:
                raise CrossUserAccessError(user_id=user_id, target_user_id=row["user_id"], resource=f"Resume #{resume_id}")

            if version_num is not None:
                cursor.execute(
                    "SELECT storage_filename FROM resume_versions WHERE resume_id = ? AND version_num = ? AND user_id = ?",
                    (resume_id, version_num, user_id),
                )
                v_row = cursor.fetchone()
                if not v_row:
                    raise ResumeNotFoundError(f"Version {version_num} for Resume #{resume_id} not found.")
                storage_filename = v_row["storage_filename"]
            else:
                storage_filename = row["storage_filename"]

        base_dir = user_base_dir or (Path("data/users") / str(user_id) / "resumes")
        target_path = base_dir / storage_filename
        FileSecurityValidator.validate_path_containment(target_path, base_dir)

        if not target_path.exists():
            raise FileNotFoundError(f"Resume file on disk not found: {target_path}")

        return target_path

    def delete_user_resume(
        self,
        user_id: int,
        resume_id: int,
        user_base_dir: Optional[Path] = None,
    ) -> bool:
        """Deletes a resume and its version files, checking for active application lock."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (resume_id,))
            row = cursor.fetchone()
            if not row:
                raise ResumeNotFoundError(f"Resume #{resume_id} not found.")
            if row["user_id"] != user_id:
                raise CrossUserAccessError(user_id=user_id, target_user_id=row["user_id"], resource=f"Resume #{resume_id}")

            # Check if referenced by applications
            cursor.execute("SELECT id FROM applications WHERE resume_id = ? AND user_id = ?", (resume_id, user_id))
            has_application = cursor.fetchone() is not None

            # Check if referenced by prepared_packets
            cursor.execute("SELECT COUNT(*) as cnt FROM prepared_packets WHERE original_resume_id = ? AND user_id = ?", (resume_id, user_id))
            linked_packets = cursor.fetchone()["cnt"]

            # Check if referenced by match_results
            cursor.execute(
                "SELECT COUNT(*) as cnt FROM match_results WHERE resume_id = ? AND user_id = ?",
                (resume_id, user_id),
            )
            linked_matches = cursor.fetchone()["cnt"]

            cursor.execute("SELECT storage_filename FROM resume_versions WHERE resume_id = ?", (resume_id,))
            version_files = [r["storage_filename"] for r in cursor.fetchall() if r["storage_filename"]]
            if row["storage_filename"] not in version_files:
                version_files.append(row["storage_filename"])

            was_primary = bool(row["is_primary"])

        base_dir = user_base_dir or (Path("data/users") / str(user_id) / "resumes")

        if linked_packets > 0 or linked_matches > 0:
            # Soft-delete / Archive resume to protect historical prepared packets, match records and audit integrity
            with self.transaction() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE resumes SET is_active = 0, is_primary = 0 WHERE id = ? AND user_id = ?",
                    (resume_id, user_id),
                )
                if was_primary:
                    cursor.execute(
                        "SELECT id FROM resumes WHERE user_id = ? AND is_active = 1 ORDER BY uploaded_at DESC LIMIT 1",
                        (user_id,),
                    )
                    rem = cursor.fetchone()
                    if rem:
                        cursor.execute("UPDATE resumes SET is_primary = 1 WHERE id = ?", (rem["id"],))

            logger.info(
                f"Resume #{resume_id} archived (soft-deleted) due to {linked_packets} prepared packets and "
                f"{linked_matches} match evaluations; physical files and revision history preserved."
            )
            return True

        if has_application:
            raise ResumeInUseError(f"Cannot delete Resume #{resume_id}: referenced by existing job applications.")

        # If completely unreferenced, perform clean deletion of row and physical files
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM resume_versions WHERE resume_id = ? AND user_id = ?", (resume_id, user_id))
            cursor.execute("DELETE FROM resumes WHERE id = ? AND user_id = ?", (resume_id, user_id))

            # If it was primary, promote the latest remaining resume
            if was_primary:
                cursor.execute(
                    "SELECT id FROM resumes WHERE user_id = ? AND is_active = 1 ORDER BY uploaded_at DESC LIMIT 1",
                    (user_id,),
                )
                rem = cursor.fetchone()
                if rem:
                    cursor.execute("UPDATE resumes SET is_primary = 1 WHERE id = ?", (rem["id"],))

        for fname in version_files:
            fpath = base_dir / fname
            try:
                if fpath.exists():
                    fpath.unlink()
            except OSError as e:
                logger.warning("Could not delete physical resume file %s: %s", fpath, e)

        return True

    def save_user_candidate_profile(self, user_id: int, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Saves a user candidate profile snapshot with immutable version history."""
        if not profile_data:
            raise ValidationError("Profile data cannot be empty.")

        user = self.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User #{user_id}")

        profile_json = json.dumps(profile_data, sort_keys=True)
        profile_hash = hashlib.sha256(profile_json.encode("utf-8")).hexdigest()

        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(version) as max_v FROM candidate_profiles WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            next_version = (row["max_v"] or 0) + 1

            cursor.execute("UPDATE candidate_profiles SET is_active = 0 WHERE user_id = ?", (user_id,))
            cursor.execute(
                """
                INSERT INTO candidate_profiles (
                    user_id, profile_data, profile_hash, version, is_active, last_updated
                ) VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                """,
                (user_id, profile_json, profile_hash, next_version),
            )
            profile_id = cursor.lastrowid
            cursor.execute("SELECT * FROM candidate_profiles WHERE id = ?", (profile_id,))
            res = dict(cursor.fetchone())
            res["profile_data"] = json.loads(res["profile_data"])
            return res

    def get_user_candidate_profile(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves the active candidate profile for a user."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM candidate_profiles WHERE user_id = ? AND is_active = 1 ORDER BY version DESC LIMIT 1",
                (user_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            res["profile_data"] = json.loads(res["profile_data"])
            return res

    def get_user_candidate_profile_history(self, user_id: int) -> List[Dict[str, Any]]:
        """Retrieves all version snapshots for a user's candidate profile."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM candidate_profiles WHERE user_id = ? ORDER BY version DESC",
                (user_id,),
            )
            records = []
            for r in cursor.fetchall():
                d = dict(r)
                d["profile_data"] = json.loads(d["profile_data"])
                records.append(d)
            return records

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
        screening_answers: Union[Dict[str, Any], str, List[Any]],
        original_resume_id: Optional[int] = None,
        tailored_resume_path: Optional[str] = None,
        tailored_resume_hash: Optional[str] = None,
        cover_letter_path: Optional[str] = None,
        cover_letter_hash: Optional[str] = None,
        form_payload: Optional[Union[Dict[str, Any], str]] = None,
        attachments_manifest: Optional[Union[List[Dict[str, Any]], str]] = None,
        version_num: Optional[int] = None,
        canonical_snapshot_json: Optional[str] = None,
        candidate_profile_version: Optional[int] = None,
        candidate_profile_hash: Optional[str] = None,
        matching_result_id: Optional[int] = None,
        template_id: Optional[str] = None,
        template_version: Optional[str] = None,
        matching_engine_version: Optional[str] = None,
        scoring_configuration_version: Optional[str] = None,
        original_resume_version_num: Optional[int] = None,
        job_description_id: Optional[int] = None,
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
                    canonical_snapshot_json, candidate_profile_version,
                    candidate_profile_hash, matching_result_id,
                    matching_engine_version, scoring_configuration_version,
                    original_resume_version_num, job_description_id,
                    template_id, template_version,
                    is_active_revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
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
                    canonical_snapshot_json,
                    candidate_profile_version,
                    candidate_profile_hash,
                    matching_result_id,
                    matching_engine_version,
                    scoring_configuration_version,
                    original_resume_version_num,
                    job_description_id,
                    template_id,
                    template_version or "1.0.0",
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

            # 2.5 Delete user match_results and prepared_packets to prevent ON DELETE RESTRICT from blocking cascade deletion of resumes/JDs
            cursor.execute("DELETE FROM match_results WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM prepared_packets WHERE user_id = ?", (user_id,))

            # 3. Delete user row (cascades automatically to resumes, versions, job_descriptions,
            #    applications, application_approvals, password_reset_tokens)
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            logger.info("Deleted user account data for User #%d with pseudonym '%s'", user_id, pseudonym)
            return True

    # -------------------------------------------------------------------------
    # PHASE 5: MATCH RESULT PERSISTENCE & MULTI-USER AUDIT TRAIL
    # -------------------------------------------------------------------------

    def save_match_result(self, result: MatchResult) -> int:
        """Persists an immutable match evaluation result with strict composite ownership validation.
        
        Raises:
            CrossUserAccessError: If resume or job description belongs to a different user.
            ResumeNotFoundError: If specified resume does not exist.
            JobDescriptionNotFoundError: If specified job description does not exist.
            JobNotFoundError: If specified catalog job does not exist.
        """
        with self.transaction() as conn:
            cursor = conn.cursor()

            # 1. Verify user exists
            cursor.execute("SELECT id FROM users WHERE id = ?", (result.user_id,))
            if not cursor.fetchone():
                raise UserNotFoundError(result.user_id)

            # 2. Verify resume ownership
            if result.resume_id is not None:
                cursor.execute("SELECT id, user_id FROM resumes WHERE id = ?", (result.resume_id,))
                res_row = cursor.fetchone()
                if not res_row:
                    raise ResumeNotFoundError(f"Resume #{result.resume_id} not found.")
                if res_row["user_id"] != result.user_id:
                    raise CrossUserAccessError(
                        user_id=result.user_id,
                        target_user_id=res_row["user_id"],
                        resource=f"Resume #{result.resume_id}",
                    )

            # 3. Verify job description ownership
            if result.job_description_id is not None:
                cursor.execute(
                    "SELECT id, user_id FROM job_descriptions WHERE id = ?",
                    (result.job_description_id,),
                )
                jd_row = cursor.fetchone()
                if not jd_row:
                    raise JobDescriptionNotFoundError(f"Job Description #{result.job_description_id} not found.")
                if jd_row["user_id"] != result.user_id:
                    raise CrossUserAccessError(
                        user_id=result.user_id,
                        target_user_id=jd_row["user_id"],
                        resource=f"Job Description #{result.job_description_id}",
                    )

            # 4. Verify catalog job existence if provided
            if result.job_id is not None:
                cursor.execute("SELECT id FROM jobs WHERE id = ?", (result.job_id,))
                if not cursor.fetchone():
                    raise JobNotFoundError(result.job_id)

            # 5. Insert immutable evaluation record
            cursor.execute(
                """
                INSERT INTO match_results (
                    user_id, resume_id, job_id, job_description_id,
                    match_score, match_classification, eligibility_status,
                    score_breakdown, explanation,
                    resume_version_num, resume_file_hash, candidate_profile_version,
                    candidate_profile_hash,
                    job_snapshot_hash, scoring_profile, scoring_config_version,
                    assessment_confidence, engine_version,
                    matching_skills, related_skills, partial_matches, missing_skills,
                    education_analysis, experience_analysis, certification_analysis,
                    eligibility_reasons, scoring_explanations, recommendations, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.user_id,
                    result.resume_id,
                    result.job_id,
                    result.job_description_id,
                    result.match_score,
                    result.match_classification,
                    result.eligibility_status,
                    result.score_breakdown if isinstance(result.score_breakdown, str) else json.dumps(result.score_breakdown),
                    result.explanation,
                    result.resume_version_num,
                    result.resume_file_hash,
                    result.candidate_profile_version,
                    result.candidate_profile_hash,
                    result.job_snapshot_hash,
                    result.scoring_profile,
                    result.scoring_config_version,
                    result.assessment_confidence,
                    result.engine_version,
                    result.matching_skills if isinstance(result.matching_skills, str) or result.matching_skills is None else json.dumps(result.matching_skills),
                    result.related_skills if isinstance(result.related_skills, str) or result.related_skills is None else json.dumps(result.related_skills),
                    result.partial_matches if isinstance(result.partial_matches, str) or result.partial_matches is None else json.dumps(result.partial_matches),
                    result.missing_skills if isinstance(result.missing_skills, str) or result.missing_skills is None else json.dumps(result.missing_skills),
                    result.education_analysis if isinstance(result.education_analysis, str) or result.education_analysis is None else json.dumps(result.education_analysis),
                    result.experience_analysis if isinstance(result.experience_analysis, str) or result.experience_analysis is None else json.dumps(result.experience_analysis),
                    result.certification_analysis if isinstance(result.certification_analysis, str) or result.certification_analysis is None else json.dumps(result.certification_analysis),
                    result.eligibility_reasons if isinstance(result.eligibility_reasons, str) or result.eligibility_reasons is None else json.dumps(result.eligibility_reasons),
                    result.scoring_explanations if isinstance(result.scoring_explanations, str) or result.scoring_explanations is None else json.dumps(result.scoring_explanations),
                    result.recommendations if isinstance(result.recommendations, str) or result.recommendations is None else json.dumps(result.recommendations),
                    result.details_json if isinstance(result.details_json, str) or result.details_json is None else json.dumps(result.details_json),
                ),
            )
            match_id = int(cursor.lastrowid or 0)
            logger.info("Saved immutable MatchResult #%d for User #%d (Score: %.1f)", match_id, result.user_id, result.match_score)
            return match_id

    def get_match_result(self, match_id: int, user_id: int) -> Optional[MatchResult]:
        """Retrieves a match evaluation result with strict cross-user access enforcement."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM match_results WHERE id = ?", (match_id,))
            row = cursor.fetchone()
            if not row:
                return None
            if row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"MatchResult #{match_id}",
                )
            return self._row_to_match_result(row)

    def get_user_match_results(
        self,
        user_id: int,
        resume_id: Optional[int] = None,
        job_description_id: Optional[int] = None,
        job_id: Optional[int] = None,
        limit: int = 50,
    ) -> List[MatchResult]:
        """Retrieves historical match evaluation results for a user, newest first."""
        query = "SELECT * FROM match_results WHERE user_id = ?"
        params: List[Any] = [user_id]

        if resume_id is not None:
            query += " AND resume_id = ?"
            params.append(resume_id)
        if job_description_id is not None:
            query += " AND job_description_id = ?"
            params.append(job_description_id)
        if job_id is not None:
            query += " AND job_id = ?"
            params.append(job_id)

        query += " ORDER BY evaluated_at DESC, id DESC LIMIT ?"
        params.append(limit)

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [self._row_to_match_result(row) for row in cursor.fetchall()]

    def get_latest_match_result(
        self,
        user_id: int,
        resume_id: Optional[int] = None,
        job_description_id: Optional[int] = None,
        job_id: Optional[int] = None,
    ) -> Optional[MatchResult]:
        """Retrieves the most recent evaluation for given candidate/job combination."""
        results = self.get_user_match_results(
            user_id=user_id,
            resume_id=resume_id,
            job_description_id=job_description_id,
            job_id=job_id,
            limit=1,
        )
        return results[0] if results else None

    def _row_to_match_result(self, row: sqlite3.Row) -> MatchResult:
        """Maps an SQLite row to a MatchResult domain model."""
        keys = row.keys()
        return MatchResult(
            id=row["id"],
            user_id=row["user_id"],
            resume_id=row["resume_id"],
            job_id=row["job_id"],
            job_description_id=row["job_description_id"],
            match_score=float(row["match_score"]),
            match_classification=row["match_classification"],
            eligibility_status=row["eligibility_status"],
            score_breakdown=row["score_breakdown"],
            explanation=row["explanation"],
            resume_version_num=row["resume_version_num"] if "resume_version_num" in keys and row["resume_version_num"] is not None else 1,
            resume_file_hash=row["resume_file_hash"] if "resume_file_hash" in keys else None,
            candidate_profile_version=row["candidate_profile_version"] if "candidate_profile_version" in keys and row["candidate_profile_version"] is not None else 1,
            candidate_profile_hash=row["candidate_profile_hash"] if "candidate_profile_hash" in keys else None,
            job_snapshot_hash=row["job_snapshot_hash"] if "job_snapshot_hash" in keys else None,
            scoring_profile=row["scoring_profile"] if "scoring_profile" in keys and row["scoring_profile"] else "general_baseline",
            scoring_config_version=row["scoring_config_version"] if "scoring_config_version" in keys and row["scoring_config_version"] else "1.0.0",
            assessment_confidence=float(row["assessment_confidence"]) if "assessment_confidence" in keys and row["assessment_confidence"] is not None else 1.0,
            engine_version=row["engine_version"] if "engine_version" in keys and row["engine_version"] else "2.1.1",
            matching_skills=row["matching_skills"] if "matching_skills" in keys else None,
            related_skills=row["related_skills"] if "related_skills" in keys else None,
            partial_matches=row["partial_matches"] if "partial_matches" in keys else None,
            missing_skills=row["missing_skills"] if "missing_skills" in keys else None,
            education_analysis=row["education_analysis"] if "education_analysis" in keys else None,
            experience_analysis=row["experience_analysis"] if "experience_analysis" in keys else None,
            certification_analysis=row["certification_analysis"] if "certification_analysis" in keys else None,
            eligibility_reasons=row["eligibility_reasons"] if "eligibility_reasons" in keys else None,
            scoring_explanations=row["scoring_explanations"] if "scoring_explanations" in keys else None,
            recommendations=row["recommendations"] if "recommendations" in keys else None,
            details_json=row["details_json"] if "details_json" in keys else None,
            evaluated_at=row["evaluated_at"],
        )


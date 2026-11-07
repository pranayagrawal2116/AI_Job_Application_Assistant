"""SQLite Database Manager for AI Job Application Assistant."""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional, Set, Tuple, Union

import pandas as pd

from src.database.exceptions import (
    ApplicationNotFoundError,
    ConcurrencyConflictError,
    CrossUserAccessError,
    DatabaseError,
    DatabaseMigrationError,
    DuplicateJobDescriptionError,
    DuplicateJobError,
    DuplicateResumeError,
    EventIntegrityError,
    InvalidFileFormatError,
    InvalidStatusError,
    InvalidStatusTransitionError,
    JobDescriptionNotFoundError,
    JobNotFoundError,
    KeyRevokedError,
    MigrationPreflightError,
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
    ApplicationEvent,
    ApplicationFollowUp,
    ApplicationLog,
    ApplicationSource,
    ApplicationStatus,
    CandidateProfileRecord,
    Company,
    FollowUpType,
    Job,
    JobDescription,
    MatchResult,
    PreparedPacket,
    SubmissionChannel,
    SubmissionConfirmation,
    VerifiedApprovalGrant,
    SecurityScan,
    SecurityScanOverride,
    LegacyIntegrityException,
    LegacyEvidenceAttestation,
)
from src.database.url_normalizer import (
    generate_company_title_key,
    normalize_job_url,
)
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash
from src.utils.logger import setup_logger

logger = setup_logger("DatabaseManager")

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
_env_db_path = os.environ.get("DATABASE_PATH") or os.environ.get("SQLITE_DB_PATH")
DEFAULT_DB_PATH = (
    Path(_env_db_path).resolve()
    if _env_db_path
    else (Path(__file__).resolve().parent.parent.parent / "data" / "storage" / "job_assistant.db")
)
_env_exports_dir = os.environ.get("EXPORTS_DIR")
DEFAULT_EXPORTS_DIR = (
    Path(_env_exports_dir).resolve()
    if _env_exports_dir
    else (Path(__file__).resolve().parent.parent.parent / "data" / "exports")
)
_env_backup_dir = os.environ.get("BACKUP_DIR")
DEFAULT_BACKUP_DIR = (
    Path(_env_backup_dir).resolve()
    if _env_backup_dir
    else (Path(__file__).resolve().parent.parent.parent / "data" / "storage" / "backups")
)


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


class ImmediateAwareCursor(sqlite3.Cursor):
    """SQLite cursor subclass that notifies its ImmediateAwareConnection on BEGIN IMMEDIATE."""

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        clean_sql = sql.strip().upper() if isinstance(sql, str) else ""
        conn = self.connection
        if conn is not None and hasattr(conn, "_tx_is_immediate"):
            if clean_sql.startswith("BEGIN IMMEDIATE"):
                conn._tx_is_immediate = True
            elif clean_sql.startswith("BEGIN") and not clean_sql.startswith("BEGIN IMMEDIATE"):
                conn._tx_is_immediate = False
            elif clean_sql.startswith("COMMIT") or clean_sql.startswith("ROLLBACK"):
                conn._tx_is_immediate = False
        return super().execute(sql, *args, **kwargs)


class ImmediateAwareConnection(sqlite3.Connection):
    """SQLite connection subclass that explicitly tracks whether an IMMEDIATE transaction write-lock is held."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tx_is_immediate: bool = False

    def cursor(self, factory: Any = ImmediateAwareCursor) -> sqlite3.Cursor:
        return super().cursor(factory=factory)

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        clean_sql = sql.strip().upper() if isinstance(sql, str) else ""
        if clean_sql.startswith("BEGIN IMMEDIATE"):
            self._tx_is_immediate = True
        elif clean_sql.startswith("BEGIN") and not clean_sql.startswith("BEGIN IMMEDIATE"):
            self._tx_is_immediate = False
        elif clean_sql.startswith("COMMIT") or clean_sql.startswith("ROLLBACK"):
            self._tx_is_immediate = False
        return super().execute(sql, *args, **kwargs)

    def commit(self) -> None:
        self._tx_is_immediate = False
        super().commit()

    def rollback(self) -> None:
        self._tx_is_immediate = False
        super().rollback()


def _normalize_datetime(dt_val: Any) -> datetime:
    """Normalizes a timestamp string or datetime object to a UTC-aware datetime.

    Strictly rejects timezone-naive timestamps and non-datetime values.
    """
    if dt_val is None:
        raise SecurityAuthorizationError("Timestamp value cannot be None.")
    if isinstance(dt_val, bool):
        raise SecurityAuthorizationError("Timestamp value cannot be boolean.")
    if isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            raise SecurityAuthorizationError("Timezone-naive datetime is strictly prohibited.")
        return dt_val.astimezone(timezone.utc)
    if isinstance(dt_val, str):
        clean_str = dt_val.strip()
        if not clean_str:
            raise SecurityAuthorizationError("Timestamp string cannot be empty.")
        try:
            if clean_str.endswith("Z") or clean_str.endswith("z"):
                clean_str = clean_str[:-1] + "+00:00"
            parsed = datetime.fromisoformat(clean_str)
            if parsed.tzinfo is None:
                raise SecurityAuthorizationError(f"Timezone-naive timestamp string '{dt_val}' is strictly prohibited.")
            return parsed.astimezone(timezone.utc)
        except Exception as e:
            if isinstance(e, SecurityAuthorizationError):
                raise
            raise SecurityAuthorizationError(f"Invalid timestamp format '{dt_val}': {e}") from e
    raise SecurityAuthorizationError(f"Unsupported timestamp type '{type(dt_val).__name__}'.")


class DatabaseManager:
    """Manages SQLite database connections, transactions, and CRUD operations."""

    def __init__(
        self,
        db_path: Union[str, Path] = DEFAULT_DB_PATH,
        schema_path: Union[str, Path] = DEFAULT_SCHEMA_PATH,
        session_manager: Optional[Any] = None,
        service_authenticator: Optional[Any] = None,
    ):
        self.db_path = str(db_path)
        self.schema_path = Path(schema_path)
        self.exports_dir = Path(DEFAULT_EXPORTS_DIR)
        self.backup_dir = Path(DEFAULT_BACKUP_DIR)
        self._service_authenticator: Optional[Any] = None
        if service_authenticator is not None:
            self.set_service_authenticator(service_authenticator)

        from src.security.session_manager import SessionManager
        if session_manager is not None:
            if type(session_manager) is not SessionManager:
                raise SecurityAuthorizationError(
                    f"Invalid verifier configuration: session_manager must be an exact SessionManager instance, got {type(session_manager)}."
                )
            if hasattr(session_manager, "register_db_manager"):
                session_manager.register_db_manager(self)
        self._session_manager = session_manager

        # Ensure parent directory exists for file-based DB and exports/backups
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            self.exports_dir.mkdir(parents=True, exist_ok=True)

        self._init_db()

    @property
    def session_manager(self) -> Any:
        from src.security.session_manager import SessionManager
        sm = self._session_manager if self._session_manager is not None else SessionManager.get_instance()
        if type(sm) is not SessionManager:
            raise SecurityAuthorizationError(
                f"Invalid verifier configuration: session_manager must be an exact SessionManager instance, got {type(sm)}."
            )
        if hasattr(sm, "register_db_manager"):
            sm.register_db_manager(self)
        return sm

    def set_service_authenticator(self, authenticator: Optional[Any]) -> None:
        """Configures the authoritative ServiceAuthenticationProvider for attestation persistence.

        Invariants:
        - Must be an instance of ServiceAuthenticationProvider (or None in dev/test only).
        - Cannot replace an already configured authenticator with a different provider instance.
        - Re-registering the identical provider instance is idempotent.
        - Cannot replace with None in production/staging/qa once configured.
        - Provider configured for development/test cannot be attached in production-like environments.
        """
        from src.security.legacy_evidence_verifier import ServiceAuthenticationProvider
        app_env = getattr(self, "app_env", None) or os.environ.get("APP_ENV", "development").strip().lower()
        is_production_like = app_env in ("production", "staging", "qa")

        if authenticator is None:
            if is_production_like and self._service_authenticator is not None:
                raise SecurityAuthorizationError(
                    f"Cannot remove configured service authenticator in '{app_env}' environment."
                )
            self._service_authenticator = None
            return

        if not isinstance(authenticator, ServiceAuthenticationProvider):
            raise SecurityAuthorizationError(
                f"Invalid service authenticator: must be an instance of ServiceAuthenticationProvider, got {type(authenticator).__name__}."
            )

        auth_env = getattr(authenticator, "app_env", None)
        if is_production_like and auth_env not in ("production", "staging", "qa"):
            raise SecurityAuthorizationError(
                f"ServiceAuthenticationProvider configured for '{auth_env}' cannot be used in production-like environment '{app_env}'."
            )

        if self._service_authenticator is not None:
            if authenticator is not self._service_authenticator:
                raise SecurityAuthorizationError(
                    "DatabaseManager service authenticator is already configured and locked. "
                    "Replacing configured authenticator with a different instance is strictly prohibited."
                )
            return

        self._service_authenticator = authenticator

    @property
    def service_authenticator(self) -> Optional[Any]:
        return self._service_authenticator

    @service_authenticator.setter
    def service_authenticator(self, authenticator: Optional[Any]) -> None:
        self.set_service_authenticator(authenticator)

    def get_connection(self, timeout: Optional[float] = None) -> sqlite3.Connection:
        """Creates and configures a new SQLite connection."""
        timeout_val = timeout if timeout is not None else 5.0
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=timeout_val,
            factory=ImmediateAwareConnection,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL;")
        # Register default connection-scoped authorization function rejecting application_events deletions
        conn.create_function("verify_privacy_erasure_authorization", 1, lambda uid: 0)
        return conn

    @contextmanager
    def _authorized_privacy_erasure_scope(
        self, conn: sqlite3.Connection, user_id: int
    ) -> Generator[None, None, None]:
        """Activates an ephemeral, connection-scoped authorization granting deletion of application_events
        strictly for the specified user_id for the duration of the context block.
        """
        def _verify_auth(uid: int) -> int:
            return 1 if uid == user_id else 0

        conn.create_function("verify_privacy_erasure_authorization", 1, _verify_auth)
        try:
            yield
        finally:
            conn.create_function("verify_privacy_erasure_authorization", 1, lambda uid: 0)

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

    @contextmanager
    def immediate_transaction(self, timeout: Optional[float] = None) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing an atomic database transaction with an immediate write lock (BEGIN IMMEDIATE).

        Prevents concurrent read-before-write races by acquiring SQLite's RESERVED write lock
        at the beginning of the transaction before any SELECT or inspection statements.
        Commits on normal block exit, rolls back on any exception, and closes connection.
        """
        conn = self.get_connection(timeout=timeout)
        conn.isolation_level = None  # Autocommit mode to allow explicit BEGIN IMMEDIATE
        txn_started = False
        try:
            conn.execute("BEGIN IMMEDIATE")
            txn_started = True
            yield conn
            conn.execute("COMMIT")
            txn_started = False
        except Exception as e:
            if txn_started:
                try:
                    conn.execute("ROLLBACK")
                except Exception as rollback_err:
                    logger.warning("Rollback failed in immediate_transaction: %s", rollback_err)
            logger.error("Immediate transaction failed and was rolled back: %s", e)
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
        add_col_if_missing("resumes", "file_size_bytes", "INTEGER")
        add_col_if_missing("resumes", "file_hash", "TEXT")
        add_col_if_missing("resume_versions", "file_size_bytes", "INTEGER")
        add_col_if_missing("resume_versions", "file_hash", "TEXT")
        add_col_if_missing("resume_versions", "storage_filename", "TEXT")
        add_col_if_missing("jobs", "company_id", "INTEGER")
        add_col_if_missing("candidate_profiles", "profile_hash", "TEXT")
        add_col_if_missing("job_descriptions", "source_url", "TEXT")
        add_col_if_missing("job_descriptions", "original_filename", "TEXT")
        add_col_if_missing("job_descriptions", "storage_filename", "TEXT")
        add_col_if_missing("job_descriptions", "parser_version", "TEXT DEFAULT '1.0.0'")
        add_col_if_missing("job_descriptions", "extraction_confidence", "REAL DEFAULT 1.0")
        add_col_if_missing("job_descriptions", "content_hash", "TEXT")
        add_col_if_missing("job_descriptions", "supersedes_job_description_id", "INTEGER")
        add_col_if_missing("job_descriptions", "snapshot_hash", "TEXT")
        add_col_if_missing("job_descriptions", "is_active", "INTEGER DEFAULT 1")
        add_col_if_missing("job_descriptions", "file_hash", "TEXT")
        add_col_if_missing("job_descriptions", "file_size_bytes", "INTEGER")
        add_col_if_missing("job_descriptions", "file_format", "TEXT")
        add_col_if_missing("job_descriptions", "binary_integrity_state", "TEXT DEFAULT 'REQUIRED'")
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
        add_col_if_missing("prepared_packets", "scoring_profile", "TEXT")
        add_col_if_missing("prepared_packets", "original_resume_version_num", "INTEGER")
        add_col_if_missing("prepared_packets", "job_description_id", "INTEGER")
        add_col_if_missing("prepared_packets", "template_id", "TEXT")
        add_col_if_missing("prepared_packets", "template_version", "TEXT DEFAULT '1.0.0'")
        add_col_if_missing("applications", "application_source", "TEXT NOT NULL DEFAULT 'JOB_DESCRIPTION'")
        add_col_if_missing("applications", "external_application_url", "TEXT")
        add_col_if_missing("applications", "target_role", "TEXT")
        add_col_if_missing("applications", "employment_type", "TEXT")
        add_col_if_missing("applications", "location", "TEXT")
        add_col_if_missing("applications", "salary_range", "TEXT")
        add_col_if_missing("applications", "application_deadline", "DATETIME")
        add_col_if_missing("applications", "is_archived", "INTEGER DEFAULT 0")
        add_col_if_missing("application_approvals", "is_revoked", "INTEGER DEFAULT 0")
        add_col_if_missing("application_approvals", "revoked_at", "DATETIME")
        add_col_if_missing("application_approvals", "revocation_reason", "TEXT")
        add_col_if_missing("security_scans", "source_binary_hash", "TEXT")
        add_col_if_missing("security_scans", "source_binary_size_bytes", "INTEGER")
        add_col_if_missing("security_scans", "source_binary_format", "TEXT")
        add_col_if_missing("security_scans", "manifest_version", "TEXT DEFAULT 'v1'")
        add_col_if_missing("legacy_integrity_exceptions", "evidence_type", "TEXT")
        add_col_if_missing("legacy_integrity_exceptions", "evidence_reference_id", "TEXT")

        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS revoked_signing_keys (
                    key_id TEXT PRIMARY KEY,
                    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT NOT NULL
                )
            """)
        except sqlite3.OperationalError:
            pass

        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS revoked_attesting_principals (
                    principal_id TEXT PRIMARY KEY,
                    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT NOT NULL
                )
            """)
        except sqlite3.OperationalError:
            pass

        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS _sqlite_write_lock_sentinel (
                    id INTEGER PRIMARY KEY,
                    updated_at TEXT NOT NULL
                )
            """)
        except sqlite3.OperationalError:
            pass

        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS resume_recovery_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    resume_id INTEGER NOT NULL,
                    version_num INTEGER NOT NULL,
                    previous_state_json TEXT NOT NULL,
                    recovered_file_hash TEXT,
                    recovered_file_size_bytes INTEGER,
                    recovery_outcome TEXT NOT NULL,
                    details TEXT,
                    recovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_resume_recovery_audit_update
                BEFORE UPDATE ON resume_recovery_audit
                BEGIN
                    SELECT RAISE(FAIL, 'resume_recovery_audit records are append-only and cannot be updated.');
                END
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_resume_recovery_audit_delete
                BEFORE DELETE ON resume_recovery_audit
                BEGIN
                    SELECT RAISE(FAIL, 'resume_recovery_audit records are immutable and cannot be deleted except via authorized privacy erasure.')
                    WHERE verify_privacy_erasure_authorization(OLD.user_id) != 1;
                END
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    source_type TEXT NOT NULL CHECK(source_type IN ('job_description', 'resume')),
                    source_id INTEGER NOT NULL,
                    source_version INTEGER NOT NULL DEFAULT 1,
                    source_hash TEXT NOT NULL,
                    snapshot_hash TEXT,
                    scanner_version TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    classification TEXT NOT NULL CHECK(classification IN ('CLEAN', 'SUSPICIOUS', 'QUARANTINED')),
                    threats_detected_json TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    hmac_signature TEXT NOT NULL,
                    source_binary_hash TEXT,
                    source_binary_size_bytes INTEGER,
                    source_binary_format TEXT,
                    manifest_version TEXT DEFAULT 'v1',
                    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_security_scans_update
                BEFORE UPDATE ON security_scans
                BEGIN
                    SELECT RAISE(FAIL, 'security_scans records are append-only and cannot be updated.');
                END
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_security_scans_delete
                BEFORE DELETE ON security_scans
                BEGIN
                    SELECT RAISE(FAIL, 'security_scans records are immutable and cannot be deleted except via authorized privacy erasure.')
                    WHERE verify_privacy_erasure_authorization(OLD.user_id) != 1;
                END
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_scan_overrides (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    scan_id INTEGER NOT NULL REFERENCES security_scans(id),
                    source_type TEXT NOT NULL,
                    source_id INTEGER NOT NULL,
                    source_version INTEGER NOT NULL,
                    override_reason TEXT NOT NULL,
                    actor_type TEXT NOT NULL DEFAULT 'candidate',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_security_scan_overrides_update
                BEFORE UPDATE ON security_scan_overrides
                BEGIN
                    SELECT RAISE(FAIL, 'security_scan_overrides records are append-only and cannot be updated.');
                END
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_security_scan_overrides_delete
                BEFORE DELETE ON security_scan_overrides
                BEGIN
                    SELECT RAISE(FAIL, 'security_scan_overrides records are immutable and cannot be deleted except via authorized privacy erasure.')
                    WHERE verify_privacy_erasure_authorization(OLD.user_id) != 1;
                END
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_scans_lookup ON security_scans(user_id, source_type, source_id, source_version)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_scans_hash ON security_scans(source_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_scan_overrides_lookup ON security_scan_overrides(user_id, scan_id)")
        except sqlite3.OperationalError:
            pass

        # Legacy integrity exceptions table and triggers (Phase 9.1.2.3 Durable Migration Audit)
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS legacy_integrity_exceptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    job_description_id INTEGER NOT NULL REFERENCES job_descriptions(id) ON DELETE RESTRICT,
                    original_source_type TEXT NOT NULL,
                    previous_binary_state TEXT,
                    assigned_legacy_state TEXT NOT NULL,
                    source_snapshot_hash TEXT,
                    migration_version TEXT NOT NULL,
                    evidence_type TEXT,
                    evidence_reference_id TEXT,
                    migration_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    migration_reason TEXT NOT NULL,
                    outcome TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_legacy_integrity_exceptions_update
                BEFORE UPDATE ON legacy_integrity_exceptions
                BEGIN
                    SELECT RAISE(FAIL, 'legacy_integrity_exceptions records are append-only and cannot be updated.');
                END
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_legacy_integrity_exceptions_delete
                BEFORE DELETE ON legacy_integrity_exceptions
                BEGIN
                    SELECT RAISE(FAIL, 'legacy_integrity_exceptions records are immutable and cannot be deleted.');
                END
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_legacy_integrity_exceptions_lookup ON legacy_integrity_exceptions(user_id, job_description_id)")
        except sqlite3.OperationalError:
            pass

        add_col_if_missing("legacy_integrity_exceptions", "evidence_type", "TEXT")
        add_col_if_missing("legacy_integrity_exceptions", "evidence_reference_id", "TEXT")

        # Legacy evidence attestations table and triggers (Phase 9.1.2.5 & 9.1.2.6 Authoritative Provenance)
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS legacy_evidence_attestations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    job_description_id INTEGER NOT NULL REFERENCES job_descriptions(id) ON DELETE CASCADE,
                    evidence_type TEXT NOT NULL,
                    evidence_reference_id TEXT NOT NULL,
                    source_snapshot_hash TEXT NOT NULL,
                    evidence_artifact_hash TEXT,
                    evidence_payload_hash TEXT,
                    issuer_id TEXT,
                    key_id TEXT,
                    signature_algorithm TEXT,
                    evidence_signature TEXT,
                    migration_boundary TEXT,
                    attested_by TEXT NOT NULL,
                    attested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    verified_at DATETIME,
                    details TEXT
                )
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_legacy_evidence_attestations_update
                BEFORE UPDATE ON legacy_evidence_attestations
                BEGIN
                    SELECT RAISE(FAIL, 'legacy_evidence_attestations records are append-only and cannot be updated.');
                END
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_legacy_evidence_attestations_delete
                BEFORE DELETE ON legacy_evidence_attestations
                BEGIN
                    SELECT RAISE(FAIL, 'legacy_evidence_attestations records are immutable and cannot be deleted.');
                END
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_legacy_evidence_attestations_lookup ON legacy_evidence_attestations(job_description_id, user_id)")
        except sqlite3.OperationalError:
            pass

        add_col_if_missing("legacy_evidence_attestations", "evidence_artifact_hash", "TEXT")
        add_col_if_missing("legacy_evidence_attestations", "evidence_payload_hash", "TEXT")
        add_col_if_missing("legacy_evidence_attestations", "issuer_id", "TEXT")
        add_col_if_missing("legacy_evidence_attestations", "key_id", "TEXT")
        add_col_if_missing("legacy_evidence_attestations", "signature_algorithm", "TEXT")
        add_col_if_missing("legacy_evidence_attestations", "evidence_signature", "TEXT")
        add_col_if_missing("legacy_evidence_attestations", "migration_boundary", "TEXT")
        add_col_if_missing("legacy_evidence_attestations", "verified_at", "DATETIME")

        # Database schema migration ledger table (Phase 9.1.2.4 Migration Finality)
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    migration_id TEXT PRIMARY KEY,
                    migration_version TEXT NOT NULL,
                    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)
        except sqlite3.OperationalError:
            pass

        self._migrate_historical_job_description_integrity(cursor)
        self._migrate_phase_9_1_2_5_legacy_evidence_reconciliation(cursor)
        self._migrate_phase_9_1_2_6_legacy_evidence_verification_closure(cursor)

        # Composite indexes required to safely satisfy composite foreign keys in application_approvals
        try:
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_applications_id_user ON applications(id, user_id)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_prepared_packets_id_user ON prepared_packets(id, user_id)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_applications_user_jd ON applications(user_id, job_description_id) WHERE job_description_id IS NOT NULL")
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_job_descriptions_unique_active_child
                ON job_descriptions(user_id, supersedes_job_description_id)
                WHERE supersedes_job_description_id IS NOT NULL AND is_active = 1
            """)
        except sqlite3.OperationalError:
            pass

    def _migrate_historical_job_description_integrity(self, cursor: sqlite3.Cursor) -> None:
        """Migrates historical job descriptions to authoritative binary_integrity_state.

        Enforces one-time finality via schema_migrations ledger:
        1. Checks if 'phase_9_1_2_3_legacy_binary_integrity' has already been recorded. If so, skips.
        2. Non-uploaded records (pasted, url, etc.) -> NOT_APPLICABLE.
        3. Uploaded records with all 4 binary fields populated -> VERIFIED.
        4. Evaluates candidates for LEGACY_TEXT_ONLY:
           - source_type in ('uploaded_document', 'upload')
           - all 4 binary metadata fields are strictly NULL
           - binary_integrity_state != 'VERIFIED' (never downgrade VERIFIED)
           - rejects partially populated metadata
           - rejects candidates with signed scans having binary provenance (source_binary_hash IS NOT NULL)
           - validates pre-migration canonical snapshot hash against 9-key manifest schema
           - validates pre-migration database provenance (created_at present, pre-migration snapshot)
        5. For each verified candidate, inserts an immutable audit record in legacy_integrity_exceptions
           and sets binary_integrity_state = 'LEGACY_TEXT_ONLY'.
        6. Atomically records completion marker 'phase_9_1_2_3_legacy_binary_integrity' in schema_migrations.
        """
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='job_descriptions'")
        if not cursor.fetchone():
            return  # Table will be created fresh by schema.sql

        # Ensure schema_migrations table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_id TEXT PRIMARY KEY,
                migration_version TEXT NOT NULL,
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        """)

        # 1. One-time finality check via migration ledger
        cursor.execute("SELECT 1 FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
        if cursor.fetchone():
            logger.debug("Migration phase_9_1_2_3_legacy_binary_integrity already applied; skipping.")
            return

        # 2. Non-uploaded records (pasted, url, etc.) -> NOT_APPLICABLE
        cursor.execute(
            """
            UPDATE job_descriptions
            SET binary_integrity_state = 'NOT_APPLICABLE'
            WHERE (binary_integrity_state = 'REQUIRED' OR binary_integrity_state IS NULL)
              AND lower(source_type) NOT IN ('uploaded_document', 'upload')
            """
        )

        # 3. Uploaded records with all 4 binary fields populated -> VERIFIED
        cursor.execute(
            """
            UPDATE job_descriptions
            SET binary_integrity_state = 'VERIFIED'
            WHERE (binary_integrity_state = 'REQUIRED' OR binary_integrity_state IS NULL)
              AND lower(source_type) IN ('uploaded_document', 'upload')
              AND storage_filename IS NOT NULL
              AND file_hash IS NOT NULL
              AND file_size_bytes IS NOT NULL
              AND file_format IS NOT NULL
            """
        )

        # 4. Check candidates for LEGACY_TEXT_ONLY
        # Section 3.3: Never convert existing VERIFIED records to LEGACY_TEXT_ONLY
        cursor.execute(
            """
            SELECT id, user_id, source_type, company_name, job_title, raw_content, content_hash,
                   snapshot_hash, parsed_data, parser_version, source_url, original_filename,
                   binary_integrity_state, created_at, storage_filename, file_hash, file_size_bytes, file_format
            FROM job_descriptions
            WHERE lower(source_type) IN ('uploaded_document', 'upload')
              AND (binary_integrity_state = 'REQUIRED' OR binary_integrity_state IS NULL)
              AND binary_integrity_state != 'VERIFIED'
            """
        )
        candidates = cursor.fetchall()
        migrated_count = 0

        for cand in candidates:
            jd_id = cand[0] if isinstance(cand, tuple) else cand["id"]
            u_id = cand[1] if isinstance(cand, tuple) else cand["user_id"]
            s_type = cand[2] if isinstance(cand, tuple) else cand["source_type"]
            comp_name = cand[3] if isinstance(cand, tuple) else cand["company_name"]
            j_title = cand[4] if isinstance(cand, tuple) else cand["job_title"]
            c_hash = cand[6] if isinstance(cand, tuple) else cand["content_hash"]
            s_hash = cand[7] if isinstance(cand, tuple) else cand["snapshot_hash"]
            p_data = cand[8] if isinstance(cand, tuple) else cand["parsed_data"]
            p_ver = cand[9] if isinstance(cand, tuple) else cand["parser_version"]
            s_url = cand[10] if isinstance(cand, tuple) else cand["source_url"]
            orig_name = cand[11] if isinstance(cand, tuple) else cand["original_filename"]
            prev_state = cand[12] if isinstance(cand, tuple) else cand["binary_integrity_state"]
            created_at = cand[13] if isinstance(cand, tuple) else cand["created_at"]
            s_fn = cand[14] if isinstance(cand, tuple) else cand["storage_filename"]
            f_hash = cand[15] if isinstance(cand, tuple) else cand["file_hash"]
            f_size = cand[16] if isinstance(cand, tuple) else cand["file_size_bytes"]
            f_fmt = cand[17] if isinstance(cand, tuple) else cand["file_format"]

            # Section 3.3: Reject partially populated metadata
            # All 4 binary fields must be strictly NULL for a legacy text-only candidate
            if s_fn is not None or f_hash is not None or f_size is not None or f_fmt is not None:
                continue

            # Section 3.3: Check for previous signed scans with binary provenance
            cursor.execute(
                """
                SELECT 1 FROM security_scans
                WHERE source_type = 'job_description'
                  AND source_id = ?
                  AND source_binary_hash IS NOT NULL
                LIMIT 1
                """,
                (jd_id,),
            )
            if cursor.fetchone():
                continue

            # Section 3.3: Verify candidate snapshot hash matches canonical 9-key pre-migration manifest
            # A modern Phase 9.1.1+ record has a 13-key manifest (including binary fields)
            try:
                parsed_dict = json.loads(p_data) if p_data and isinstance(p_data, str) else p_data
            except Exception:
                parsed_dict = None

            manifest_9 = {
                "user_id": u_id,
                "company_name": comp_name,
                "job_title": j_title,
                "raw_content_hash": c_hash,
                "parsed_data": parsed_dict,
                "parser_version": p_ver or "1.0.0",
                "source_type": s_type,
                "source_url": s_url,
                "original_filename": orig_name,
            }
            expected_legacy_hash = canonical_json_hash(manifest_9)
            if not s_hash or s_hash != expected_legacy_hash:
                continue

            # Section 3.2 & Phase 9.1.2.5 Part B: Evidence-based eligibility
            # Manifest structure and created_at timestamps alone do not prove historical provenance.
            # A candidate may enter LEGACY_TEXT_ONLY only when its historical origin is supported
            # by an authoritative independent evidence source in legacy_evidence_attestations.
            if not created_at:
                continue

            cursor.execute(
                """
                SELECT evidence_type, evidence_reference_id, source_snapshot_hash, attested_by
                FROM legacy_evidence_attestations
                WHERE job_description_id = ? AND user_id = ?
                LIMIT 1
                """,
                (jd_id, u_id),
            )
            attestation = cursor.fetchone()
            if not attestation:
                # Unknown historical origin = NOT VERIFIED (Phase 9.1.2.5 Section 4.2).
                # Remains in REQUIRED (fail-closed); do not grandfather without external evidence.
                continue

            ev_type = attestation[0] if isinstance(attestation, tuple) else attestation["evidence_type"]
            ev_ref = attestation[1] if isinstance(attestation, tuple) else attestation["evidence_reference_id"]
            ev_hash = attestation[2] if isinstance(attestation, tuple) else attestation["source_snapshot_hash"]
            att_by = attestation[3] if len(attestation) > 3 else "system_migration"

            if not ev_type or not str(ev_type).strip() or not ev_ref or not str(ev_ref).strip():
                continue
            if ev_hash != s_hash:
                continue

            # Phase 9.1.2.6 Section 5.1: Independently resolve and cryptographically verify evidence artifact
            from src.security.legacy_evidence_verifier import LegacyEvidenceVerifier

            verifier = LegacyEvidenceVerifier(db_manager=self)
            try:
                verifier.verify(
                    evidence_type=ev_type,
                    evidence_reference_id=ev_ref,
                    user_id=u_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=s_hash,
                    attesting_principal=att_by or "system_migration_coordinator",
                )
            except Exception as e:
                logger.warning("Historical migration evidence verification failed for JD #%d: %s", jd_id, e)
                continue

            # Check if already recorded in legacy_integrity_exceptions
            cursor.execute(
                """
                SELECT 1 FROM legacy_integrity_exceptions
                WHERE job_description_id = ? AND user_id = ?
                LIMIT 1
                """,
                (jd_id, u_id),
            )
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT INTO legacy_integrity_exceptions (
                        user_id, job_description_id, original_source_type,
                        previous_binary_state, assigned_legacy_state,
                        source_snapshot_hash, migration_version,
                        evidence_type, evidence_reference_id,
                        migration_reason, outcome
                    ) VALUES (?, ?, ?, ?, 'LEGACY_TEXT_ONLY', ?, '9.1.2.3', ?, ?,
                              'Grandfathered historical record supported by authoritative external evidence', 'SUCCESS')
                    """,
                    (u_id, jd_id, s_type, prev_state or "REQUIRED", s_hash, ev_type, ev_ref),
                )

            cursor.execute(
                """
                UPDATE job_descriptions
                SET binary_integrity_state = 'LEGACY_TEXT_ONLY'
                WHERE id = ?
                """,
                (jd_id,),
            )
            migrated_count += 1

        # Section 3.1 & 3.4 & Phase 9.1.2.5 Section 7: Record completion in schema_migrations
        self.record_schema_migration(
            migration_id="phase_9_1_2_3_legacy_binary_integrity",
            migration_version="9.1.2.3",
            details=f"Migrated {migrated_count} legacy records to LEGACY_TEXT_ONLY",
            cursor=cursor,
        )

    def _migrate_phase_9_1_2_5_legacy_evidence_reconciliation(self, cursor: sqlite3.Cursor) -> None:
        """Phase 9.1.2.5 corrective migration: reconciles existing legacy exception records.

        Enforces Section 4.3 & 4.4:
        1. Checks if 'phase_9_1_2_5_legacy_evidence_closure' has already been recorded in schema_migrations. If so, skips.
        2. Queries all records currently claiming LEGACY_TEXT_ONLY state.
        3. For each record:
           - Verifies if authoritative independent evidence exists in legacy_evidence_attestations matching source_snapshot_hash.
           - If verified evidence exists: records reconciliation audit in legacy_integrity_exceptions (SUCCESS).
           - If NO verified evidence exists (unknown historical origin): reverts binary_integrity_state to 'REQUIRED' (fail closed)
             and records reconciliation audit in legacy_integrity_exceptions (REVERTED).
        4. Atomically records completion marker 'phase_9_1_2_5_legacy_evidence_closure' in schema_migrations.
        """
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='job_descriptions'")
        if not cursor.fetchone():
            return

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_id TEXT PRIMARY KEY,
                migration_version TEXT NOT NULL,
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        """)

        cursor.execute("SELECT 1 FROM schema_migrations WHERE migration_id = 'phase_9_1_2_5_legacy_evidence_closure'")
        if cursor.fetchone():
            logger.debug("Migration phase_9_1_2_5_legacy_evidence_closure already applied; skipping.")
            return

        cursor.execute(
            """
            SELECT id, user_id, source_type, snapshot_hash, binary_integrity_state
            FROM job_descriptions
            WHERE binary_integrity_state = 'LEGACY_TEXT_ONLY'
            """
        )
        legacy_records = cursor.fetchall()
        reconciled_count = 0
        reverted_count = 0

        for rec in legacy_records:
            jd_id = rec[0] if isinstance(rec, tuple) else rec["id"]
            u_id = rec[1] if isinstance(rec, tuple) else rec["user_id"]
            s_type = rec[2] if isinstance(rec, tuple) else rec["source_type"]
            s_hash = rec[3] if isinstance(rec, tuple) else rec["snapshot_hash"]

            # Query authoritative independent evidence
            cursor.execute(
                """
                SELECT evidence_type, evidence_reference_id, source_snapshot_hash
                FROM legacy_evidence_attestations
                WHERE job_description_id = ? AND user_id = ?
                LIMIT 1
                """,
                (jd_id, u_id),
            )
            attestation = cursor.fetchone()

            has_valid_evidence = False
            ev_type = None
            ev_ref = None
            if attestation:
                ev_type = attestation[0] if isinstance(attestation, tuple) else attestation["evidence_type"]
                ev_ref = attestation[1] if isinstance(attestation, tuple) else attestation["evidence_reference_id"]
                ev_hash = attestation[2] if isinstance(attestation, tuple) else attestation["source_snapshot_hash"]
                if ev_type and str(ev_type).strip() and ev_ref and str(ev_ref).strip() and ev_hash == s_hash:
                    has_valid_evidence = True

            if has_valid_evidence:
                cursor.execute(
                    """
                    INSERT INTO legacy_integrity_exceptions (
                        user_id, job_description_id, original_source_type,
                        previous_binary_state, assigned_legacy_state,
                        source_snapshot_hash, migration_version,
                        evidence_type, evidence_reference_id,
                        migration_reason, outcome
                    ) VALUES (?, ?, ?, 'LEGACY_TEXT_ONLY', 'LEGACY_TEXT_ONLY', ?, '9.1.2.5', ?, ?,
                              'Phase 9.1.2.5 evidence reconciliation: authoritative external evidence verified', 'SUCCESS')
                    """,
                    (u_id, jd_id, s_type, s_hash, ev_type, ev_ref),
                )
                reconciled_count += 1
            else:
                # Unknown historical origin = NOT VERIFIED (Section 4.2). Revert to REQUIRED.
                cursor.execute(
                    "UPDATE job_descriptions SET binary_integrity_state = 'REQUIRED' WHERE id = ?",
                    (jd_id,),
                )
                cursor.execute(
                    """
                    INSERT INTO legacy_integrity_exceptions (
                        user_id, job_description_id, original_source_type,
                        previous_binary_state, assigned_legacy_state,
                        source_snapshot_hash, migration_version,
                        evidence_type, evidence_reference_id,
                        migration_reason, outcome
                    ) VALUES (?, ?, ?, 'LEGACY_TEXT_ONLY', 'REQUIRED', ?, '9.1.2.5', 'NONE', 'NONE',
                              'Phase 9.1.2.5 evidence reconciliation: lacked independent historical evidence proof; reverted to REQUIRED', 'REVERTED')
                    """,
                    (u_id, jd_id, s_type, s_hash),
                )
                reverted_count += 1

        self.record_schema_migration(
            migration_id="phase_9_1_2_5_legacy_evidence_closure",
            migration_version="9.1.2.5",
            details=f"Reconciled {reconciled_count} verified legacy records; reverted {reverted_count} unattested records to REQUIRED",
            cursor=cursor,
        )

    def _migrate_phase_9_1_2_6_legacy_evidence_verification_closure(
        self,
        cursor: sqlite3.Cursor,
        verifier: Optional[Any] = None,
    ) -> None:
        """Phase 9.1.2.6 cryptographic legacy evidence verification reconciliation migration.

        Enforces Section 5.2:
        1. Checks if 'phase_9_1_2_6_legacy_evidence_verification_closure' has already been recorded in schema_migrations. If so, skips.
        2. Queries all records currently claiming LEGACY_TEXT_ONLY state.
        3. For each record:
           - Retrieves independent evidence attestation from legacy_evidence_attestations.
           - Invokes LegacyEvidenceVerifier to independently resolve and cryptographically verify the backing artifact.
           - If verified: preserves 'LEGACY_TEXT_ONLY', records reconciliation audit in legacy_integrity_exceptions (outcome='RECONCILED').
           - If missing, unverifiable, or tampered evidence:
             Reverts binary_integrity_state to 'REQUIRED'.
             Records audit in legacy_integrity_exceptions (outcome='REVERTED', assigned_legacy_state='REQUIRED',
             previous_binary_state='LEGACY_TEXT_ONLY', migration_version='phase_9_1_2_6',
             migration_reason='Phase 9.1.2.6 reconciliation: evidence artifact could not be independently verified').
        4. Atomically records completion marker 'phase_9_1_2_6_legacy_evidence_verification_closure' in schema_migrations.
        """
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='job_descriptions'")
        if not cursor.fetchone():
            return

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_id TEXT PRIMARY KEY,
                migration_version TEXT NOT NULL,
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        """)

        cursor.execute("SELECT 1 FROM schema_migrations WHERE migration_id = 'phase_9_1_2_6_legacy_evidence_verification_closure'")
        if cursor.fetchone():
            logger.debug("Migration phase_9_1_2_6_legacy_evidence_verification_closure already applied; skipping.")
            return

        from src.security.legacy_evidence_verifier import LegacyEvidenceVerifier

        active_verifier = verifier or LegacyEvidenceVerifier(db_manager=self)

        cursor.execute(
            """
            SELECT id, user_id, source_type, snapshot_hash, binary_integrity_state
            FROM job_descriptions
            WHERE binary_integrity_state = 'LEGACY_TEXT_ONLY'
            """
        )
        legacy_records = cursor.fetchall()
        reconciled_count = 0
        reverted_count = 0

        for rec in legacy_records:
            jd_id = rec[0] if isinstance(rec, tuple) else rec["id"]
            u_id = rec[1] if isinstance(rec, tuple) else rec["user_id"]
            s_type = rec[2] if isinstance(rec, tuple) else rec["source_type"]
            s_hash = rec[3] if isinstance(rec, tuple) else rec["snapshot_hash"]

            cursor.execute(
                """
                SELECT evidence_type, evidence_reference_id, source_snapshot_hash, attested_by
                FROM legacy_evidence_attestations
                WHERE job_description_id = ? AND user_id = ?
                LIMIT 1
                """,
                (jd_id, u_id),
            )
            attestation = cursor.fetchone()

            has_valid_evidence = False
            ev_type = None
            ev_ref = None

            if attestation:
                ev_type = attestation[0] if isinstance(attestation, tuple) else attestation["evidence_type"]
                ev_ref = attestation[1] if isinstance(attestation, tuple) else attestation["evidence_reference_id"]
                ev_hash = attestation[2] if isinstance(attestation, tuple) else attestation["source_snapshot_hash"]
                att_by = attestation[3] if len(attestation) > 3 else "system_migration"

                if ev_type and str(ev_type).strip() and ev_ref and str(ev_ref).strip() and ev_hash == s_hash:
                    try:
                        active_verifier.verify(
                            evidence_type=ev_type,
                            evidence_reference_id=ev_ref,
                            user_id=u_id,
                            job_description_id=jd_id,
                            source_snapshot_hash=s_hash,
                            attesting_principal=att_by or "system_migration_coordinator",
                        )
                        has_valid_evidence = True
                    except Exception as e:
                        logger.warning("Phase 9.1.2.6 reconciliation: failed to verify evidence for JD #%d: %s", jd_id, e)
                        has_valid_evidence = False

            if has_valid_evidence:
                cursor.execute(
                    """
                    INSERT INTO legacy_integrity_exceptions (
                        user_id, job_description_id, original_source_type,
                        previous_binary_state, assigned_legacy_state,
                        source_snapshot_hash, migration_version,
                        evidence_type, evidence_reference_id,
                        migration_reason, outcome
                    ) VALUES (?, ?, ?, 'LEGACY_TEXT_ONLY', 'LEGACY_TEXT_ONLY', ?, 'phase_9_1_2_6', ?, ?,
                              'Phase 9.1.2.6 evidence reconciliation: authoritative external evidence verified', 'RECONCILED')
                    """,
                    (u_id, jd_id, s_type, s_hash, ev_type, ev_ref),
                )
                reconciled_count += 1
            else:
                cursor.execute(
                    "UPDATE job_descriptions SET binary_integrity_state = 'REQUIRED' WHERE id = ?",
                    (jd_id,),
                )
                cursor.execute(
                    """
                    INSERT INTO legacy_integrity_exceptions (
                        user_id, job_description_id, original_source_type,
                        previous_binary_state, assigned_legacy_state,
                        source_snapshot_hash, migration_version,
                        evidence_type, evidence_reference_id,
                        migration_reason, outcome
                    ) VALUES (?, ?, ?, 'LEGACY_TEXT_ONLY', 'REQUIRED', ?, 'phase_9_1_2_6', ?, ?,
                              'Phase 9.1.2.6 reconciliation: evidence artifact could not be independently verified; reverted to REQUIRED', 'REVERTED')
                    """,
                    (u_id, jd_id, s_type, s_hash, ev_type or "NONE", ev_ref or "NONE"),
                )
                reverted_count += 1

        self.record_schema_migration(
            migration_id="phase_9_1_2_6_legacy_evidence_verification_closure",
            migration_version="phase_9_1_2_6",
            details=f"Reconciled {reconciled_count} verified records, reverted {reverted_count} unverified records to REQUIRED",
            cursor=cursor,
        )

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
                scoring_profile TEXT,
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
            "scoring_configuration_version", "scoring_profile", "original_resume_version_num",
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

    def _migrate_application_logs_job_id_nullable(self, conn: sqlite3.Connection) -> None:
        """Migrates application_logs table to allow NULL job_id (aligning with schema.sql).

        Candidate applications created from user job descriptions or custom roles may not have a catalog job_id.
        """
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='application_logs'")
        if not cursor.fetchone():
            return

        cursor.execute("PRAGMA table_info(application_logs)")
        cols = cursor.fetchall()
        job_id_not_null = False
        for c in cols:
            name = c[1]
            notnull = c[3]
            if name == "job_id" and notnull == 1:
                job_id_not_null = True
                break

        if not job_id_not_null:
            return

        logger.info("Migrating application_logs to allow NULL job_id...")
        cursor.execute("PRAGMA foreign_keys = OFF")
        cursor.execute("DROP TABLE IF EXISTS application_logs_new")
        cursor.execute("""
            CREATE TABLE application_logs_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
                application_id INTEGER REFERENCES applications(id) ON DELETE SET NULL,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                anonymized_user_pseudonym TEXT,
                action TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        """)

        col_names = [c[1] for c in cols]
        common = [col for col in ["id", "job_id", "application_id", "user_id", "anonymized_user_pseudonym", "action", "timestamp", "details"] if col in col_names]
        cols_str = ", ".join(common)
        cursor.execute(f"INSERT INTO application_logs_new ({cols_str}) SELECT {cols_str} FROM application_logs")
        cursor.execute("DROP TABLE application_logs")
        cursor.execute("ALTER TABLE application_logs_new RENAME TO application_logs")
        cursor.execute("PRAGMA foreign_keys = ON")
        logger.info("application_logs migration completed successfully.")

    def _migrate_discovery_runs_table(self, conn: sqlite3.Connection) -> None:
        """Creates or updates the discovery_runs table for persistent candidate-scoped discovery runs."""
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discovery_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK(status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIAL')),
                target_roles_json TEXT NOT NULL DEFAULT '[]',
                target_locations_json TEXT NOT NULL DEFAULT '[]',
                query_count INTEGER DEFAULT 0,
                new_jobs_count INTEGER DEFAULT 0,
                duplicates_skipped INTEGER DEFAULT 0,
                restricted_count INTEGER DEFAULT 0,
                source_outcomes_json TEXT NOT NULL DEFAULT '{}',
                error_message TEXT,
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovery_runs_user_status ON discovery_runs(user_id, status)")
        # Cleanly mark stale in-memory runs from prior server process as FAILED
        cursor.execute("UPDATE discovery_runs SET status = 'FAILED', error_message = 'Interrupted by server restart' WHERE status = 'RUNNING'")
        logger.info("discovery_runs migration checked successfully.")

    def _migrate_phase7_lifecycle_tables(self, conn: sqlite3.Connection) -> None:
        """Migrates applications and lifecycle tables to Phase 7 universal architecture.

        Enforces:
        - Strict user_id NOT NULL on applications
        - ON DELETE RESTRICT on job_descriptions and resumes (via composite FKs)
        - ON DELETE RESTRICT on prepared_packets in submission_confirmations
        - Status CHECK constraint allowing 12 universal lifecycle statuses + legacy aliases
        - Zero-fabrication legacy status translation (with approval verification for Awaiting Approval)
        - Creation and verification of application_events (with append-only and privacy-erasure triggers)
        - Preflight verification aborting on NULL user_id or cross-user references under write lock
        """
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='applications'")
        if not cursor.fetchone():
            return  # Table will be created fresh by schema.sql

        # Check existing schema on applications
        cursor.execute("PRAGMA table_info(applications)")
        app_cols = {r["name"]: dict(r) for r in cursor.fetchall()}
        user_id_col = app_cols.get("user_id")
        is_user_id_not_null = user_id_col is not None and bool(user_id_col["notnull"])

        cursor.execute("PRAGMA foreign_key_list(applications)")
        fks = [dict(r) for r in cursor.fetchall()]
        has_jd_restrict = any(
            fk.get("table") == "job_descriptions" and fk.get("on_delete") == "RESTRICT" for fk in fks
        )
        has_resume_restrict = any(
            fk.get("table") == "resumes" and fk.get("on_delete") == "RESTRICT" for fk in fks
        )

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='application_events'")
        has_events = cursor.fetchone() is not None

        needs_app_migration = not (is_user_id_not_null and has_jd_restrict and has_resume_restrict and has_events)

        # Check if submission_confirmations needs migration (e.g. existing Phase 7.1 db where packet_id was not RESTRICT)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='submission_confirmations'")
        has_sub_conf_table = cursor.fetchone() is not None
        needs_sub_conf_migration = False
        if has_sub_conf_table:
            cursor.execute("PRAGMA foreign_key_list(submission_confirmations)")
            sub_fks = [dict(r) for r in cursor.fetchall()]
            has_packet_restrict = any(
                fk.get("table") == "prepared_packets" and fk.get("on_delete") == "RESTRICT" for fk in sub_fks
            )
            if not has_packet_restrict:
                needs_sub_conf_migration = True

        # Check if legacy privacy erasure table or trigger exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='_privacy_erasure_tokens'")
        has_tokens_table = cursor.fetchone() is not None
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='trg_prevent_application_events_delete'")
        trg_row = cursor.fetchone()
        has_old_trigger = trg_row is not None and ("_privacy_erasure_tokens" in (trg_row[0] or ""))
        needs_trigger_migration = has_tokens_table or has_old_trigger

        if not needs_app_migration and not needs_sub_conf_migration and not needs_trigger_migration:
            return  # Already migrated and fully up to date

        logger.info("Phase 7.1: Running migration preflight checks for application lifecycle...")

        # Step 1: Set manual transaction mode, disable FKs, and acquire RESERVED write lock IMMEDIATELY
        old_isolation = conn.isolation_level
        try:
            conn.isolation_level = None  # Manual transaction mode
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys = OFF;")
            cursor.execute("BEGIN IMMEDIATE TRANSACTION;")

            # Step 1.1: Ensure quarantine tables exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS legacy_quarantined_applications (
                    id INTEGER PRIMARY KEY,
                    job_id INTEGER,
                    job_description_id INTEGER,
                    user_id INTEGER,
                    resume_id INTEGER,
                    company_name TEXT,
                    job_title TEXT,
                    status TEXT,
                    application_source TEXT,
                    external_application_url TEXT,
                    target_role TEXT,
                    employment_type TEXT,
                    location TEXT,
                    salary_range TEXT,
                    application_deadline TEXT,
                    date_prepared TEXT,
                    date_submitted TEXT,
                    resume_used TEXT,
                    cover_letter_reference TEXT,
                    notes TEXT,
                    is_archived INTEGER,
                    created_at TEXT,
                    updated_at TEXT,
                    quarantine_reason TEXT NOT NULL,
                    quarantined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS legacy_quarantined_application_events (
                    id INTEGER PRIMARY KEY,
                    application_id INTEGER,
                    user_id INTEGER,
                    sequence_no INTEGER,
                    event_type TEXT,
                    previous_status TEXT,
                    new_status TEXT,
                    actor_type TEXT,
                    actor_identifier TEXT,
                    session_reference TEXT,
                    event_payload_json TEXT,
                    previous_event_hash TEXT,
                    event_hash TEXT,
                    created_at TEXT,
                    quarantined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Step 1.2: Reconcile or quarantine unowned or invalid applications
            try:
                conn.create_function("verify_privacy_erasure_authorization", 1, lambda uid: 1)
            except Exception:
                pass

            cursor.execute("""
                SELECT id, job_id, job_description_id, user_id, resume_id,
                       company_name, job_title, status, application_source,
                       external_application_url, target_role, employment_type,
                       location, salary_range, application_deadline, date_prepared,
                       date_submitted, resume_used, cover_letter_reference, notes,
                       is_archived, created_at, updated_at
                FROM applications
                WHERE user_id IS NULL OR user_id NOT IN (SELECT id FROM users)
            """)
            problematic_apps = [dict(r) for r in cursor.fetchall()]

            if problematic_apps:
                logger.info(f"Phase 7.1 migration: Found {len(problematic_apps)} unowned or invalid application(s). Running reconciliation & quarantine...")
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='job_descriptions'")
                has_jd_tbl = cursor.fetchone() is not None
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='resumes'")
                has_res_tbl = cursor.fetchone() is not None
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='prepared_packets'")
                has_pkt_tbl = cursor.fetchone() is not None
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='application_approvals'")
                has_appr_tbl = cursor.fetchone() is not None
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='submission_confirmations'")
                has_sub_tbl = cursor.fetchone() is not None
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='application_events'")
                has_evt_tbl = cursor.fetchone() is not None

                for app in problematic_apps:
                    app_id = app["id"]
                    candidate_owners = set()

                    if has_jd_tbl and app.get("job_description_id"):
                        cursor.execute("SELECT user_id FROM job_descriptions WHERE id = ?", (app["job_description_id"],))
                        jd_r = cursor.fetchone()
                        if jd_r and jd_r[0] is not None:
                            candidate_owners.add(jd_r[0])

                    if has_res_tbl and app.get("resume_id"):
                        cursor.execute("SELECT user_id FROM resumes WHERE id = ?", (app["resume_id"],))
                        res_r = cursor.fetchone()
                        if res_r and res_r[0] is not None:
                            candidate_owners.add(res_r[0])

                    if has_pkt_tbl:
                        cursor.execute("SELECT DISTINCT user_id FROM prepared_packets WHERE application_id = ? AND user_id IS NOT NULL", (app_id,))
                        for r in cursor.fetchall():
                            candidate_owners.add(r[0])

                    if has_appr_tbl:
                        cursor.execute("SELECT DISTINCT user_id FROM application_approvals WHERE application_id = ? AND user_id IS NOT NULL", (app_id,))
                        for r in cursor.fetchall():
                            candidate_owners.add(r[0])

                    if has_sub_tbl:
                        cursor.execute("SELECT DISTINCT user_id FROM submission_confirmations WHERE application_id = ? AND user_id IS NOT NULL", (app_id,))
                        for r in cursor.fetchall():
                            candidate_owners.add(r[0])

                    if has_evt_tbl:
                        cursor.execute("SELECT DISTINCT user_id FROM application_events WHERE application_id = ? AND user_id IS NOT NULL", (app_id,))
                        for r in cursor.fetchall():
                            candidate_owners.add(r[0])

                    # Verify which candidates exist in users table
                    valid_candidates = set()
                    if candidate_owners:
                        q_marks = ",".join("?" for _ in candidate_owners)
                        cursor.execute(f"SELECT id FROM users WHERE id IN ({q_marks})", list(candidate_owners))
                        valid_candidates = {r[0] for r in cursor.fetchall()}

                    if len(valid_candidates) == 1 and len(candidate_owners) == 1:
                        # Unambiguous ownership: Reconcile!
                        reconciled_user = list(valid_candidates)[0]
                        cursor.execute("UPDATE applications SET user_id = ? WHERE id = ?", (reconciled_user, app_id))
                        if has_evt_tbl:
                            cursor.execute("UPDATE application_events SET user_id = ? WHERE application_id = ? AND (user_id IS NULL OR user_id NOT IN (SELECT id FROM users))", (reconciled_user, app_id))
                        logger.info(f"Reconciled unowned application {app_id} to user {reconciled_user} based on verified linked evidence.")
                    else:
                        # Cannot safely reconcile -> Quarantine
                        if len(candidate_owners) > 1 or len(valid_candidates) > 1:
                            quarantine_reason = "CONFLICTING_OWNERSHIP"
                        elif app.get("user_id") is None:
                            quarantine_reason = "UNOWNED_LEGACY_APPLICATION_NULL_USER_ID"
                        else:
                            quarantine_reason = "INVALID_USER_ID_NOT_IN_USERS"

                        logger.warning(f"Quarantining application {app_id}: {quarantine_reason}")
                        cursor.execute("""
                            INSERT INTO legacy_quarantined_applications (
                                id, job_id, job_description_id, user_id, resume_id,
                                company_name, job_title, status, application_source,
                                external_application_url, target_role, employment_type,
                                location, salary_range, application_deadline, date_prepared,
                                date_submitted, resume_used, cover_letter_reference, notes,
                                is_archived, created_at, updated_at, quarantine_reason
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            app["id"], app.get("job_id"), app.get("job_description_id"), app.get("user_id"), app.get("resume_id"),
                            app.get("company_name"), app.get("job_title"), app.get("status"), app.get("application_source"),
                            app.get("external_application_url"), app.get("target_role"), app.get("employment_type"),
                            app.get("location"), app.get("salary_range"), app.get("application_deadline"), app.get("date_prepared"),
                            app.get("date_submitted"), app.get("resume_used"), app.get("cover_letter_reference"), app.get("notes"),
                            app.get("is_archived") or 0, app.get("created_at"), app.get("updated_at"), quarantine_reason
                        ))

                        if has_evt_tbl:
                            cursor.execute("SELECT * FROM application_events WHERE application_id = ?", (app_id,))
                            evts = [dict(r) for r in cursor.fetchall()]
                            for evt in evts:
                                cursor.execute("""
                                    INSERT INTO legacy_quarantined_application_events (
                                        id, application_id, user_id, sequence_no, event_type,
                                        previous_status, new_status, actor_type, actor_identifier,
                                        session_reference, event_payload_json, previous_event_hash, event_hash,
                                        created_at
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """, (
                                    evt["id"], evt["application_id"], evt.get("user_id"), evt["sequence_no"], evt["event_type"],
                                    evt.get("previous_status"), evt.get("new_status"), evt["actor_type"], evt["actor_identifier"],
                                    evt.get("session_reference"), evt["event_payload_json"], evt["previous_event_hash"], evt["event_hash"],
                                    evt["created_at"]
                                ))
                            cursor.execute("DELETE FROM application_events WHERE application_id = ?", (app_id,))

                        # Null out references in application_logs if present
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='application_logs'")
                        if cursor.fetchone():
                            cursor.execute("UPDATE application_logs SET application_id = NULL WHERE application_id = ?", (app_id,))

                        # Delete from applications
                        cursor.execute("DELETE FROM applications WHERE id = ?", (app_id,))

            # Preflight Check 1: Null user_ids in applications
            cursor.execute("SELECT COUNT(*) FROM applications WHERE user_id IS NULL")
            null_users = cursor.fetchone()[0]
            if null_users > 0:
                raise MigrationPreflightError(
                    f"Migration preflight failed: {null_users} application record(s) have NULL user_id. "
                    "Historical records cannot be arbitrarily misattributed to any user."
                )

            # Preflight Check 2: Invalid user_ids (not existing in users table)
            cursor.execute("SELECT COUNT(*) FROM applications WHERE user_id NOT IN (SELECT id FROM users)")
            invalid_users = cursor.fetchone()[0]
            if invalid_users > 0:
                raise MigrationPreflightError(
                    f"Migration preflight failed: {invalid_users} application record(s) reference non-existent user_id."
                )

            # Preflight Check 3: Cross-user Job Description references
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='job_descriptions'")
            if cursor.fetchone():
                cursor.execute("""
                    SELECT COUNT(*) FROM applications a
                    JOIN job_descriptions jd ON a.job_description_id = jd.id
                    WHERE a.job_description_id IS NOT NULL AND a.user_id != jd.user_id
                """)
                cross_jd = cursor.fetchone()[0]
                if cross_jd > 0:
                    raise MigrationPreflightError(
                        f"Migration preflight failed: {cross_jd} application(s) reference job descriptions owned by another user."
                    )

            # Preflight Check 4: Cross-user Resume references
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='resumes'")
            if cursor.fetchone():
                cursor.execute("""
                    SELECT COUNT(*) FROM applications a
                    JOIN resumes r ON a.resume_id = r.id
                    WHERE a.resume_id IS NOT NULL AND a.user_id != r.user_id
                """)
                cross_res = cursor.fetchone()[0]
                if cross_res > 0:
                    raise MigrationPreflightError(
                        f"Migration preflight failed: {cross_res} application(s) reference resumes owned by another user."
                    )

            # Preflight Check 5: Cross-user Prepared Packet references
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='prepared_packets'")
            if cursor.fetchone():
                cursor.execute("""
                    SELECT COUNT(*) FROM prepared_packets p
                    JOIN applications a ON p.application_id = a.id
                    WHERE p.user_id != a.user_id
                """)
                cross_pkt = cursor.fetchone()[0]
                if cross_pkt > 0:
                    raise MigrationPreflightError(
                        f"Migration preflight failed: {cross_pkt} prepared packet(s) reference applications owned by another user."
                    )

            # Preflight Check 6: Cross-user Approval references
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='application_approvals'")
            if cursor.fetchone():
                cursor.execute("""
                    SELECT COUNT(*) FROM application_approvals ap
                    JOIN applications a ON ap.application_id = a.id
                    WHERE ap.user_id != a.user_id
                """)
                cross_appr = cursor.fetchone()[0]
                if cross_appr > 0:
                    raise MigrationPreflightError(
                        f"Migration preflight failed: {cross_appr} approval(s) reference applications owned by another user."
                    )

            logger.info("Phase 7.1 preflight passed under write lock. Executing atomic table rebuild migration...")

            if needs_app_migration:
                # Fetch applications to migrate
                cursor.execute("SELECT * FROM applications")
                old_apps = [dict(r) for r in cursor.fetchall()]

                # Query approved application IDs for deterministic status mapping
                approved_app_pairs = set()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='application_approvals'")
                has_approvals = cursor.fetchone() is not None
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='prepared_packets'")
                has_packets = cursor.fetchone() is not None
                if has_approvals and has_packets:
                    cursor.execute("""
                        SELECT DISTINCT p.application_id, p.user_id
                        FROM prepared_packets p
                        JOIN application_approvals a ON a.packet_id = p.id
                            AND a.user_id = p.user_id
                            AND a.application_id = p.application_id
                            AND a.packet_version_hash = p.packet_version_hash
                        WHERE a.is_consumed = 0
                            AND p.is_active_revision = 1
                    """)
                    approved_app_pairs = {(r[0], r[1]) for r in cursor.fetchall()}

                def map_legacy_status(app_id: int, app_user_id: Optional[int], old_status: Optional[str]) -> str:
                    if not old_status:
                        return ApplicationStatus.DRAFT.value
                    s_clean = old_status.strip()
                    s_lower = s_clean.lower()
                    if s_lower in ("discovered", "draft"):
                        return ApplicationStatus.DRAFT.value
                    if s_lower in ("under review", "shortlisted", "preparing"):
                        return ApplicationStatus.PREPARING.value
                    if s_lower in ("application prepared", "ready_for_review"):
                        return ApplicationStatus.READY_FOR_REVIEW.value
                    if s_lower == "awaiting approval":
                        is_approved = (app_id, app_user_id) in approved_app_pairs
                        return ApplicationStatus.APPROVED.value if is_approved else ApplicationStatus.READY_FOR_REVIEW.value
                    if s_lower in ("applied", "submitted"):
                        return ApplicationStatus.SUBMITTED.value
                    if s_lower in ("in_progress", "in progress"):
                        return ApplicationStatus.IN_PROGRESS.value
                    if s_lower == "assessment":
                        return ApplicationStatus.ASSESSMENT.value
                    if s_lower == "interview":
                        return ApplicationStatus.INTERVIEW.value
                    if s_lower == "offer":
                        return ApplicationStatus.OFFER.value
                    if s_lower == "rejected":
                        return ApplicationStatus.REJECTED.value
                    if s_lower == "withdrawn":
                        return ApplicationStatus.WITHDRAWN.value
                    if s_lower == "closed":
                        return ApplicationStatus.CLOSED.value
                    return ApplicationStatus.DRAFT.value

                new_status_map = {app["id"]: map_legacy_status(app["id"], app.get("user_id"), app.get("status")) for app in old_apps}

                cursor.execute("DROP TABLE IF EXISTS applications_v7")
                cursor.execute("""
                    CREATE TABLE applications_v7 (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
                        job_description_id INTEGER,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        resume_id INTEGER,
                        company_name TEXT NOT NULL,
                        job_title TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'DRAFT' CHECK(status IN (
                            'DRAFT', 'PREPARING', 'READY_FOR_REVIEW', 'APPROVED',
                            'SUBMITTED', 'IN_PROGRESS', 'ASSESSMENT', 'INTERVIEW',
                            'OFFER', 'REJECTED', 'WITHDRAWN', 'CLOSED',
                            'Discovered', 'Under Review', 'Shortlisted', 'Application Prepared',
                            'Awaiting Approval', 'Applied', 'Interview', 'Rejected', 'Withdrawn'
                        )),
                        application_source TEXT NOT NULL DEFAULT 'JOB_DESCRIPTION' CHECK(application_source IN ('JOB_DESCRIPTION', 'MATCH_RESULT', 'PREPARED_PACKET', 'MANUAL')),
                        external_application_url TEXT,
                        target_role TEXT,
                        employment_type TEXT,
                        location TEXT,
                        salary_range TEXT,
                        application_deadline DATETIME,
                        date_prepared DATETIME,
                        date_submitted DATETIME,
                        resume_used TEXT,
                        cover_letter_reference TEXT,
                        notes TEXT,
                        is_archived INTEGER DEFAULT 0 CHECK(is_archived IN (0, 1)),
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(id, user_id),
                        FOREIGN KEY (job_description_id, user_id) REFERENCES job_descriptions(id, user_id) ON DELETE RESTRICT,
                        FOREIGN KEY (resume_id, user_id) REFERENCES resumes(id, user_id) ON DELETE RESTRICT
                    )
                """)

                for app in old_apps:
                    cursor.execute("""
                        INSERT INTO applications_v7 (
                            id, job_id, job_description_id, user_id, resume_id,
                            company_name, job_title, status, application_source,
                            external_application_url, target_role, employment_type,
                            location, salary_range, application_deadline, date_prepared,
                            date_submitted, resume_used, cover_letter_reference, notes,
                            is_archived, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        app["id"],
                        app.get("job_id"),
                        app.get("job_description_id"),
                        app["user_id"],
                        app.get("resume_id"),
                        app.get("company_name") or "Unknown",
                        app.get("job_title") or "Role",
                        new_status_map[app["id"]],
                        app.get("application_source") or "JOB_DESCRIPTION",
                        app.get("external_application_url"),
                        app.get("target_role"),
                        app.get("employment_type"),
                        app.get("location"),
                        app.get("salary_range"),
                        app.get("application_deadline"),
                        app.get("date_prepared"),
                        app.get("date_submitted"),
                        app.get("resume_used"),
                        app.get("cover_letter_reference"),
                        app.get("notes"),
                        app.get("is_archived") or 0,
                        app.get("created_at"),
                        app.get("updated_at"),
                    ))

                cursor.execute("DROP TABLE applications")
                cursor.execute("ALTER TABLE applications_v7 RENAME TO applications")

                # Recreate application indexes
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_applications_user ON applications(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_applications_user_status ON applications(user_id, status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_applications_job_id ON applications(job_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_applications_archived ON applications(user_id, is_archived)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status)")
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_applications_id_user ON applications(id, user_id)")
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_applications_user_jd ON applications(user_id, job_description_id) WHERE job_description_id IS NOT NULL")

            if needs_sub_conf_migration:
                # Rebuild submission_confirmations with ON DELETE RESTRICT on prepared_packets
                logger.info("Migrating submission_confirmations to enforce ON DELETE RESTRICT on prepared_packets...")
                cursor.execute("SELECT * FROM submission_confirmations")
                old_confs = [dict(r) for r in cursor.fetchall()]

                cursor.execute("DROP TABLE IF EXISTS submission_confirmations_v7")
                cursor.execute("""
                    CREATE TABLE submission_confirmations_v7 (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        application_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        packet_id INTEGER,
                        packet_version_hash TEXT,
                        submission_timestamp DATETIME NOT NULL,
                        submission_channel TEXT NOT NULL CHECK(submission_channel IN ('COMPANY_PORTAL', 'LINKEDIN', 'INDEED', 'EMAIL', 'RECRUITER', 'REFERRAL', 'OTHER')),
                        confirmation_reference TEXT,
                        confirmation_doc_path TEXT,
                        confirmation_doc_hash TEXT,
                        candidate_notes TEXT,
                        is_active_confirmation INTEGER DEFAULT 1 CHECK(is_active_confirmation IN (0, 1)),
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE,
                        FOREIGN KEY (packet_id, user_id) REFERENCES prepared_packets(id, user_id) ON DELETE RESTRICT
                    )
                """)
                for conf_row in old_confs:
                    cursor.execute("""
                        INSERT INTO submission_confirmations_v7 (
                            id, application_id, user_id, packet_id, packet_version_hash,
                            submission_timestamp, submission_channel, confirmation_reference,
                            confirmation_doc_path, confirmation_doc_hash, candidate_notes,
                            is_active_confirmation, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        conf_row["id"],
                        conf_row["application_id"],
                        conf_row["user_id"],
                        conf_row.get("packet_id"),
                        conf_row.get("packet_version_hash"),
                        conf_row["submission_timestamp"],
                        conf_row["submission_channel"],
                        conf_row.get("confirmation_reference"),
                        conf_row.get("confirmation_doc_path"),
                        conf_row.get("confirmation_doc_hash"),
                        conf_row.get("candidate_notes"),
                        conf_row.get("is_active_confirmation", 1),
                        conf_row.get("created_at"),
                    ))

                cursor.execute("DROP TABLE submission_confirmations")
                cursor.execute("ALTER TABLE submission_confirmations_v7 RENAME TO submission_confirmations")
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_conf_active_app ON submission_confirmations(application_id) WHERE is_active_confirmation = 1")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_conf_app ON submission_confirmations(application_id, user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_conf_user_channel ON submission_confirmations(user_id, submission_channel)")

            # Create child tables if not existing
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS application_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    application_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    sequence_no INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    previous_status TEXT,
                    new_status TEXT,
                    actor_type TEXT NOT NULL DEFAULT 'CANDIDATE' CHECK(actor_type IN ('CANDIDATE', 'SYSTEM')),
                    actor_identifier TEXT NOT NULL,
                    session_reference TEXT,
                    event_payload_json TEXT NOT NULL DEFAULT '{}',
                    previous_event_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(application_id, sequence_no),
                    FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE RESTRICT
                )
            """)

            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_application_events_update
                BEFORE UPDATE ON application_events
                BEGIN
                    SELECT RAISE(FAIL, 'application_events records are append-only and cannot be updated.');
                END
            """)

            # Drop obsolete _privacy_erasure_tokens table if present
            cursor.execute("DROP TABLE IF EXISTS _privacy_erasure_tokens")

            # Recreate trg_prevent_application_events_delete with connection-scoped UDF
            cursor.execute("DROP TRIGGER IF EXISTS trg_prevent_application_events_delete")
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_prevent_application_events_delete
                BEFORE DELETE ON application_events
                BEGIN
                    SELECT RAISE(FAIL, 'application_events records are immutable and cannot be deleted except via authorized privacy erasure.')
                    WHERE verify_privacy_erasure_authorization(OLD.user_id) != 1;
                END
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS submission_confirmations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    application_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    packet_id INTEGER,
                    packet_version_hash TEXT,
                    submission_timestamp DATETIME NOT NULL,
                    submission_channel TEXT NOT NULL CHECK(submission_channel IN ('COMPANY_PORTAL', 'LINKEDIN', 'INDEED', 'EMAIL', 'RECRUITER', 'REFERRAL', 'OTHER')),
                    confirmation_reference TEXT,
                    confirmation_doc_path TEXT,
                    confirmation_doc_hash TEXT,
                    candidate_notes TEXT,
                    is_active_confirmation INTEGER DEFAULT 1 CHECK(is_active_confirmation IN (0, 1)),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE,
                    FOREIGN KEY (packet_id, user_id) REFERENCES prepared_packets(id, user_id) ON DELETE RESTRICT
                )
            """)
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_conf_active_app ON submission_confirmations(application_id) WHERE is_active_confirmation = 1")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS application_follow_ups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    application_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    follow_up_date DATE NOT NULL,
                    follow_up_type TEXT NOT NULL CHECK(follow_up_type IN ('STATUS_INQUIRY', 'THANK_YOU_NOTE', 'PORTFOLIO_UPDATE', 'RECRUITER_CHECKIN', 'PHONE_CALL', 'OTHER')),
                    description TEXT NOT NULL,
                    is_completed INTEGER DEFAULT 0 CHECK(is_completed IN (0, 1)),
                    completed_at DATETIME,
                    outcome_notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (application_id, user_id) REFERENCES applications(id, user_id) ON DELETE CASCADE
                )
            """)

            # Child table indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_app_events_app_seq ON application_events(application_id, sequence_no)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_app_events_user_type ON application_events(user_id, event_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_app_events_created ON application_events(application_id, created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_conf_app ON submission_confirmations(application_id, user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sub_conf_user_channel ON submission_confirmations(user_id, submission_channel)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_follow_ups_due ON application_follow_ups(user_id, is_completed, follow_up_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_follow_ups_app ON application_follow_ups(application_id, user_id)")

            # Backfill initial events for historical applications without events
            cursor.execute("SELECT id, user_id, status, created_at FROM applications")
            current_apps = [dict(r) for r in cursor.fetchall()]
            for app in current_apps:
                cursor.execute("SELECT COUNT(*) FROM application_events WHERE application_id = ?", (app["id"],))
                if cursor.fetchone()[0] == 0:
                    app_status = app.get("status") or "DRAFT"
                    payload = {
                        "migration_version": "7.1",
                        "migrated_to_status": app_status,
                    }
                    payload_json = canonical_json_bytes(payload).decode("utf-8")
                    backfill_ts = app.get("created_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                    evt_hash = DatabaseManager.compute_event_hash(
                        actor_identifier="system_migration",
                        actor_type="SYSTEM",
                        application_id=app["id"],
                        event_payload_json=payload_json,
                        event_type="MIGRATION_INITIALIZED",
                        new_status=app_status,
                        previous_event_hash="GENESIS",
                        previous_status=None,
                        sequence_no=1,
                        session_reference=None,
                        user_id=app["user_id"],
                        created_at=backfill_ts,
                        hash_version="v2",
                    )
                    cursor.execute("""
                        INSERT INTO application_events (
                            application_id, user_id, sequence_no, event_type,
                            previous_status, new_status, actor_type, actor_identifier,
                            session_reference, event_payload_json, previous_event_hash, event_hash,
                            created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        app["id"], app["user_id"], 1, "MIGRATION_INITIALIZED",
                        None, app_status, "SYSTEM", "system_migration",
                        None, payload_json, "GENESIS", evt_hash, backfill_ts
                    ))

            # Validate post-migration foreign keys and database integrity before commit
            cursor.execute("PRAGMA foreign_key_check;")
            fk_errors = cursor.fetchall()
            if fk_errors:
                cursor.execute("ROLLBACK;")
                raise DatabaseMigrationError(f"Foreign key integrity check failed after Phase 7.1 migration: {fk_errors}")

            cursor.execute("PRAGMA integrity_check;")
            integrity_errors = [r[0] for r in cursor.fetchall() if r[0] != "ok"]
            if integrity_errors:
                cursor.execute("ROLLBACK;")
                raise DatabaseMigrationError(f"Database integrity check failed after Phase 7.1 migration: {integrity_errors}")

            cursor.execute("COMMIT;")
        except Exception as e:
            try:
                cursor.execute("ROLLBACK;")
            except Exception:
                pass
            if isinstance(e, (DatabaseMigrationError, MigrationPreflightError)):
                raise
            raise DatabaseMigrationError(f"Phase 7.1 application lifecycle migration failed and was rolled back: {e}") from e
        finally:
            try:
                cursor.execute("PRAGMA foreign_keys = ON;")
            finally:
                conn.isolation_level = old_isolation

        logger.info("Phase 7.1 application lifecycle migration completed successfully.")

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
            self._migrate_application_logs_job_id_nullable(conn)
            conn.commit()
            self._migrate_discovery_runs_table(conn)
            conn.commit()
            self._migrate_phase7_lifecycle_tables(conn)
            conn.commit()
            conn.executescript(schema_sql)
            conn.commit()
            self._migrate_historical_job_description_integrity(cursor)
            conn.commit()
            self._migrate_phase_9_1_2_5_legacy_evidence_reconciliation(cursor)
            conn.commit()
            self._migrate_phase_9_1_2_6_legacy_evidence_verification_closure(cursor)
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

    def insert_job(
        self,
        job: Job,
        auto_create_company: bool = True,
        user_id: Optional[int] = None,
    ) -> Job:
        """Inserts a new job posting with duplicate checking and optional user application registration.

        If user_id is provided, validates that the user exists and creates an application record
        bound to that candidate with an initial APPLICATION_CREATED event.
        If user_id is None, the job is registered purely in the global catalog without creating
        applications or defaulting to placeholder users.
        """
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

            if user_id is not None:
                cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
                if not cursor.fetchone():
                    raise UserNotFoundError(f"User ID {user_id}")

                cursor.execute(
                    """
                    INSERT INTO applications (
                        user_id, job_id, company_name, job_title, status, application_source
                    ) VALUES (?, ?, ?, ?, ?, 'JOB_DESCRIPTION')
                    """,
                    (
                        user_id,
                        job.id,
                        job.company_name.strip(),
                        job.job_title.strip(),
                        ApplicationStatus.DISCOVERED.value,
                    ),
                )
                app_id = int(cursor.lastrowid or 0)

                cursor.execute(
                    """
                    INSERT INTO application_logs (job_id, application_id, user_id, action, details)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        job.id,
                        app_id,
                        user_id,
                        "JOB_DISCOVERED",
                        json.dumps({"platform": job.platform, "score": job.match_score}),
                    ),
                )

                now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                event_payload = {"source": "catalog_job_insert", "job_id": job.id, "platform": job.platform}
                payload_json = canonical_json_bytes(event_payload).decode("utf-8")
                evt_hash = DatabaseManager.compute_event_hash(
                    actor_identifier="system",
                    actor_type="SYSTEM",
                    application_id=app_id,
                    event_payload_json=payload_json,
                    event_type="APPLICATION_CREATED",
                    new_status=ApplicationStatus.DISCOVERED.value,
                    previous_event_hash="GENESIS",
                    previous_status=None,
                    sequence_no=1,
                    session_reference=None,
                    user_id=user_id,
                    created_at=now_iso,
                    hash_version="v2",
                )
                cursor.execute(
                    """
                    INSERT INTO application_events (
                        application_id, user_id, sequence_no, event_type,
                        previous_status, new_status, actor_type, actor_identifier,
                        session_reference, event_payload_json, previous_event_hash, event_hash,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        app_id,
                        user_id,
                        1,
                        "APPLICATION_CREATED",
                        None,
                        ApplicationStatus.DISCOVERED.value,
                        "SYSTEM",
                        "system",
                        None,
                        payload_json,
                        "GENESIS",
                        evt_hash,
                        now_iso,
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

    def get_application_by_id(self, application_id: int) -> Optional[Application]:
        """Fetches the application record linked to a given primary key application ID."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM applications WHERE id = ?", (int(application_id),))
            row = cursor.fetchone()
            return Application(**dict(row)) if row else None

    def get_application_by_job_id(
        self,
        job_id: int,
        user_id: Optional[Union[int, str]] = None,
    ) -> Optional[Application]:
        """Fetches the application record linked to a given job ID.

        When user_id is provided, scopes the lookup to that candidate's application.
        When user_id is omitted:
        - If no applications exist for job_id, returns None.
        - If multiple applications exist for job_id across candidates, fails closed by raising SecurityAuthorizationError.
        - If exactly 1 application exists, returns that application.
        """
        clean_user_id: Optional[int] = None
        if user_id is not None:
            try:
                clean_user_id = int(user_id)
                if clean_user_id <= 0:
                    return None
            except (ValueError, TypeError):
                return None

        with self.connection() as conn:
            cursor = conn.cursor()
            if clean_user_id is not None:
                cursor.execute(
                    "SELECT * FROM applications WHERE job_id = ? AND user_id = ?",
                    (int(job_id), clean_user_id),
                )
                row = cursor.fetchone()
                return Application(**dict(row)) if row else None
            else:
                cursor.execute("SELECT * FROM applications WHERE job_id = ?", (int(job_id),))
                rows = cursor.fetchall()
                if not rows:
                    return None
                if len(rows) > 1:
                    raise SecurityAuthorizationError(
                        f"Ambiguous application lookup for job {job_id}: multiple applications exist across candidates. "
                        f"Explicit user_id or application_id is required."
                    )
                return Application(**dict(rows[0]))

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
        job_id: Optional[int] = None,
        new_status: Optional[Union[str, ApplicationStatus]] = None,
        confirmed: bool = False,
        notes: Optional[str] = None,
        resume_used: Optional[str] = None,
        cover_letter_reference: Optional[str] = None,
        packet_version_hash: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        *,
        application_id: Optional[int] = None,
    ) -> Application:
        """Updates the application status for an exact application or job, with strict transition state machines,
        application-scoped human authorization, and immutable audit logging.

        Raises:
            JobNotFoundError: If job does not exist.
            ApplicationNotFoundError: If application record does not exist.
            InvalidStatusError: If new_status is not a recognized status.
            InvalidStatusTransitionError: If the transition skips intermediate state machines.
            SecurityAuthorizationError: If human approval, user ownership, or packet verification fails.
            UnconfirmedSubmissionError: If trying to set 'Applied' without confirmed=True or valid approval.
        """
        if new_status is None:
            raise ValidationError("new_status is required.")

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

        clean_user_id: Optional[int] = None
        if user_id is not None:
            try:
                clean_user_id = int(user_id)
                if clean_user_id <= 0:
                    raise SecurityAuthorizationError(f"Invalid user_id: {user_id}")
            except (ValueError, TypeError):
                raise SecurityAuthorizationError(f"Malformed user_id: {user_id}")

        # Resolve exact target application
        app: Optional[Application] = None
        with self.connection() as conn:
            cursor = conn.cursor()
            if application_id is not None:
                cursor.execute("SELECT * FROM applications WHERE id = ?", (int(application_id),))
                row = cursor.fetchone()
                if not row:
                    raise ApplicationNotFoundError(f"Application ID {application_id}")
                app = Application(**dict(row))

                if job_id is not None and app.job_id != int(job_id):
                    raise SecurityAuthorizationError(
                        f"Application #{application_id} (Job #{app.job_id}) does not match requested Job #{job_id}."
                    )

                if app.user_id is not None:
                    if clean_user_id is None:
                        raise SecurityAuthorizationError(
                            f"Candidate-owned application #{app.id} mutation requires authenticated user_id."
                        )
                    if int(app.user_id) != clean_user_id:
                        raise SecurityAuthorizationError(
                            f"Unauthorized update: Application #{app.id} is owned by User #{app.user_id}, "
                            f"but request authenticated as User #{clean_user_id}."
                        )
            else:
                if job_id is None:
                    raise ValidationError("Either application_id or job_id must be provided to update application status.")

                cursor.execute("SELECT * FROM applications WHERE job_id = ?", (int(job_id),))
                rows = cursor.fetchall()
                if not rows:
                    raise ApplicationNotFoundError(f"Job ID {job_id}")

                if len(rows) > 1:
                    if clean_user_id is None:
                        raise SecurityAuthorizationError(
                            f"Ambiguous application update for Job ID {job_id}: multiple candidate applications exist. "
                            f"Explicit application_id or authenticated user_id is required."
                        )
                    matched_rows = [r for r in rows if r["user_id"] is not None and int(r["user_id"]) == clean_user_id]
                    if len(matched_rows) != 1:
                        raise SecurityAuthorizationError(
                            f"Ambiguous or missing application for Job ID {job_id} and User #{clean_user_id}."
                        )
                    app = Application(**dict(matched_rows[0]))
                else:
                    single_row = rows[0]
                    if single_row["user_id"] is not None:
                        if clean_user_id is not None:
                            if int(single_row["user_id"]) != clean_user_id:
                                raise SecurityAuthorizationError(
                                    f"Unauthorized update: Application for Job ID {job_id} belongs to User #{single_row['user_id']}, "
                                    f"but request authenticated as User #{clean_user_id}."
                                )
                        elif matched_status in (ApplicationStatus.APPLIED.value, ApplicationStatus.AWAITING_APPROVAL.value):
                            raise SecurityAuthorizationError(
                                f"Candidate-owned application status transition to '{matched_status}' requires authenticated user_id."
                            )
                    app = Application(**dict(single_row))

        if app is None:
            raise ApplicationNotFoundError(f"Application for Job ID {job_id}")

        old_status = app.status
        if old_status == matched_status:
            return app

        # 1. State Machine Validation
        allowed = ALLOWED_TRANSITIONS.get(old_status, [])
        if matched_status not in allowed:
            raise InvalidStatusTransitionError(old_status=old_status, new_status=matched_status, allowed=allowed)

        effective_user_id = clean_user_id if clean_user_id is not None else app.user_id

        # 2. Strict Human Authorization Validation for Awaiting Approval
        if matched_status == ApplicationStatus.AWAITING_APPROVAL.value:
            if not self.has_valid_human_approval(
                application_id=app.id,
                job_id=app.job_id,
                expected_packet_hash=packet_version_hash,
                user_id=effective_user_id,
            ):
                raise SecurityAuthorizationError(
                    f"Transition to 'Awaiting Approval' rejected: Application #{app.id} (Job #{app.job_id}) requires valid, authenticated "
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
            if not self.has_valid_human_approval(
                application_id=app.id,
                job_id=app.job_id,
                expected_packet_hash=packet_version_hash,
                user_id=effective_user_id,
            ):
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

            params.append(app.id)
            params.append(old_status)

            if app.user_id is not None:
                params.append(app.user_id)
                owner_where = "AND user_id = ?"
            else:
                owner_where = "AND user_id IS NULL"

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
                WHERE id = ? AND status = ? {owner_where}
                """,
                params,
            )

            if cursor.rowcount != 1:
                raise DatabaseError(
                    f"Failed to update application status for Application #{app.id}: "
                    f"expected 1 row affected, got {cursor.rowcount}. Possible concurrent modification."
                )

            # Record immutable audit log
            log_details = {
                "old_status": old_status,
                "new_status": matched_status,
                "notes": notes,
                "application_id": app.id,
                "user_id": str(app.user_id if app.user_id is not None else (clean_user_id or "candidate_user")),
                "packet_version_hash": packet_version_hash or "",
            }
            cursor.execute(
                """
                INSERT INTO application_logs (job_id, application_id, user_id, action, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    app.job_id,
                    app.id,
                    app.user_id if app.user_id is not None else clean_user_id,
                    f"STATUS_TRANSITION: {old_status} -> {matched_status}",
                    json.dumps(log_details),
                ),
            )

            if matched_status == ApplicationStatus.APPLIED.value:
                cursor.execute(
                    """
                    INSERT INTO application_logs (job_id, application_id, user_id, action, details)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        app.job_id,
                        app.id,
                        app.user_id if app.user_id is not None else clean_user_id,
                        "HUMAN_APPROVAL_CONSUMED",
                        json.dumps({
                            "action": "CONSUMED",
                            "consumed_at": datetime.now().isoformat(),
                            "application_id": app.id,
                            "user_id": str(app.user_id if app.user_id is not None else (clean_user_id or "candidate_user")),
                            "packet_version_hash": packet_version_hash or "",
                            "notes": notes or "Approval record consumed for confirmed manual application submission.",
                        }),
                    ),
                )

            cursor.execute("SELECT * FROM applications WHERE id = ?", (app.id,))
            updated_row = cursor.fetchone()
            logger.info("Updated application #%d for job %s: %s -> %s", app.id, str(app.job_id), old_status, matched_status)
            return Application(**dict(updated_row))

    def record_human_approval(
        self,
        job_id: Optional[int] = None,
        approver_name: str = "",
        approver_id: Optional[str] = None,
        session_id: Optional[str] = None,
        packet_version_hash: Optional[str] = None,
        ticket_nonce: Optional[str] = None,
        approval_notes: Optional[str] = None,
        *,
        application_id: Optional[int] = None,
        user_id: Optional[Union[str, int]] = None,
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

        app: Optional[Application] = None
        if application_id is not None:
            app = self.get_application_by_id(int(application_id))
            if not app:
                raise ApplicationNotFoundError(f"Application ID {application_id}")
            effective_job_id = app.job_id
        else:
            if job_id is None:
                raise ValidationError("job_id or application_id is required.")
            resolved_user = user_id or (int(approver_id) if approver_id and approver_id.isdigit() else None)
            app = self.get_application_by_job_id(job_id, user_id=resolved_user)
            if not app:
                raise ApplicationNotFoundError(f"Job ID {job_id}")
            effective_job_id = job_id

        effective_user_id = user_id if user_id is not None else app.user_id

        details = {
            "approver": clean_approver,
            "approver_id": approver_id or (str(effective_user_id) if effective_user_id else "candidate_user"),
            "user_id": str(effective_user_id) if effective_user_id is not None else "candidate_user",
            "application_id": app.id,
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
                INSERT INTO application_logs (job_id, application_id, user_id, action, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (effective_job_id, app.id, effective_user_id, "HUMAN_APPROVAL_GRANTED", json.dumps(details)),
            )
            log_id = cursor.lastrowid
            cursor.execute("SELECT * FROM application_logs WHERE id = ?", (log_id,))
            logger.info("Human approval granted for app %d (job %s) by '%s'", app.id, str(effective_job_id), clean_approver)
            return ApplicationLog(**dict(cursor.fetchone()))

    def consume_human_approval(
        self,
        job_id: Optional[int] = None,
        packet_version_hash: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        ticket_nonce: Optional[str] = None,
        notes: Optional[str] = None,
        *,
        application_id: Optional[int] = None,
    ) -> None:
        """Marks a prior human approval as consumed upon manual submission confirmation, preventing replay."""
        app: Optional[Application] = None
        if application_id is not None:
            app = self.get_application_by_id(int(application_id))
            if not app:
                raise ApplicationNotFoundError(f"Application ID {application_id}")
            effective_job_id = app.job_id
        else:
            if job_id is None:
                raise ValidationError("job_id or application_id is required.")
            app = self.get_application_by_job_id(job_id, user_id=user_id)
            if not app:
                raise ApplicationNotFoundError(f"Job ID {job_id}")
            effective_job_id = job_id

        effective_user_id = user_id if user_id is not None else app.user_id

        if ticket_nonce:
            self.consume_action_nonce_persistently(
                ticket_nonce=ticket_nonce,
                key_id="v1",
                user_id=int(effective_user_id) if (effective_user_id and str(effective_user_id).isdigit()) else None,
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
            "user_id": str(effective_user_id or "candidate_user"),
            "application_id": app.id,
            "session_id": session_id or "",
            "packet_version_hash": packet_version_hash or "",
            "ticket_nonce": ticket_nonce or "",
            "notes": notes or "Approval record consumed for confirmed manual application submission.",
        }
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO application_logs (job_id, application_id, user_id, action, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (effective_job_id, app.id, effective_user_id, "HUMAN_APPROVAL_CONSUMED", json.dumps(details)),
            )
            logger.info("Human approval consumed for app %d (job %s) (replay prevention active)", app.id, str(effective_job_id))

    def has_valid_human_approval(
        self,
        identifier: Optional[int] = None,
        expected_packet_hash: Optional[str] = None,
        user_id: Optional[Union[int, str]] = None,
        *,
        application_id: Optional[int] = None,
        job_id: Optional[int] = None,
    ) -> bool:
        """Checks whether an active, unrevoked, and unconsumed human approval record exists.

        Explicit call semantics:
        - Modern callers: has_valid_human_approval(application_id=..., user_id=..., expected_packet_hash=...)
        - Legacy callers: has_valid_human_approval(job_id=..., user_id=..., expected_packet_hash=...)

        Positional identifier fallback is rejected (fails closed) to eliminate ambiguity.
        """
        # Positional identifier is ambiguous and unsafe; fail closed immediately
        if application_id is None and job_id is None:
            return False

        clean_user_id: Optional[int] = None
        if user_id is not None:
            try:
                clean_user_id = int(user_id)
                if clean_user_id <= 0:
                    return False
            except (ValueError, TypeError):
                return False

        with self.connection() as conn:
            cursor = conn.cursor()

            # 1. Modern application_id lookup
            if application_id is not None:
                cursor.execute("SELECT id, user_id, job_id FROM applications WHERE id = ?", (application_id,))
                app_row = cursor.fetchone()
                if not app_row:
                    return False

                # If job_id was also passed, verify they match
                if job_id is not None and app_row["job_id"] != job_id:
                    return False

                # Reject missing or mismatched user_id for modern candidate-owned approvals
                if app_row["user_id"] is not None:
                    if clean_user_id is None or int(app_row["user_id"]) != clean_user_id:
                        return False
                elif clean_user_id is not None:
                    return False

                app_id = app_row["id"]

                # Check active prepared packet revision
                cursor.execute(
                    "SELECT id, version_num, packet_version_hash, is_active_revision FROM prepared_packets WHERE application_id = ? AND is_active_revision = 1 ORDER BY version_num DESC LIMIT 1",
                    (app_id,),
                )
                active_packet_row = cursor.fetchone()

                cursor.execute("SELECT COUNT(*) AS cnt FROM prepared_packets WHERE application_id = ?", (app_id,))
                pkt_cnt = cursor.fetchone()["cnt"]

                # If prepared packets exist for this application, an active revision is mandatory
                if pkt_cnt > 0:
                    if not active_packet_row:
                        return False
                    target_hash = expected_packet_hash or active_packet_row["packet_version_hash"]
                else:
                    target_hash = expected_packet_hash

                if target_hash:
                    if expected_packet_hash:
                        cursor.execute(
                            "SELECT is_active_revision FROM prepared_packets WHERE application_id = ? AND packet_version_hash = ?",
                            (app_id, expected_packet_hash),
                        )
                        pkt_chk = cursor.fetchone()
                        if pkt_chk and not pkt_chk["is_active_revision"]:
                            return False

                    cursor.execute(
                        """
                        SELECT id, user_id, key_id, is_consumed, consumed_at, is_revoked, revoked_at, packet_version_hash
                        FROM application_approvals
                        WHERE application_id = ? AND packet_version_hash = ?
                          AND (is_revoked IS NULL OR is_revoked = 0) AND revoked_at IS NULL
                          AND (is_consumed IS NULL OR is_consumed = 0) AND consumed_at IS NULL
                        ORDER BY approved_at DESC, id DESC
                        """,
                        (app_id, target_hash),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT id, user_id, key_id, is_consumed, consumed_at, is_revoked, revoked_at, packet_version_hash
                        FROM application_approvals
                        WHERE application_id = ?
                          AND (is_revoked IS NULL OR is_revoked = 0) AND revoked_at IS NULL
                          AND (is_consumed IS NULL OR is_consumed = 0) AND consumed_at IS NULL
                        ORDER BY approved_at DESC, id DESC
                        """,
                        (app_id,),
                    )

                appr_rows = cursor.fetchall()
                for appr_row in appr_rows:
                    if clean_user_id is not None and appr_row["user_id"] is not None:
                        if int(appr_row["user_id"]) != clean_user_id:
                            continue

                    if appr_row["is_consumed"] or appr_row["consumed_at"] is not None:
                        continue

                    if appr_row["is_revoked"] or appr_row["revoked_at"] is not None:
                        continue

                    if self.is_key_revoked(appr_row["key_id"]):
                        continue

                    if active_packet_row:
                        if active_packet_row["packet_version_hash"] != appr_row["packet_version_hash"]:
                            continue

                    return True

                # If application has prepared packets, fail closed (never fallback to legacy logs)
                cursor.execute("SELECT COUNT(*) as pkt_count FROM prepared_packets WHERE application_id = ?", (app_id,))
                pkt_count = cursor.fetchone()["pkt_count"]
                if pkt_count > 0:
                    return False

                leg_app_id = app_id
                leg_job_id = app_row["job_id"]

            # 2. Legacy job_id lookup
            if job_id is not None and application_id is None:
                if clean_user_id is not None:
                    cursor.execute(
                        "SELECT id, user_id FROM applications WHERE job_id = ? AND user_id = ?",
                        (job_id, clean_user_id),
                    )
                    app_rows = cursor.fetchall()
                else:
                    cursor.execute(
                        "SELECT id, user_id FROM applications WHERE job_id = ?",
                        (job_id,),
                    )
                    app_rows = cursor.fetchall()

                # Reject when no uniquely matching owned application exists
                if len(app_rows) != 1:
                    return False

                leg_app = app_rows[0]
                leg_app_id = leg_app["id"]
                leg_job_id = job_id

                # Candidate-owned application REQUIRES valid authenticated user_id matching owner
                if leg_app["user_id"] is not None:
                    if clean_user_id is None or int(leg_app["user_id"]) != clean_user_id:
                        return False
                elif clean_user_id is not None:
                    return False

                # Modern applications with prepared packets must never fall back to legacy logs
                cursor.execute(
                    "SELECT COUNT(*) as pkt_count FROM prepared_packets WHERE application_id = ?",
                    (leg_app_id,),
                )
                if cursor.fetchone()["pkt_count"] > 0:
                    return False

            if "leg_app_id" in locals():
                # Retrieve audit logs scoped to exact application_id and job_id
                cursor.execute(
                    """
                    SELECT id, action, details, timestamp
                    FROM application_logs
                    WHERE application_id = ? AND job_id = ?
                    ORDER BY id DESC
                    """,
                    (leg_app_id, leg_job_id),
                )
                logs = cursor.fetchall()
                if not logs:
                    return False

                for log in logs:
                    action = log["action"]
                    # If approval was revoked or consumed, reject immediately
                    if action in ("HUMAN_APPROVAL_REVOKED", "HUMAN_APPROVAL_CONSUMED"):
                        return False

                    det = {}
                    try:
                        det = json.loads(log["details"]) if log["details"] else {}
                    except Exception:
                        det = {}

                    if det.get("action") == "CONSUMED" or det.get("status") in ("CONSUMED", "REVOKED"):
                        return False

                    if action == "HUMAN_APPROVAL_GRANTED":
                        # Verify candidate ownership if clean_user_id provided
                        approver_id = det.get("approver_id")
                        log_user_id = det.get("user_id")
                        if clean_user_id is not None:
                            if log_user_id is not None and int(log_user_id) != clean_user_id:
                                continue
                            if approver_id and approver_id.startswith("user_"):
                                try:
                                    if int(approver_id.split("_")[1]) != clean_user_id:
                                        continue
                                except (ValueError, IndexError):
                                    pass

                        # If expected_packet_hash is provided, verify match
                        if expected_packet_hash:
                            if det.get("packet_version_hash") != expected_packet_hash:
                                return False

                        return True

                return False

        return False

    def get_application_logs(
        self,
        job_id: Optional[int] = None,
        *,
        application_id: Optional[int] = None,
        user_id: Optional[Union[str, int]] = None,
    ) -> List[ApplicationLog]:
        """Retrieves audit trail logs for a given job or application."""
        query = "SELECT * FROM application_logs"
        conditions = []
        params: List[Any] = []
        if application_id is not None:
            conditions.append("application_id = ?")
            params.append(int(application_id))
        if job_id is not None:
            conditions.append("job_id = ?")
            params.append(int(job_id))
        if user_id is not None and str(user_id).isdigit():
            conditions.append("user_id = ?")
            params.append(int(user_id))

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id ASC, timestamp ASC"

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
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
            self.exports_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.exports_dir / f"applications_export_{timestamp}.csv"
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
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            backup_path = self.backup_dir / f"backup_job_assistant_{timestamp}.db"
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
        if not ticket_nonce or not isinstance(ticket_nonce, str) or not ticket_nonce.strip():
            raise ValidationError("ticket_nonce cannot be empty.")

        clean_nonce = ticket_nonce.strip()
        import re
        if not re.match(r"^[a-zA-Z0-9_\-]+$", clean_nonce) or len(clean_nonce) < 8 or len(clean_nonce) > 128:
            raise ValidationError(f"Invalid ticket_nonce format: '{clean_nonce}'.")

        clean_key = (key_id or "v1").strip()
        if not re.match(r"^[a-zA-Z0-9_\-]+$", clean_key):
            raise ValidationError(f"Invalid key_id format: '{clean_key}'.")

        clean_action = (action_type or "SUBMIT_APPLICATION").strip()
        if not clean_action:
            raise ValidationError("action_type cannot be empty.")

        # Connect and acquire an immediate transaction lock
        conn = self.get_connection(timeout=10.0)
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
            if approval_row and (approval_row["is_consumed"] or clean_action == "HUMAN_APPROVAL"):
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
                    (clean_nonce, clean_key, user_id, clean_action),
                )
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK")
                raise TicketAlreadyConsumedError(
                    f"Action ticket nonce '{clean_nonce}' has already been consumed (race condition detected)."
                )

            # 4. Mark approval record as consumed if exists (for submission action)
            if approval_row and clean_action != "HUMAN_APPROVAL":
                cursor.execute(
                    """
                    UPDATE application_approvals
                    SET is_consumed = 1, consumed_at = CURRENT_TIMESTAMP
                    WHERE ticket_nonce = ?
                    """,
                    (clean_nonce,),
                )

            conn.execute("COMMIT")
            logger.info("Successfully consumed ticket nonce '%s' for action '%s'", clean_nonce, clean_action)
        except (TicketAlreadyConsumedError, ValidationError):
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
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

    def revoke_signing_key_approvals(
        self,
        key_id: str,
        reason: str = "EMERGENCY_KEY_REVOCATION",
    ) -> int:
        """Persists emergency key revocation and invalidates all unconsumed approvals issued under the key."""
        if not key_id:
            return 0
        clean_key = key_id.strip()
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO revoked_signing_keys (key_id, revoked_at, reason)
                VALUES (?, CURRENT_TIMESTAMP, ?)
                """,
                (clean_key, reason),
            )
            cursor.execute(
                """
                UPDATE application_approvals
                SET is_revoked = 1, revoked_at = CURRENT_TIMESTAMP, revocation_reason = ?
                WHERE key_id = ? AND is_consumed = 0 AND (is_revoked IS NULL OR is_revoked = 0)
                """,
                (reason, clean_key),
            )
            revoked_count = cursor.rowcount
            logger.warning(
                "Revoked signing key '%s' and invalidated %d unconsumed approvals in SQLite (reason: %s)",
                clean_key, revoked_count, reason
            )
            return revoked_count

    def record_key_revocation(
        self,
        key_id: str,
        reason: str = "EMERGENCY_KEY_REVOCATION",
    ) -> int:
        """Records a signing key revocation in SQLite (delegates to revoke_signing_key_approvals)."""
        return self.revoke_signing_key_approvals(key_id=key_id, reason=reason)

    def revoke_signing_key(
        self,
        key_id: str,
        reason: str = "EMERGENCY_KEY_REVOCATION",
    ) -> int:
        """Alias for record_key_revocation."""
        return self.record_key_revocation(key_id=key_id, reason=reason)

    def is_key_revoked(self, key_id: str) -> bool:
        """Checks if a signing key has been revoked in SQLite."""
        if not key_id:
            return False
        clean_key = key_id.strip()
        try:
            with self.connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM revoked_signing_keys WHERE key_id = ?", (clean_key,))
                return cursor.fetchone() is not None
        except Exception as e:
            raise SecurityAuthorizationError(f"Database revocation query failure checking revoked key '{clean_key}': {e}") from e

    def record_principal_revocation(
        self,
        principal_id: str,
        reason: str = "Principal Revoked",
    ) -> None:
        """Persists an attesting principal revocation durably in SQLite."""
        if not principal_id or not isinstance(principal_id, str) or not principal_id.strip():
            raise SecurityAuthorizationError(f"Invalid principal_id to revoke: '{principal_id}'")
        clean_p = principal_id.strip()
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO revoked_attesting_principals (principal_id, revoked_at, reason)
                VALUES (?, CURRENT_TIMESTAMP, ?)
                """,
                (clean_p, reason),
            )
            logger.warning("Revoked attesting principal '%s' in SQLite (reason: %s)", clean_p, reason)

    def revoke_attesting_principal(
        self,
        principal_id: str,
        reason: str = "Principal Revoked",
    ) -> None:
        """Alias for record_principal_revocation."""
        self.record_principal_revocation(principal_id, reason=reason)

    def is_principal_revoked(self, principal_id: str, cursor: Optional[sqlite3.Cursor] = None) -> bool:
        """Checks if an attesting principal has been revoked in SQLite."""
        if not principal_id or not isinstance(principal_id, str):
            return True
        clean_p = principal_id.strip()
        if not clean_p:
            return True
        try:
            if cursor is not None:
                cursor.execute("SELECT 1 FROM revoked_attesting_principals WHERE principal_id = ?", (clean_p,))
                return cursor.fetchone() is not None
            with self.connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT 1 FROM revoked_attesting_principals WHERE principal_id = ?", (clean_p,))
                return cur.fetchone() is not None
        except Exception as e:
            raise SecurityAuthorizationError(f"Database revocation query failure checking revoked principal '{clean_p}': {e}") from e

    def get_revoked_principals(self) -> Set[str]:
        """Returns all revoked attesting principal IDs from SQLite."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT principal_id FROM revoked_attesting_principals")
            return {row[0] for row in cursor.fetchall()}

    def _record_packet_approval_internal(
        self,
        cursor: sqlite3.Cursor,
        application_id: int,
        user_id: int,
        packet_version_hash: str,
        ticket_nonce: str,
        key_id: str = "v1",
        approver_name: str = "Human Candidate",
        session_id: str = "",
        packet_id: Optional[int] = None,
    ) -> ApplicationApproval:
        """Internal worker recording human approval and log on an existing transaction cursor."""
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

        if ticket_nonce:
            cursor.execute("SELECT nonce FROM consumed_action_nonces WHERE nonce = ?", (ticket_nonce,))
            if cursor.fetchone():
                raise TicketAlreadyConsumedError(
                    f"Ticket nonce '{ticket_nonce}' is already registered in approvals."
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

        # Ensure ticket_nonce is also registered in consumed_action_nonces within this atomic transaction
        cursor.execute(
            """
            INSERT OR IGNORE INTO consumed_action_nonces (nonce, key_id, user_id, action_type, consumed_at)
            VALUES (?, ?, ?, 'HUMAN_APPROVAL', CURRENT_TIMESTAMP)
            """,
            (ticket_nonce, key_id, user_id),
        )

        # Also log to application_logs
        app_job_id = None
        cursor.execute("SELECT job_id FROM applications WHERE id = ?", (application_id,))
        app_j = cursor.fetchone()
        if app_j and app_j["job_id"]:
            app_job_id = app_j["job_id"]

        cursor.execute(
            """
            INSERT INTO application_logs (job_id, application_id, user_id, action, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                app_job_id,
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

    def record_packet_approval(
        self,
        *args: Any,
        auth_grant: Optional[VerifiedApprovalGrant] = None,
        **kwargs: Any,
    ) -> ApplicationApproval:
        """DEPRECATED / PROHIBITED: Direct creation of approval records without verified authorization evidence is prohibited.

        All human packet approvals must proceed exclusively through HumanApprovalGate.authorize_universal_packet()
        with a cryptographically verified single-use approval grant.
        """
        if auth_grant is None:
            raise SecurityAuthorizationError(
                "Direct invocation of record_packet_approval() without verified authorization evidence is prohibited. "
                "Human packet approval must proceed exclusively through HumanApprovalGate.authorize_universal_packet()."
            )
        return self._authorize_application_packet_atomic(auth_grant=auth_grant)

    def _authorize_application_packet_atomic(
        self,
        auth_grant: Optional[VerifiedApprovalGrant] = None,
        **kwargs: Any,
    ) -> ApplicationApproval:
        """Internal atomic persistence helper for human approvals under an immediate write lock.

        TRUSTED WORKFLOW INVARIANT:
        This internal method may ONLY be invoked by HumanApprovalGate after successful cryptographic
        session validation, active packet integrity verification, candidate confirmation, and action ticket consumption.
        It requires a cryptographically verified, single-use VerifiedApprovalGrant.
        It is strictly NOT exposed as a public service API.

        Target status is derived exclusively from the application's current status (READY_FOR_REVIEW -> APPROVED,
        or legacy Application Prepared -> Awaiting Approval) and is strictly non-caller-selectable.
        """
        grant = auth_grant or kwargs.pop("auth_context", None)
        if kwargs:
            raise SecurityAuthorizationError(
                f"Raw parameter bypass rejected: _authorize_application_packet_atomic accepts only auth_grant: VerifiedApprovalGrant, got unexpected: {list(kwargs.keys())}."
            )

        if grant is None:
            raise SecurityAuthorizationError(
                "Missing authorization evidence: A valid, cryptographically verified VerifiedApprovalGrant is mandatory."
            )

        if not isinstance(grant, VerifiedApprovalGrant):
            raise SecurityAuthorizationError(
                f"Invalid authorization evidence: Expected VerifiedApprovalGrant, got {type(grant).__name__}."
            )

        trusted_sm = self.session_manager
        from src.security.session_manager import SessionManager
        if type(trusted_sm) is not SessionManager:
            raise SecurityAuthorizationError("Invalid verifier configuration: Exact trusted SessionManager instance required.")

        try:
            verif_res = trusted_sm.verify_and_consume_approval_grant(grant)
            if verif_res is None or not isinstance(verif_res, tuple) or len(verif_res) != 2:
                raise SecurityAuthorizationError("Authorization rejected: Invalid verifier response format.")
            is_valid, verif_msg = verif_res
            if is_valid is not True:
                raise SecurityAuthorizationError(f"Authorization rejected: Verifier rejected grant: {verif_msg}")
        except (TicketAlreadyConsumedError, CrossUserAccessError, SecurityAuthorizationError):
            raise
        except Exception as exc:
            raise SecurityAuthorizationError(f"Authorization rejected: Verifier error: {exc}") from exc

        application_id = grant.application_id
        user_id = grant.user_id
        packet_id = grant.packet_id
        packet_version_hash = grant.packet_version_hash
        ticket_nonce = grant.ticket_nonce
        key_id = grant.key_id
        approver_name = grant.approver_name
        session_id = grant.session_id

        from src.lifecycle.state_machine import ApplicationStateMachine

        with self.immediate_transaction() as conn:
            cursor = conn.cursor()

            # 1. Verify application exists and belongs to user
            cursor.execute("SELECT id, user_id, status FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise ApplicationNotFoundError(application_id)
            if app_row["user_id"] is not None and app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )

            current_status = app_row["status"]
            norm_status = ApplicationStateMachine.normalize_status(current_status)
            if norm_status not in (ApplicationStatus.READY_FOR_REVIEW, ApplicationStatus.APPROVED):
                raise InvalidStatusTransitionError(
                    old_status=current_status,
                    new_status=ApplicationStatus.APPROVED.value,
                    allowed=[
                        ApplicationStatus.READY_FOR_REVIEW.value,
                        ApplicationStatus.APPLICATION_PREPARED.value,
                    ],
                )

            # Re-authorizing an already APPROVED application is only allowed if a prior approval was revoked
            if norm_status == ApplicationStatus.APPROVED:
                cursor.execute(
                    """
                    SELECT id FROM application_approvals
                    WHERE application_id = ? AND is_revoked = 1
                    """,
                    (application_id,),
                )
                has_revoked = cursor.fetchone()
                if not has_revoked:
                    raise InvalidStatusTransitionError(
                        old_status=current_status,
                        new_status=ApplicationStatus.APPROVED.value,
                        allowed=[
                            ApplicationStatus.READY_FOR_REVIEW.value,
                            ApplicationStatus.APPLICATION_PREPARED.value,
                        ],
                    )

            # Derive new status exclusively from existing application status representation (never caller-selectable)
            if current_status == ApplicationStatus.READY_FOR_REVIEW.value:
                new_status = ApplicationStatus.APPROVED.value
            elif current_status in (ApplicationStatus.APPLICATION_PREPARED.value, ApplicationStatus.AWAITING_APPROVAL.value):
                new_status = ApplicationStatus.AWAITING_APPROVAL.value
            elif current_status == ApplicationStatus.APPROVED.value:
                new_status = ApplicationStatus.APPROVED.value
            else:
                new_status = ApplicationStatus.APPROVED.value

            # Strict guard against setting unauthorized statuses
            if new_status not in (ApplicationStatus.APPROVED.value, ApplicationStatus.AWAITING_APPROVAL.value):
                raise SecurityAuthorizationError(
                    f"Illegal approval target status '{new_status}'. Approval can only transition to APPROVED or Awaiting Approval."
                )

            # 2. Record approval & log via internal helper
            approval = self._record_packet_approval_internal(
                cursor=cursor,
                application_id=application_id,
                user_id=user_id,
                packet_version_hash=packet_version_hash,
                ticket_nonce=ticket_nonce,
                key_id=key_id,
                approver_name=approver_name,
                session_id=session_id,
                packet_id=packet_id,
            )

            # 3. Update application status
            cursor.execute(
                """
                UPDATE applications
                SET status = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
                """,
                (new_status, application_id, user_id),
            )

            # 4. Append immutable timeline event PACKET_HUMAN_APPROVED
            event_payload = {
                "approval_id": approval.id,
                "packet_id": packet_id,
                "packet_version_hash": packet_version_hash,
                "ticket_nonce": ticket_nonce,
                "key_id": key_id,
                "approver": approver_name,
                "session_id": session_id,
            }
            self._insert_application_event_internal(
                cursor=cursor,
                application_id=application_id,
                user_id=user_id,
                event_type="PACKET_HUMAN_APPROVED",
                previous_status=current_status,
                new_status=new_status,
                actor_type="CANDIDATE",
                actor_identifier=approver_name,
                session_reference=session_id,
                event_payload=event_payload,
            )

            return approval

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
                SELECT id, key_id FROM application_approvals
                WHERE application_id = ? AND user_id = ? AND packet_version_hash = ?
                  AND is_consumed = 0 AND (is_revoked IS NULL OR is_revoked = 0)
                ORDER BY approved_at DESC, id DESC LIMIT 1
                """,
                (application_id, user_id, expected_packet_hash),
            )
            row = cursor.fetchone()
            if not row:
                return False
            if self.is_key_revoked(row["key_id"]):
                return False
            return True

    def get_packet_approval(
        self,
        packet_id: int,
        user_id: int,
        include_revoked: bool = False,
    ) -> Optional[ApplicationApproval]:
        """Retrieves the latest human approval record for a prepared packet, enforcing user ownership."""
        with self.connection() as conn:
            cursor = conn.cursor()
            # First check for an active, unrevoked approval
            cursor.execute(
                """
                SELECT * FROM application_approvals
                WHERE packet_id = ? AND user_id = ? AND (is_revoked IS NULL OR is_revoked = 0)
                ORDER BY approved_at DESC, id DESC LIMIT 1
                """,
                (packet_id, user_id),
            )
            row = cursor.fetchone()
            if not row and include_revoked:
                # If no unrevoked approval exists and caller requested include_revoked, return latest revoked approval
                cursor.execute(
                    """
                    SELECT * FROM application_approvals
                    WHERE packet_id = ? AND user_id = ?
                    ORDER BY approved_at DESC, id DESC LIMIT 1
                    """,
                    (packet_id, user_id),
                )
                row = cursor.fetchone()

            if not row:
                return None
            row_dict = dict(row)
            row_dict["is_consumed"] = bool(row_dict.get("is_consumed", 0))
            row_dict["is_revoked"] = bool(row_dict.get("is_revoked", 0))
            return ApplicationApproval(**row_dict)

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
        file_hash: Optional[str] = None,
        file_size_bytes: Optional[int] = None,
        file_format: Optional[str] = None,
        parser_version: str = "1.0.0",
        extraction_confidence: float = 1.0,
        supersedes_job_description_id: Optional[int] = None,
        is_active: bool = True,
        binary_integrity_state: Optional[str] = None,
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
        computed_raw_hash = hashlib.sha256(raw_content_clean.encode("utf-8")).hexdigest()

        # Independently calculate and validate caller-supplied content_hash
        if content_hash is not None and content_hash != computed_raw_hash:
            raise ValidationError(
                f"Supplied content_hash '{content_hash}' does not match computed hash '{computed_raw_hash}'."
            )
        content_hash = computed_raw_hash

        # Independently calculate and validate caller-supplied RFC 8785 canonical snapshot_hash
        manifest = {
            "user_id": user_id,
            "company_name": company_name.strip(),
            "job_title": job_title.strip(),
            "raw_content_hash": computed_raw_hash,
            "parsed_data": parsed_data,
            "parser_version": parser_version,
            "source_type": source_type,
            "source_url": source_url,
            "original_filename": original_filename,
        }
        computed_snapshot_hash = canonical_json_hash(manifest)

        if snapshot_hash is not None and snapshot_hash != computed_snapshot_hash:
            raise ValidationError(
                f"Supplied snapshot_hash '{snapshot_hash}' does not match computed canonical manifest hash '{computed_snapshot_hash}'."
            )
        snapshot_hash = computed_snapshot_hash

        # Determine and validate binary_integrity_state
        normalized_source_type = (source_type or "").lower().strip()
        is_uploaded = normalized_source_type in ("uploaded_document", "upload")
        has_all_binary = bool(storage_filename and file_hash and file_size_bytes is not None and file_format)

        if binary_integrity_state is not None:
            if binary_integrity_state == "LEGACY_TEXT_ONLY":
                raise SecurityAuthorizationError(
                    "LEGACY_TEXT_ONLY binary integrity state cannot be assigned via public API; "
                    "it is reserved exclusively for historical database migrations."
                )
            if binary_integrity_state not in ("REQUIRED", "VERIFIED", "NOT_APPLICABLE"):
                raise ValidationError(f"Invalid binary_integrity_state: '{binary_integrity_state}'.")
            resolved_binary_state = binary_integrity_state
        else:
            if is_uploaded:
                resolved_binary_state = "VERIFIED" if has_all_binary else "REQUIRED"
            else:
                resolved_binary_state = "NOT_APPLICABLE"

        parsed_json = json.dumps(parsed_data) if parsed_data else None

        with self.immediate_transaction() as conn:
            cursor = conn.cursor()

            # Check deduplication per-user for root snapshots
            if supersedes_job_description_id is None:
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

            # If superseding, verify parent ownership, active status, and linear lineage
            if supersedes_job_description_id is not None:
                cursor.execute(
                    "SELECT id, user_id, is_active FROM job_descriptions WHERE id = ?",
                    (supersedes_job_description_id,),
                )
                parent = cursor.fetchone()
                if not parent:
                    raise JobDescriptionNotFoundError(
                        f"Job Description #{supersedes_job_description_id} not found."
                    )
                if parent["user_id"] != user_id:
                    raise CrossUserAccessError(
                        user_id=user_id,
                        target_user_id=parent["user_id"],
                        resource=f"JobDescription #{supersedes_job_description_id}",
                    )
                if not parent["is_active"]:
                    raise ValidationError(
                        f"Cannot supersede Job Description #{supersedes_job_description_id}: record is already inactive."
                    )

                cursor.execute(
                    "SELECT id FROM job_descriptions WHERE supersedes_job_description_id = ? AND user_id = ? AND is_active = 1",
                    (supersedes_job_description_id, user_id),
                )
                active_child = cursor.fetchone()
                if active_child:
                    raise ValidationError(
                        f"Cannot supersede Job Description #{supersedes_job_description_id}: an active child revision already exists as ID #{active_child['id']}."
                    )

                cursor.execute(
                    "UPDATE job_descriptions SET is_active = 0 WHERE id = ? AND user_id = ? AND is_active = 1",
                    (supersedes_job_description_id, user_id),
                )
                if cursor.rowcount != 1:
                    raise ConcurrencyConflictError(
                        f"Failed to deactivate parent Job Description #{supersedes_job_description_id} (concurrent modification)."
                    )

            cursor.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content, content_hash, snapshot_hash, parsed_data,
                    source_url, original_filename, storage_filename, file_hash, file_size_bytes, file_format,
                    parser_version, extraction_confidence, supersedes_job_description_id, binary_integrity_state, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    file_hash,
                    file_size_bytes,
                    file_format,
                    parser_version,
                    extraction_confidence,
                    supersedes_job_description_id,
                    resolved_binary_state,
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
        file_hash: Optional[str] = None,
        file_size_bytes: Optional[int] = None,
        file_format: Optional[str] = None,
        parser_version: str = "1.0.0",
        extraction_confidence: float = 1.0,
        supersedes_job_description_id: Optional[int] = None,
        is_active: bool = True,
        binary_integrity_state: Optional[str] = None,
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
            file_hash=file_hash,
            file_size_bytes=file_size_bytes,
            file_format=file_format,
            parser_version=parser_version,
            extraction_confidence=extraction_confidence,
            supersedes_job_description_id=supersedes_job_description_id,
            is_active=is_active,
            binary_integrity_state=binary_integrity_state,
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
            file_hash=existing.file_hash,
            file_size_bytes=existing.file_size_bytes,
            file_format=existing.file_format,
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

        storage_filename, detected_format, file_size, file_hash = validator.save_user_job_description_file(
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
            file_hash=file_hash,
            file_size_bytes=file_size,
            file_format=detected_format,
            parser_version=structured.parser_version,
            extraction_confidence=structured.extraction_confidence,
            parsed_data=structured.to_dict(),
        )

    def recover_unverified_job_description(
        self,
        user_id: int,
        job_description_id: int,
        file_bytes: bytes,
        original_filename: str,
        user_base_dir: Optional[Path] = None,
    ) -> JobDescription:
        """Controlled recovery path for historical job descriptions missing verified binary metadata (Phase 9.1.2.5 Section 5.1).

        1. Validates user identity and resource ownership.
        2. Inspects existing job description: must be active uploaded record in REQUIRED / unverified state.
        3. Preserves original record and snapshot immutable (superseded via new child revision).
        4. Validates actual file bytes using FileSecurityValidator (PDF/DOCX, magic bytes, size cap).
        5. Computes physical SHA-256 and exact size in bytes.
        6. Persists file securely to user storage.
        7. Parses text content using JobParser.
        8. Creates authoritative child revision linked via supersedes_job_description_id, with binary_integrity_state = 'VERIFIED'.
        9. Performs fresh security scan and persists authenticated v2 scan record with source_binary_hash.
        10. Audits recovery outcome in application_logs.
        """
        from src.security.file_security import FileSecurityValidator
        from src.preparer.job_parser import JobParser
        from src.security.security_preflight import SecurityPreflightManager
        from src.security.scan_signer import SecurityScanSigner

        user = self.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User #{user_id}")

        existing = self.get_job_description(job_description_id, user_id=user_id)
        if not existing:
            raise JobDescriptionNotFoundError(f"Job Description #{job_description_id} not found.")

        if existing.user_id != user_id:
            raise CrossUserAccessError(
                user_id=user_id,
                target_user_id=existing.user_id,
                resource=f"JobDescription #{job_description_id}",
            )

        if not existing.is_active:
            raise ValidationError(
                f"Cannot recover Job Description #{job_description_id}: record is inactive."
            )

        norm_source = (existing.source_type or "").lower().strip()
        if norm_source not in ("uploaded_document", "upload"):
            raise ValidationError(
                f"Cannot recover Job Description #{job_description_id}: only uploaded documents require binary recovery (source_type is '{existing.source_type}')."
            )

        if existing.binary_integrity_state == "VERIFIED" and existing.file_hash:
            raise ValidationError(
                f"Job Description #{job_description_id} already possesses VERIFIED binary integrity metadata."
            )

        # 4 & 5. Validate file bytes and format
        validator = FileSecurityValidator(base_storage_dir=user_base_dir)
        validator.validate_file(file_bytes, original_filename)

        ext = Path(original_filename).suffix.lstrip(".").lower()
        if ext not in ("pdf", "docx"):
            raise InvalidFileFormatError(f"Unsupported file format '.{ext}'. Only PDF and DOCX documents are accepted.")

        storage_filename, detected_format, file_size, file_hash = validator.save_user_job_description_file(
            user_id=user_id,
            file_bytes=file_bytes,
            original_filename=original_filename,
        )

        job_dir = validator.get_user_job_descriptions_dir(user_id)
        dest_path = job_dir / storage_filename

        # Extract text and parse
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

        company = structured.company_name or existing.company_name or "Unknown Company"
        title = structured.job_title or existing.job_title or stem_name or "Untitled Position"

        # 8. Create child revision linked via supersedes_job_description_id
        recovered_jd = self.save_job_description_snapshot(
            user_id=user_id,
            company_name=company,
            job_title=title,
            raw_content=raw_text or existing.raw_content,
            source_type="upload",
            original_filename=original_filename,
            storage_filename=storage_filename,
            file_hash=file_hash,
            file_size_bytes=file_size,
            file_format=detected_format,
            parser_version=structured.parser_version,
            extraction_confidence=structured.extraction_confidence,
            parsed_data=structured.to_dict() if structured else existing.parsed_data,
            supersedes_job_description_id=job_description_id,
            binary_integrity_state="VERIFIED",
        )

        # 9. Perform fresh security scan and persist authenticated v2 scan record
        preflight = SecurityPreflightManager(db_manager=self, file_validator=validator)
        scan_signer = SecurityScanSigner()

        scan_res = preflight.detector.scan(
            raw_text or existing.raw_content
        )

        manifest, sig, key_id = scan_signer.sign_scan_result(
            user_id=user_id,
            source_type="job_description",
            source_id=recovered_jd.id,
            source_version=1,
            source_hash=recovered_jd.content_hash,
            snapshot_hash=recovered_jd.snapshot_hash,
            scan_result=scan_res,
            manifest_version="v2",
            source_binary_hash=file_hash,
            source_binary_size_bytes=file_size,
            source_binary_format=detected_format,
        )

        self.save_security_scan(
            user_id=user_id,
            source_type="job_description",
            source_id=recovered_jd.id,
            source_version=1,
            source_hash=recovered_jd.content_hash,
            snapshot_hash=recovered_jd.snapshot_hash,
            scanner_version=scan_res.engine_version,
            policy_version=scan_res.policy_version,
            risk_score=scan_res.risk_score,
            classification=scan_res.classification,
            threats_detected=[t.to_dict() for t in scan_res.threats_detected],
            key_id=key_id,
            hmac_signature=sig,
            scanned_at=manifest["scanned_at"],
            source_binary_hash=file_hash,
            source_binary_size_bytes=file_size,
            source_binary_format=detected_format,
            manifest_version="v2",
        )

        # 10. Audit recovery outcome
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO application_logs (user_id, action, details)
                VALUES (?, ?, ?)
                """,
                (
                    user_id,
                    "JOB_DESCRIPTION_RECOVERED",
                    f"Job Description #{job_description_id} successfully recovered as #{recovered_jd.id} (SHA-256: {file_hash[:16]}..., size: {file_size} bytes)",
                ),
            )

        logger.info(
            "Successfully recovered historical Job Description #%d as new revision #%d (user %d, SHA-256: %s...)",
            job_description_id, recovered_jd.id, user_id, file_hash[:16],
        )
        return recovered_jd

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
        resume_id: Optional[int] = None,
        status: str = ApplicationStatus.DRAFT.value,
        notes: Optional[str] = None,
        application_source: str = ApplicationSource.JOB_DESCRIPTION.value,
        external_application_url: Optional[str] = None,
        target_role: Optional[str] = None,
        employment_type: Optional[str] = None,
        location: Optional[str] = None,
        salary_range: Optional[str] = None,
        application_deadline: Optional[str] = None,
        is_archived: int = 0,
    ) -> Application:
        """Creates an application owned by a specific user with composite foreign key validation and timeline initialization."""
        if not company_name or not company_name.strip():
            raise ValidationError("company_name cannot be empty.")
        if not job_title or not job_title.strip():
            raise ValidationError("job_title cannot be empty.")

        valid_statuses = ApplicationStatus.list()
        if status not in valid_statuses:
            raise InvalidStatusError(status, valid_statuses)

        valid_sources = ApplicationSource.list()
        if application_source not in valid_sources:
            raise ValidationError(f"Invalid application_source: '{application_source}'. Valid options: {valid_sources}")

        with self.transaction() as conn:
            cursor = conn.cursor()

            # Verify user exists
            cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
            if not cursor.fetchone():
                raise UserNotFoundError(user_id)

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

            # If resume_id is provided, verify it belongs to user_id and is active
            if resume_id is not None:
                cursor.execute("SELECT id, user_id, is_active FROM resumes WHERE id = ?", (resume_id,))
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

            cursor.execute(
                """
                INSERT INTO applications (
                    user_id, company_name, job_title, job_id, job_description_id, resume_id,
                    status, notes, application_source, external_application_url, target_role,
                    employment_type, location, salary_range, application_deadline, is_archived
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    company_name.strip(),
                    job_title.strip(),
                    job_id,
                    job_description_id,
                    resume_id,
                    status,
                    notes,
                    application_source,
                    external_application_url,
                    target_role,
                    employment_type,
                    location,
                    salary_range,
                    application_deadline,
                    is_archived,
                ),
            )
            app_id = int(cursor.lastrowid or 0)

            # Emit initial timeline event
            event_payload = {
                "source": application_source,
                "job_id": job_id,
                "job_description_id": job_description_id,
                "resume_id": resume_id,
            }
            payload_json = canonical_json_bytes(event_payload).decode("utf-8")
            now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            evt_hash = DatabaseManager.compute_event_hash(
                actor_identifier=f"user_{user_id}",
                actor_type="CANDIDATE",
                application_id=app_id,
                event_payload_json=payload_json,
                event_type="APPLICATION_CREATED",
                new_status=status,
                previous_event_hash="GENESIS",
                previous_status=None,
                sequence_no=1,
                session_reference=None,
                user_id=user_id,
                created_at=now_ts,
                hash_version="v2",
            )
            cursor.execute(
                """
                INSERT INTO application_events (
                    application_id, user_id, sequence_no, event_type,
                    previous_status, new_status, actor_type, actor_identifier,
                    session_reference, event_payload_json, previous_event_hash, event_hash,
                    created_at
                ) VALUES (?, ?, 1, 'APPLICATION_CREATED', NULL, ?, 'CANDIDATE', ?, NULL, ?, 'GENESIS', ?, ?)
                """,
                (
                    app_id,
                    user_id,
                    status,
                    f"user_{user_id}",
                    payload_json,
                    evt_hash,
                    now_ts,
                ),
            )

            cursor.execute("SELECT * FROM applications WHERE id = ?", (app_id,))
            return Application(**dict(cursor.fetchone()))

    def update_application_resume_and_job(
        self,
        application_id: int,
        user_id: int,
        resume_id: Optional[int] = None,
        job_id: Optional[int] = None,
    ) -> bool:
        """Updates resume_id and/or job_id on a user-owned application with cross-user isolation."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id FROM applications WHERE id = ?", (application_id,))
            row = cursor.fetchone()
            if not row:
                return False
            if row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"Application #{application_id}",
                )
            updates = []
            params: list = []
            if resume_id is not None:
                updates.append("resume_id = ?")
                params.append(resume_id)
            if job_id is not None:
                updates.append("job_id = ?")
                params.append(job_id)
            if not updates:
                return True
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.extend([application_id, user_id])
            sql = f"UPDATE applications SET {', '.join(updates)} WHERE id = ? AND user_id = ?"
            cursor.execute(sql, params)
            return cursor.rowcount == 1

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

    def list_user_applications(
        self,
        user_id: int,
        status: Optional[str] = None,
        search_term: Optional[str] = None,
        sort_by: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        include_archived: bool = False,
        status_in: Optional[List[str]] = None,
        employment_type: Optional[str] = None,
    ) -> List[Application]:
        """Lists applications belonging to a user, with status, archive, employment type, search filtering, sorting and pagination."""
        query = "SELECT * FROM applications WHERE user_id = ?"
        params: List[Any] = [user_id]

        if not include_archived:
            query += " AND is_archived = 0"

        if status:
            from src.lifecycle.state_machine import ApplicationStateMachine
            try:
                norm_status = ApplicationStateMachine.normalize_status(status).value
            except Exception:
                norm_status = status
            query += " AND status = ?"
            params.append(norm_status)
        elif status_in:
            from src.lifecycle.state_machine import ApplicationStateMachine
            norm_statuses = []
            for s in status_in:
                if not s or not isinstance(s, str):
                    continue
                try:
                    norm_statuses.append(ApplicationStateMachine.normalize_status(s).value)
                except Exception:
                    norm_statuses.append(s.strip())
            if norm_statuses:
                placeholders = ", ".join(["?"] * len(norm_statuses))
                query += f" AND status IN ({placeholders})"
                params.extend(norm_statuses)

        if employment_type and employment_type.strip():
            query += " AND employment_type = ?"
            params.append(employment_type.strip())

        if search_term and search_term.strip():
            term = f"%{search_term.strip()}%"
            query += " AND (company_name LIKE ? OR job_title LIKE ? OR notes LIKE ?)"
            params.extend([term, term, term])

        # Sorting whitelist
        ALLOWED_SORT_ORDERS = {
            "updated_at_desc": "updated_at DESC",
            "created_at_desc": "created_at DESC",
            "created_at_asc": "created_at ASC",
            "deadline_asc": "application_deadline ASC NULLS LAST",
            "company_name_asc": "company_name ASC, updated_at DESC",
            "job_title_asc": "job_title ASC, updated_at DESC",
            "company_name": "company_name ASC, updated_at DESC",
            "job_title": "job_title ASC, updated_at DESC",
        }

        if sort_by and sort_by.strip():
            clean_sort = sort_by.strip().lower()
            if clean_sort not in ALLOWED_SORT_ORDERS:
                raise ValidationError(
                    f"Invalid sort_by value '{sort_by}'. Allowed options: {sorted(ALLOWED_SORT_ORDERS.keys())}"
                )
            query += f" ORDER BY {ALLOWED_SORT_ORDERS[clean_sort]}"
        else:
            query += " ORDER BY updated_at DESC"

        # Validate pagination arguments independently before SQL construction
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
                raise ValidationError("limit must be a non-negative integer or None.")

        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValidationError("offset must be a non-negative integer.")

        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        elif offset > 0:
            query += " LIMIT -1 OFFSET ?"
            params.append(offset)

        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [Application(**dict(row)) for row in cursor.fetchall()]

    def transition_application_status(
        self,
        application_id: int,
        user_id: int,
        new_status: Union[str, ApplicationStatus],
        expected_current_status: Optional[Union[str, ApplicationStatus]] = None,
        actor_type: str = "CANDIDATE",
        actor_identifier: Optional[str] = None,
        session_reference: Optional[str] = None,
        transition_metadata: Optional[Dict[str, Any]] = None,
        reopen_rationale: Optional[str] = None,
        **kwargs: Any,
    ) -> Application:
        """Atomically transitions an application's lifecycle status and appends an immutable timeline event.

        Enforces:
        1. Immediate SQLite write lock (BEGIN IMMEDIATE) acquired before reading current state.
        2. Strict candidate ownership verification (application_id + user_id).
        3. Stale-state detection if expected_current_status is provided.
        4. ApplicationStateMachine transition validation (rejects invalid transitions).
        5. Gate protection: Generic transitions to APPROVED or SUBMITTED are strictly prohibited
           and cannot be bypassed by caller-supplied booleans (e.g. is_gate_authorized=True).
        6. Reopening rationale: Reopening from terminal states to IN_PROGRESS requires a mandatory,
           non-empty, non-whitespace rationale string.
        7. Audit payload protection: Reserved audit fields cannot be overridden by transition_metadata.
        8. Conditional UPDATE preventing concurrent overwrite races.
        9. Complete atomic rollback of status mutation and timeline event if any step fails.
        """
        from src.lifecycle.state_machine import ApplicationStateMachine

        target_status = ApplicationStateMachine.normalize_status(new_status)

        # Gate-protected statuses cannot be set via generic status transitions
        if target_status in ApplicationStateMachine.GATE_PROTECTED_TARGETS:
            if target_status == ApplicationStatus.APPROVED:
                raise SecurityAuthorizationError(
                    f"Transition to '{target_status.value}' is gate-protected and cannot be performed via generic status transitions. "
                    "Transition to 'APPROVED' requires explicit human packet approval via HumanApprovalGate, not generic status updates."
                )
            if target_status == ApplicationStatus.SUBMITTED:
                raise SecurityAuthorizationError(
                    f"Transition to '{target_status.value}' is gate-protected and cannot be performed via generic status transitions. "
                    "Transition to 'SUBMITTED' requires candidate manual submission confirmation with an action ticket, not generic status updates."
                )

        # Reject attempts to overwrite reserved audit payload fields
        RESERVED_AUDIT_KEYS = {
            "previous_status",
            "new_status",
            "application_id",
            "user_id",
            "actor_type",
            "session_reference",
            "reopen_rationale",
            "created_at",
            "sequence_no",
            "event_hash",
            "prev_event_hash",
            "event_type",
        }
        if transition_metadata:
            for key in transition_metadata:
                if key in RESERVED_AUDIT_KEYS:
                    raise ValidationError(
                        f"transition_metadata cannot override reserved audit payload field '{key}'."
                    )

        # Acquire SQLite RESERVED write lock BEFORE reading current state to prevent concurrency races
        with self.immediate_transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise ApplicationNotFoundError(application_id)

            if app_row["user_id"] is not None and app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )

            current_status_raw = app_row["status"]
            current_status = ApplicationStateMachine.normalize_status(current_status_raw)

            if expected_current_status is not None:
                expected_norm = ApplicationStateMachine.normalize_status(expected_current_status)
                if current_status != expected_norm:
                    raise ValidationError(
                        f"Stale state conflict: Expected application #{application_id} to be in status "
                        f"'{expected_norm.value}', but found '{current_status.value}'."
                    )

            ApplicationStateMachine.validate_transition(
                current_status=current_status,
                new_status=target_status,
            )

            is_reopening = ApplicationStateMachine.is_reopening_transition(current_status, target_status)
            if is_reopening:
                if not reopen_rationale or not reopen_rationale.strip():
                    raise ValidationError(
                        f"A non-empty reopening rationale is required when reopening an application from "
                        f"'{current_status.value}' to '{target_status.value}'."
                    )

            # Conditional UPDATE to prevent concurrency races
            cursor.execute(
                """
                UPDATE applications
                SET status = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ? AND status = ?
                """,
                (target_status.value, application_id, user_id, current_status_raw),
            )
            if cursor.rowcount == 0:
                raise ValidationError(
                    f"Concurrent status modification conflict detected on application #{application_id}."
                )

            event_type = ApplicationStateMachine.get_transition_event_type(current_status, target_status)
            payload = dict(transition_metadata or {})
            payload["previous_status"] = current_status.value
            payload["new_status"] = target_status.value
            payload["application_id"] = application_id
            payload["user_id"] = user_id
            payload["actor_type"] = actor_type
            if session_reference is not None:
                payload["session_reference"] = session_reference
            if is_reopening and reopen_rationale:
                payload["reopen_rationale"] = reopen_rationale.strip()

            self._insert_application_event_internal(
                cursor=cursor,
                application_id=application_id,
                user_id=user_id,
                event_type=event_type,
                new_status=target_status.value,
                previous_status=current_status.value,
                actor_type=actor_type,
                actor_identifier=actor_identifier or f"user_{user_id}",
                session_reference=session_reference,
                event_payload=payload,
            )

            cursor.execute("SELECT * FROM applications WHERE id = ?", (application_id,))
            fresh_row = cursor.fetchone()
            return Application(**dict(fresh_row))

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
            new_id = int(cursor.lastrowid or 0)

            # Emit initial event for workspace-created application
            event_payload = {
                "source": "workspace_created",
                "job_description_id": job_description_id,
                "resume_id": resume_id,
            }
            payload_json = canonical_json_bytes(event_payload).decode("utf-8")
            now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            evt_hash = DatabaseManager.compute_event_hash(
                actor_identifier=f"user_{user_id}",
                actor_type="CANDIDATE",
                application_id=new_id,
                event_payload_json=payload_json,
                event_type="APPLICATION_CREATED",
                new_status=ApplicationStatus.UNDER_REVIEW.value,
                previous_event_hash="GENESIS",
                previous_status=None,
                sequence_no=1,
                session_reference=None,
                user_id=user_id,
                created_at=now_ts,
                hash_version="v2",
            )
            cursor.execute(
                """
                INSERT INTO application_events (
                    application_id, user_id, sequence_no, event_type,
                    previous_status, new_status, actor_type, actor_identifier,
                    session_reference, event_payload_json, previous_event_hash, event_hash,
                    created_at
                ) VALUES (?, ?, 1, 'APPLICATION_CREATED', NULL, ?, 'CANDIDATE', ?, NULL, ?, 'GENESIS', ?, ?)
                """,
                (
                    new_id,
                    user_id,
                    ApplicationStatus.UNDER_REVIEW.value,
                    f"user_{user_id}",
                    payload_json,
                    evt_hash,
                    now_ts,
                ),
            )

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
        if user_base_dir:
            if user_base_dir.name == "resumes":
                base_dir = user_base_dir
            elif user_base_dir.name == str(user_id):
                base_dir = user_base_dir / "resumes"
            else:
                base_dir = user_base_dir / str(user_id) / "resumes"
        else:
            base_dir = validator.get_user_resumes_dir(user_id)
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
        base_dir = user_base_dir or validator.get_user_resumes_dir(user_id)
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

        validator = FileSecurityValidator()
        if user_base_dir:
            base_dir = user_base_dir
        elif hasattr(self, "db_path") and self.db_path and self.db_path != ":memory:":
            cand_users = Path(self.db_path).parent / "users"
            cand_users_parent = Path(self.db_path).parent.parent / "users"
            if (cand_users / str(user_id) / "resumes").is_dir():
                base_dir = cand_users / str(user_id) / "resumes"
            elif (cand_users_parent / str(user_id) / "resumes").is_dir():
                base_dir = cand_users_parent / str(user_id) / "resumes"
            else:
                base_dir = validator.get_user_resumes_dir(user_id)
        else:
            base_dir = validator.get_user_resumes_dir(user_id)
        target_path = base_dir / storage_filename
        FileSecurityValidator.validate_path_containment(target_path, base_dir)

        if not target_path.exists():
            raise FileNotFoundError(f"Resume file on disk not found: {target_path}")

        return target_path

    def verify_and_load_resume(
        self,
        user_id: int,
        resume_id: int,
        version_num: Optional[int] = None,
        user_base_dir: Optional[Path] = None,
        fresh_parse: bool = True,
    ):
        """Just-in-time verifies and loads candidate resume binary via ResumeIntegrityVerifier."""
        from src.security.resume_verifier import ResumeIntegrityVerifier
        verifier = ResumeIntegrityVerifier(db_manager=self)
        return verifier.verify_and_load_resume(
            user_id=user_id,
            resume_id=resume_id,
            version_num=version_num,
            user_base_dir=user_base_dir,
            fresh_parse=fresh_parse,
        )

    def record_resume_recovery_audit(
        self,
        user_id: int,
        resume_id: int,
        version_num: int,
        previous_state: Dict[str, Any],
        recovery_outcome: str,
        recovered_file_hash: Optional[str] = None,
        recovered_file_size_bytes: Optional[int] = None,
        details: Optional[str] = None,
    ) -> int:
        """Persists durable audit record for resume integrity recovery."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO resume_recovery_audit (
                    user_id, resume_id, version_num, previous_state_json,
                    recovered_file_hash, recovered_file_size_bytes, recovery_outcome, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    resume_id,
                    version_num,
                    json.dumps(previous_state),
                    recovered_file_hash,
                    recovered_file_size_bytes,
                    recovery_outcome,
                    details,
                ),
            )
            return cursor.lastrowid

    def get_resume_recovery_audit(
        self,
        user_id: int,
        resume_id: Optional[int] = None,
        version_num: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves durable audit records for resume recovery."""
        with self.connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM resume_recovery_audit WHERE user_id = ?"
            params: List[Any] = [user_id]
            if resume_id is not None:
                query += " AND resume_id = ?"
                params.append(resume_id)
            if version_num is not None:
                query += " AND version_num = ?"
                params.append(version_num)
            query += " ORDER BY id DESC"
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def _row_to_security_scan(row: sqlite3.Row) -> SecurityScan:
        keys = row.keys()
        return SecurityScan(
            id=row["id"],
            user_id=row["user_id"],
            source_type=row["source_type"],
            source_id=row["source_id"],
            source_version=row["source_version"],
            source_hash=row["source_hash"],
            snapshot_hash=row["snapshot_hash"],
            scanner_version=row["scanner_version"],
            policy_version=row["policy_version"],
            risk_score=row["risk_score"],
            classification=row["classification"],
            threats_detected_json=row["threats_detected_json"],
            key_id=row["key_id"],
            hmac_signature=row["hmac_signature"],
            source_binary_hash=row["source_binary_hash"] if "source_binary_hash" in keys else None,
            source_binary_size_bytes=row["source_binary_size_bytes"] if "source_binary_size_bytes" in keys else None,
            source_binary_format=row["source_binary_format"] if "source_binary_format" in keys else None,
            manifest_version=row["manifest_version"] if "manifest_version" in keys and row["manifest_version"] else "v1",
            scanned_at=row["scanned_at"],
        )

    def save_security_scan(
        self,
        user_id: int,
        source_type: str,
        source_id: int,
        source_version: int,
        source_hash: str,
        snapshot_hash: Optional[str],
        scanner_version: str,
        policy_version: str,
        risk_score: float,
        classification: str,
        threats_detected: List[Dict[str, Any]],
        key_id: str,
        hmac_signature: str,
        scanned_at: Optional[str] = None,
        source_binary_hash: Optional[str] = None,
        source_binary_size_bytes: Optional[int] = None,
        source_binary_format: Optional[str] = None,
        manifest_version: Optional[str] = None,
    ) -> SecurityScan:
        """Persists an authenticated, HMAC-signed security scan record."""
        resolved_manifest_version = manifest_version or ("v2" if source_binary_hash is not None else "v1")
        threats_json = json.dumps(threats_detected)
        with self.transaction() as conn:
            cursor = conn.cursor()
            if scanned_at:
                cursor.execute(
                    """
                    INSERT INTO security_scans (
                        user_id, source_type, source_id, source_version,
                        source_hash, snapshot_hash, scanner_version, policy_version,
                        risk_score, classification, threats_detected_json,
                        key_id, hmac_signature, scanned_at,
                        source_binary_hash, source_binary_size_bytes, source_binary_format, manifest_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id, source_type, source_id, source_version,
                        source_hash, snapshot_hash, scanner_version, policy_version,
                        risk_score, classification, threats_json,
                        key_id, hmac_signature, scanned_at,
                        source_binary_hash, source_binary_size_bytes, source_binary_format, resolved_manifest_version,
                    ),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO security_scans (
                        user_id, source_type, source_id, source_version,
                        source_hash, snapshot_hash, scanner_version, policy_version,
                        risk_score, classification, threats_detected_json,
                        key_id, hmac_signature,
                        source_binary_hash, source_binary_size_bytes, source_binary_format, manifest_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id, source_type, source_id, source_version,
                        source_hash, snapshot_hash, scanner_version, policy_version,
                        risk_score, classification, threats_json,
                        key_id, hmac_signature,
                        source_binary_hash, source_binary_size_bytes, source_binary_format, resolved_manifest_version,
                    ),
                )
            scan_id = cursor.lastrowid
            cursor.execute("SELECT * FROM security_scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            return self._row_to_security_scan(row)

    def get_latest_security_scan(
        self,
        user_id: int,
        source_type: str,
        source_id: int,
        source_version: Optional[int] = None,
    ) -> Optional[SecurityScan]:
        """Retrieves the newest security scan record for a given source."""
        with self.connection() as conn:
            cursor = conn.cursor()
            if source_version is not None:
                cursor.execute(
                    """
                    SELECT * FROM security_scans
                    WHERE user_id = ? AND source_type = ? AND source_id = ? AND source_version = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (user_id, source_type, source_id, source_version),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM security_scans
                    WHERE user_id = ? AND source_type = ? AND source_id = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (user_id, source_type, source_id),
                )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_security_scan(row)

    def get_security_scan_by_id(self, scan_id: int) -> Optional[SecurityScan]:
        """Retrieves a security scan record by its primary key ID."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM security_scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_security_scan(row)

    def list_security_scans(
        self,
        user_id: int,
        source_type: Optional[str] = None,
        source_id: Optional[int] = None,
    ) -> List[SecurityScan]:
        """Lists historical security scan records for a user."""
        with self.connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM security_scans WHERE user_id = ?"
            params: List[Any] = [user_id]
            if source_type is not None:
                query += " AND source_type = ?"
                params.append(source_type)
            if source_id is not None:
                query += " AND source_id = ?"
                params.append(source_id)
            query += " ORDER BY id DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._row_to_security_scan(row) for row in rows]

    def record_security_scan_override(
        self,
        user_id: int,
        scan_id: int,
        override_reason: str,
        actor_type: str = "candidate",
    ) -> int:
        """Records an immutable candidate or admin override for a quarantined security scan."""
        if not override_reason or not override_reason.strip():
            raise ValidationError("Security scan override reason cannot be empty.")

        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM security_scans WHERE id = ?", (scan_id,))
            scan_row = cursor.fetchone()
            if not scan_row:
                raise ValidationError(f"Security scan #{scan_id} not found.")
            if scan_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=scan_row["user_id"],
                    resource=f"security_scans #{scan_id}",
                )

            cursor.execute(
                """
                INSERT INTO security_scan_overrides (
                    user_id, scan_id, source_type, source_id, source_version,
                    override_reason, actor_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    scan_id,
                    scan_row["source_type"],
                    scan_row["source_id"],
                    scan_row["source_version"],
                    override_reason.strip(),
                    actor_type,
                ),
            )
            return cursor.lastrowid

    def get_security_scan_override(
        self,
        user_id: int,
        scan_id: int,
    ) -> Optional[SecurityScanOverride]:
        """Retrieves override audit record for a security scan."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM security_scan_overrides
                WHERE user_id = ? AND scan_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (user_id, scan_id),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return SecurityScanOverride(
                id=row["id"],
                user_id=row["user_id"],
                scan_id=row["scan_id"],
                source_type=row["source_type"],
                source_id=row["source_id"],
                source_version=row["source_version"],
                override_reason=row["override_reason"],
                actor_type=row["actor_type"],
                created_at=row["created_at"],
            )

    def record_legacy_integrity_exception(
        self,
        user_id: int,
        job_description_id: int,
        original_source_type: str,
        previous_binary_state: Optional[str],
        assigned_legacy_state: str,
        source_snapshot_hash: Optional[str],
        migration_version: str = "9.1.2.3",
        migration_reason: str = "Grandfathered pre-9.1.1 uploaded record with NULL binary metadata",
        outcome: str = "SUCCESS",
        evidence_type: Optional[str] = None,
        evidence_reference_id: Optional[str] = None,
        cursor: Optional[sqlite3.Cursor] = None,
    ) -> int:
        """Records an immutable audit entry in legacy_integrity_exceptions."""
        sql = """
            INSERT INTO legacy_integrity_exceptions (
                user_id, job_description_id, original_source_type,
                previous_binary_state, assigned_legacy_state,
                source_snapshot_hash, migration_version,
                evidence_type, evidence_reference_id,
                migration_reason, outcome
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            user_id,
            job_description_id,
            original_source_type,
            previous_binary_state,
            assigned_legacy_state,
            source_snapshot_hash,
            migration_version,
            evidence_type,
            evidence_reference_id,
            migration_reason,
            outcome,
        )
        if cursor:
            cursor.execute(sql, params)
            return cursor.lastrowid
        else:
            with self.immediate_transaction() as conn:
                cur = conn.cursor()
                cur.execute(sql, params)
                return cur.lastrowid

    def get_legacy_integrity_exception(
        self,
        job_description_id: int,
        user_id: Optional[int] = None,
    ) -> Optional[LegacyIntegrityException]:
        """Retrieves the legacy integrity exception record for a job description."""
        with self.connection() as conn:
            cursor = conn.cursor()
            if user_id is not None:
                cursor.execute(
                    """
                    SELECT * FROM legacy_integrity_exceptions
                    WHERE job_description_id = ? AND user_id = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (job_description_id, user_id),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM legacy_integrity_exceptions
                    WHERE job_description_id = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (job_description_id,),
                )
            row = cursor.fetchone()
            if not row:
                return None
            return LegacyIntegrityException(
                id=row["id"],
                user_id=row["user_id"],
                job_description_id=row["job_description_id"],
                original_source_type=row["original_source_type"],
                previous_binary_state=row["previous_binary_state"],
                assigned_legacy_state=row["assigned_legacy_state"],
                source_snapshot_hash=row["source_snapshot_hash"],
                migration_version=row["migration_version"],
                migration_timestamp=row["migration_timestamp"],
                migration_reason=row["migration_reason"],
                outcome=row["outcome"],
                evidence_type=row["evidence_type"] if "evidence_type" in row.keys() else None,
                evidence_reference_id=row["evidence_reference_id"] if "evidence_reference_id" in row.keys() else None,
            )

    def record_legacy_evidence_attestation(
        self,
        verified_evidence: Any,
        attesting_principal: Optional[Any] = None,
        details: Optional[str] = None,
        cursor: Optional[sqlite3.Cursor] = None,
        **kwargs: Any,
    ) -> int:
        """Records an authoritative independent evidence attestation for a historical job description.

        Enforces Phase 9.1.2.11 Contracts:
        - Requires a VerifiedLegacyEvidence instance produced by LegacyEvidenceVerifier.verify().
        - In production, requires a genuine provider-bound AuthenticatedMigrationPrincipal context.
        - Persists strictly the authenticated principal matching verified_evidence.
        - Revalidates principal against the authoritative ServiceAuthenticationProvider.
        - Eliminates TOCTOU revocation races by performing revocation checks and insertion
          within a single atomic write transaction (BEGIN IMMEDIATE) or caller write cursor.
        """
        from src.security.legacy_evidence_verifier import (
            VerifiedLegacyEvidence,
            AuthenticatedMigrationPrincipal,
            get_default_evidence_trust_store,
            get_current_utc_time,
            _AUTH_TOKEN,
        )

        if not isinstance(verified_evidence, VerifiedLegacyEvidence):
            raise SecurityAuthorizationError(
                "Direct insertion or arbitrary evidence references are strictly prohibited. "
                "record_legacy_evidence_attestation() requires a VerifiedLegacyEvidence instance "
                "produced by LegacyEvidenceVerifier.verify()."
            )

        app_env = getattr(self, "app_env", None) or os.environ.get("APP_ENV", "development").strip().lower()
        is_production_like = app_env in ("production", "staging", "qa")

        # In production, attesting_principal is mandatory and must not be a string
        if is_production_like:
            if attesting_principal is None:
                raise SecurityAuthorizationError(
                    "Missing authenticated service context: attesting_principal is required in production."
                )
            if self.service_authenticator is None:
                raise SecurityAuthorizationError(
                    "No trusted service authenticator configured: cannot persist attestation in production."
                )
            if isinstance(attesting_principal, str):
                raise SecurityAuthorizationError(
                    "Caller-supplied principal strings are rejected as authentication proof in production. "
                    "An AuthenticatedMigrationPrincipal context is required."
                )
            if not isinstance(attesting_principal, AuthenticatedMigrationPrincipal):
                raise SecurityAuthorizationError(
                    f"Invalid attesting_principal type '{type(attesting_principal).__name__}'. "
                    "An AuthenticatedMigrationPrincipal context is required."
                )

        verified_principal = (verified_evidence.attested_by or "").strip()
        if not verified_principal:
            raise SecurityAuthorizationError("Verified evidence lacks mandatory attested_by principal.")

        clean_p_id: str = ""

        if isinstance(attesting_principal, AuthenticatedMigrationPrincipal):
            if attesting_principal._token is not _AUTH_TOKEN:
                raise SecurityAuthorizationError("Tampered or unverified AuthenticatedMigrationPrincipal context.")

            # Check expiry
            now_utc = get_current_utc_time()
            if attesting_principal.expires_at is not None and attesting_principal.expires_at <= now_utc:
                raise SecurityAuthorizationError(
                    f"Principal credential for '{attesting_principal.principal_id}' has expired."
                )

            # Check scope
            if "legacy_migration" not in attesting_principal.scopes:
                raise SecurityAuthorizationError(
                    f"Principal '{attesting_principal.principal_id}' lacks legacy_migration authorization scope."
                )

            # Clean principal ID
            clean_p_id = attesting_principal.principal_id.strip()

            # Prevent candidate user self-attestation
            if (
                clean_p_id in (f"user_{verified_evidence.user_id}", str(verified_evidence.user_id), "candidate_user")
                or clean_p_id.startswith("user_")
                or clean_p_id.startswith("candidate_")
            ):
                raise SecurityAuthorizationError(
                    f"Candidate user '{clean_p_id}' cannot self-attest own source as historical evidence."
                )

            # Strict equality with verified evidence attested_by
            if clean_p_id != verified_principal:
                raise SecurityAuthorizationError(
                    f"Attesting principal mismatch: passed principal '{clean_p_id}' does not match "
                    f"verified evidence principal '{verified_principal}'. Attestation misattribution is strictly prohibited."
                )

            # In production, require complete provenance fields on verified_evidence
            if is_production_like:
                req_provenance = [
                    ("attesting_principal_id", getattr(verified_evidence, "attesting_principal_id", "")),
                    ("provider_instance_id", getattr(verified_evidence, "provider_instance_id", "")),
                    ("credential_id", getattr(verified_evidence, "credential_id", "")),
                    ("credential_key_id", getattr(verified_evidence, "credential_key_id", "")),
                    ("issuer", getattr(verified_evidence, "issuer", "")),
                    ("audience", getattr(verified_evidence, "audience", "")),
                    ("scopes", getattr(verified_evidence, "scopes", ())),
                    ("issued_at", getattr(verified_evidence, "issued_at", "")),
                    ("expires_at", getattr(verified_evidence, "expires_at", "")),
                ]
                for fname, fval in req_provenance:
                    if not fval or (isinstance(fval, str) and not fval.strip()) or (isinstance(fval, (tuple, list)) and len(fval) == 0):
                        raise SecurityAuthorizationError(
                            f"Old verified evidence without current authentication provenance ({fname}) cannot be persisted in production."
                        )

            # Context provenance comparison against verified_evidence
            if is_production_like or getattr(verified_evidence, "provider_instance_id", ""):
                ve_pid = getattr(verified_evidence, "attesting_principal_id", "").strip()
                if clean_p_id != ve_pid:
                    raise SecurityAuthorizationError(
                        f"Provenance mismatch: attesting_principal_id '{ve_pid}' does not match principal ID '{clean_p_id}'."
                    )
                if getattr(verified_evidence, "provider_instance_id", "") != attesting_principal._provider_instance_id:
                    raise SecurityAuthorizationError("Evidence created by one provider cannot be persisted under another provider's context.")
                if getattr(verified_evidence, "credential_id", "") != attesting_principal.credential_id:
                    raise SecurityAuthorizationError("Verified evidence credential_id does not match attesting principal context.")
                if getattr(verified_evidence, "credential_key_id", "") != attesting_principal.credential_key_id:
                    raise SecurityAuthorizationError("Verified evidence credential_key_id does not match attesting principal context.")
                if getattr(verified_evidence, "issuer", "") != attesting_principal.issuer:
                    raise SecurityAuthorizationError("Verified evidence issuer does not match attesting principal context.")
                if getattr(verified_evidence, "audience", "") != attesting_principal.audience:
                    raise SecurityAuthorizationError("Verified evidence audience does not match attesting principal context.")
                if tuple(getattr(verified_evidence, "scopes", ())) != tuple(attesting_principal.scopes):
                    raise SecurityAuthorizationError("Verified evidence scopes do not match attesting principal context.")

                ve_iat = _normalize_datetime(getattr(verified_evidence, "issued_at", None))
                ap_iat = _normalize_datetime(attesting_principal.issued_at)
                if ve_iat != ap_iat:
                    raise SecurityAuthorizationError("Verified evidence issued_at timestamp does not match attesting principal context.")

                ve_exp = _normalize_datetime(getattr(verified_evidence, "expires_at", None))
                ap_exp = _normalize_datetime(attesting_principal.expires_at)
                if ve_exp != ap_exp:
                    raise SecurityAuthorizationError("Verified evidence expires_at timestamp does not match attesting principal context.")

        elif isinstance(attesting_principal, str):
            if is_production_like:
                raise SecurityAuthorizationError(
                    "Caller-supplied principal strings are rejected as authentication proof in production. "
                    "An AuthenticatedMigrationPrincipal context is required."
                )
            clean_p_id = attesting_principal.strip()
            if not clean_p_id:
                raise SecurityAuthorizationError("Attesting principal is required and cannot be empty.")
            if clean_p_id != verified_principal:
                raise SecurityAuthorizationError(
                    f"Attesting principal mismatch: passed principal '{clean_p_id}' does not match "
                    f"verified evidence principal '{verified_principal}'. Attestation misattribution is strictly prohibited."
                )
            if (
                clean_p_id in (f"user_{verified_evidence.user_id}", str(verified_evidence.user_id), "candidate_user")
                or clean_p_id.startswith("candidate_")
            ):
                raise SecurityAuthorizationError(
                    f"Candidate user '{clean_p_id}' cannot self-attest own source as historical evidence."
                )
        elif attesting_principal is None:
            if is_production_like:
                raise SecurityAuthorizationError(
                    "Missing authenticated service context: attesting_principal is required in production."
                )
            clean_p_id = verified_principal
            if (
                clean_p_id in (f"user_{verified_evidence.user_id}", str(verified_evidence.user_id), "candidate_user")
                or clean_p_id.startswith("candidate_")
            ):
                raise SecurityAuthorizationError(
                    f"Candidate user '{clean_p_id}' cannot self-attest own source as historical evidence."
                )
        else:
            raise SecurityAuthorizationError(
                f"Invalid attesting_principal type '{type(attesting_principal).__name__}'."
            )

        # Trust store instance resolution
        trust_store = kwargs.get("trust_store") or get_default_evidence_trust_store()

        sql = """
            INSERT INTO legacy_evidence_attestations (
                user_id, job_description_id, evidence_type,
                evidence_reference_id, source_snapshot_hash,
                evidence_artifact_hash, evidence_payload_hash,
                issuer_id, key_id, signature_algorithm,
                evidence_signature, migration_boundary,
                attested_by, verified_at, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            getattr(verified_evidence, "user_id", None),
            getattr(verified_evidence, "job_description_id", None),
            getattr(verified_evidence, "evidence_type", None),
            getattr(verified_evidence, "evidence_reference_id", None),
            getattr(verified_evidence, "source_snapshot_hash", None),
            getattr(verified_evidence, "evidence_artifact_hash", None),
            getattr(verified_evidence, "evidence_payload_hash", None),
            getattr(verified_evidence, "issuer_id", None),
            getattr(verified_evidence, "key_id", None),
            getattr(verified_evidence, "signature_algorithm", None),
            getattr(verified_evidence, "evidence_signature", None),
            getattr(verified_evidence, "migration_boundary", None),
            clean_p_id,
            getattr(verified_evidence, "verified_at", None),
            details,
        )

        def _execute_atomic_attestation(cur: sqlite3.Cursor) -> int:
            # -1. Physical write lock verification before any inspection queries
            try:
                cur.execute(
                    "INSERT OR REPLACE INTO _sqlite_write_lock_sentinel (id, updated_at) VALUES (1, ?)",
                    (get_current_utc_time().isoformat(),),
                )
            except sqlite3.OperationalError as op_err:
                raise SecurityAuthorizationError(
                    f"Failed to acquire physical write lock on cursor: {op_err}"
                ) from op_err

            # 0. Atomic revalidation via configured service authenticator directly on this write cursor
            if self.service_authenticator is not None and isinstance(attesting_principal, AuthenticatedMigrationPrincipal):
                self.service_authenticator.validate_principal(attesting_principal, cursor=cur)

            # 1. Atomic principal revocation check directly on write cursor
            try:
                cur.execute(
                    "SELECT 1 FROM revoked_attesting_principals WHERE principal_id = ?",
                    (clean_p_id,),
                )
                if cur.fetchone() is not None:
                    raise SecurityAuthorizationError(
                        f"Attesting principal '{clean_p_id}' has been revoked in database."
                    )
            except SecurityAuthorizationError:
                raise
            except Exception as e:
                raise SecurityAuthorizationError(
                    f"Database revocation query failure for principal '{clean_p_id}': {e}"
                ) from e

            # 2. Atomic signing key revocation check directly on write cursor
            keys_to_check = set()
            if getattr(verified_evidence, "key_id", None):
                keys_to_check.add(str(verified_evidence.key_id).strip())
            if isinstance(attesting_principal, AuthenticatedMigrationPrincipal) and attesting_principal.credential_key_id:
                keys_to_check.add(str(attesting_principal.credential_key_id).strip())

            for clean_key in keys_to_check:
                if clean_key:
                    try:
                        cur.execute(
                            "SELECT 1 FROM revoked_signing_keys WHERE key_id = ?",
                            (clean_key,),
                        )
                        if cur.fetchone() is not None:
                            raise KeyRevokedError(f"Signing key '{clean_key}' has been revoked in database.")
                    except (SecurityAuthorizationError, KeyRevokedError):
                        raise
                    except Exception as e:
                        raise SecurityAuthorizationError(
                            f"Database revocation query failure for key '{clean_key}': {e}"
                        ) from e

            # 3. Atomic trust store authorization check directly on write cursor
            if trust_store is not None:
                if not trust_store.is_attesting_principal_trusted(clean_p_id, cursor=cur):
                    raise SecurityAuthorizationError(
                        f"Attesting principal '{clean_p_id}' is not authorized in trust store or has been revoked."
                    )

            # 4. Insert attestation on write cursor
            cur.execute(sql, params)
            return cur.lastrowid

        if cursor is not None:
            if not isinstance(cursor, sqlite3.Cursor):
                raise SecurityAuthorizationError(f"Invalid cursor: expected sqlite3.Cursor, got {type(cursor).__name__}.")
            try:
                cur_conn = cursor.connection
                if cur_conn is None:
                    raise SecurityAuthorizationError("Invalid cursor: cursor connection is closed or None.")
                if cur_conn.isolation_level is not None:
                    raise SecurityAuthorizationError(
                        "Caller transaction must have isolation_level=None (autocommit mode) with explicit BEGIN IMMEDIATE."
                    )
                if not cur_conn.in_transaction:
                    raise SecurityAuthorizationError("Caller cursor must be inside an active transaction.")
                if not getattr(cur_conn, "_tx_is_immediate", False):
                    raise SecurityAuthorizationError(
                        "Caller transaction must hold an immediate write lock (BEGIN IMMEDIATE). "
                        "Deferred transactions are strictly prohibited for legacy attestation persistence."
                    )
            except SecurityAuthorizationError:
                raise
            except Exception as conn_err:
                raise SecurityAuthorizationError(f"Invalid cursor: connection is closed or in invalid state: {conn_err}") from conn_err
            return _execute_atomic_attestation(cursor)
        else:
            timeout = kwargs.get("timeout")
            with self.immediate_transaction(timeout=timeout) as conn:
                cur = conn.cursor()
                return _execute_atomic_attestation(cur)

    def get_legacy_evidence_attestation(
        self,
        job_description_id: int,
        user_id: Optional[int] = None,
        cursor: Optional[sqlite3.Cursor] = None,
    ) -> Optional[LegacyEvidenceAttestation]:
        """Retrieves an authoritative evidence attestation for a job description."""
        if user_id is not None:
            sql = """
                SELECT * FROM legacy_evidence_attestations
                WHERE job_description_id = ? AND user_id = ?
                ORDER BY id DESC LIMIT 1
            """
            params = (job_description_id, user_id)
        else:
            sql = """
                SELECT * FROM legacy_evidence_attestations
                WHERE job_description_id = ?
                ORDER BY id DESC LIMIT 1
            """
            params = (job_description_id,)

        if cursor:
            cursor.execute(sql, params)
            row = cursor.fetchone()
        else:
            with self.connection() as conn:
                cur = conn.cursor()
                cur.execute(sql, params)
                row = cur.fetchone()

        if not row:
            return None
        return LegacyEvidenceAttestation(
            id=row["id"],
            user_id=row["user_id"],
            job_description_id=row["job_description_id"],
            evidence_type=row["evidence_type"],
            evidence_reference_id=row["evidence_reference_id"],
            source_snapshot_hash=row["source_snapshot_hash"],
            attested_by=row["attested_by"],
            attested_at=row["attested_at"],
            evidence_artifact_hash=row["evidence_artifact_hash"] if "evidence_artifact_hash" in row.keys() else None,
            evidence_payload_hash=row["evidence_payload_hash"] if "evidence_payload_hash" in row.keys() else None,
            issuer_id=row["issuer_id"] if "issuer_id" in row.keys() else None,
            key_id=row["key_id"] if "key_id" in row.keys() else None,
            signature_algorithm=row["signature_algorithm"] if "signature_algorithm" in row.keys() else None,
            evidence_signature=row["evidence_signature"] if "evidence_signature" in row.keys() else None,
            migration_boundary=row["migration_boundary"] if "migration_boundary" in row.keys() else None,
            verified_at=row["verified_at"] if "verified_at" in row.keys() else None,
            details=row["details"] if "details" in row.keys() else None,
        )

    def record_schema_migration(
        self,
        migration_id: str,
        migration_version: str,
        details: Optional[str] = None,
        cursor: Optional[sqlite3.Cursor] = None,
    ) -> None:
        """Records a completed migration in schema_migrations ledger.

        Enforces immutable history (Section 7): does NOT use INSERT OR REPLACE.
        If migration is already recorded with identical version, no-ops cleanly.
        If migration is already recorded with an inconsistent version, raises ConcurrencyConflictError.
        """
        def _execute(cur: sqlite3.Cursor) -> None:
            cur.execute(
                "SELECT migration_version, applied_at, details FROM schema_migrations WHERE migration_id = ?",
                (migration_id,),
            )
            existing = cur.fetchone()
            if existing:
                existing_ver = existing[0] if isinstance(existing, tuple) else existing["migration_version"]
                if existing_ver != migration_version:
                    raise ConcurrencyConflictError(
                        f"Migration '{migration_id}' already applied with version '{existing_ver}', "
                        f"cannot overwrite with inconsistent version '{migration_version}'."
                    )
                return  # Identical migration already recorded; preserve original applied_at
            cur.execute(
                """
                INSERT INTO schema_migrations (
                    migration_id, migration_version, applied_at, details
                ) VALUES (?, ?, CURRENT_TIMESTAMP, ?)
                """,
                (migration_id, migration_version, details),
            )

        if cursor:
            _execute(cursor)
        else:
            with self.immediate_transaction() as conn:
                _execute(conn.cursor())

    def is_schema_migration_applied(
        self,
        migration_id: str,
        cursor: Optional[sqlite3.Cursor] = None,
    ) -> bool:
        """Checks if a migration has already been completed in schema_migrations ledger."""
        sql = "SELECT 1 FROM schema_migrations WHERE migration_id = ?"
        if cursor:
            cursor.execute(sql, (migration_id,))
            return cursor.fetchone() is not None
        else:
            with self.connection() as conn:
                cur = conn.cursor()
                cur.execute(sql, (migration_id,))
                return cur.fetchone() is not None

    def get_schema_migrations(
        self,
        cursor: Optional[sqlite3.Cursor] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves all completed schema migrations."""
        sql = "SELECT migration_id, migration_version, applied_at, details FROM schema_migrations ORDER BY applied_at ASC"
        if cursor:
            cursor.execute(sql)
            rows = cursor.fetchall()
        else:
            with self.connection() as conn:
                cur = conn.cursor()
                cur.execute(sql)
                rows = cur.fetchall()
        results = []
        for r in rows:
            if isinstance(r, dict):
                results.append(dict(r))
            else:
                results.append({
                    "migration_id": r[0],
                    "migration_version": r[1],
                    "applied_at": r[2],
                    "details": r[3],
                })
        return results

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

        from src.security.file_security import FileSecurityValidator
        validator = FileSecurityValidator()
        if user_base_dir:
            base_dir = user_base_dir
        elif hasattr(self, "db_path") and self.db_path and self.db_path != ":memory:":
            cand_users = Path(self.db_path).parent / "users"
            cand_users_parent = Path(self.db_path).parent.parent / "users"
            if (cand_users / str(user_id) / "resumes").is_dir():
                base_dir = cand_users / str(user_id) / "resumes"
            elif (cand_users_parent / str(user_id) / "resumes").is_dir():
                base_dir = cand_users_parent / str(user_id) / "resumes"
            else:
                base_dir = validator.get_user_resumes_dir(user_id)
        else:
            base_dir = validator.get_user_resumes_dir(user_id)

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

            # Finding D: Invalidate any unconsumed approvals for this candidate and transition affected applications
            cursor.execute(
                """
                SELECT id, application_id, packet_id, packet_version_hash, ticket_nonce, key_id
                FROM application_approvals
                WHERE user_id = ? AND is_consumed = 0 AND (is_revoked IS NULL OR is_revoked = 0)
                """,
                (user_id,),
            )
            unconsumed_approvals = [dict(r) for r in cursor.fetchall()]

            cursor.execute(
                """
                UPDATE application_approvals
                SET is_revoked = 1, revoked_at = CURRENT_TIMESTAMP, revocation_reason = 'CANDIDATE_PROFILE_UPDATED'
                WHERE user_id = ? AND is_consumed = 0 AND (is_revoked IS NULL OR is_revoked = 0)
                """,
                (user_id,),
            )
            revoked_count = cursor.rowcount
            if revoked_count > 0:
                logger.info(
                    "Invalidated %d unconsumed approvals for user #%d due to candidate profile update",
                    revoked_count, user_id
                )

            # Group unconsumed approvals by application_id so multiple approvals for the same application do not duplicate events
            from src.lifecycle.state_machine import ApplicationStateMachine
            apps_to_approvals: Dict[int, List[Dict[str, Any]]] = {}
            for appr in unconsumed_approvals:
                aid = appr.get("application_id")
                if aid:
                    apps_to_approvals.setdefault(aid, []).append(appr)

            for app_id, app_apprs in apps_to_approvals.items():
                cursor.execute(
                    "SELECT id, status FROM applications WHERE id = ? AND user_id = ?",
                    (app_id, user_id),
                )
                app_row = cursor.fetchone()
                if not app_row:
                    continue

                cur_status = app_row["status"]
                norm_status = ApplicationStateMachine.normalize_status(cur_status)

                # Only applications in APPROVED (or alias Awaiting Approval) transition to READY_FOR_REVIEW
                if norm_status == ApplicationStatus.APPROVED:
                    # Validate transition using authoritative state machine
                    ApplicationStateMachine.validate_transition(
                        current_status=norm_status,
                        new_status=ApplicationStatus.READY_FOR_REVIEW,
                    )

                    new_status = ApplicationStatus.READY_FOR_REVIEW.value
                    cursor.execute(
                        """
                        UPDATE applications
                        SET status = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ? AND user_id = ? AND status = ?
                        """,
                        (new_status, app_id, user_id, cur_status),
                    )
                    if cursor.rowcount == 0:
                        raise DatabaseError(
                            f"Concurrent/stale status change detected for Application #{app_id}: "
                            f"expected status '{cur_status}'"
                        )

                    event_payload = {
                        "revoked_approval_ids": [a["id"] for a in app_apprs],
                        "approval_id": app_apprs[0]["id"],
                        "packet_id": app_apprs[0].get("packet_id"),
                        "packet_version_hash": app_apprs[0].get("packet_version_hash"),
                        "revocation_reason": "CANDIDATE_PROFILE_UPDATED",
                        "ticket_nonce": app_apprs[0].get("ticket_nonce"),
                        "key_id": app_apprs[0].get("key_id"),
                    }
                    self._insert_application_event_internal(
                        cursor=cursor,
                        application_id=app_id,
                        user_id=user_id,
                        event_type="PACKET_APPROVAL_REVOKED",
                        previous_status=cur_status,
                        new_status=new_status,
                        actor_type="SYSTEM",
                        actor_identifier=f"user_{user_id}",
                        session_reference=None,
                        event_payload=event_payload,
                    )
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
        scoring_profile: Optional[str] = None,
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
                    scoring_profile,
                    original_resume_version_num, job_description_id,
                    template_id, template_version,
                    is_active_revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
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
                    scoring_profile,
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

            # 2.5 Delete Phase 7 application lifecycle child tables and historical records in topological order:
            cursor.execute("DELETE FROM submission_confirmations WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM application_follow_ups WHERE user_id = ?", (user_id,))

            with self._authorized_privacy_erasure_scope(conn, user_id):
                cursor.execute("DELETE FROM application_events WHERE user_id = ?", (user_id,))

            cursor.execute("DELETE FROM match_results WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM prepared_packets WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM applications WHERE user_id = ?", (user_id,))

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

    def get_user_match_results_for_jobs(
        self,
        user_id: int,
        job_ids: List[int],
    ) -> Dict[int, MatchResult]:
        """Fetches the latest match result for each job_id for the user."""
        if not job_ids:
            return {}
        q_marks = ",".join("?" for _ in job_ids)
        query = f"""
            SELECT * FROM match_results
            WHERE user_id = ? AND job_id IN ({q_marks})
            ORDER BY evaluated_at DESC, id DESC
        """
        params: List[Any] = [user_id] + list(job_ids)
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            results: Dict[int, MatchResult] = {}
            for row in cursor.fetchall():
                mr = self._row_to_match_result(row)
                if mr.job_id is not None and mr.job_id not in results:
                    results[mr.job_id] = mr
            return results

    # -------------------------------------------------------------------------
    # DISCOVERY RUNS PERSISTENCE & LIFECYCLE
    # -------------------------------------------------------------------------

    def create_discovery_run(
        self,
        user_id: int,
        target_roles: List[str],
        target_locations: List[str],
    ) -> Dict[str, Any]:
        """Creates a new PENDING discovery run record for a candidate."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO discovery_runs (user_id, status, target_roles_json, target_locations_json, started_at)
                VALUES (?, 'PENDING', ?, ?, CURRENT_TIMESTAMP)
                """,
                (user_id, json.dumps(target_roles), json.dumps(target_locations)),
            )
            run_id = cursor.lastrowid
            cursor.execute("SELECT * FROM discovery_runs WHERE id = ?", (run_id,))
            return dict(cursor.fetchone())

    def get_active_discovery_run(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Returns currently active PENDING or RUNNING discovery run for the user."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM discovery_runs
                WHERE user_id = ? AND status IN ('PENDING', 'RUNNING')
                ORDER BY id DESC LIMIT 1
                """,
                (user_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_latest_discovery_run(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Returns the most recent discovery run for the user."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM discovery_runs
                WHERE user_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (user_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_discovery_run(
        self,
        run_id: int,
        status: str,
        query_count: Optional[int] = None,
        new_jobs_count: Optional[int] = None,
        duplicates_skipped: Optional[int] = None,
        restricted_count: Optional[int] = None,
        source_outcomes: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
    ) -> bool:
        """Updates metrics and completion status of a discovery run."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            updates = ["status = ?"]
            params: list = [status]
            if query_count is not None:
                updates.append("query_count = ?")
                params.append(query_count)
            if new_jobs_count is not None:
                updates.append("new_jobs_count = ?")
                params.append(new_jobs_count)
            if duplicates_skipped is not None:
                updates.append("duplicates_skipped = ?")
                params.append(duplicates_skipped)
            if restricted_count is not None:
                updates.append("restricted_count = ?")
                params.append(restricted_count)
            if source_outcomes is not None:
                updates.append("source_outcomes_json = ?")
                params.append(json.dumps(source_outcomes))
            if error_message is not None:
                updates.append("error_message = ?")
                params.append(error_message)
            if status in ("COMPLETED", "FAILED", "PARTIAL"):
                updates.append("completed_at = CURRENT_TIMESTAMP")
            params.append(run_id)
            cursor.execute(f"UPDATE discovery_runs SET {', '.join(updates)} WHERE id = ?", params)
            return cursor.rowcount == 1

    def list_user_discovery_runs(self, user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """Lists discovery runs for a user, newest first."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM discovery_runs
                WHERE user_id = ?
                ORDER BY id DESC LIMIT ?
                """,
                (user_id, limit),
            )
            return [dict(r) for r in cursor.fetchall()]

    # -------------------------------------------------------------------------
    # PHASE 7: APPLICATION LIFECYCLE, EVENTS, SUBMISSION CONFIRMATION & FOLLOW-UPS
    # -------------------------------------------------------------------------

    @staticmethod
    def compute_event_hash(
        actor_identifier: str,
        actor_type: str,
        application_id: int,
        event_payload_json: str,
        event_type: str,
        new_status: Optional[str],
        previous_event_hash: str,
        previous_status: Optional[str],
        sequence_no: int,
        session_reference: Optional[str],
        user_id: int,
        created_at: Optional[str] = None,
        hash_version: str = "v2",
    ) -> str:
        """Computes deterministic RFC 8785 canonical hash for an application event.

        hash_version 'v2' (Phase 7.1.1+) binds the exact UTC created_at timestamp.
        hash_version 'v1' (Phase 7.1 legacy compatibility) omits created_at.
        """
        hash_payload = {
            "actor_identifier": actor_identifier,
            "actor_type": actor_type,
            "application_id": application_id,
            "event_payload_json": event_payload_json,
            "event_type": event_type,
            "new_status": new_status,
            "previous_event_hash": previous_event_hash,
            "previous_status": previous_status,
            "sequence_no": sequence_no,
            "session_reference": session_reference,
            "user_id": user_id,
        }
        if hash_version == "v2":
            if not created_at:
                raise ValueError("created_at timestamp is mandatory for v2 event hashing.")
            hash_payload["created_at"] = created_at

        return canonical_json_hash(hash_payload)

    def _insert_application_event_internal(
        self,
        cursor: sqlite3.Cursor,
        application_id: int,
        user_id: int,
        event_type: str,
        new_status: Optional[str] = None,
        previous_status: Optional[str] = None,
        actor_type: str = "CANDIDATE",
        actor_identifier: Optional[str] = None,
        session_reference: Optional[str] = None,
        event_payload: Optional[Dict[str, Any]] = None,
        created_at: Optional[str] = None,
    ) -> ApplicationEvent:
        """Appends an immutable event to application_events on the provided cursor/connection.

        Does NOT manage transaction boundaries or mutate applications.status, enabling callers
        to execute atomic multi-table updates and event audit logging within a single transaction.
        """
        if actor_type not in ("CANDIDATE", "SYSTEM"):
            raise ValidationError(f"Invalid actor_type '{actor_type}'. Must be 'CANDIDATE' or 'SYSTEM'.")

        # Verify user exists
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            raise UserNotFoundError(user_id)

        # Verify application exists and belongs to user
        cursor.execute("SELECT id, user_id, status FROM applications WHERE id = ?", (application_id,))
        app_row = cursor.fetchone()
        if not app_row:
            raise ApplicationNotFoundError(application_id)
        if app_row["user_id"] != user_id:
            raise CrossUserAccessError(
                user_id=user_id,
                target_user_id=app_row["user_id"],
                resource=f"Application #{application_id}",
            )

        # Query max sequence_no and last event_hash
        cursor.execute(
            """
            SELECT sequence_no, event_hash FROM application_events
            WHERE application_id = ? AND user_id = ?
            ORDER BY sequence_no DESC LIMIT 1
            """,
            (application_id, user_id),
        )
        last_event = cursor.fetchone()
        if not last_event:
            sequence_no = 1
            previous_event_hash = "GENESIS"
        else:
            sequence_no = last_event["sequence_no"] + 1
            previous_event_hash = last_event["event_hash"]

        current_status = app_row["status"]
        prev_status = previous_status if previous_status is not None else current_status

        # Canonical serialization of event payload
        payload_dict = event_payload or {}
        event_payload_json = canonical_json_bytes(payload_dict).decode("utf-8")
        actor_ident = (actor_identifier or f"user_{user_id}").strip()
        event_ts = created_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        event_hash = DatabaseManager.compute_event_hash(
            actor_identifier=actor_ident,
            actor_type=actor_type,
            application_id=application_id,
            event_payload_json=event_payload_json,
            event_type=event_type,
            new_status=new_status,
            previous_event_hash=previous_event_hash,
            previous_status=prev_status,
            sequence_no=sequence_no,
            session_reference=session_reference,
            user_id=user_id,
            created_at=event_ts,
            hash_version="v2",
        )

        cursor.execute(
            """
            INSERT INTO application_events (
                application_id, user_id, sequence_no, event_type,
                previous_status, new_status, actor_type, actor_identifier,
                session_reference, event_payload_json, previous_event_hash, event_hash,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                application_id,
                user_id,
                sequence_no,
                event_type,
                prev_status,
                new_status,
                actor_type,
                actor_ident,
                session_reference,
                event_payload_json,
                previous_event_hash,
                event_hash,
                event_ts,
            ),
        )
        event_id = cursor.lastrowid
        cursor.execute("SELECT * FROM application_events WHERE id = ?", (event_id,))
        return ApplicationEvent(**dict(cursor.fetchone()))

    def create_application_event(
        self,
        application_id: int,
        user_id: int,
        event_type: str,
        new_status: Optional[str] = None,
        previous_status: Optional[str] = None,
        actor_type: str = "CANDIDATE",
        actor_identifier: Optional[str] = None,
        session_reference: Optional[str] = None,
        event_payload: Optional[Dict[str, Any]] = None,
    ) -> ApplicationEvent:
        """Appends an immutable event to the application timeline with RFC 8785 canonical hash linkage."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            return self._insert_application_event_internal(
                cursor=cursor,
                application_id=application_id,
                user_id=user_id,
                event_type=event_type,
                new_status=new_status,
                previous_status=previous_status,
                actor_type=actor_type,
                actor_identifier=actor_identifier,
                session_reference=session_reference,
                event_payload=event_payload,
            )

    def get_application_events(self, application_id: int, user_id: int) -> List[ApplicationEvent]:
        """Fetches all timeline events for an application, enforcing user ownership."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise ApplicationNotFoundError(application_id)
            if app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )

            cursor.execute(
                """
                SELECT * FROM application_events
                WHERE application_id = ? AND user_id = ?
                ORDER BY sequence_no ASC
                """,
                (application_id, user_id),
            )
            return [ApplicationEvent(**dict(row)) for row in cursor.fetchall()]

    def verify_application_event_chain(
        self, application_id: int, user_id: int, raise_on_error: bool = False
    ) -> Tuple[bool, str]:
        """Independently verifies the cryptographic hash chain and sequence continuity of an application's event timeline.

        If raise_on_error is True, raises EventIntegrityError on any sequence or cryptographic hash failure.
        """
        events = self.get_application_events(application_id, user_id)
        if not events:
            return True, "No events found for this application."

        expected_seq = 1
        expected_prev_hash = "GENESIS"

        for evt in events:
            if evt.sequence_no != expected_seq:
                msg = f"Sequence discontinuity: expected sequence {expected_seq}, found {evt.sequence_no} (Event #{evt.id})"
                if raise_on_error:
                    raise EventIntegrityError(msg)
                return False, msg

            if evt.previous_event_hash != expected_prev_hash:
                msg = f"Broken hash linkage at sequence {evt.sequence_no}: expected previous_event_hash '{expected_prev_hash}', found '{evt.previous_event_hash}'"
                if raise_on_error:
                    raise EventIntegrityError(msg)
                return False, msg

            # Try v2 (with created_at)
            recomputed = DatabaseManager.compute_event_hash(
                actor_identifier=evt.actor_identifier,
                actor_type=evt.actor_type,
                application_id=evt.application_id,
                event_payload_json=evt.event_payload_json,
                event_type=evt.event_type,
                new_status=evt.new_status,
                previous_event_hash=evt.previous_event_hash,
                previous_status=evt.previous_status,
                sequence_no=evt.sequence_no,
                session_reference=evt.session_reference,
                user_id=evt.user_id,
                created_at=evt.created_at,
                hash_version="v2",
            )
            if recomputed != evt.event_hash:
                # Fallback to v1 for legacy events created before Phase 7.1.1
                recomputed_v1 = DatabaseManager.compute_event_hash(
                    actor_identifier=evt.actor_identifier,
                    actor_type=evt.actor_type,
                    application_id=evt.application_id,
                    event_payload_json=evt.event_payload_json,
                    event_type=evt.event_type,
                    new_status=evt.new_status,
                    previous_event_hash=evt.previous_event_hash,
                    previous_status=evt.previous_status,
                    sequence_no=evt.sequence_no,
                    session_reference=evt.session_reference,
                    user_id=evt.user_id,
                    hash_version="v1",
                )
                if recomputed_v1 != evt.event_hash:
                    msg = f"Event tamper detected at sequence {evt.sequence_no}: stored hash '{evt.event_hash}' != recomputed hash '{recomputed}'"
                    if raise_on_error:
                        raise EventIntegrityError(msg)
                    return False, msg

            expected_seq += 1
            expected_prev_hash = evt.event_hash

        return True, f"All {len(events)} events verified successfully."

    def create_submission_confirmation(
        self,
        application_id: int,
        user_id: int,
        submission_channel: str,
        submission_timestamp: Optional[str] = None,
        packet_id: Optional[int] = None,
        confirmation_reference: Optional[str] = None,
        confirmation_doc_path: Optional[str] = None,
        confirmation_doc_hash: Optional[str] = None,
        candidate_notes: Optional[str] = None,
        transition_status: bool = False,
    ) -> SubmissionConfirmation:
        """Records an authoritative candidate-confirmed submission, superseding any prior active confirmation.

        If transition_status=True:
        - packet_id is mandatory.
        - Application status cannot be DRAFT, PREPARING, or READY_FOR_REVIEW.
        - Packet must belong to user, application, and be the active revision.
        - A valid, active, unconsumed human approval must exist for this packet.
        - The approval record is atomically consumed.
        - Application status is updated to SUBMITTED and date_submitted is recorded.

        If transition_status=False (storage-only mode):
        - Confirmation record is persisted and an audit event is appended.
        - Application status is NOT modified.
        """
        valid_channels = SubmissionChannel.list()
        if submission_channel not in valid_channels:
            raise ValidationError(
                f"Invalid submission_channel '{submission_channel}'. Valid options: {valid_channels}"
            )

        # Distinguish candidate-provided submission time from server UTC event recording time
        sub_ts = submission_timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        with self.transaction() as conn:
            cursor = conn.cursor()

            # Verify user exists
            cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
            if not cursor.fetchone():
                raise UserNotFoundError(user_id)

            # Verify application exists and belongs to user
            cursor.execute("SELECT id, user_id, status FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise ApplicationNotFoundError(application_id)
            if app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )

            current_status = app_row["status"]

            # If transition_status requested, enforce strict preconditions
            packet_hash = None
            if transition_status:
                if packet_id is None:
                    raise ValidationError("packet_id is required to confirm submission and transition application to SUBMITTED.")

                # Status check: only APPROVED or legacy 'Awaiting Approval' can transition to SUBMITTED
                allowed_statuses = (
                    ApplicationStatus.APPROVED.value.lower(),
                    "awaiting approval",
                )
                if current_status.strip().lower() not in allowed_statuses:
                    raise SecurityAuthorizationError(
                        f"Cannot transition application #{application_id} in '{current_status}' status to SUBMITTED. "
                        f"Application must be approved by candidate (in APPROVED or Awaiting Approval status) before submission."
                    )

                cursor.execute(
                    "SELECT id, user_id, application_id, packet_version_hash, is_active_revision FROM prepared_packets WHERE id = ?",
                    (packet_id,),
                )
                pkt_row = cursor.fetchone()
                if not pkt_row:
                    raise ValidationError(f"PreparedPacket #{packet_id} not found.")
                if pkt_row["user_id"] != user_id:
                    raise CrossUserAccessError(
                        user_id=user_id,
                        target_user_id=pkt_row["user_id"],
                        resource=f"PreparedPacket #{packet_id}",
                    )
                if pkt_row["application_id"] != application_id:
                    raise ValidationError(
                        f"PreparedPacket #{packet_id} belongs to Application #{pkt_row['application_id']}, "
                        f"not Application #{application_id}."
                    )
                if not pkt_row["is_active_revision"]:
                    raise SecurityAuthorizationError(
                        f"PreparedPacket #{packet_id} is not the active revision. Outdated packet revisions cannot be submitted."
                    )

                packet_hash = pkt_row["packet_version_hash"]

                # Verify valid active unconsumed human approval exists
                cursor.execute(
                    """
                    SELECT id, is_consumed, is_revoked, key_id FROM application_approvals
                    WHERE application_id = ? AND user_id = ? AND packet_id = ? AND packet_version_hash = ?
                      AND (is_revoked IS NULL OR is_revoked = 0)
                    ORDER BY approved_at DESC, id DESC LIMIT 1
                    """,
                    (application_id, user_id, packet_id, packet_hash),
                )
                appr_row = cursor.fetchone()
                if not appr_row:
                    raise SecurityAuthorizationError(
                        f"No valid human approval record found for Application #{application_id} and PreparedPacket #{packet_id}."
                    )
                if appr_row["is_consumed"]:
                    raise SecurityAuthorizationError(
                        f"Human approval for PreparedPacket #{packet_id} has already been consumed."
                    )
                if self.is_key_revoked(appr_row["key_id"]):
                    raise SecurityAuthorizationError(
                        f"Human approval for PreparedPacket #{packet_id} was signed with revoked key '{appr_row['key_id']}'."
                    )

                # Consume the approval record with current server timestamp
                cursor.execute(
                    "UPDATE application_approvals SET is_consumed = 1, consumed_at = ? WHERE id = ?",
                    (now_ts, appr_row["id"]),
                )
            else:
                # Storage-only mode: if packet_id is provided, validate ownership
                if packet_id is not None:
                    cursor.execute(
                        "SELECT id, user_id, application_id, packet_version_hash FROM prepared_packets WHERE id = ?",
                        (packet_id,),
                    )
                    pkt_row = cursor.fetchone()
                    if not pkt_row:
                        raise ValidationError(f"PreparedPacket #{packet_id} not found.")
                    if pkt_row["user_id"] != user_id:
                        raise CrossUserAccessError(
                            user_id=user_id,
                            target_user_id=pkt_row["user_id"],
                            resource=f"PreparedPacket #{packet_id}",
                        )
                    if pkt_row["application_id"] != application_id:
                        raise ValidationError(
                            f"PreparedPacket #{packet_id} belongs to Application #{pkt_row['application_id']}, "
                            f"not Application #{application_id}."
                        )
                    packet_hash = pkt_row["packet_version_hash"]

            # Supersede prior active confirmations for this application
            cursor.execute(
                """
                UPDATE submission_confirmations
                SET is_active_confirmation = 0
                WHERE application_id = ? AND user_id = ? AND is_active_confirmation = 1
                """,
                (application_id, user_id),
            )

            # Insert new confirmation
            cursor.execute(
                """
                INSERT INTO submission_confirmations (
                    application_id, user_id, packet_id, packet_version_hash,
                    submission_timestamp, submission_channel, confirmation_reference,
                    confirmation_doc_path, confirmation_doc_hash, candidate_notes,
                    is_active_confirmation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    application_id,
                    user_id,
                    packet_id,
                    packet_hash,
                    sub_ts,
                    submission_channel,
                    confirmation_reference,
                    confirmation_doc_path,
                    confirmation_doc_hash,
                    candidate_notes,
                ),
            )
            conf_id = cursor.lastrowid

            # Only transition application status if transition_status=True
            if transition_status:
                cursor.execute(
                    """
                    UPDATE applications
                    SET status = ?, date_submitted = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND user_id = ?
                    """,
                    (ApplicationStatus.SUBMITTED.value, sub_ts, application_id, user_id),
                )

            # Emit timeline event for submission atomically within the same transaction
            conf_payload = {
                "submission_channel": submission_channel,
                "confirmation_reference": confirmation_reference,
                "packet_id": packet_id,
                "packet_version_hash": packet_hash,
                "confirmation_doc_hash": confirmation_doc_hash,
                "transition_status": transition_status,
                "submission_timestamp": sub_ts,
            }

            new_status_val = ApplicationStatus.SUBMITTED.value if transition_status else current_status
            event_type_val = "SUBMISSION_CONFIRMED" if transition_status else "SUBMISSION_CONFIRMATION_RECORDED"

            self._insert_application_event_internal(
                cursor=cursor,
                application_id=application_id,
                user_id=user_id,
                event_type=event_type_val,
                new_status=new_status_val,
                previous_status=current_status,
                actor_type="CANDIDATE",
                actor_identifier=f"user_{user_id}",
                event_payload=conf_payload,
            )

            cursor.execute("SELECT * FROM submission_confirmations WHERE id = ?", (conf_id,))
            return SubmissionConfirmation(**dict(cursor.fetchone()))

    def correct_submission_confirmation(
        self,
        confirmation_id: int,
        user_id: int,
        confirmation_reference: Optional[str] = None,
        confirmation_doc_path: Optional[str] = None,
        confirmation_doc_hash: Optional[str] = None,
        candidate_notes: Optional[str] = None,
        submission_channel: Optional[str] = None,
    ) -> SubmissionConfirmation:
        """Allows candidates to correct or attach confirmation artifacts to an existing submission confirmation
        without requiring re-submission or re-approving packets. Does not modify application status.

        The confirmation update and its corresponding SUBMISSION_CONFIRMATION_UPDATED timeline event
        are executed atomically within the same database transaction.
        """
        if submission_channel is not None:
            valid_channels = SubmissionChannel.list()
            if submission_channel not in valid_channels:
                raise ValidationError(
                    f"Invalid submission_channel '{submission_channel}'. Valid options: {valid_channels}"
                )

        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM submission_confirmations WHERE id = ?", (confirmation_id,))
            row = cursor.fetchone()
            if not row:
                raise ValidationError(f"SubmissionConfirmation #{confirmation_id} not found.")
            if row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"SubmissionConfirmation #{confirmation_id}",
                )

            cursor.execute(
                """
                UPDATE submission_confirmations
                SET confirmation_reference = COALESCE(?, confirmation_reference),
                    confirmation_doc_path = COALESCE(?, confirmation_doc_path),
                    confirmation_doc_hash = COALESCE(?, confirmation_doc_hash),
                    candidate_notes = COALESCE(?, candidate_notes),
                    submission_channel = COALESCE(?, submission_channel)
                WHERE id = ? AND user_id = ?
                """,
                (
                    confirmation_reference,
                    confirmation_doc_path,
                    confirmation_doc_hash,
                    candidate_notes,
                    submission_channel,
                    confirmation_id,
                    user_id,
                ),
            )
            cursor.execute("SELECT * FROM submission_confirmations WHERE id = ?", (confirmation_id,))
            updated = SubmissionConfirmation(**dict(cursor.fetchone()))

            # Emit timeline event atomically within the same transaction with before/after audit tracking
            new_fields = {
                k: v for k, v in {
                    "confirmation_reference": confirmation_reference,
                    "confirmation_doc_path": confirmation_doc_path,
                    "confirmation_doc_hash": confirmation_doc_hash,
                    "candidate_notes": candidate_notes,
                    "submission_channel": submission_channel,
                }.items() if v is not None
            }
            previous_fields = {
                k: row[k] for k in new_fields.keys()
            }
            corr_payload = {
                "confirmation_id": confirmation_id,
                "updated_fields": new_fields,
                "previous_fields": previous_fields,
            }
            self._insert_application_event_internal(
                cursor=cursor,
                application_id=updated.application_id,
                user_id=user_id,
                event_type="SUBMISSION_CONFIRMATION_UPDATED",
                actor_type="CANDIDATE",
                actor_identifier=f"user_{user_id}",
                event_payload=corr_payload,
            )

            return updated

    def attach_confirmation_proof(
        self,
        confirmation_id: int,
        user_id: int,
        confirmation_doc_path: str,
        confirmation_doc_hash: str,
        file_format: str,
        safe_filename: str,
    ) -> SubmissionConfirmation:
        """Attaches a verified submission confirmation proof document to an existing confirmation record.

        Atomically updates confirmation_doc_path and confirmation_doc_hash and emits a
        SUBMISSION_CONFIRMATION_PROOF_ATTACHED timeline event in the same transaction.
        The event payload strictly records metadata and hashes without exposing server filesystem paths.
        """
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM submission_confirmations WHERE id = ?", (confirmation_id,))
            row = cursor.fetchone()
            if not row:
                raise ValidationError(f"SubmissionConfirmation #{confirmation_id} not found.")
            if row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"SubmissionConfirmation #{confirmation_id}",
                )

            cursor.execute(
                """
                UPDATE submission_confirmations
                SET confirmation_doc_path = ?,
                    confirmation_doc_hash = ?
                WHERE id = ? AND user_id = ?
                """,
                (confirmation_doc_path, confirmation_doc_hash, confirmation_id, user_id),
            )
            cursor.execute("SELECT * FROM submission_confirmations WHERE id = ?", (confirmation_id,))
            updated = SubmissionConfirmation(**dict(cursor.fetchone()))

            # Emit timeline event atomically within the same transaction without leaking storage paths
            proof_payload = {
                "confirmation_id": confirmation_id,
                "proof_attached": True,
                "file_format": file_format,
                "confirmation_doc_hash": confirmation_doc_hash,
                "safe_filename": safe_filename,
                "description": "Candidate submission confirmation evidence attached",
            }
            self._insert_application_event_internal(
                cursor=cursor,
                application_id=updated.application_id,
                user_id=user_id,
                event_type="SUBMISSION_CONFIRMATION_PROOF_ATTACHED",
                actor_type="CANDIDATE",
                actor_identifier=f"user_{user_id}",
                event_payload=proof_payload,
            )

            return updated

    def get_submission_confirmation(
        self, application_id: int, user_id: int, active_only: bool = True
    ) -> Optional[SubmissionConfirmation]:
        """Retrieves submission confirmation for an application, enforcing cross-user isolation."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, user_id FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise ApplicationNotFoundError(application_id)
            if app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )

            query = "SELECT * FROM submission_confirmations WHERE application_id = ? AND user_id = ?"
            params: List[Any] = [application_id, user_id]
            if active_only:
                query += " AND is_active_confirmation = 1"
            query += " ORDER BY id DESC LIMIT 1"

            cursor.execute(query, params)
            row = cursor.fetchone()
            return SubmissionConfirmation(**dict(row)) if row else None

    def list_submission_confirmations(
        self, user_id: int, application_id: Optional[int] = None
    ) -> List[SubmissionConfirmation]:
        """Lists submission confirmations for a user, optionally filtered by application."""
        with self.connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM submission_confirmations WHERE user_id = ?"
            params: List[Any] = [user_id]
            if application_id is not None:
                query += " AND application_id = ?"
                params.append(application_id)
            query += " ORDER BY submission_timestamp DESC"

            cursor.execute(query, params)
            return [SubmissionConfirmation(**dict(row)) for row in cursor.fetchall()]

    def create_application_follow_up(
        self,
        application_id: int,
        user_id: int,
        follow_up_date: str,
        follow_up_type: str,
        description: str,
        outcome_notes: Optional[str] = None,
    ) -> ApplicationFollowUp:
        """Schedules a candidate-controlled follow-up task.

        Atomically inserts the follow-up record and appends a FOLLOW_UP_SCHEDULED timeline
        event within the same database transaction.
        """
        valid_types = FollowUpType.list()
        if follow_up_type not in valid_types:
            raise ValidationError(
                f"Invalid follow_up_type '{follow_up_type}'. Valid options: {valid_types}"
            )
        if not description or not description.strip():
            raise ValidationError("Follow-up description cannot be empty.")

        clean_date = follow_up_date.strip()
        try:
            datetime.strptime(clean_date, "%Y-%m-%d")
        except (ValueError, TypeError, AttributeError):
            raise ValidationError(f"Invalid follow_up_date format '{follow_up_date}'. Expected 'YYYY-MM-DD'.")

        clean_desc = description.strip()

        with self.transaction() as conn:
            cursor = conn.cursor()

            # Verify application exists and belongs to user
            cursor.execute("SELECT id, user_id, is_archived FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise ApplicationNotFoundError(application_id)
            if app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )
            if bool(app_row["is_archived"]):
                raise ValidationError(
                    f"Cannot create follow-up reminder for archived Application #{application_id}."
                )

            cursor.execute(
                """
                INSERT INTO application_follow_ups (
                    application_id, user_id, follow_up_date, follow_up_type,
                    description, outcome_notes
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    application_id,
                    user_id,
                    clean_date,
                    follow_up_type,
                    clean_desc,
                    outcome_notes,
                ),
            )
            follow_up_id = cursor.lastrowid

            cursor.execute("SELECT * FROM application_follow_ups WHERE id = ?", (follow_up_id,))
            created = ApplicationFollowUp(**dict(cursor.fetchone()))

            # Emit timeline event atomically within the same transaction (data minimized for privacy)
            event_payload = {
                "follow_up_id": follow_up_id,
                "follow_up_date": clean_date,
                "follow_up_type": follow_up_type,
                "action": "SCHEDULED",
            }
            self._insert_application_event_internal(
                cursor=cursor,
                application_id=application_id,
                user_id=user_id,
                event_type="FOLLOW_UP_SCHEDULED",
                actor_type="CANDIDATE",
                actor_identifier=f"user_{user_id}",
                event_payload=event_payload,
            )

            return created

    def get_application_follow_up(
        self, follow_up_id: int, user_id: int
    ) -> Optional[ApplicationFollowUp]:
        """Fetches a follow-up record, enforcing user ownership."""
        with self.connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM application_follow_ups WHERE id = ?", (follow_up_id,))
            row = cursor.fetchone()
            if not row:
                return None
            if row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"ApplicationFollowUp #{follow_up_id}",
                )
            return ApplicationFollowUp(**dict(row))

    def list_application_follow_ups(
        self,
        user_id: int,
        application_id: Optional[int] = None,
        is_completed: Optional[bool] = None,
        include_archived: bool = False,
    ) -> List[ApplicationFollowUp]:
        """Lists follow-up reminders for a user, optionally filtered by application, completion, and archive state."""
        with self.connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT f.*
                FROM application_follow_ups f
                JOIN applications a
                  ON f.application_id = a.id
                 AND f.user_id = a.user_id
                WHERE f.user_id = ?
                  AND (a.is_archived = 0 OR ? = 1)
            """
            params: List[Any] = [user_id, 1 if include_archived else 0]
            if application_id is not None:
                query += " AND f.application_id = ?"
                params.append(application_id)
            if is_completed is not None:
                query += " AND f.is_completed = ?"
                params.append(1 if is_completed else 0)
            query += " ORDER BY f.follow_up_date ASC"

            cursor.execute(query, params)
            return [ApplicationFollowUp(**dict(row)) for row in cursor.fetchall()]

    def complete_application_follow_up(
        self, follow_up_id: int, user_id: int, outcome_notes: Optional[str] = None
    ) -> ApplicationFollowUp:
        """Marks a candidate-scheduled follow-up as completed.

        Atomically updates completion status and appends a FOLLOW_UP_COMPLETED timeline
        event within the same database transaction.
        """
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM application_follow_ups WHERE id = ?", (follow_up_id,))
            row = cursor.fetchone()
            if not row:
                raise ValidationError(f"ApplicationFollowUp #{follow_up_id} not found.")
            if row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"ApplicationFollowUp #{follow_up_id}",
                )

            cursor.execute(
                """
                UPDATE application_follow_ups
                SET is_completed = 1,
                    completed_at = CURRENT_TIMESTAMP,
                    outcome_notes = COALESCE(?, outcome_notes),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
                """,
                (outcome_notes, follow_up_id, user_id),
            )
            cursor.execute("SELECT * FROM application_follow_ups WHERE id = ?", (follow_up_id,))
            completed = ApplicationFollowUp(**dict(cursor.fetchone()))

            # Emit timeline event atomically within the same transaction (data minimized for privacy)
            event_payload = {
                "follow_up_id": follow_up_id,
                "follow_up_date": completed.follow_up_date,
                "follow_up_type": completed.follow_up_type,
                "completed_at": completed.completed_at,
                "action": "COMPLETED",
            }
            self._insert_application_event_internal(
                cursor=cursor,
                application_id=completed.application_id,
                user_id=user_id,
                event_type="FOLLOW_UP_COMPLETED",
                actor_type="CANDIDATE",
                actor_identifier=f"user_{user_id}",
                event_payload=event_payload,
            )

            return completed

    def delete_application_follow_up(self, follow_up_id: int, user_id: int) -> bool:
        """Deletes a candidate follow-up record, enforcing ownership.

        Atomically records a FOLLOW_UP_DELETED timeline event prior to deletion within the same
        database transaction, ensuring that deletion remains auditable in the event chain.
        """
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM application_follow_ups WHERE id = ?", (follow_up_id,))
            row = cursor.fetchone()
            if not row:
                raise ValidationError(f"ApplicationFollowUp #{follow_up_id} not found.")
            if row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=row["user_id"],
                    resource=f"ApplicationFollowUp #{follow_up_id}",
                )

            app_id = row["application_id"]
            f_type = row["follow_up_type"]
            f_date = row["follow_up_date"]

            # Emit deletion audit event before row deletion within the same transaction (data minimized for privacy)
            event_payload = {
                "follow_up_id": follow_up_id,
                "application_id": app_id,
                "follow_up_type": f_type,
                "follow_up_date": f_date,
                "action": "DELETED",
            }
            self._insert_application_event_internal(
                cursor=cursor,
                application_id=app_id,
                user_id=user_id,
                event_type="FOLLOW_UP_DELETED",
                actor_type="CANDIDATE",
                actor_identifier=f"user_{user_id}",
                event_payload=event_payload,
            )

            cursor.execute("DELETE FROM application_follow_ups WHERE id = ? AND user_id = ?", (follow_up_id, user_id))
            return True

    def archive_user_application(
        self, application_id: int, user_id: int, archive_reason: Optional[str] = None
    ) -> Application:
        """Soft-archives an application, preserving all historical timeline events, packets, and confirmations."""
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM applications WHERE id = ?", (application_id,))
            app_row = cursor.fetchone()
            if not app_row:
                raise ApplicationNotFoundError(application_id)
            if app_row["user_id"] != user_id:
                raise CrossUserAccessError(
                    user_id=user_id,
                    target_user_id=app_row["user_id"],
                    resource=f"Application #{application_id}",
                )

            cursor.execute(
                """
                UPDATE applications
                SET is_archived = 1, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
                """,
                (application_id, user_id),
            )
            cursor.execute("SELECT * FROM applications WHERE id = ?", (application_id,))
            archived = Application(**dict(cursor.fetchone()))

        # Emit timeline event
        try:
            self.create_application_event(
                application_id=application_id,
                user_id=user_id,
                event_type="APPLICATION_ARCHIVED",
                actor_type="CANDIDATE",
                actor_identifier=f"user_{user_id}",
                event_payload={"archive_reason": archive_reason},
            )
        except Exception as e:
            logger.warning(f"Could not record timeline event for archived application #{application_id}: {e}")

        return archived


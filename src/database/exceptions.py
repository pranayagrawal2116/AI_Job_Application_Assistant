"""Custom exceptions for the SQLite database, security, and authentication engine."""

from typing import Any, Dict, Optional


class DatabaseError(Exception):
    """Base exception for all database-related operations."""
    pass


class DuplicateJobError(DatabaseError):
    """Raised when an attempt is made to insert a duplicate job (by URL or company+title)."""

    def __init__(self, message: str, existing_job_id: int | None = None, duplicate_field: str | None = None):
        super().__init__(message)
        self.existing_job_id = existing_job_id
        self.duplicate_field = duplicate_field


class DuplicateUserError(DatabaseError):
    """Raised when an attempt is made to register an email address that already exists."""

    def __init__(self, email: str):
        super().__init__(f"An account with email '{email}' already exists.")
        self.email = email


class UserNotFoundError(DatabaseError):
    """Raised when a requested user record cannot be found."""

    def __init__(self, identifier: int | str):
        super().__init__(f"User '{identifier}' was not found.")
        self.identifier = identifier


class JobNotFoundError(DatabaseError):
    """Raised when a requested job record cannot be found."""

    def __init__(self, job_id: int):
        super().__init__(f"Job with ID {job_id} was not found.")
        self.job_id = job_id


class CompanyNotFoundError(DatabaseError):
    """Raised when a requested company record cannot be found."""

    def __init__(self, company_id: int):
        super().__init__(f"Company with ID {company_id} was not found.")
        self.company_id = company_id


class ApplicationNotFoundError(DatabaseError):
    """Raised when a requested application record cannot be found."""

    def __init__(self, identifier: int | str):
        super().__init__(f"Application '{identifier}' was not found.")
        self.identifier = identifier


class InvalidStatusError(DatabaseError):
    """Raised when an invalid status transition or unrecognized application status is provided."""

    def __init__(self, status: str, allowed_statuses: list[str]):
        super().__init__(
            f"Invalid status '{status}'. Allowed statuses are: {', '.join(allowed_statuses)}"
        )
        self.status = status
        self.allowed_statuses = allowed_statuses


class UnconfirmedSubmissionError(DatabaseError):
    """Raised when attempting to mark an application as 'Applied' without explicit confirmation."""

    def __init__(self, message: str = "Cannot set status to 'Applied' without confirmed user authorization."):
        super().__init__(message)


class ValidationError(DatabaseError):
    """Raised when model or input field validation fails."""
    pass


class ConcurrencyConflictError(ValidationError):
    """Raised when a concurrent modification or race condition is detected during transactional operations."""
    pass


class InvalidStatusTransitionError(DatabaseError):
    """Raised when an illegal application status transition is attempted."""

    def __init__(
        self,
        old_status: str,
        new_status: Optional[str] = None,
        allowed: Optional[list[str]] = None,
    ):
        if new_status is None:
            super().__init__(old_status)
            self.old_status = old_status
            self.new_status = ""
            self.allowed = allowed or []
        else:
            super().__init__(
                f"Illegal status transition from '{old_status}' to '{new_status}'. "
                f"Allowed next transitions are: {', '.join(allowed or [])}"
            )
            self.old_status = old_status
            self.new_status = new_status
            self.allowed = allowed or []


class SecurityAuthorizationError(DatabaseError):
    """Raised when an operation fails security, session, or signature verification."""
    pass


class SessionExpiredError(SecurityAuthorizationError):
    """Raised when an authenticated session has expired."""
    pass


class InvalidSessionError(SecurityAuthorizationError):
    """Raised when a session is missing, invalid, or forged."""
    pass


class AccountLockedError(SecurityAuthorizationError):
    """Raised when an account is temporarily locked due to consecutive failed login attempts."""

    def __init__(self, locked_until_str: str):
        super().__init__(f"Account is temporarily locked due to failed login attempts until {locked_until_str}.")
        self.locked_until = locked_until_str


class AuthenticationFailedError(SecurityAuthorizationError):
    """Raised on invalid email or password credentials."""

    def __init__(self, message: str = "Invalid email or password."):
        super().__init__(message)


class TicketAlreadyConsumedError(SecurityAuthorizationError):
    """Raised when an action ticket or approval nonce has already been consumed (replay attack)."""

    def __init__(self, message: str = "Action ticket or approval nonce has already been consumed."):
        super().__init__(message)


class InvalidTicketError(SecurityAuthorizationError):
    """Raised when an action ticket is malformed, unrecognized, or fails signature verification."""
    pass


class KeyRevokedError(SecurityAuthorizationError):
    """Raised when an action ticket or security scan was signed with a revoked or retired HMAC key."""

    def __init__(self, key_id: str, message: Optional[str] = None):
        msg = message or (
            f"Action ticket or security scan signed with revoked key '{key_id}'. "
            f"Key rotation in effect. Fresh candidate authorization required."
        )
        super().__init__(msg)
        self.key_id = key_id
        self.failure_category = "KEY_REVOKED"


class TokenExpiredError(SecurityAuthorizationError):
    """Raised when a password reset token has expired."""

    def __init__(self, message: str = "Password reset token has expired."):
        super().__init__(message)


class TokenAlreadyUsedError(SecurityAuthorizationError):
    """Raised when a password reset token has already been consumed."""

    def __init__(self, message: str = "Password reset token has already been used."):
        super().__init__(message)


class RateLimitExceededError(SecurityAuthorizationError):
    """Raised when authentication or recovery rate limits are exceeded."""

    def __init__(self, message: str = "Rate limit exceeded. Please try again later."):
        super().__init__(message)


class CrossUserAccessError(SecurityAuthorizationError):
    """Raised when an authenticated user attempts to access or link to another user's records."""

    def __init__(self, user_id: int, target_user_id: int, resource: str):
        super().__init__(
            f"Cross-user security violation: User #{user_id} unauthorized to access or link "
            f"{resource} owned by User #{target_user_id}."
        )
        self.user_id = user_id
        self.target_user_id = target_user_id
        self.resource = resource
        self.failure_category = "CROSS_USER_ACCESS"


# -------------------------------------------------------------------------
# PHASE 3: RESUME & FILE SECURITY EXCEPTIONS
# -------------------------------------------------------------------------

class ResumeNotFoundError(DatabaseError):
    """Raised when a requested resume record cannot be found."""

    def __init__(self, resume_id: int | str):
        super().__init__(f"Resume with ID '{resume_id}' was not found.")
        self.resume_id = resume_id


class DuplicateResumeError(DatabaseError):
    """Raised when an identical resume file has already been uploaded by the user."""

    def __init__(self, message: str, existing_resume_id: int | None = None):
        super().__init__(message)
        self.existing_resume_id = existing_resume_id


class FileSecurityError(SecurityAuthorizationError):
    """Base exception for file upload validation and security checks."""
    pass


class ResumeIntegrityError(FileSecurityError, ValidationError):
    """Raised when a candidate resume fails cryptographic integrity, binary verification, or just-in-time validation."""
    pass


class InvalidFileFormatError(FileSecurityError, ValueError):
    """Raised when an uploaded document format or magic-bytes signature is unsupported."""
    pass


class FileTooLargeError(FileSecurityError):
    """Raised when an uploaded document exceeds the 10 MB limit."""
    pass


class CorruptedFileError(FileSecurityError):
    """Raised when an uploaded document is structurally invalid or unreadable."""
    pass


class EncryptedFileError(FileSecurityError):
    """Raised when an uploaded PDF is password-protected or encrypted."""
    pass


class ResumeInUseError(DatabaseError):
    """Raised when trying to delete a resume that is locked by submitted applications."""
    pass


# -----------------------------------------------------------------------------
# PHASE 4: JOB DESCRIPTION INGESTION & PARSING EXCEPTIONS
# -----------------------------------------------------------------------------

class JobDescriptionNotFoundError(DatabaseError):
    """Raised when a requested job description record cannot be found."""
    pass


class DuplicateJobDescriptionError(DatabaseError):
    """Raised when a user attempts to upload an identical job description snapshot."""

    def __init__(self, message: str, existing_id: Optional[int] = None):
        super().__init__(message)
        self.existing_id = existing_id


class UnsafeURLError(SecurityAuthorizationError):
    """Raised when a submitted job listing URL violates SSRF or network boundary safety rules."""
    pass


class URLFetchRestrictedError(DatabaseError):
    """Raised when automated fetching of a job URL is blocked by CAPTCHA, login, 403, or bot challenge."""

    def __init__(self, message: str, official_url: Optional[str] = None, restriction_type: Optional[str] = None):
        super().__init__(message)
        self.official_url = official_url
        self.restriction_type = restriction_type


# -----------------------------------------------------------------------------
# PHASE 5: UNIVERSAL RESUME-TO-JOB MATCHING EXCEPTIONS
# -----------------------------------------------------------------------------

class MatchResultNotFoundError(DatabaseError):
    """Raised when a requested match result record cannot be found."""
    pass


# -----------------------------------------------------------------------------
# PHASE 7: APPLICATION LIFECYCLE & TRACKING EXCEPTIONS
# -----------------------------------------------------------------------------

class MigrationPreflightError(DatabaseError):
    """Raised when database migration preflight checks detect unresolvable data ownership or integrity errors."""
    pass


class DatabaseMigrationError(DatabaseError):
    """Raised when an atomic database migration fails validation or integrity checks."""
    pass


class EventIntegrityError(DatabaseError):
    """Raised when an application timeline event fails cryptographic hash or chain verification."""
    pass


# -----------------------------------------------------------------------------
# PHASE 9.1.2: SECURITY PREFLIGHT & QUARANTINE EXCEPTIONS
# -----------------------------------------------------------------------------

class SecurityPreflightError(SecurityAuthorizationError):
    """Raised when security preflight detects a missing, invalid, or quarantined source scan."""
    pass


class QuarantinedSourceError(SecurityPreflightError):
    """Raised when an operation attempts to consume a quarantined source."""

    def __init__(
        self,
        message: str,
        source_type: str,
        source_id: int,
        classification: str = "QUARANTINED",
        risk_score: float = 1.0,
    ):
        super().__init__(message)
        self.source_type = source_type
        self.source_id = source_id
        self.classification = classification
        self.risk_score = risk_score


# -----------------------------------------------------------------------------
# PHASE 9.1.2 & C.0.5: SECURITY SCAN VERIFICATION & HMAC EXCEPTIONS
# -----------------------------------------------------------------------------

class SecurityScanVerificationError(SecurityAuthorizationError):
    """Base exception for security scan verification failures with precise failure categorization."""

    def __init__(
        self,
        message: str,
        failure_category: str,
        scan_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.failure_category = failure_category
        self.scan_id = scan_id
        self.details = details or {}


class ScanVerificationKeyUnavailableError(SecurityScanVerificationError):
    """Raised when the HMAC key required to verify a historical security scan is missing or unknown."""

    def __init__(self, key_id: str, scan_id: Optional[int] = None, message: Optional[str] = None):
        msg = message or f"Security scan verification key '{key_id}' is unknown or unavailable."
        super().__init__(msg, failure_category="VERIFICATION_KEY_UNAVAILABLE", scan_id=scan_id, details={"key_id": key_id})
        self.key_id = key_id


class ScanSignatureMismatchError(SecurityScanVerificationError):
    """Raised when an HMAC signature does not match the canonical manifest despite an available key (tampering/integrity failure)."""

    def __init__(self, scan_id: Optional[int] = None, message: Optional[str] = None):
        msg = message or (
            f"Cryptographic signature verification failed for scan record #{scan_id}. "
            "The scan record has been tampered with or modified."
        )
        super().__init__(msg, failure_category="SIGNATURE_MISMATCH", scan_id=scan_id)


class ScanSourceHashMismatchError(SecurityScanVerificationError):
    """Raised when the source hash in the scan record does not match the expected source hash."""

    def __init__(self, expected_hash: str, actual_hash: str, scan_id: Optional[int] = None):
        msg = f"Source hash discrepancy: current source hash '{expected_hash}' does not match scanned hash '{actual_hash}'."
        super().__init__(msg, failure_category="SOURCE_HASH_MISMATCH", scan_id=scan_id, details={"expected": expected_hash, "actual": actual_hash})


class ScanBinaryMetadataMismatchError(SecurityScanVerificationError):
    """Raised when binary metadata (hash, size, format) does not match the scanned record."""

    def __init__(self, message: str, scan_id: Optional[int] = None):
        super().__init__(message, failure_category="BINARY_METADATA_MISMATCH", scan_id=scan_id)


class ScanManifestVersionError(SecurityScanVerificationError):
    """Raised when a scan record has an unsupported or invalid manifest version."""

    def __init__(self, manifest_version: Any, scan_id: Optional[int] = None):
        msg = f"Stored scan record #{scan_id} has unsupported manifest_version '{manifest_version}'."
        super().__init__(msg, failure_category="UNSUPPORTED_MANIFEST_VERSION", scan_id=scan_id, details={"manifest_version": manifest_version})


# -----------------------------------------------------------------------------
# PHASE B.3.2: DISCOVERY LOCKING & CONCURRENCY EXCEPTIONS
# -----------------------------------------------------------------------------

class DuplicateDiscoveryRunError(DatabaseError):
    """Raised when an active discovery run (PENDING or RUNNING) already exists for the candidate."""

    def __init__(self, user_id: int, active_run_id: Optional[int] = None):
        msg = f"An active job discovery run is already in progress for candidate #{user_id}."
        if active_run_id:
            msg += f" (Run #{active_run_id})"
        super().__init__(msg)
        self.user_id = user_id
        self.active_run_id = active_run_id



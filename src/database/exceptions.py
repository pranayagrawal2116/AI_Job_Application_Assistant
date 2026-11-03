"""Custom exceptions for the SQLite database, security, and authentication engine."""

from typing import Optional


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


class InvalidStatusTransitionError(DatabaseError):
    """Raised when an illegal application status transition is attempted."""

    def __init__(self, old_status: str, new_status: str, allowed: list[str]):
        super().__init__(
            f"Illegal status transition from '{old_status}' to '{new_status}'. "
            f"Allowed next transitions are: {', '.join(allowed)}"
        )
        self.old_status = old_status
        self.new_status = new_status
        self.allowed = allowed


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
    """Raised when an action ticket was signed with a revoked or retired HMAC key."""

    def __init__(self, key_id: str):
        super().__init__(
            f"Action ticket signed with revoked or unknown key '{key_id}'. "
            f"Key rotation in effect. Fresh candidate authorization required."
        )
        self.key_id = key_id


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


"""Custom exceptions for the SQLite database and job management engine."""


class DatabaseError(Exception):
    """Base exception for all database-related operations."""
    pass


class DuplicateJobError(DatabaseError):
    """Raised when an attempt is made to insert a duplicate job (by URL or company+title)."""

    def __init__(self, message: str, existing_job_id: int | None = None, duplicate_field: str | None = None):
        super().__init__(message)
        self.existing_job_id = existing_job_id
        self.duplicate_field = duplicate_field


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


"""Database package exposing SQLite Manager, models, and exceptions."""

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ApplicationNotFoundError,
    CompanyNotFoundError,
    DatabaseError,
    DuplicateJobError,
    InvalidStatusError,
    JobNotFoundError,
    UnconfirmedSubmissionError,
    ValidationError,
)
from src.database.models import (
    Application,
    ApplicationLog,
    ApplicationStatus,
    CandidateProfileRecord,
    Company,
    Job,
)
from src.database.url_normalizer import (
    generate_company_title_key,
    normalize_entity_name,
    normalize_job_url,
)

__all__ = [
    "DatabaseManager",
    "Company",
    "Job",
    "Application",
    "ApplicationLog",
    "CandidateProfileRecord",
    "ApplicationStatus",
    "normalize_job_url",
    "normalize_entity_name",
    "generate_company_title_key",
    "DatabaseError",
    "DuplicateJobError",
    "JobNotFoundError",
    "CompanyNotFoundError",
    "ApplicationNotFoundError",
    "InvalidStatusError",
    "UnconfirmedSubmissionError",
    "ValidationError",
]

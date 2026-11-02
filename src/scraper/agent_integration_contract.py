"""Agent Integration Contract defining the boundary between Antigravity Agent and Python backend."""

from dataclasses import dataclass, field
from datetime import datetime
import json
from typing import Any, Dict, List, Optional

from src.database.db_manager import DatabaseManager
from src.database.exceptions import DuplicateJobError
from src.database.models import ApplicationStatus, Job
from src.matcher.job_matcher import EvaluationResult, JobMatcher
from src.scraper.data_validator import DataValidator, ValidationResult
from src.scraper.extraction_schema import ExtractedJobPayload
from src.utils.logger import setup_logger

logger = setup_logger("AgentIntegrationContract")


@dataclass
class IngestionResult:
    """Consolidated outcome of ingesting an agent-extracted job opportunity."""
    success: bool
    is_duplicate: bool = False
    is_restricted: bool = False
    job_id: Optional[int] = None
    job: Optional[Job] = None
    evaluation: Optional[EvaluationResult] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    official_application_url: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "is_duplicate": self.is_duplicate,
            "is_restricted": self.is_restricted,
            "job_id": self.job_id,
            "match_score": self.job.match_score if self.job else None,
            "match_classification": self.job.match_classification if self.job else None,
            "is_eligible": self.job.is_eligible if self.job else None,
            "errors": self.errors,
            "warnings": self.warnings,
            "official_application_url": self.official_application_url,
            "timestamp": self.timestamp,
        }


class AgentIntegrationContract:
    """Formal boundary contract connecting Playwright MCP browser extractions with

    the Python validation, matching, and SQLite persistence layer.
    """

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        job_matcher: Optional[JobMatcher] = None,
        data_validator: Optional[DataValidator] = None,
    ):
        self.db = db_manager or DatabaseManager()
        self.matcher = job_matcher or JobMatcher(db_manager=self.db)
        self.validator = data_validator or DataValidator()

    def ingest_payload(
        self,
        payload_or_dict: Any,
        auto_evaluate: bool = True,
    ) -> IngestionResult:
        """Processes an extracted job posting from the Antigravity Agent.

        Workflow:
        1. Parse input dictionary into ExtractedJobPayload.
        2. Validate & detect access restrictions (Cloudflare, CAPTCHA, Auth walls).
        3. Check for duplicates (URL and Company+Title).
        4. Convert to Job entity.
        5. Evaluate via JobMatcher (Domain, Skills, Eligibility, Explanations).
        6. Persist to SQLite via DatabaseManager with audit trail.
        """
        # 1. Parse payload
        if isinstance(payload_or_dict, dict):
            payload = ExtractedJobPayload.from_dict(payload_or_dict)
        elif isinstance(payload_or_dict, ExtractedJobPayload):
            payload = payload_or_dict
        else:
            return IngestionResult(
                success=False,
                errors=["Payload must be an ExtractedJobPayload instance or dictionary."],
            )

        # 2. Validate payload & check restrictions
        val_res: ValidationResult = self.validator.validate(payload)
        if not val_res.is_valid:
            if val_res.is_restricted:
                logger.warning(
                    "Automated access restricted on %s: %s. Official URL: %s",
                    payload.page_url,
                    val_res.restriction_reason,
                    val_res.official_url,
                )
                return IngestionResult(
                    success=False,
                    is_restricted=True,
                    errors=val_res.errors,
                    official_application_url=val_res.official_url,
                )
            return IngestionResult(
                success=False,
                errors=val_res.errors,
                warnings=val_res.warnings,
                official_application_url=val_res.official_url,
            )

        sanitized = val_res.sanitized_payload
        assert sanitized is not None

        # 3. Duplicate check before conversion
        is_dup, existing_id, reason = self.db.check_is_duplicate(
            job_url=sanitized.page_url,
            company_name=sanitized.company_name or "",
            job_title=sanitized.job_title or "",
        )
        if is_dup:
            logger.info("Skipping duplicate job '%s' at '%s' (Existing ID: %d)", sanitized.job_title, sanitized.company_name, existing_id)
            return IngestionResult(
                success=False,
                is_duplicate=True,
                job_id=existing_id,
                warnings=[f"Duplicate job detected ({reason})."],
                official_application_url=sanitized.application_url or sanitized.page_url,
            )

        # 4. Map to Job entity
        job_entity = Job(
            company_name=sanitized.company_name or "Unknown Company",
            job_title=sanitized.job_title or "Unspecified Internship",
            job_url=sanitized.page_url,
            platform=sanitized.platform,
            job_description=sanitized.job_description,
            location=sanitized.location,
            stipend=sanitized.stipend,
            required_skills=sanitized.required_skills,
            eligibility_criteria=sanitized.eligibility_criteria,
            application_deadline=sanitized.application_deadline,
            notes=f"Discovered via Playwright MCP at {sanitized.extracted_at}",
        )

        # 5. Evaluate matching and eligibility
        evaluation: Optional[EvaluationResult] = None
        if auto_evaluate:
            evaluation = self.matcher.evaluate_job(job_entity)
            job_entity.match_score = evaluation.match_score
            job_entity.match_classification = evaluation.match_classification
            job_entity.is_eligible = evaluation.is_eligible
            job_entity.score_breakdown = evaluation.score_breakdown

        # 6. Persist to SQLite
        try:
            inserted_job = self.db.insert_job(job_entity, auto_create_company=True)
            logger.info(
                "Ingested job '%s' (ID: %d) - Score: %.1f (%s) - Eligible: %s",
                inserted_job.job_title,
                inserted_job.id,
                inserted_job.match_score,
                inserted_job.match_classification,
                inserted_job.is_eligible,
            )
            return IngestionResult(
                success=True,
                job_id=inserted_job.id,
                job=inserted_job,
                evaluation=evaluation,
                warnings=val_res.warnings,
                official_application_url=sanitized.application_url or sanitized.page_url,
            )
        except DuplicateJobError as e:
            return IngestionResult(
                success=False,
                is_duplicate=True,
                job_id=e.existing_job_id,
                warnings=[str(e)],
                official_application_url=sanitized.application_url or sanitized.page_url,
            )


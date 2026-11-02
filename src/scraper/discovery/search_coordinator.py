"""Search Coordinator: Orchestrates multi-platform internship discovery, validation, matching, and SQLite persistence."""

from dataclasses import dataclass, field
from datetime import datetime
import json
from typing import Any, Dict, List, Optional, Tuple

from src.database.db_manager import DatabaseManager
from src.database.models import ApplicationStatus, Job
from src.database.url_normalizer import URLNormalizer
from src.matcher.job_matcher import EvaluationResult, JobMatcher
from src.scraper.adapters.base_adapter import BaseAdapter
from src.scraper.discovery.pagination_manager import PaginationManager
from src.scraper.discovery.query_generator import QueryGenerator
from src.scraper.discovery.source_registry import SourceRegistry
from src.scraper.extraction.data_validator import DataValidator
from src.scraper.extraction.extraction_schema import ExtractedJobPayload
from src.scraper.monitoring.access_monitor import AccessMonitor
from src.utils.logger import setup_logger


@dataclass
class DiscoverySummary:
    """Summary metrics of a completed discovery execution."""
    total_discovered: int = 0
    new_jobs_saved: int = 0
    duplicates_skipped: int = 0
    restricted_incidents: int = 0
    platform_breakdown: Dict[str, int] = field(default_factory=dict)
    eligibility_breakdown: Dict[str, int] = field(default_factory=dict)
    score_tier_breakdown: Dict[str, int] = field(default_factory=dict)
    saved_jobs: List[Dict[str, Any]] = field(default_factory=list)
    restricted_notices: List[Dict[str, Any]] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_discovered": self.total_discovered,
            "new_jobs_saved": self.new_jobs_saved,
            "duplicates_skipped": self.duplicates_skipped,
            "restricted_incidents": self.restricted_incidents,
            "platform_breakdown": self.platform_breakdown,
            "eligibility_breakdown": self.eligibility_breakdown,
            "score_tier_breakdown": self.score_tier_breakdown,
            "saved_jobs_count": len(self.saved_jobs),
            "restricted_notices_count": len(self.restricted_notices),
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


class SearchCoordinator:
    """Master orchestrator connecting discovery adapters, validation, matching, and database storage."""

    def __init__(
        self,
        registry: Optional[SourceRegistry] = None,
        query_generator: Optional[QueryGenerator] = None,
        pagination_manager: Optional[PaginationManager] = None,
        db_manager: Optional[DatabaseManager] = None,
        job_matcher: Optional[JobMatcher] = None,
        access_monitor: Optional[AccessMonitor] = None,
        data_validator: Optional[DataValidator] = None,
    ):
        self.logger = setup_logger("SearchCoordinator")
        self.monitor = access_monitor or AccessMonitor()
        self.validator = data_validator or DataValidator()
        self.registry = registry or SourceRegistry.create_default(access_monitor=self.monitor)
        self.query_gen = query_generator or QueryGenerator()
        self.pagination = pagination_manager or PaginationManager()
        self.db = db_manager or DatabaseManager()
        self.matcher = job_matcher or JobMatcher(db_manager=self.db)

    def run_discovery(
        self,
        roles: Optional[List[str]] = None,
        locations: Optional[List[str]] = None,
        max_queries: int = 5,
        max_results_per_source: int = 10,
        enable_evaluation: bool = True,
    ) -> DiscoverySummary:
        """Executes full discovery pipeline across all active source adapters.

        Steps:
        1. Query generation
        2. Adapter search execution with failure isolation
        3. Data validation & quality checks
        4. Normalization and SQLite deduplication
        5. Phase 3 100-pt matching & eligibility assessment
        6. Persistent storage and logging
        """
        start_ts = datetime.now().isoformat()
        summary = DiscoverySummary(start_time=start_ts)

        # 1. Generate query matrix
        query_matrix = self.query_gen.generate_query_matrix(
            roles=roles,
            locations=locations,
            max_combinations=max_queries,
        )

        active_adapters = self.registry.get_active_adapters()
        self.logger.info(
            "Starting discovery with %d active adapters across %d query combinations.",
            len(active_adapters),
            len(query_matrix),
        )

        all_payloads: List[ExtractedJobPayload] = []

        # 2. Query each adapter with isolated exception handling
        for adapter in active_adapters:
            adapter_payloads: List[ExtractedJobPayload] = []
            self.logger.info("Running discovery on adapter: %s (%s)", adapter.name, adapter.source_id)

            for role, loc in query_matrix:
                try:
                    results = adapter.discover(
                        query=role,
                        location=loc,
                        max_results=max_results_per_source,
                    )
                    adapter_payloads.extend(results)
                except Exception as exc:
                    self.logger.error("Error executing %s for ('%s', '%s'): %s", adapter.name, role, loc, exc)
                    self.monitor.record_restriction(
                        source_name=adapter.name,
                        url=adapter.base_url,
                        incident_type="ADAPTER_EXCEPTION",
                        details=str(exc),
                    )

            self.logger.info("Adapter %s returned %d total payloads.", adapter.name, len(adapter_payloads))
            all_payloads.extend(adapter_payloads)

        summary.total_discovered = len(all_payloads)

        # 3. Process, validate, deduplicate, score, and store
        for payload in all_payloads:
            # Handle restricted payload
            if payload.is_restricted:
                summary.restricted_incidents += 1
                notice = {
                    "platform": payload.platform,
                    "url": payload.page_url,
                    "reason": payload.restriction_reason,
                    "timestamp": payload.extracted_at,
                }
                summary.restricted_notices.append(notice)
                continue

            # Validate payload quality
            val_res = self.validator.validate(payload)
            if not val_res.is_valid:
                self.logger.warning("Rejecting invalid payload from %s: %s", payload.platform, val_res.issues)
                continue

            clean_payload = val_res.sanitized_payload or payload
            norm_url = URLNormalizer.normalize(clean_payload.page_url)

            # Atomic Deduplication Check (Normalized URL & Company+Title composite)
            is_dup, existing_id, dup_reason = self.db.check_is_duplicate(
                norm_url, clean_payload.company_name, clean_payload.job_title
            )
            if is_dup:
                summary.duplicates_skipped += 1
                self.logger.debug("Skipping duplicate job: %s (Existing ID: %s)", dup_reason, existing_id)
                continue

            # Convert to Job domain model
            job = Job(
                company_name=clean_payload.company_name,
                job_title=clean_payload.job_title,
                job_description=clean_payload.job_description,
                job_url=norm_url,
                platform=clean_payload.platform,
                location=clean_payload.location,
                stipend=clean_payload.stipend,
                required_skills=clean_payload.required_skills,
                eligibility_criteria=clean_payload.eligibility_criteria,
                application_deadline=clean_payload.application_deadline,
                work_arrangement=clean_payload.work_arrangement,
                publication_date=clean_payload.publication_date,
                internship_duration=clean_payload.internship_duration,
                listing_status=clean_payload.listing_status,
                extraction_confidence=clean_payload.extraction_confidence,
            )

            # 4. Phase 3 Matching and Eligibility Assessment
            eval_result: Optional[EvaluationResult] = None
            if enable_evaluation and self.matcher:
                try:
                    eval_result = self.matcher.evaluate_job(job)
                    job.match_score = eval_result.match_score
                    job.match_classification = eval_result.match_classification
                    job.is_eligible = eval_result.is_eligible
                    job.score_breakdown = eval_result.score_breakdown
                except Exception as exc:
                    self.logger.error("Matching engine error for '%s': %s", job.job_title, exc)

            # 5. Persist to SQLite
            try:
                saved_job = self.db.add_job(job)
                summary.new_jobs_saved += 1

                # Update platform tally
                plat = clean_payload.platform
                summary.platform_breakdown[plat] = summary.platform_breakdown.get(plat, 0) + 1

                # Update eligibility and score metrics
                if eval_result:
                    el_stat = eval_result.eligibility_status.value
                    summary.eligibility_breakdown[el_stat] = summary.eligibility_breakdown.get(el_stat, 0) + 1
                    tier = eval_result.match_classification
                    summary.score_tier_breakdown[tier] = summary.score_tier_breakdown.get(tier, 0) + 1

                summary.saved_jobs.append({
                    "id": saved_job.id,
                    "title": saved_job.job_title,
                    "company": saved_job.company_name,
                    "location": saved_job.location,
                    "platform": saved_job.platform,
                    "score": saved_job.match_score,
                    "eligibility": eval_result.eligibility_status.value if eval_result else "UNKNOWN",
                    "url": saved_job.job_url,
                })

            except Exception as exc:
                self.logger.error("Failed persisting job '%s' to database: %s", job.job_title, exc)

        summary.end_time = datetime.now().isoformat()
        self.logger.info(
            "Discovery complete. Discovered: %d, New Saved: %d, Duplicates: %d, Restricted: %d",
            summary.total_discovered,
            summary.new_jobs_saved,
            summary.duplicates_skipped,
            summary.restricted_incidents,
        )
        return summary

    def _check_composite_duplicate(self, company_name: str, job_title: str) -> bool:
        """Checks if a job with the same company and title is already recorded."""
        norm_comp = company_name.lower().strip()
        norm_title = job_title.lower().strip()
        all_jobs = self.db.get_all_jobs()
        for j in all_jobs:
            if j.company_name.lower().strip() == norm_comp and j.job_title.lower().strip() == norm_title:
                return True
        return False

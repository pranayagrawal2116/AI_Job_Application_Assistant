"""Base Adapter interface for all job discovery sources."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from src.scraper.extraction.data_validator import DataValidator
from src.scraper.extraction.extraction_schema import ExtractedJobPayload
from src.scraper.monitoring.access_monitor import AccessMonitor
from src.utils.logger import setup_logger


class BaseAdapter(ABC):
    """Abstract Base Class for modular job discovery adapters."""

    def __init__(
        self,
        name: str,
        source_id: str,
        base_url: str,
        rate_limit_delay: float = 3.0,
        respect_robots: bool = True,
        access_monitor: Optional[AccessMonitor] = None,
        data_validator: Optional[DataValidator] = None,
    ):
        self.name = name
        self.source_id = source_id
        self.base_url = base_url
        self.rate_limit_delay = rate_limit_delay
        self.respect_robots = respect_robots
        self.monitor = access_monitor or AccessMonitor()
        self.validator = data_validator or DataValidator()
        self.logger = setup_logger(f"Adapter:{source_id}")

    @abstractmethod
    def discover(
        self,
        query: str,
        location: Optional[str] = None,
        max_results: int = 10,
    ) -> List[ExtractedJobPayload]:
        """Discovers opportunities matching the target role and location.

        Returns:
            List of extracted job payloads (validated and quality-annotated).
        """
        pass

    @abstractmethod
    def fetch_job_details(self, job_url: str) -> Optional[ExtractedJobPayload]:
        """Fetches full job description and details for a specific opportunity."""
        pass

    def is_healthy(self) -> bool:
        """Checks whether the adapter has encountered recent blocking or failure."""
        summary = self.monitor.get_summary().get(self.name, {})
        blkd = summary.get("blocked_or_restricted", 0)
        reqs = summary.get("total_requests", 0)
        return blkd == 0 or (reqs > 0 and (blkd / reqs) < 0.8)

    def create_restricted_payload(self, url: str, reason: str) -> ExtractedJobPayload:
        """Generates a restricted payload placeholder preserving the official URL."""
        self.monitor.record_restriction(
            source_name=self.name,
            url=url,
            incident_type="RESTRICTED_ACCESS",
            details=reason,
        )
        return ExtractedJobPayload(
            page_url=url,
            platform=self.name,
            is_restricted=True,
            restriction_reason=reason,
            listing_status="RESTRICTED",
            extraction_confidence=0.0,
        )


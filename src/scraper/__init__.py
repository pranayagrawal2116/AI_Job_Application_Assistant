"""Scraper and browser automation package exposing extraction schemas, validators, and agent contracts."""

from src.scraper.agent_integration_contract import AgentIntegrationContract, IngestionResult
from src.scraper.data_validator import DataValidator, ValidationResult
from src.scraper.extraction_schema import ExtractedJobPayload
from src.scraper.url_fetcher import FetchedJobContent, URLJobFetcher

__all__ = [
    "ExtractedJobPayload",
    "DataValidator",
    "ValidationResult",
    "AgentIntegrationContract",
    "IngestionResult",
    "URLJobFetcher",
    "FetchedJobContent",
]

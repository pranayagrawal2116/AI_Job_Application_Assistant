"""Discovery orchestration package."""

from src.scraper.discovery.pagination_manager import PaginationManager
from src.scraper.discovery.query_generator import QueryGenerator
from src.scraper.discovery.search_coordinator import DiscoverySummary, SearchCoordinator
from src.scraper.discovery.source_registry import SourceRegistry

__all__ = [
    "QueryGenerator",
    "PaginationManager",
    "SourceRegistry",
    "SearchCoordinator",
    "DiscoverySummary",
]


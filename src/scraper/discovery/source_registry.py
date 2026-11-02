"""Source Registry for managing modular job discovery adapters."""

from typing import Any, Dict, List, Optional

from src.scraper.adapters.base_adapter import BaseAdapter
from src.scraper.adapters.company_careers_adapter import CompanyCareersAdapter
from src.scraper.adapters.indeed_adapter import IndeedAdapter
from src.scraper.adapters.internshala_adapter import InternshalaAdapter
from src.scraper.adapters.linkedin_adapter import LinkedInAdapter
from src.scraper.adapters.naukri_adapter import NaukriAdapter
from src.scraper.monitoring.access_monitor import AccessMonitor
from src.utils.logger import setup_logger


class SourceRegistry:
    """Registry managing available job source adapters and their operational state."""

    def __init__(self, access_monitor: Optional[AccessMonitor] = None):
        self.logger = setup_logger("SourceRegistry")
        self.monitor = access_monitor or AccessMonitor()
        self._adapters: Dict[str, BaseAdapter] = {}
        self._enabled_sources: Dict[str, bool] = {}

    def register(self, adapter: BaseAdapter, enabled: bool = True) -> None:
        """Registers a new source adapter."""
        self._adapters[adapter.source_id] = adapter
        self._enabled_sources[adapter.source_id] = enabled
        self.logger.info("Registered adapter '%s' (ID: %s, Enabled: %s)", adapter.name, adapter.source_id, enabled)

    def unregister(self, source_id: str) -> Optional[BaseAdapter]:
        """Removes an adapter from the registry."""
        self._enabled_sources.pop(source_id, None)
        return self._adapters.pop(source_id, None)

    def get(self, source_id: str) -> Optional[BaseAdapter]:
        """Retrieves adapter by its source_id."""
        return self._adapters.get(source_id)

    def enable(self, source_id: str) -> None:
        """Enables a registered source."""
        if source_id in self._adapters:
            self._enabled_sources[source_id] = True

    def disable(self, source_id: str) -> None:
        """Disables a registered source."""
        if source_id in self._adapters:
            self._enabled_sources[source_id] = False

    def is_enabled(self, source_id: str) -> bool:
        """Checks if a source is currently enabled."""
        return self._enabled_sources.get(source_id, False)

    def get_active_adapters(self) -> List[BaseAdapter]:
        """Returns list of all enabled adapters."""
        return [
            adapter for sid, adapter in self._adapters.items()
            if self._enabled_sources.get(sid, False)
        ]

    def get_source_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Returns health and status summary for each registered source."""
        statuses = {}
        summary = self.monitor.get_summary()
        for sid, adapter in self._adapters.items():
            mon_data = summary.get(adapter.name, {})
            statuses[sid] = {
                "name": adapter.name,
                "enabled": self._enabled_sources.get(sid, False),
                "healthy": adapter.is_healthy(),
                "total_requests": mon_data.get("total_requests", 0),
                "successful_requests": mon_data.get("successful_requests", 0),
                "blocked_or_restricted": mon_data.get("blocked_or_restricted", 0),
            }
        return statuses

    @classmethod
    def create_default(cls, access_monitor: Optional[AccessMonitor] = None) -> "SourceRegistry":
        """Creates registry populated with default production adapters."""
        reg = cls(access_monitor=access_monitor)
        mon = reg.monitor

        reg.register(InternshalaAdapter(access_monitor=mon), enabled=True)
        reg.register(CompanyCareersAdapter(access_monitor=mon), enabled=True)
        reg.register(LinkedInAdapter(access_monitor=mon), enabled=True)
        reg.register(IndeedAdapter(access_monitor=mon), enabled=True)
        reg.register(NaukriAdapter(access_monitor=mon), enabled=True)

        return reg

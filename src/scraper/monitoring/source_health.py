"""Source Health module evaluating adapter availability and status."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

from src.scraper.monitoring.access_monitor import AccessMonitor


class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    RESTRICTED = "RESTRICTED"
    OFFLINE = "OFFLINE"


@dataclass
class SourceHealthReport:
    source_name: str
    status: HealthStatus
    success_rate: float
    total_requests: int
    last_error: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "status": self.status.value,
            "success_rate": self.success_rate,
            "total_requests": self.total_requests,
            "last_error": self.last_error,
            "notes": self.notes,
        }


class SourceHealthManager:
    """Manages and reports operational health for all registered discovery sources."""

    def __init__(self, access_monitor: Optional[AccessMonitor] = None):
        self.monitor = access_monitor or AccessMonitor()

    def evaluate_source_health(self, source_name: str) -> SourceHealthReport:
        """Determines health status based on recent incident metrics."""
        summary = self.monitor.get_summary().get(source_name, {})
        total = summary.get("total_requests", 0)
        blocked = summary.get("blocked_or_restricted", 0)
        rate = summary.get("success_rate_pct", 100.0)

        if total == 0:
            status = HealthStatus.HEALTHY
            notes = "No requests recorded yet; default healthy."
        elif blocked > 0 and blocked >= total:
            status = HealthStatus.RESTRICTED
            notes = "All recent attempts were restricted or blocked by anti-bot controls."
        elif rate < 50.0:
            status = HealthStatus.DEGRADED
            notes = f"High failure rate detected ({rate}% success rate)."
        else:
            status = HealthStatus.HEALTHY
            notes = "Operating normally."

        # Find last incident error
        last_error = None
        for inc in reversed(self.monitor.incidents):
            if inc.source_name == source_name:
                last_error = f"{inc.incident_type}: {inc.details}"
                break

        return SourceHealthReport(
            source_name=source_name,
            status=status,
            success_rate=rate,
            total_requests=total,
            last_error=last_error,
            notes=notes,
        )


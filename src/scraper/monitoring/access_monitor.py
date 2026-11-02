"""Access Monitor tracking rate limits, HTTP status codes, and security restrictions per domain."""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.utils.logger import setup_logger

logger = setup_logger("AccessMonitor")


@dataclass
class AccessIncident:
    """Record of an access restriction or rate-limit event."""
    source_name: str
    url: str
    incident_type: str  # 'CLOUDFLARE_BLOCKED', 'CAPTCHA', 'LOGIN_WALL', 'HTTP_429', 'TIMEOUT'
    details: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class AccessMonitor:
    """Tracks and records health and security events across job discovery portals."""

    def __init__(self):
        self.incidents: List[AccessIncident] = []
        self.request_counts: Dict[str, int] = defaultdict(int)
        self.success_counts: Dict[str, int] = defaultdict(int)
        self.blocked_counts: Dict[str, int] = defaultdict(int)

    def record_request(self, source_name: str, url: str) -> None:
        """Records an attempted fetch or navigation."""
        self.request_counts[source_name] += 1

    def record_success(self, source_name: str, url: str) -> None:
        """Records a successful discovery or extraction."""
        self.success_counts[source_name] += 1

    def record_restriction(
        self, source_name: str, url: str, incident_type: str, details: str
    ) -> AccessIncident:
        """Records an access restriction and logs a warning."""
        self.blocked_counts[source_name] += 1
        incident = AccessIncident(
            source_name=source_name,
            url=url,
            incident_type=incident_type,
            details=details,
        )
        self.incidents.append(incident)
        logger.warning(
            "Access restriction recorded for %s [%s]: %s (URL: %s)",
            source_name,
            incident_type,
            details,
            url,
        )
        return incident

    def get_summary(self) -> Dict[str, Any]:
        """Returns statistics summary across all sources."""
        sources = set(list(self.request_counts.keys()) + list(self.blocked_counts.keys()))
        summary = {}
        for s in sources:
            reqs = self.request_counts.get(s, 0)
            succ = self.success_counts.get(s, 0)
            blkd = self.blocked_counts.get(s, 0)
            rate = (succ / reqs * 100.0) if reqs > 0 else 0.0
            summary[s] = {
                "total_requests": reqs,
                "successful": succ,
                "blocked_or_restricted": blkd,
                "success_rate_pct": round(rate, 1),
            }
        return summary


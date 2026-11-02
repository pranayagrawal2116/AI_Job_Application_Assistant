"""Pagination Manager with bounded limits and rate limiting."""

import time
from typing import Optional


class PaginationManager:
    """Manages pagination offsets, safety bounds, and polite delay pacing."""

    def __init__(
        self,
        max_pages_per_query: int = 5,
        default_page_size: int = 10,
        polite_delay_seconds: float = 2.0,
    ):
        self.max_pages_per_query = max(1, min(max_pages_per_query, 10))
        self.default_page_size = default_page_size
        self.polite_delay_seconds = polite_delay_seconds

    def should_continue(
        self,
        current_page: int,
        results_in_current_page: int,
        consecutive_empty_pages: int = 0,
    ) -> bool:
        """Determines whether pagination should proceed to the next page."""
        if current_page >= self.max_pages_per_query:
            return False
        if results_in_current_page == 0:
            return False
        if consecutive_empty_pages >= 2:
            return False
        return True

    def calculate_offset(self, page_index: int, page_size: Optional[int] = None) -> int:
        """Calculates 0-indexed item offset for page number."""
        size = page_size or self.default_page_size
        return max(0, (page_index - 1) * size)

    def pace_request(self, delay: Optional[float] = None) -> None:
        """Applies polite delay between successive page fetches."""
        sleep_time = delay if delay is not None else self.polite_delay_seconds
        if sleep_time > 0:
            time.sleep(sleep_time)


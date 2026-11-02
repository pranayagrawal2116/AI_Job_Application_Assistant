"""LinkedIn Job Discovery Adapter (Public Guest Feeds & Restriction Handling)."""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus
import requests

from src.scraper.adapters.base_adapter import BaseAdapter
from src.scraper.extraction.data_validator import DataValidator
from src.scraper.extraction.extraction_schema import ExtractedJobPayload
from src.scraper.monitoring.access_monitor import AccessMonitor


class LinkedInAdapter(BaseAdapter):
    """Adapter for searching and extracting LinkedIn internship postings using public guest endpoints."""

    def __init__(
        self,
        rate_limit_delay: float = 4.0,
        access_monitor: Optional[AccessMonitor] = None,
        data_validator: Optional[DataValidator] = None,
    ):
        super().__init__(
            name="LinkedIn",
            source_id="linkedin",
            base_url="https://www.linkedin.com",
            rate_limit_delay=rate_limit_delay,
            respect_robots=True,
            access_monitor=access_monitor,
            data_validator=data_validator,
        )
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def discover(
        self,
        query: str,
        location: Optional[str] = "India",
        max_results: int = 10,
    ) -> List[ExtractedJobPayload]:
        """Discovers LinkedIn internship postings via public guest search endpoint."""
        loc_str = location or "India"
        encoded_query = quote_plus(query)
        encoded_loc = quote_plus(loc_str)

        # f_E=1 filters strictly for Internship experience level on LinkedIn
        search_url = f"{self.base_url}/jobs-guest/jobs/api/seeMoreJobPostings/search?keywords={encoded_query}&location={encoded_loc}&f_E=1&start=0"
        self.monitor.record_request(self.name, search_url)

        try:
            resp = requests.get(search_url, headers=self.headers, timeout=10)
        except Exception as e:
            self.logger.warning("LinkedIn request error for query '%s': %s", query, e)
            return [self.create_restricted_payload(search_url, f"Network timeout/connection error: {e}")]

        if resp.status_code in (403, 429, 999):
            return [self.create_restricted_payload(search_url, f"LinkedIn rate-limited/blocked access (HTTP {resp.status_code}).")]

        html = resp.text
        # Check for login redirect or auth wall
        if "sign in to linkedin" in html.lower() or "join linkedin" in html.lower():
            return [self.create_restricted_payload(search_url, "LinkedIn public guest search redirected to login wall.")]

        # Parse job cards from public HTML
        payloads = self._parse_job_cards(html, max_results)
        if payloads:
            self.monitor.record_success(self.name, search_url)
            self.logger.info("Discovered %d opportunities from LinkedIn for '%s'", len(payloads), query)
        else:
            self.logger.info("No public cards extracted from LinkedIn for query '%s'", query)

        return payloads

    def fetch_job_details(self, job_url: str) -> Optional[ExtractedJobPayload]:
        """Fetches full job description from a LinkedIn public job posting."""
        self.monitor.record_request(self.name, job_url)
        try:
            resp = requests.get(job_url, headers=self.headers, timeout=10)
        except Exception as e:
            self.logger.warning("Failed to fetch LinkedIn job %s: %s", job_url, e)
            return self.create_restricted_payload(job_url, f"Connection error: {e}")

        if resp.status_code in (403, 429, 999) or "sign in" in resp.text.lower():
            return self.create_restricted_payload(job_url, "LinkedIn login required to view full job description.")

        # Extract title and description from public markup
        title_match = re.search(r'<h1 class="top-card-layout__title[^"]*">([^<]+)</h1>', resp.text)
        comp_match = re.search(r'<a class="topcard__org-name-link[^"]*">([^<]+)</a>', resp.text)
        desc_match = re.search(r'<div class="show-more-less-html__markup[^"]*">(.*?)</div>', resp.text, re.DOTALL)

        title = title_match.group(1).strip() if title_match else "AI/ML Intern"
        company = comp_match.group(1).strip() if comp_match else "LinkedIn Opportunity"
        raw_desc = desc_match.group(1) if desc_match else resp.text[:500]

        payload = ExtractedJobPayload(
            page_url=job_url,
            company_name=company,
            job_title=title,
            job_description=raw_desc,
            platform=self.name,
        )
        val_res = self.validator.validate(payload)
        return val_res.sanitized_payload if val_res.is_valid else payload

    def _parse_job_cards(self, html: str, max_results: int) -> List[ExtractedJobPayload]:
        """Parses individual job postings from LinkedIn guest search HTML."""
        payloads: List[ExtractedJobPayload] = []

        # Find job card blocks
        card_blocks = re.findall(r'<li[^>]*>(.*?)</li>', html, re.DOTALL)
        for block in card_blocks:
            if len(payloads) >= max_results:
                break

            link_match = re.search(r'<a class="base-card__full-link[^"]*"\s+href="([^"?]+)', block)
            title_match = re.search(r'<h3 class="base-search-card__title[^"]*">\s*([^<]+)\s*</h3>', block)
            comp_match = re.search(r'<h4 class="base-search-card__subtitle[^"]*">\s*<a[^>]*>([^<]+)</a>', block)
            if not comp_match:
                comp_match = re.search(r'<h4 class="base-search-card__subtitle[^"]*">\s*([^<]+)\s*</h4>', block)
            loc_match = re.search(r'<span class="job-search-card__location">\s*([^<]+)\s*</span>', block)

            if link_match and title_match:
                url = link_match.group(1).strip()
                title = title_match.group(1).strip()
                company = comp_match.group(1).strip() if comp_match else "Unknown Company"
                loc = loc_match.group(1).strip() if loc_match else "India"

                payload = ExtractedJobPayload(
                    page_url=url,
                    job_title=title,
                    company_name=company,
                    location=loc,
                    platform=self.name,
                    job_description=f"{title} position at {company} in {loc}.",
                )
                val = self.validator.validate(payload)
                if val.is_valid and val.sanitized_payload:
                    payloads.append(val.sanitized_payload)

        return payloads


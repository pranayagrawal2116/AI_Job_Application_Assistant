"""Indeed Job Discovery Adapter (Public Search & Cloudflare Defense Fallback)."""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus
import requests

from src.scraper.adapters.base_adapter import BaseAdapter
from src.scraper.extraction.data_validator import DataValidator
from src.scraper.extraction.extraction_schema import ExtractedJobPayload
from src.scraper.monitoring.access_monitor import AccessMonitor


class IndeedAdapter(BaseAdapter):
    """Adapter for querying Indeed public listings with strict anti-bot and Cloudflare detection."""

    def __init__(
        self,
        rate_limit_delay: float = 3.0,
        access_monitor: Optional[AccessMonitor] = None,
        data_validator: Optional[DataValidator] = None,
    ):
        super().__init__(
            name="Indeed",
            source_id="indeed",
            base_url="https://in.indeed.com",
            rate_limit_delay=rate_limit_delay,
            respect_robots=True,
            access_monitor=access_monitor,
            data_validator=data_validator,
        )
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def _build_search_url(self, query: str, location: Optional[str] = None) -> str:
        q = f"{query} intern" if "intern" not in query.lower() else query
        loc = location or "India"
        return f"{self.base_url}/jobs?q={quote_plus(q)}&l={quote_plus(loc)}"

    def discover(
        self,
        query: str,
        location: Optional[str] = "India",
        max_results: int = 10,
    ) -> List[ExtractedJobPayload]:
        """Queries Indeed for internship listings, safely handling anti-bot protections."""
        search_url = self._build_search_url(query, location)
        self.monitor.record_request(self.name, search_url)

        try:
            resp = requests.get(search_url, headers=self.headers, timeout=10)
        except Exception as e:
            self.logger.warning("Indeed request error for '%s': %s", query, e)
            return [self.create_restricted_payload(search_url, f"Network connection error: {e}")]

        # Check for Cloudflare / HTTP 403 / 429
        if resp.status_code in (403, 429, 503):
            self.logger.info("Indeed returned HTTP %d (Cloudflare / Bot Defense active).", resp.status_code)
            return [self.create_restricted_payload(
                search_url,
                f"Indeed anti-bot protection active (HTTP {resp.status_code}). Human inspection recommended."
            )]

        html = resp.text
        if "challenge-running" in html.lower() or "cf-turnstile" in html.lower() or "just a moment..." in html.lower():
            self.logger.info("Indeed Cloudflare challenge detected in response text.")
            return [self.create_restricted_payload(
                search_url,
                "Indeed Cloudflare Turnstile challenge encountered. Automated access restricted."
            )]

        payloads = self._parse_indeed_cards(html, max_results)
        if payloads:
            self.monitor.record_success(self.name, search_url)
            self.logger.info("Extracted %d listings from Indeed for '%s'", len(payloads), query)
        else:
            self.logger.info("No listings parsed from Indeed for '%s'", query)

        return payloads

    def fetch_job_details(self, job_url: str) -> Optional[ExtractedJobPayload]:
        """Fetches full job description from an Indeed posting, respecting anti-bot limits."""
        self.monitor.record_request(self.name, job_url)
        try:
            resp = requests.get(job_url, headers=self.headers, timeout=10)
        except Exception as e:
            self.logger.warning("Indeed detail fetch error: %s", e)
            return self.create_restricted_payload(job_url, f"Connection error: {e}")

        if resp.status_code in (403, 429, 503):
            return self.create_restricted_payload(
                job_url,
                f"Indeed job details access restricted (HTTP {resp.status_code})."
            )

        html = resp.text
        if "cf-turnstile" in html.lower() or "challenge-running" in html.lower():
            return self.create_restricted_payload(job_url, "Cloudflare challenge on Indeed detail page.")

        # Extract title and company
        title_m = re.search(r'<h1[^>]*class="[^\"]*jobsearch-JobInfoHeader-title[^\"]*"[^>]*>([^<]+)</h1>', html)
        if not title_m:
            title_m = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
        comp_m = re.search(r'data-company-name="true"[^>]*>([^<]+)<', html)
        if not comp_m:
            comp_m = re.search(r'<div[^>]*class="[^\"]*jobsearch-InlineCompanyRating[^\"]*"[^>]*>.*?<a[^>]*>([^<]+)</a>', html, re.DOTALL)

        desc_m = re.search(r'<div[^>]*id="jobDescriptionText"[^>]*>(.*?)</div>', html, re.DOTALL)
        if desc_m:
            clean_desc = re.sub(r'<[^>]+>', ' ', desc_m.group(1))
            clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
        else:
            clean_desc = "Indeed Job Opportunity Details."

        title = title_m.group(1).strip() if title_m else "AI/ML Intern"
        company = comp_m.group(1).strip() if comp_m else "Indeed Employer"

        payload = ExtractedJobPayload(
            page_url=job_url,
            job_title=title,
            company_name=company,
            job_description=clean_desc,
            platform=self.name,
        )
        val = self.validator.validate(payload)
        return val.sanitized_payload if val.is_valid else payload

    def _parse_indeed_cards(self, html: str, max_results: int) -> List[ExtractedJobPayload]:
        """Parses job cards from unblocked Indeed search result HTML."""
        payloads: List[ExtractedJobPayload] = []

        # Find job card blocks
        cards = re.findall(r'<div[^>]*class="[^\"]*job_seen_beacon[^\"]*"[^>]*>(.*?)</td>\s*</tr>', html, re.DOTALL)
        if not cards:
            cards = re.findall(r'<div[^>]*class="[^\"]*cardOutline[^\"]*"[^>]*>(.*?)</div>\s*</div>', html, re.DOTALL)

        for card in cards:
            if len(payloads) >= max_results:
                break

            title_m = re.search(r'<a[^>]*class="[^\"]*jcs-JobTitle[^\"]*"[^>]*href="([^"]+)"[^>]*>.*?<span[^>]*>([^<]+)</span>', card, re.DOTALL)
            comp_m = re.search(r'data-testid="company-name"[^>]*>([^<]+)<', card)
            loc_m = re.search(r'data-testid="text-location"[^>]*>([^<]+)<', card)
            snippet_m = re.search(r'<div[^>]*class="[^\"]*job-snippet[^\"]*"[^>]*>(.*?)</div>', card, re.DOTALL)

            if title_m:
                rel_url = title_m.group(1).strip()
                full_url = f"{self.base_url}{rel_url}" if rel_url.startswith("/") else rel_url
                title = title_m.group(2).strip()
                company = comp_m.group(1).strip() if comp_m else "Indeed Employer"
                location = loc_m.group(1).strip() if loc_m else "India"

                snippet = ""
                if snippet_m:
                    snippet = re.sub(r'<[^>]+>', ' ', snippet_m.group(1)).strip()
                desc = snippet or f"{title} internship at {company} in {location}."

                payload = ExtractedJobPayload(
                    page_url=full_url,
                    job_title=title,
                    company_name=company,
                    location=location,
                    platform=self.name,
                    job_description=desc,
                )
                val = self.validator.validate(payload)
                if val.is_valid and val.sanitized_payload:
                    payloads.append(val.sanitized_payload)

        return payloads


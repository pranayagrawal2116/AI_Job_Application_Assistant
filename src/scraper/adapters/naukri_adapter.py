"""Naukri Job Discovery Adapter (Public Endpoints & Restriction Detection)."""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus
import requests

from src.scraper.adapters.base_adapter import BaseAdapter
from src.scraper.extraction.data_validator import DataValidator
from src.scraper.extraction.extraction_schema import ExtractedJobPayload
from src.scraper.monitoring.access_monitor import AccessMonitor


class NaukriAdapter(BaseAdapter):
    """Adapter for searching Naukri opportunities with Akamai/Bot-defense handling."""

    def __init__(
        self,
        rate_limit_delay: float = 3.0,
        access_monitor: Optional[AccessMonitor] = None,
        data_validator: Optional[DataValidator] = None,
    ):
        super().__init__(
            name="Naukri",
            source_id="naukri",
            base_url="https://www.naukri.com",
            rate_limit_delay=rate_limit_delay,
            respect_robots=True,
            access_monitor=access_monitor,
            data_validator=data_validator,
        )
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "appid": "109",
            "systemid": "109",
        }

    def _format_slug(self, query: str) -> str:
        words = re.sub(r"[^a-zA-Z0-9\s]", "", query).lower().split()
        if "intern" not in words:
            words.append("intern")
        return "-".join(words)

    def discover(
        self,
        query: str,
        location: Optional[str] = "India",
        max_results: int = 10,
    ) -> List[ExtractedJobPayload]:
        """Queries Naukri public listings, handling anti-scraping controls gracefully."""
        slug = self._format_slug(query)
        search_url = f"{self.base_url}/{slug}-jobs"
        if location and location.lower() != "india":
            search_url += f"-in-{quote_plus(location.lower())}"

        self.monitor.record_request(self.name, search_url)

        try:
            resp = requests.get(search_url, headers=self.headers, timeout=10)
        except Exception as e:
            self.logger.warning("Naukri request error: %s", e)
            return [self.create_restricted_payload(search_url, f"Network timeout: {e}")]

        if resp.status_code in (403, 429, 503):
            self.logger.info("Naukri returned HTTP %d (Anti-automation active).", resp.status_code)
            return [self.create_restricted_payload(
                search_url,
                f"Naukri bot-defense active (HTTP {resp.status_code}). Official URL preserved for manual review."
            )]

        html = resp.text
        if "access denied" in html.lower() or "security check" in html.lower():
            return [self.create_restricted_payload(search_url, "Naukri security challenge encountered.")]

        payloads = self._parse_naukri_cards(html, max_results)
        if payloads:
            self.monitor.record_success(self.name, search_url)
            self.logger.info("Discovered %d listings from Naukri for '%s'", len(payloads), query)
        else:
            self.logger.info("No listings parsed from Naukri HTML for '%s'", query)

        return payloads

    def fetch_job_details(self, job_url: str) -> Optional[ExtractedJobPayload]:
        """Fetches full job description from a Naukri listing."""
        self.monitor.record_request(self.name, job_url)
        try:
            resp = requests.get(job_url, headers=self.headers, timeout=10)
        except Exception as e:
            self.logger.warning("Naukri detail fetch error: %s", e)
            return self.create_restricted_payload(job_url, f"Connection error: {e}")

        if resp.status_code in (403, 429, 503):
            return self.create_restricted_payload(job_url, f"Naukri details restricted (HTTP {resp.status_code}).")

        html = resp.text
        title_m = re.search(r'<h1 class="styles_jd-header-title[^"]*">([^<]+)</h1>', html)
        comp_m = re.search(r'<div class="styles_jd-header-comp-name[^"]*">.*?<a[^>]*>([^<]+)</a>', html, re.DOTALL)
        desc_m = re.search(r'<section class="styles_job-desc-container[^"]*">(.*?)</section>', html, re.DOTALL)

        title = title_m.group(1).strip() if title_m else "AI/ML Intern"
        company = comp_m.group(1).strip() if comp_m else "Naukri Employer"
        desc = re.sub(r'<[^>]+>', ' ', desc_m.group(1)).strip() if desc_m else resp.text[:500]

        payload = ExtractedJobPayload(
            page_url=job_url,
            job_title=title,
            company_name=company,
            job_description=desc,
            platform=self.name,
        )
        val = self.validator.validate(payload)
        return val.sanitized_payload if val.is_valid else payload

    def _parse_naukri_cards(self, html: str, max_results: int) -> List[ExtractedJobPayload]:
        """Parses job listings from Naukri markup."""
        payloads: List[ExtractedJobPayload] = []

        # Find job tuples
        tuples = re.findall(r'<div[^>]*class="[^\"]*srp-jobtuple-wrapper[^\"]*"[^>]*>(.*?)</div>\s*</div>', html, re.DOTALL)
        if not tuples:
            tuples = re.findall(r'<article class="jobTuple[^"]*">(.*?)</article>', html, re.DOTALL)

        for card in tuples:
            if len(payloads) >= max_results:
                break

            title_m = re.search(r'<a[^>]*class="[^\"]*title[^\"]*"[^>]*href="([^"]+)"[^>]*>([^<]+)</a>', card)
            comp_m = re.search(r'<a[^>]*class="[^\"]*comp-name[^\"]*"[^>]*>([^<]+)</a>', card)
            loc_m = re.search(r'<span class="locWdth"[^>]*>([^<]+)</span>', card)
            desc_m = re.search(r'<span class="job-desc[^\"]*"[^>]*>([^<]+)</span>', card)

            if title_m:
                url = title_m.group(1).strip()
                title = title_m.group(2).strip()
                company = comp_m.group(1).strip() if comp_m else "Naukri Employer"
                location = loc_m.group(1).strip() if loc_m else "India"
                desc = desc_m.group(1).strip() if desc_m else f"{title} at {company} in {location}."

                payload = ExtractedJobPayload(
                    page_url=url,
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


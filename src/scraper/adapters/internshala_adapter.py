"""Internshala Job Discovery Adapter."""

import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus
import requests

from src.scraper.adapters.base_adapter import BaseAdapter
from src.scraper.extraction.data_validator import DataValidator
from src.scraper.extraction.extraction_schema import ExtractedJobPayload
from src.scraper.monitoring.access_monitor import AccessMonitor


class InternshalaAdapter(BaseAdapter):
    """Adapter for searching and extracting verified internship opportunities from Internshala."""

    CATEGORY_MAP = {
        "artificial intelligence": "artificial-intelligence-ai-internship",
        "ai": "artificial-intelligence-ai-internship",
        "machine learning": "machine-learning-internship",
        "ml": "machine-learning-internship",
        "data science": "data-science-internship",
        "deep learning": "machine-learning-internship",
        "generative ai": "artificial-intelligence-ai-internship",
        "genai": "artificial-intelligence-ai-internship",
        "nlp": "artificial-intelligence-ai-internship",
        "computer vision": "artificial-intelligence-ai-internship",
        "python": "python-django-internship",
        "data analyst": "data-science-internship",
    }

    def __init__(
        self,
        rate_limit_delay: float = 2.0,
        access_monitor: Optional[AccessMonitor] = None,
        data_validator: Optional[DataValidator] = None,
    ):
        super().__init__(
            name="Internshala",
            source_id="internshala",
            base_url="https://internshala.com",
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
        """Determines the most accurate public Internshala URL for the given query and location."""
        norm_query = query.lower().strip()
        category_slug = None
        for key, slug in self.CATEGORY_MAP.items():
            if key in norm_query:
                category_slug = slug
                break

        if category_slug:
            url = f"{self.base_url}/internships/{category_slug}"
        else:
            encoded = quote_plus(query)
            url = f"{self.base_url}/internships/keywords-{encoded}"

        if location:
            loc_norm = location.lower().strip()
            if "remote" in loc_norm or "work from home" in loc_norm:
                url += "/work-from-home"

        return url

    def discover(
        self,
        query: str,
        location: Optional[str] = None,
        max_results: int = 10,
    ) -> List[ExtractedJobPayload]:
        """Discovers real internship postings from Internshala."""
        search_url = self._build_search_url(query, location)
        self.monitor.record_request(self.name, search_url)

        try:
            resp = requests.get(search_url, headers=self.headers, timeout=12)
        except Exception as e:
            self.logger.warning("Internshala request error for query '%s': %s", query, e)
            return [self.create_restricted_payload(search_url, f"Network timeout/connection error: {e}")]

        if resp.status_code in (403, 429, 503):
            return [self.create_restricted_payload(search_url, f"Internshala blocked access or rate limited (HTTP {resp.status_code}).")]

        html = resp.text
        if "challenge-running" in html.lower() or "cf-turnstile" in html.lower():
            return [self.create_restricted_payload(search_url, "Cloudflare anti-bot challenge detected.")]

        payloads = self._parse_internships(html, max_results)
        if payloads:
            self.monitor.record_success(self.name, search_url)
            self.logger.info("Discovered %d opportunities from Internshala for '%s'", len(payloads), query)
        else:
            self.logger.info("No internships found on Internshala for '%s'", query)

        return payloads

    def fetch_job_details(self, job_url: str) -> Optional[ExtractedJobPayload]:
        """Fetches full job description from an Internshala internship detail page."""
        self.monitor.record_request(self.name, job_url)
        try:
            resp = requests.get(job_url, headers=self.headers, timeout=12)
        except Exception as e:
            self.logger.warning("Failed to fetch Internshala detail %s: %s", job_url, e)
            return self.create_restricted_payload(job_url, f"Connection error: {e}")

        if resp.status_code in (403, 429, 503):
            return self.create_restricted_payload(job_url, f"HTTP {resp.status_code} restriction on detail page.")

        html = resp.text
        # Extract title and company
        title_m = re.search(r'<span class="profile_on_detail_page"[^>]*>([^<]+)</span>', html)
        if not title_m:
            title_m = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
        company_m = re.search(r'<div class="company_name"[^>]*>.*?<a[^>]*>([^<]+)</a>', html, re.DOTALL)
        if not company_m:
            company_m = re.search(r'<p class="company-name"[^>]*>([^<]+)</p>', html)

        # Extract detailed about text
        desc_m = re.search(r'<div class="internship_details">(.*?)<div class="buttons_container', html, re.DOTALL)
        if desc_m:
            clean_desc = re.sub(r'<[^>]+>', ' ', desc_m.group(1))
            clean_desc = re.sub(r'\s+', ' ', clean_desc).strip()
        else:
            clean_desc = "Internshala Internship Details."

        title = title_m.group(1).strip() if title_m else "AI/ML Intern"
        company = company_m.group(1).strip() if company_m else "Internshala Partner"

        payload = ExtractedJobPayload(
            page_url=job_url,
            job_title=title,
            company_name=company,
            job_description=clean_desc,
            platform=self.name,
        )
        val = self.validator.validate(payload)
        return val.sanitized_payload if val.is_valid else payload

    def _parse_internships(self, html: str, max_results: int) -> List[ExtractedJobPayload]:
        """Parses individual job postings from Internshala search HTML."""
        payloads: List[ExtractedJobPayload] = []

        # Find all detail links and their enclosing context
        links = re.findall(
            r'href="(/internship/detail/[^"]+)"[^>]*>([^<]+)</a>',
            html
        )
        seen_urls = set()

        # Split html into cards by individual_internship id or class
        card_chunks = re.split(r'id=[\'"]individual_internship_\d+[\'"]', html)
        if len(card_chunks) <= 1:
            card_chunks = re.split(r'class=[\'"]individual_internship\b(?!\w)', html)

        for chunk in card_chunks[1:]:
            if len(payloads) >= max_results:
                break

            # Extract job url from data-href or href
            url_match = re.search(r'data-href=[\'"](/internship/detail/[^\'"]+)[\'"]', chunk)
            if not url_match:
                url_match = re.search(r'href="(/internship/detail/[^"]+)"', chunk)
            if not url_match:
                continue

            rel_url = url_match.group(1).strip()
            full_url = f"{self.base_url}{rel_url}" if rel_url.startswith("/") else rel_url
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)

            # Title
            title_match = re.search(r'<a[^>]*class="[^"]*job-title-href[^"]*"[^>]*>([^<]+)</a>', chunk)
            if not title_match:
                title_match = re.search(r'<a[^>]*class="[^"]*job-internship-name[^"]*"[^>]*>([^<]+)</a>', chunk)
            if not title_match:
                title_match = re.search(r'class="job-internship-name"[^>]*>\s*<a[^>]*>([^<]+)</a>', chunk)
            if not title_match:
                title_match = re.search(r'href="/internship/detail/[^"]+"[^>]*>([^<]+)</a>', chunk)

            raw_title = title_match.group(1).strip() if title_match else "Intern"
            if "intern" not in raw_title.lower():
                title = f"{raw_title} Intern"
            else:
                title = raw_title

            # Company
            comp_match = re.search(r'class="company-name"[^>]*>\s*([^<]+)\s*</p>', chunk)
            if not comp_match:
                comp_match = re.search(r'class="link_display_like_text"[^>]*>\s*([^<]+)\s*</a>', chunk)
            company = comp_match.group(1).strip() if comp_match else "Internshala Partner"

            # Location
            loc_match = re.search(r'class="[^\"]*locations[^\"]*"[^>]*>.*?<span>\s*(?:<a[^>]*>)?([^<]+)(?:</a>)?\s*</span>', chunk, re.DOTALL)
            if not loc_match:
                loc_match = re.search(r'class="[^\"]*locations[^\"]*"[^>]*>.*?<a[^>]*>([^<]+)</a>', chunk, re.DOTALL)
            location = loc_match.group(1).strip() if loc_match else "India"

            # Stipend
            stipend_match = re.search(r'class=[\'"]stipend[\'"][^>]*>\s*([^<]+)\s*</span>', chunk)
            stipend = stipend_match.group(1).strip() if stipend_match else None

            # Duration
            dur_match = re.search(r'<i class="ic-16-calendar"></i>\s*<span>\s*([^<]+)\s*</span>', chunk)
            duration = dur_match.group(1).strip() if dur_match else None

            # Teaser description
            desc_match = re.search(r'class="about_job".*?class="text">\s*([^<]+)\s*</div>', chunk, re.DOTALL)
            desc_text = desc_match.group(1).strip() if desc_match else f"{title} internship at {company} in {location}."
            if stipend:
                desc_text += f" Stipend: {stipend}."
            if duration:
                desc_text += f" Duration: {duration}."

            work_arrangement = "Remote" if "home" in location.lower() or "remote" in location.lower() else "On-site"

            payload = ExtractedJobPayload(
                page_url=full_url,
                job_title=title,
                company_name=company,
                location=location,
                stipend=stipend,
                internship_duration=duration,
                work_arrangement=work_arrangement,
                platform=self.name,
                job_description=desc_text,
            )

            val = self.validator.validate(payload)
            if val.is_valid and val.sanitized_payload:
                payloads.append(val.sanitized_payload)

        return payloads

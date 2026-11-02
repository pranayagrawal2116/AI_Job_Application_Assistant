"""Direct Company Careers and ATS Discovery Adapter (Greenhouse & Lever Feeds)."""

import html
import re
from typing import Any, Dict, List, Optional
import requests

from src.scraper.adapters.base_adapter import BaseAdapter
from src.scraper.extraction.data_validator import DataValidator
from src.scraper.extraction.extraction_schema import ExtractedJobPayload
from src.scraper.monitoring.access_monitor import AccessMonitor


class CompanyCareersAdapter(BaseAdapter):
    """Discovers authentic early career and AI/ML opportunities directly from company ATS feeds."""

    # Curated technology companies with direct ATS feeds offering engineering & AI internships
    KNOWN_GREENHOUSE_BOARDS = {
        "databricks": "Databricks",
        "anthropic": "Anthropic",
        "rubrik": "Rubrik",
        "cloudflare": "Cloudflare",
        "groww": "Groww India",
        "pinterest": "Pinterest",
        "elastic": "Elastic",
        "canonical": "Canonical",
        "gitlab": "GitLab",
    }

    KNOWN_LEVER_BOARDS = {
        "atlan": "Atlan",
        "postman": "Postman",
        "browserstack": "BrowserStack",
    }

    def __init__(
        self,
        rate_limit_delay: float = 1.0,
        access_monitor: Optional[AccessMonitor] = None,
        data_validator: Optional[DataValidator] = None,
    ):
        super().__init__(
            name="Company Careers",
            source_id="company_careers",
            base_url="https://boards-api.greenhouse.io",
            rate_limit_delay=rate_limit_delay,
            respect_robots=True,
            access_monitor=access_monitor,
            data_validator=data_validator,
        )
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "application/json",
        }
        self._board_cache: Dict[str, List[Dict[str, Any]]] = {}

    def discover(
        self,
        query: str,
        location: Optional[str] = None,
        max_results: int = 10,
    ) -> List[ExtractedJobPayload]:
        """Discovers verified internships across configured corporate ATS boards."""
        payloads: List[ExtractedJobPayload] = []
        target_tokens = set(re.findall(r"\w+", query.lower()))

        # Search Greenhouse boards
        for board_slug, company_name in self.KNOWN_GREENHOUSE_BOARDS.items():
            if len(payloads) >= max_results:
                break
            api_url = f"https://boards-api.greenhouse.io/v1/boards/{board_slug}/jobs"
            jobs_data = self._board_cache.get(api_url)

            if jobs_data is None:
                self.monitor.record_request(self.name, api_url)
                try:
                    resp = requests.get(api_url, headers=self.headers, timeout=3)
                    if resp.status_code == 200:
                        jobs_data = resp.json().get("jobs", [])
                        self._board_cache[api_url] = jobs_data
                        self.monitor.record_success(self.name, api_url)
                    elif resp.status_code in (403, 429):
                        self.monitor.record_restriction(self.name, api_url, "RATE_LIMIT", f"Status {resp.status_code}")
                        self._board_cache[api_url] = []
                    else:
                        self._board_cache[api_url] = []
                except Exception as e:
                    self.logger.debug("Failed checking Greenhouse board %s: %s", board_slug, e)
                    self._board_cache[api_url] = []
                    continue

            if jobs_data:
                extracted = self._process_greenhouse_jobs(
                    jobs_data, company_name, board_slug, target_tokens, location, max_results - len(payloads)
                )
                payloads.extend(extracted)

        # Search Lever boards if more results needed
        if len(payloads) < max_results:
            for board_slug, company_name in self.KNOWN_LEVER_BOARDS.items():
                if len(payloads) >= max_results:
                    break
                api_url = f"https://api.lever.co/v0/postings/{board_slug}?mode=json"
                lever_jobs = self._board_cache.get(api_url)

                if lever_jobs is None:
                    self.monitor.record_request(self.name, api_url)
                    try:
                        resp = requests.get(api_url, headers=self.headers, timeout=3)
                        if resp.status_code == 200:
                            lever_jobs = resp.json()
                            self._board_cache[api_url] = lever_jobs
                            self.monitor.record_success(self.name, api_url)
                        else:
                            self._board_cache[api_url] = []
                    except Exception as e:
                        self.logger.debug("Failed checking Lever board %s: %s", board_slug, e)
                        self._board_cache[api_url] = []
                        continue

                if lever_jobs:
                    extracted = self._process_lever_jobs(
                        lever_jobs, company_name, target_tokens, location, max_results - len(payloads)
                    )
                    payloads.extend(extracted)

        self.logger.info("CompanyCareersAdapter discovered %d opportunities for query '%s'", len(payloads), query)
        return payloads

    def fetch_job_details(self, job_url: str) -> Optional[ExtractedJobPayload]:
        """Fetches full job posting details from Greenhouse API or public web URL."""
        # Check if URL contains greenhouse job id
        gh_match = re.search(r"gh_jid=(\d+)", job_url)
        if gh_match:
            job_id = gh_match.group(1)
            # Find board slug from url
            for board in self.KNOWN_GREENHOUSE_BOARDS:
                api_url = f"https://boards-api.greenhouse.io/v1/boards/{board}/jobs/{job_id}"
                try:
                    r = requests.get(api_url, headers=self.headers, timeout=5)
                    if r.status_code == 200:
                        data = r.json()
                        raw_content = html.unescape(data.get("content", ""))
                        clean_content = re.sub(r"<[^>]+>", " ", raw_content).strip()
                        return ExtractedJobPayload(
                            page_url=data.get("absolute_url", job_url),
                            job_title=data.get("title", "Intern"),
                            company_name=self.KNOWN_GREENHOUSE_BOARDS.get(board, "Company"),
                            location=data.get("location", {}).get("name", "Remote"),
                            job_description=clean_content,
                            platform=self.name,
                        )
                except Exception:
                    continue

        return None

    def _process_greenhouse_jobs(
        self,
        jobs: List[Dict[str, Any]],
        company_name: str,
        board_slug: str,
        target_tokens: set,
        location_filter: Optional[str],
        limit: int,
    ) -> List[ExtractedJobPayload]:
        matched: List[ExtractedJobPayload] = []

        for j in jobs:
            if len(matched) >= limit:
                break
            title = j.get("title", "")
            title_lower = title.lower()

            # Must match early career/internship keywords (exact word match)
            if not re.search(r"\b(intern|internship|apprentice|fellow|student|fresher)\b", title_lower):
                continue

            domain_tokens = {
                t for t in target_tokens
                if t not in {"intern", "internship", "apprentice", "fellow", "student", "fresher"}
            }
            if domain_tokens:
                if not any(re.search(rf"\b{re.escape(tok)}\b", title_lower) for tok in domain_tokens):
                    continue
            else:
                if not re.search(r"\b(ai|ml|data|software|python|developer|engineer|deep learning|machine learning|genai)\b", title_lower):
                    continue

            # Must match at least one relevant tech/role keyword if domain tokens provided
            domain_tokens = {
                t for t in target_tokens
                if t not in {"intern", "internship", "apprentice", "fellow", "student", "fresher"}
            }
            tech_match = False
            if domain_tokens:
                tech_match = any(re.search(rf"\b{re.escape(tok)}\b", title_lower) for tok in domain_tokens)
            else:
                tech_match = bool(re.search(r"\b(ai|ml|data|software|python|developer|engineer|deep learning|machine learning|genai)\b", title_lower))

            if not tech_match:
                continue

            loc_name = j.get("location", {}).get("name", "Global / Remote")
            if location_filter:
                loc_lower = loc_name.lower()
                target_loc = location_filter.lower()
                # Accept if matches location, or if India / Remote
                if target_loc not in loc_lower and "remote" not in loc_lower and "india" not in loc_lower:
                    continue

            url = j.get("absolute_url") or f"https://boards.greenhouse.io/{board_slug}/jobs/{j.get('id')}"
            work_arr = "Remote" if "remote" in loc_name.lower() else "On-site"

            payload = ExtractedJobPayload(
                page_url=url,
                job_title=title,
                company_name=company_name,
                location=loc_name,
                work_arrangement=work_arr,
                platform=f"Company Careers ({company_name})",
                job_description=f"{title} position at {company_name} ({loc_name}). Official posting on company career board.",
                publication_date=j.get("updated_at"),
            )
            val = self.validator.validate(payload)
            if val.is_valid and val.sanitized_payload:
                matched.append(val.sanitized_payload)

        return matched

    def _process_lever_jobs(
        self,
        jobs: List[Dict[str, Any]],
        company_name: str,
        target_tokens: set,
        location_filter: Optional[str],
        limit: int,
    ) -> List[ExtractedJobPayload]:
        matched: List[ExtractedJobPayload] = []
        for j in jobs:
            if len(matched) >= limit:
                break
            title = j.get("text", "")
            title_lower = title.lower()

            if not re.search(r"\b(intern|internship|apprentice|fellow|student|fresher)\b", title_lower):
                continue

            domain_tokens = {
                t for t in target_tokens
                if t not in {"intern", "internship", "apprentice", "fellow", "student", "fresher"}
            }
            if domain_tokens:
                if not any(re.search(rf"\b{re.escape(tok)}\b", title_lower) for tok in domain_tokens):
                    continue
            else:
                if not re.search(r"\b(ai|ml|data|software|python|developer|engineer|deep learning|machine learning|genai)\b", title_lower):
                    continue

            categories = j.get("categories", {})
            loc_name = categories.get("location", "Remote")
            work_type = categories.get("workplaceType", "Remote")
            url = j.get("hostedUrl", "")
            desc_text = j.get("descriptionPlain", f"{title} internship at {company_name}.")

            payload = ExtractedJobPayload(
                page_url=url,
                job_title=title,
                company_name=company_name,
                location=loc_name,
                work_arrangement="Remote" if "remote" in work_type.lower() else "On-site",
                platform=f"Company Careers ({company_name})",
                job_description=desc_text[:1000],
            )
            val = self.validator.validate(payload)
            if val.is_valid and val.sanitized_payload:
                matched.append(val.sanitized_payload)

        return matched

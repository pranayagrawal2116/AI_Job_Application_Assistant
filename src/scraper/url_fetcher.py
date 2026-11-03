"""Universal Safe Job URL Fetcher with SSRF Defense and Anti-Bot Detection.

Safely fetches remote job posting web pages, enforcing SSRF boundaries,
redirect validation, size caps, timeouts, and automated anti-bot restriction detection.
"""

from dataclasses import dataclass
import json
import re
from typing import Dict, List, Optional
import urllib.parse

from bs4 import BeautifulSoup
import requests

from src.database.exceptions import (
    FileTooLargeError,
    InvalidFileFormatError,
    UnsafeURLError,
    URLFetchRestrictedError,
)
from src.security.url_validator import URLSafetyValidator
from src.utils.logger import setup_logger

logger = setup_logger("URLJobFetcher")

# Fetch limits
MAX_JOB_URL_REDIRECTS = 3
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 10.0

ALLOWED_CONTENT_TYPES = (
    "text/html",
    "text/plain",
    "application/xhtml+xml",
    "application/json",
)

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Common anti-bot, login-wall, or challenge signatures
RESTRICTION_SIGNATURES = [
    (re.compile(r"cf-turnstile|cf-browser-verification|challenge-running|Just a moment\.\.\.", re.IGNORECASE), "Cloudflare Challenge"),
    (re.compile(r"pardon our interruption|perimeterx|px-captcha", re.IGNORECASE), "PerimeterX Bot Defense"),
    (re.compile(r"akamai|access denied.*requested url could not be retrieved", re.IGNORECASE), "Akamai Bot Block"),
    (re.compile(r"g-recaptcha|recaptcha|hcaptcha|captcha-delivery", re.IGNORECASE), "CAPTCHA Challenge"),
    (re.compile(r"linkedin\.com/authwall|authwall|join linkedin", re.IGNORECASE), "LinkedIn Authwall"),
    (re.compile(r"sign in to view|please sign in to continue|login to apply|log in to continue", re.IGNORECASE), "Login Wall"),
]


@dataclass
class FetchedJobContent:
    """Represents safely fetched job web page content and metadata."""
    url: str
    raw_text: str
    title: Optional[str] = None
    company_name: Optional[str] = None
    location: Optional[str] = None
    content_type: str = "text/html"
    status_code: int = 200
    is_restricted: bool = False
    restriction_reason: Optional[str] = None
    json_ld_data: Optional[Dict[str, object]] = None


class URLJobFetcher:
    """Universal safe HTTP fetcher for job listings with strict SSRF defense."""

    def __init__(
        self,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        max_redirects: int = MAX_JOB_URL_REDIRECTS,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes

    def fetch_job_url(self, target_url: str) -> FetchedJobContent:
        """Safely fetches a job listing URL with complete SSRF and redirect validation.

        Args:
            target_url: Public URL of the job listing.

        Returns:
            FetchedJobContent with extracted text and metadata.

        Raises:
            UnsafeURLError: If destination is private, loopback, or non-routable.
            URLFetchRestrictedError: If blocked by bot protection, CAPTCHA, or login wall.
            FileTooLargeError: If response body exceeds 5 MB.
            InvalidFileFormatError: If response is a binary/unsupported media type.
        """
        # 1. Validate initial target URL
        current_url = URLSafetyValidator.validate_url(target_url)

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        redirect_count = 0
        final_response: Optional[requests.Response] = None

        with requests.Session() as session:
            # We manage redirects manually to validate every hop against SSRF
            while redirect_count <= self.max_redirects:
                try:
                    resp = session.get(
                        current_url,
                        headers=headers,
                        timeout=(self.connect_timeout, self.read_timeout),
                        allow_redirects=False,
                        stream=True,
                    )
                except requests.RequestException as exc:
                    logger.warning(f"Network error fetching '{current_url}': {exc}")
                    raise URLFetchRestrictedError(
                        f"Unable to reach job URL ({exc}). Please verify the link or paste the text directly.",
                        official_url=target_url,
                        restriction_type="NetworkError",
                    )

                # Check for redirect status codes
                if resp.status_code in (301, 302, 303, 307, 308):
                    redirect_count += 1
                    if redirect_count > self.max_redirects:
                        raise UnsafeURLError(f"Too many redirects (exceeded limit of {self.max_redirects}).")

                    location = resp.headers.get("Location")
                    if not location:
                        raise UnsafeURLError("Redirect response missing Location header.")

                    # Resolve relative redirect URLs against current URL
                    resolved_url = urllib.parse.urljoin(current_url, location)
                    logger.info(f"Validating redirect #{redirect_count} from '{current_url}' to '{resolved_url}'")
                    current_url = URLSafetyValidator.validate_url(resolved_url)
                    continue

                final_response = resp
                break

        if final_response is None:
            raise UnsafeURLError("Failed to establish safe HTTP connection.")

        # 2. Check HTTP status code for anti-bot / permissions
        status_code = final_response.status_code
        if status_code in (401, 403, 429):
            reason = {
                401: "Authentication Required",
                403: "Access Forbidden / Bot Protection Active",
                429: "Rate Limit Exceeded",
            }.get(status_code, "Access Restricted")

            logger.warning(f"Access restricted (HTTP {status_code}) on '{current_url}': {reason}")
            raise URLFetchRestrictedError(
                f"Automated access was restricted by the host (HTTP {status_code}: {reason}). "
                "Please inspect the job listing in your browser and paste the job description text directly.",
                official_url=current_url,
                restriction_type=f"HTTP_{status_code}",
            )
        elif status_code >= 400:
            raise URLFetchRestrictedError(
                f"Job posting page returned HTTP error {status_code}. "
                "Please verify the URL or paste the job description text manually.",
                official_url=current_url,
                restriction_type=f"HTTP_{status_code}",
            )

        # 3. Validate Content-Type
        content_type_header = final_response.headers.get("Content-Type", "").lower()
        if not any(allowed in content_type_header for allowed in ALLOWED_CONTENT_TYPES):
            logger.warning(f"Unsupported content type '{content_type_header}' from '{current_url}'")
            raise InvalidFileFormatError(
                f"URL returned unsupported content type '{content_type_header}'. "
                "Expected HTML, plain text, or JSON."
            )

        # 4. Stream response body enforcing max size limit
        chunks: List[bytes] = []
        downloaded_bytes = 0

        for chunk in final_response.iter_content(chunk_size=8192):
            if chunk:
                chunks.append(chunk)
                downloaded_bytes += len(chunk)
                if downloaded_bytes > self.max_bytes:
                    raise FileTooLargeError(
                        f"Job page content exceeds maximum allowed download limit of {self.max_bytes // (1024 * 1024)} MB."
                    )

        raw_bytes = b"".join(chunks)

        # Determine encoding
        encoding = final_response.encoding or "utf-8"
        try:
            body_text = raw_bytes.decode(encoding, errors="replace")
        except Exception:
            body_text = raw_bytes.decode("utf-8", errors="replace")

        # 5. Check response content for anti-bot signatures and login walls
        for pattern, label in RESTRICTION_SIGNATURES:
            if pattern.search(body_text):
                logger.warning(f"Anti-bot restriction detected on '{current_url}': {label}")
                raise URLFetchRestrictedError(
                    f"Job page triggered automated protection ({label}). "
                    "Please open the URL in your browser and paste the job description text directly.",
                    official_url=current_url,
                    restriction_type=label,
                )

        # 6. Parse structured metadata and extract visible job text
        return self._extract_job_content(current_url, body_text, content_type_header, status_code)

    def _extract_job_content(
        self,
        url: str,
        body_text: str,
        content_type: str,
        status_code: int,
    ) -> FetchedJobContent:
        """Extracts clean text, title, company, location, and JSON-LD from HTML body."""
        if "application/json" in content_type:
            try:
                data = json.loads(body_text)
                title = data.get("title") or data.get("job_title")
                company = data.get("company") or data.get("company_name")
                loc = data.get("location")
                raw = json.dumps(data, indent=2)
                return FetchedJobContent(
                    url=url,
                    raw_text=raw,
                    title=str(title) if title else None,
                    company_name=str(company) if company else None,
                    location=str(loc) if loc else None,
                    content_type="application/json",
                    status_code=status_code,
                    json_ld_data=data if isinstance(data, dict) else None,
                )
            except Exception:
                pass

        soup = BeautifulSoup(body_text, "html.parser")

        # Extract JSON-LD JobPosting if present
        json_ld_job: Optional[Dict[str, object]] = None
        for script_tag in soup.find_all("script", type="application/ld+json"):
            try:
                script_content = script_tag.string or script_tag.get_text()
                if not script_content:
                    continue
                parsed_json = json.loads(script_content)
                if isinstance(parsed_json, dict) and "JobPosting" in str(parsed_json.get("@type", "")):
                    json_ld_job = parsed_json
                    break
                elif isinstance(parsed_json, list):
                    for item in parsed_json:
                        if isinstance(item, dict) and "JobPosting" in str(item.get("@type", "")):
                            json_ld_job = item
                            break
            except Exception:
                continue

        # Extract title
        extracted_title: Optional[str] = None
        if json_ld_job and json_ld_job.get("title"):
            extracted_title = str(json_ld_job["title"]).strip()
        elif soup.find("meta", property="og:title"):
            extracted_title = str(soup.find("meta", property="og:title").get("content", "")).strip()  # type: ignore[union-attr]
        elif soup.find("title"):
            extracted_title = str(soup.find("title").get_text()).strip()  # type: ignore[union-attr]
        elif soup.find("h1"):
            extracted_title = str(soup.find("h1").get_text()).strip()  # type: ignore[union-attr]

        # Extract company
        extracted_company: Optional[str] = None
        if json_ld_job:
            hiring_org = json_ld_job.get("hiringOrganization")
            if isinstance(hiring_org, dict):
                extracted_company = str(hiring_org.get("name", "")).strip() or None
            elif hiring_org:
                extracted_company = str(hiring_org).strip() or None
        if not extracted_company and soup.find("meta", property="og:site_name"):
            extracted_company = str(soup.find("meta", property="og:site_name").get("content", "")).strip() or None  # type: ignore[union-attr]

        # Extract location
        extracted_location: Optional[str] = None
        if json_ld_job:
            job_loc = json_ld_job.get("jobLocation")
            if isinstance(job_loc, dict):
                address = job_loc.get("address")
                if isinstance(address, dict):
                    parts = [address.get("addressLocality"), address.get("addressRegion"), address.get("addressCountry")]
                    extracted_location = ", ".join([str(p) for p in parts if p])
                elif address:
                    extracted_location = str(address)

        # Remove noisy elements
        for tag in soup(["script", "style", "noscript", "nav", "footer", "header", "svg", "button", "input"]):
            tag.decompose()

        # Clean text
        text_lines: List[str] = []
        for line in soup.get_text(separator="\n").splitlines():
            clean = line.strip()
            if clean:
                text_lines.append(clean)

        clean_text = "\n".join(text_lines)

        return FetchedJobContent(
            url=url,
            raw_text=clean_text,
            title=extracted_title,
            company_name=extracted_company,
            location=extracted_location,
            content_type="text/html",
            status_code=status_code,
            json_ld_data=json_ld_job,
        )

"""URL and string normalization utilities for duplicate job detection."""

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import Tuple

# Common marketing, analytics, and session query parameters to strip
TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "gclid",
    "fbclid",
    "trk",
    "ref",
    "refid",
    "trackingid",
    "source",
    "session_id",
    "spm",
    "orig",
    "context",
    "mc_cid",
    "mc_eid",
    "_hsenc",
    "_hsmi",
    "bhs",
}


def normalize_job_url(raw_url: str) -> str:
    """Normalizes a job URL to prevent duplicates caused by tracking parameters,

    casing differences, trailing slashes, or query string order variations.

    Args:
        raw_url: Raw URL string.

    Returns:
        Canonicalized normalized URL string.
    """
    if not raw_url or not isinstance(raw_url, str):
        return ""

    url = raw_url.strip()
    if not url:
        return ""

    # Add default scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parts = urlsplit(url)
    except Exception:
        return raw_url.strip()

    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()

    # Remove standard default ports
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]
    elif netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]

    # Normalize path: remove redundant trailing slash unless root path
    path = parts.path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Normalize query parameters: strip tracking parameters, sort remainder
    query_params = []
    if parts.query:
        for key, value in parse_qsl(parts.query, keep_blank_values=False):
            if key.lower() not in TRACKING_PARAMS:
                query_params.append((key, value))
        query_params.sort(key=lambda x: x[0])

    normalized_query = urlencode(query_params)

    # Omit fragment/anchor tags for job matching canonicalization
    normalized = urlunsplit((scheme, netloc, path, normalized_query, ""))
    return normalized


def normalize_entity_name(text: str) -> str:
    """Normalizes company names or job titles for fuzzy duplicate matching.

    Lowercases, strips leading/trailing spaces, and collapses internal whitespace.
    """
    if not text:
        return ""
    # Collapse multiple whitespaces and trim
    cleaned = re.sub(r"\s+", " ", text.strip().lower())
    return cleaned


def generate_company_title_key(company: str, title: str) -> Tuple[str, str]:
    """Generates a normalized composite key for company and job title."""
    return (normalize_entity_name(company), normalize_entity_name(title))


class URLNormalizer:
    """Class wrapper for URL normalization utilities."""

    @staticmethod
    def normalize(raw_url: str) -> str:
        return normalize_job_url(raw_url)

    @staticmethod
    def composite_key(company: str, title: str) -> Tuple[str, str]:
        return generate_company_title_key(company, title)



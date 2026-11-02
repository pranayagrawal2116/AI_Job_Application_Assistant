"""Job Extractor module parsing unstructured HTML, JSON-LD, and text into ExtractedJobPayload."""

import json
import re
from typing import Any, Dict, List, Optional

from src.scraper.extraction.extraction_schema import ExtractedJobPayload


class JobExtractor:
    """Extracts structured fields from raw web content, HTML snippets, or JSON-LD feeds."""

    @staticmethod
    def extract_from_json_ld(json_ld_data: Dict[str, Any], page_url: str, platform: str = "Direct") -> Optional[ExtractedJobPayload]:
        """Extracts job posting from Schema.org JobPosting structured JSON-LD."""
        if not isinstance(json_ld_data, dict):
            return None

        # Check if type is JobPosting
        item_type = str(json_ld_data.get("@type", ""))
        if "JobPosting" not in item_type:
            return None

        title = json_ld_data.get("title")
        desc = json_ld_data.get("description")

        hiring_org = json_ld_data.get("hiringOrganization")
        company = hiring_org.get("name") if isinstance(hiring_org, dict) else str(hiring_org or "")

        job_loc = json_ld_data.get("jobLocation")
        loc_str = None
        if isinstance(job_loc, dict):
            address = job_loc.get("address")
            if isinstance(address, dict):
                loc_parts = [address.get("addressLocality"), address.get("addressRegion"), address.get("addressCountry")]
                loc_str = ", ".join([str(p) for p in loc_parts if p])
            elif address:
                loc_str = str(address)

        # Work arrangement
        work_arr = None
        job_loc_type = json_ld_data.get("jobLocationType")
        if job_loc_type == "TELECOMMUTE" or "remote" in str(desc or "").lower():
            work_arr = "Remote"

        # Stipend / Base salary
        stipend_str = None
        base_salary = json_ld_data.get("baseSalary")
        if isinstance(base_salary, dict):
            val = base_salary.get("value")
            cur = base_salary.get("currency", "INR")
            if isinstance(val, dict):
                stipend_str = f"{cur} {val.get('minValue', '')} - {val.get('maxValue', '')}"
            elif val:
                stipend_str = f"{cur} {val}"

        date_posted = json_ld_data.get("datePosted")
        valid_through = json_ld_data.get("validThrough")

        return ExtractedJobPayload(
            page_url=page_url,
            company_name=company,
            job_title=title,
            location=loc_str,
            job_description=desc,
            stipend=stipend_str,
            application_deadline=valid_through,
            publication_date=date_posted,
            platform=platform,
            work_arrangement=work_arr,
        )

    @staticmethod
    def extract_from_text(
        text: str,
        page_url: str,
        title: Optional[str] = None,
        company: Optional[str] = None,
        location: Optional[str] = None,
        platform: str = "Direct",
    ) -> ExtractedJobPayload:
        """Extracts fields from plain text / accessibility snapshot description."""
        clean_text = text or ""

        # Extract stipend
        stipend = None
        stipend_match = re.search(r"(?:₹|rs\.?|inr|stipend[:\s]*)\s*([0-9,]+(?:\s*-\s*[0-9,]+)?(?:\s*\/(?:month|mo|pm))?)", clean_text, re.IGNORECASE)
        if stipend_match:
            stipend = stipend_match.group(0).strip()

        # Extract duration
        duration = None
        dur_match = re.search(r"([1-6]\s*(?:months?|weeks?)|summer|winter)", clean_text, re.IGNORECASE)
        if dur_match:
            duration = dur_match.group(0).strip()

        # Extract deadline
        deadline = None
        dl_match = re.search(r"(?:apply by|deadline[:\s]*)\s*([0-9]{1,2}(?:st|nd|rd|th)?\s+[a-z]{3,9}(?:\s+[0-9]{2,4})?|[0-9]{4}-[0-9]{2}-[0-9]{2})", clean_text, re.IGNORECASE)
        if dl_match:
            deadline = dl_match.group(1).strip()

        # Extract common skills mentioned
        skills = []
        tech_keywords = [
            "Python", "Machine Learning", "Deep Learning", "Data Science", "NLP",
            "Computer Vision", "Generative AI", "Pandas", "NumPy", "Scikit-Learn",
            "PyTorch", "TensorFlow", "SQL", "Flutter", "Dart", "Docker", "Git"
        ]
        for kw in tech_keywords:
            if re.search(r"\b" + re.escape(kw) + r"\b", clean_text, re.IGNORECASE):
                skills.append(kw)

        return ExtractedJobPayload(
            page_url=page_url,
            company_name=company,
            job_title=title,
            location=location,
            job_description=clean_text,
            required_skills=skills,
            stipend=stipend,
            internship_duration=duration,
            application_deadline=deadline,
            platform=platform,
        )


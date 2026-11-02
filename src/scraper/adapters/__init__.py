"""Modular Job Discovery Adapters."""

from src.scraper.adapters.base_adapter import BaseAdapter
from src.scraper.adapters.company_careers_adapter import CompanyCareersAdapter
from src.scraper.adapters.indeed_adapter import IndeedAdapter
from src.scraper.adapters.internshala_adapter import InternshalaAdapter
from src.scraper.adapters.linkedin_adapter import LinkedInAdapter
from src.scraper.adapters.naukri_adapter import NaukriAdapter

__all__ = [
    "BaseAdapter",
    "LinkedInAdapter",
    "InternshalaAdapter",
    "IndeedAdapter",
    "NaukriAdapter",
    "CompanyCareersAdapter",
]


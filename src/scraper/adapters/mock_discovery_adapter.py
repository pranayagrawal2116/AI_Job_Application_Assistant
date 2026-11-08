"""Mock discovery adapter for hermetic, deterministic testing without external network calls."""

from typing import Any, List, Optional
from src.scraper.adapters.base_adapter import BaseAdapter
from src.scraper.extraction.extraction_schema import ExtractedJobPayload


class MockDiscoveryAdapter(BaseAdapter):
    """Deterministic, offline discovery adapter providing realistic job payloads for automated tests."""

    def __init__(
        self,
        source_id: str = "mock_source",
        name: str = "Mock Discovery Engine",
        access_monitor: Optional[Any] = None,
    ):
        super().__init__(
            name=name,
            source_id=source_id,
            base_url="https://mock.jobflow.internal",
            rate_limit_delay=0.01,
            respect_robots=True,
            access_monitor=access_monitor,
        )

    def discover(
        self,
        query: str,
        location: Optional[str] = None,
        max_results: int = 5,
    ) -> List[ExtractedJobPayload]:
        """Returns deterministic, domain-appropriate job payloads based on query keywords."""
        q_lower = (query or "").lower()
        loc = location or "Remote"
        results: List[ExtractedJobPayload] = []

        if any(k in q_lower for k in ["tax", "account", "audit", "finance", "acca", "vat"]):
            # Accounting / Finance Domain
            templates = [
                {
                    "title": "UK Tax Associate",
                    "company": "BDO Advisory",
                    "skills": ["UK Taxation", "SA100", "Tax Computations", "Digita", "Excel"],
                    "desc": "Join our tax compliance team assisting with personal tax computations, SA100 returns, and Making Tax Digital compliance.",
                    "slug": "tax-assoc",
                },
                {
                    "title": "Audit & Assurance Assistant",
                    "company": "Grant Thornton",
                    "skills": ["Internal Audit", "Reconciliation", "Financial Reporting", "Xero"],
                    "desc": "Assist with statutory and internal audits, client balance sheet reconciliations, and internal control reviews.",
                    "slug": "audit-assist",
                },
                {
                    "title": "Junior Financial Accountant",
                    "company": "Mazars Group",
                    "skills": ["Accounts Payable", "General Ledger", "Tally", "Reconciliation", "Working Capital"],
                    "desc": "Support day-to-day ledger reconciliation, invoice processing via ApprovalMax, and monthly financial statement preparation.",
                    "slug": "jr-accountant",
                },
            ]
        elif any(k in q_lower for k in ["flutter", "dart", "mobile", "android", "ios"]):
            # Mobile App / Flutter Domain
            templates = [
                {
                    "title": "Flutter Developer Intern",
                    "company": "Sarita Technologies",
                    "skills": ["Flutter", "Dart", "REST API", "State Management", "Mobile Development"],
                    "desc": "Develop responsive, cross-platform Android and iOS applications with Flutter and Dart, integrating with backend REST APIs.",
                    "slug": "flutter-intern",
                },
                {
                    "title": "Mobile Software Engineer",
                    "company": "Apex Labs",
                    "skills": ["Flutter", "Android", "Dart", "Git", "UI/UX"],
                    "desc": "Design client architecture and interactive components for healthcare and enterprise mobile applications.",
                    "slug": "mobile-eng",
                },
            ]
        elif any(k in q_lower for k in ["python", "ai", "machine learning", "data", "deep learning"]):
            # Python / AI / Data Science Domain
            templates = [
                {
                    "title": "Python Software Engineer",
                    "company": "CloudWorks Tech",
                    "skills": ["Python", "FastAPI", "PostgreSQL", "Docker", "PyTest"],
                    "desc": "Build scalable backend APIs and data processing microservices using Python, FastAPI, and relational databases.",
                    "slug": "py-eng",
                },
                {
                    "title": "Machine Learning Intern",
                    "company": "Pledge India Foundation",
                    "skills": ["Python", "Machine Learning", "Data Analysis", "Scikit-Learn", "Pandas"],
                    "desc": "Implement predictive machine learning models and NLP data preprocessing pipelines for social impact platforms.",
                    "slug": "ml-intern",
                },
            ]
        else:
            # General Entry-Level Role
            templates = [
                {
                    "title": f"Junior {query.title() if query else 'Associate'}",
                    "company": "Pinnacle Global",
                    "skills": ["Communication", "Problem Solving", "Documentation", "Teamwork"],
                    "desc": f"Entry-level position supporting {query} workflows and cross-functional deliverables.",
                    "slug": "jr-assoc",
                }
            ]

        for i, t in enumerate(templates[:max_results]):
            url = f"https://mock.jobflow.internal/{self.source_id}/{t['slug']}-{i + 1}"
            payload = ExtractedJobPayload(
                page_url=url,
                page_title=f"{t['title']} at {t['company']}",
                company_name=t["company"],
                job_title=t["title"],
                location=loc,
                job_description=t["desc"],
                required_skills=t["skills"],
                stipend="Competitive / Standard",
                platform=self.name,
                work_arrangement="Remote" if "remote" in loc.lower() else "Hybrid",
                listing_status="ACTIVE",
                extraction_confidence=1.0,
            )
            results.append(payload)

        self.monitor.record_success(self.name)
        return results

    def fetch_job_details(self, job_url: str) -> Optional[ExtractedJobPayload]:
        """Simulates immediate retrieval of job details for a mock URL."""
        return ExtractedJobPayload(
            page_url=job_url,
            job_title="Verified Mock Role",
            company_name="Mock Employer",
            location="Remote",
            job_description="Comprehensive job details retrieved deterministically.",
            platform=self.name,
            listing_status="ACTIVE",
            extraction_confidence=1.0,
        )

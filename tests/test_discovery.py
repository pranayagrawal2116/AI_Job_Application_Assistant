"""Unit tests for Phase 5 Discovery Engine: Adapters, Coordinators, Registries, and Persistence."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.database.db_manager import DatabaseManager
from src.matcher.job_matcher import JobMatcher
from src.scraper.adapters.base_adapter import BaseAdapter
from src.scraper.adapters.company_careers_adapter import CompanyCareersAdapter
from src.scraper.adapters.indeed_adapter import IndeedAdapter
from src.scraper.adapters.internshala_adapter import InternshalaAdapter
from src.scraper.adapters.linkedin_adapter import LinkedInAdapter
from src.scraper.adapters.naukri_adapter import NaukriAdapter
from src.scraper.discovery.pagination_manager import PaginationManager
from src.scraper.discovery.query_generator import QueryGenerator
from src.scraper.discovery.search_coordinator import DiscoverySummary, SearchCoordinator
from src.scraper.discovery.source_registry import SourceRegistry
from src.scraper.extraction.data_validator import DataValidator
from src.scraper.extraction.extraction_schema import ExtractedJobPayload
from src.scraper.monitoring.access_monitor import AccessMonitor


class TestDiscoveryEngine(unittest.TestCase):
    """Comprehensive test suite for Phase 5 discovery architecture."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_discovery.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.monitor = AccessMonitor()
        self.validator = DataValidator()

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Query Generator Tests
    def test_query_generator_defaults(self):
        gen = QueryGenerator()
        matrix = gen.generate_query_matrix(max_combinations=5)
        self.assertEqual(len(matrix), 5)
        # Verify Remote or Pune are prioritized first for locations
        first_role, first_loc = matrix[0]
        self.assertIn(first_loc.lower(), ["remote", "work from home", "pune"])

    def test_query_generator_keywords(self):
        gen = QueryGenerator()
        ai_kw = gen.generate_keywords_for_role("Artificial Intelligence Intern")
        self.assertTrue(any("Deep Learning" in k or "LLM" in k for k in ai_kw))
        ml_kw = gen.generate_keywords_for_role("Machine Learning Intern")
        self.assertTrue(any("Scikit-Learn" in k or "Supervised" in k for k in ml_kw))

    # 2. Pagination Manager Tests
    def test_pagination_bounds(self):
        p = PaginationManager(max_pages_per_query=3, polite_delay_seconds=0.0)
        self.assertTrue(p.should_continue(current_page=1, results_in_current_page=10))
        self.assertTrue(p.should_continue(current_page=2, results_in_current_page=5))
        self.assertFalse(p.should_continue(current_page=3, results_in_current_page=5))
        self.assertFalse(p.should_continue(current_page=1, results_in_current_page=0))
        self.assertEqual(p.calculate_offset(page_index=2, page_size=10), 10)

    # 3. Source Registry Tests
    def test_source_registry_lifecycle(self):
        reg = SourceRegistry(access_monitor=self.monitor)
        adapter = InternshalaAdapter(access_monitor=self.monitor)
        reg.register(adapter, enabled=True)

        self.assertTrue(reg.is_enabled("internshala"))
        self.assertIn(adapter, reg.get_active_adapters())

        reg.disable("internshala")
        self.assertFalse(reg.is_enabled("internshala"))
        self.assertEqual(len(reg.get_active_adapters()), 0)

        reg.enable("internshala")
        self.assertTrue(reg.is_enabled("internshala"))

    def test_default_registry_initialization(self):
        reg = SourceRegistry.create_default(access_monitor=self.monitor)
        active = reg.get_active_adapters()
        self.assertGreaterEqual(len(active), 5)
        names = [a.name for a in active]
        self.assertIn("Internshala", names)
        self.assertIn("Company Careers", names)
        self.assertIn("LinkedIn", names)
        self.assertIn("Indeed", names)
        self.assertIn("Naukri", names)

    # 4. Internshala Adapter HTML Parsing & URL Construction
    def test_internshala_url_construction(self):
        adapter = InternshalaAdapter(access_monitor=self.monitor)
        url_ai = adapter._build_search_url("Artificial Intelligence Intern", "Remote")
        self.assertIn("artificial-intelligence-ai-internship/work-from-home", url_ai)

        url_ml = adapter._build_search_url("Machine Learning Intern", "Pune")
        self.assertIn("machine-learning-internship", url_ml)

    def test_internshala_card_parsing(self):
        adapter = InternshalaAdapter(access_monitor=self.monitor)
        sample_html = """
        <html>
        <div class="individual_internship" id="individual_internship_1">
            <p class="company-name">Visionary AI Corp</p>
            <a class="job-internship-name" href="/internship/detail/ai-intern-123">Computer Vision Intern</a>
            <div class="individual_internship_details">
                <div class="row-1-item locations"><span><a>Pune</a></span></div>
                <div class="row-1-item"><span class='stipend'>₹ 25,000 /month</span></div>
                <div class="row-1-item"><i class="ic-16-calendar"></i><span>3 Months</span></div>
                <div class="about_job"><div class="text">Work with PyTorch, CNNs, and OpenCV.</div></div>
            </div>
        </div>
        </html>
        """
        payloads = adapter._parse_internships(sample_html, max_results=5)
        self.assertEqual(len(payloads), 1)
        p = payloads[0]
        self.assertEqual(p.job_title, "Computer Vision Intern")
        self.assertEqual(p.company_name, "Visionary AI Corp")
        self.assertEqual(p.location, "Pune")
        self.assertEqual(p.stipend, "₹ 25,000 /month")
        self.assertEqual(p.internship_duration, "3 Months")
        self.assertEqual(p.work_arrangement, "On-site")
        self.assertEqual(p.page_url, "https://internshala.com/internship/detail/ai-intern-123")

    # 5. Indeed Adapter Anti-Bot & Restriction Handling
    @patch("requests.get")
    def test_indeed_restriction_handling(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Cloudflare Turnstile Access Denied"
        mock_get.return_value = mock_resp

        adapter = IndeedAdapter(access_monitor=self.monitor)
        payloads = adapter.discover("Machine Learning Intern", "India")

        self.assertEqual(len(payloads), 1)
        p = payloads[0]
        self.assertTrue(p.is_restricted)
        self.assertEqual(p.listing_status, "RESTRICTED")
        self.assertIn("anti-bot protection active", p.restriction_reason.lower())
        self.assertIn("in.indeed.com", p.page_url)

    # 6. Naukri Adapter Slug & Restriction Handling
    def test_naukri_slug_formatting(self):
        adapter = NaukriAdapter(access_monitor=self.monitor)
        slug = adapter._format_slug("Data Science Intern")
        self.assertEqual(slug, "data-science-intern")

    @patch("requests.get")
    def test_naukri_restriction_handling(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Access Denied by Akamai"
        mock_get.return_value = mock_resp

        adapter = NaukriAdapter(access_monitor=self.monitor)
        payloads = adapter.discover("Data Science Intern", "India")
        self.assertEqual(len(payloads), 1)
        self.assertTrue(payloads[0].is_restricted)

    # 7. Company Careers Adapter (Greenhouse & Lever)
    def test_company_careers_greenhouse_filtering(self):
        adapter = CompanyCareersAdapter(access_monitor=self.monitor)
        mock_jobs = [
            {
                "id": 101,
                "title": "Machine Learning Intern (Summer 2027)",
                "absolute_url": "https://company.com/jobs/101",
                "location": {"name": "Bengaluru, India"},
                "updated_at": "2026-10-01",
            },
            {
                "id": 102,
                "title": "Senior Internal Auditor",  # Should NOT match because 'intern' is not a whole word
                "absolute_url": "https://company.com/jobs/102",
                "location": {"name": "Remote"},
                "updated_at": "2026-10-01",
            },
            {
                "id": 103,
                "title": "Sales Operations Intern",  # Does NOT match AI/ML/data tech terms
                "absolute_url": "https://company.com/jobs/103",
                "location": {"name": "Pune"},
                "updated_at": "2026-10-01",
            },
        ]
        extracted = adapter._process_greenhouse_jobs(
            jobs=mock_jobs,
            company_name="MockTech Labs",
            board_slug="mocktech",
            target_tokens={"machine", "learning", "intern"},
            location_filter=None,
            limit=5,
        )
        self.assertEqual(len(extracted), 1)
        p = extracted[0]
        self.assertEqual(p.job_title, "Machine Learning Intern (Summer 2027)")
        self.assertEqual(p.company_name, "MockTech Labs")
        self.assertEqual(p.location, "Bengaluru, India")

    # 8. Search Coordinator End-to-End Orchestration & Deduplication
    def test_coordinator_orchestration_and_scoring(self):
        mock_adapter = MagicMock(spec=BaseAdapter)
        mock_adapter.name = "MockAdapter"
        mock_adapter.source_id = "mock_adapter"
        mock_adapter.is_healthy.return_value = True

        p1 = ExtractedJobPayload(
            page_url="https://mock.com/job1?ref=test",
            job_title="AI Research Intern",
            company_name="Alpha Brain AI",
            location="Pune, India",
            job_description="Python, Machine Learning, Deep Learning, PyTorch, model training.",
            platform="MockAdapter",
            stipend="₹35,000 / month",
        )
        p2 = ExtractedJobPayload(
            page_url="https://mock.com/job2",
            job_title="Machine Learning Intern",
            company_name="Beta Neural Corp",
            location="Remote",
            job_description="Develop NLP pipelines with Python, scikit-learn, and Hugging Face.",
            platform="MockAdapter",
            stipend="₹40,000 / month",
        )
        p_restricted = ExtractedJobPayload(
            page_url="https://mock.com/restricted",
            platform="MockAdapter",
            is_restricted=True,
            restriction_reason="Blocked by Cloudflare challenge",
            listing_status="RESTRICTED",
        )
        mock_adapter.discover.return_value = [p1, p2, p_restricted]

        reg = SourceRegistry(access_monitor=self.monitor)
        reg.register(mock_adapter, enabled=True)

        matcher = JobMatcher(db_manager=self.db)
        coord = SearchCoordinator(
            registry=reg,
            db_manager=self.db,
            job_matcher=matcher,
            access_monitor=self.monitor,
            data_validator=self.validator,
        )

        # Run discovery
        summary = coord.run_discovery(
            roles=["AI Research Intern"],
            locations=["Pune"],
            max_queries=1,
            enable_evaluation=True,
        )

        self.assertEqual(summary.total_discovered, 3)
        self.assertEqual(summary.new_jobs_saved, 2)
        self.assertEqual(summary.restricted_incidents, 1)
        self.assertEqual(len(summary.restricted_notices), 1)

        # Verify database records
        all_jobs = self.db.get_all_jobs()
        self.assertEqual(len(all_jobs), 2)
        for j in all_jobs:
            self.assertIsNotNone(j.match_score)
            self.assertGreater(j.match_score, 50.0)  # Strong AI match
            self.assertTrue(j.is_eligible)
            self.assertIn(j.match_classification, ["Excellent", "Good"])

        # Test Deduplication: Run again with same payload
        summary2 = coord.run_discovery(
            roles=["AI Research Intern"],
            locations=["Pune"],
            max_queries=1,
            enable_evaluation=True,
        )
        self.assertEqual(summary2.new_jobs_saved, 0)
        self.assertEqual(summary2.duplicates_skipped, 2)
        # Total jobs in db remains 2
        self.assertEqual(len(self.db.get_all_jobs()), 2)


if __name__ == "__main__":
    unittest.main()

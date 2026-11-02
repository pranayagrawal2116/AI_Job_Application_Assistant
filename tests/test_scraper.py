"""Unit and integration tests for Phase 4 Scraper, Extractor, Validator, and Agent Contract."""

from pathlib import Path
import tempfile
import unittest

from src.config import config
from src.database.db_manager import DatabaseManager
from src.matcher.job_matcher import JobMatcher
from src.scraper.agent_integration_contract import AgentIntegrationContract, IngestionResult
from src.scraper.data_validator import DataValidator, ValidationResult
from src.scraper.extraction_schema import ExtractedJobPayload


class TestScraperIntegration(unittest.TestCase):
    """Test suite verifying extraction validation, anti-automation detection, and backend ingestion."""

    def setUp(self):
        self.validator = DataValidator()

    def _create_sample_payload(
        self,
        title: str = "Machine Learning Intern",
        company: str = "Cognitive Labs India",
        url: str = "https://cognitivelabs.ai/careers/ml-intern?utm_source=linkedin&ref=feed",
        description: str = "Looking for an ML intern to build NLP and computer vision pipelines using Python and PyTorch.",
        skills: list | None = None,
        location: str = "Bengaluru, India (Remote)",
    ) -> ExtractedJobPayload:
        return ExtractedJobPayload(
            page_url=url,
            page_title=f"{title} at {company}",
            company_name=company,
            job_title=title,
            location=location,
            job_description=description,
            required_skills=skills or ["Python", "Machine Learning", "PyTorch"],
            eligibility_criteria={"min_cgpa": 7.0, "graduation_years": [2027, 2028]},
            stipend="₹40,000 / month",
            application_deadline="2026-12-31",
            application_url=url,
            platform="LinkedIn",
        )

    # 1. Extraction Schema & Null Handling
    def test_extraction_schema_null_handling(self):
        """Verifies schema handles missing or unknown fields without inventing information."""
        minimal_payload = ExtractedJobPayload(page_url="https://example.com/job1")
        self.assertIsNone(minimal_payload.job_title)
        self.assertIsNone(minimal_payload.company_name)
        self.assertIsNone(minimal_payload.stipend)
        self.assertEqual(minimal_payload.required_skills, [])
        self.assertEqual(minimal_payload.eligibility_criteria, {})

        # Serialization
        data_dict = minimal_payload.to_dict()
        restored = ExtractedJobPayload.from_dict(data_dict)
        self.assertEqual(restored.page_url, "https://example.com/job1")
        self.assertIsNone(restored.job_title)

    # 2. Data Validation & Sanitization
    def test_data_validator_sanitization(self):
        """Verifies string cleaning, HTML stripping, and URL normalization."""
        raw_payload = self._create_sample_payload(
            title="<b>Generative AI</b> Intern  ",
            description="<p>Build LLM agents using Python.</p><br>   Extra whitespace.   ",
            url="https://company.com/jobs/1/?utm_medium=email&trk=share",
        )
        res = self.validator.validate(raw_payload)

        self.assertTrue(res.is_valid)
        self.assertFalse(res.is_restricted)
        cleaned = res.sanitized_payload
        self.assertIsNotNone(cleaned)

        # HTML stripped & whitespace collapsed
        self.assertEqual(cleaned.job_title, "Generative AI Intern")
        self.assertEqual(cleaned.job_description, "Build LLM agents using Python. Extra whitespace.")
        # URL normalized (tracking params and trailing slash stripped)
        self.assertEqual(cleaned.page_url, "https://company.com/jobs/1")

    # 3. Missing Core Fields
    def test_validator_rejects_missing_fields(self):
        """Checks validation fails when URL or job title are missing."""
        # Empty URL
        p1 = ExtractedJobPayload(page_url="", job_title="AI Intern")
        self.assertFalse(self.validator.validate(p1).is_valid)

        # Missing Job Title
        p2 = ExtractedJobPayload(page_url="https://company.com/job", job_title=None)
        res2 = self.validator.validate(p2)
        self.assertFalse(res2.is_valid)
        self.assertTrue(any("job_title" in err for err in res2.errors))

    # 4. Anti-Automation & Restriction Detection
    def test_cloudflare_restriction_detection(self):
        """Verifies detection of Cloudflare anti-bot challenge."""
        payload = ExtractedJobPayload(
            page_url="https://blocked-portal.com/job/123",
            page_title="Just a moment... Please wait",
            job_description="Checking your browser before accessing the website.",
        )
        res = self.validator.validate(payload)
        self.assertFalse(res.is_valid)
        self.assertTrue(res.is_restricted)
        self.assertIn("Cloudflare", res.restriction_reason)
        self.assertEqual(res.official_url, "https://blocked-portal.com/job/123")

    def test_captcha_restriction_detection(self):
        """Verifies detection of CAPTCHA challenges."""
        payload = ExtractedJobPayload(
            page_url="https://portal.com/careers/intern",
            page_title="Security Check",
            job_description="Please complete the reCAPTCHA to verify you are human.",
        )
        res = self.validator.validate(payload)
        self.assertFalse(res.is_valid)
        self.assertTrue(res.is_restricted)
        self.assertIn("CAPTCHA", res.restriction_reason)

    def test_login_wall_detection(self):
        """Verifies detection of authentication login walls."""
        payload = ExtractedJobPayload(
            page_url="https://linkedin.com/jobs/view/12345",
            page_title="Sign in to LinkedIn | LinkedIn",
            job_description="Sign in to view job details and apply.",
        )
        res = self.validator.validate(payload)
        self.assertFalse(res.is_valid)
        self.assertTrue(res.is_restricted)
        self.assertIn("login wall", res.restriction_reason)

    # 5. Agent Integration Contract Pipeline (End-to-End)
    def test_agent_integration_contract_ingestion(self):
        """Tests the complete ingestion pipeline: Validation -> Deduplication -> Scoring -> DB Storage."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_ingestion.db"
            db = DatabaseManager(db_path=db_path)
            matcher = JobMatcher(candidate_profile=config.candidate_profile, scoring_rules=config.scoring_rules, db_manager=db)
            contract = AgentIntegrationContract(db_manager=db, job_matcher=matcher, data_validator=self.validator)

            payload = self._create_sample_payload(
                title="Machine Learning Intern",
                company="OpenAI Applied Research",
                url="https://openai.com/careers/ml-intern-2028?utm_campaign=campus",
                skills=["Python", "Machine Learning", "Deep Learning", "Data Preprocessing"],
                location="Remote - India",
            )

            # Ingest payload
            result: IngestionResult = contract.ingest_payload(payload)

            self.assertTrue(result.success)
            self.assertFalse(result.is_duplicate)
            self.assertFalse(result.is_restricted)
            self.assertIsNotNone(result.job_id)
            self.assertGreater(result.job.match_score, 85.0)
            self.assertEqual(result.job.match_classification, "Excellent")
            self.assertTrue(result.job.is_eligible)

            # Confirm record in SQLite
            db_job = db.get_job_by_id(result.job_id)
            self.assertIsNotNone(db_job)
            self.assertEqual(db_job.company_name, "OpenAI Applied Research")

            # 6. Verify duplicate detection prevents second identical ingestion
            dup_payload = self._create_sample_payload(
                title="Machine Learning Intern",
                company="OpenAI Applied Research",
                url="https://openai.com/careers/ml-intern-2028?ref=another_ref",
            )
            dup_result = contract.ingest_payload(dup_payload)
            self.assertFalse(dup_result.success)
            self.assertTrue(dup_result.is_duplicate)
            self.assertEqual(dup_result.job_id, result.job_id)

    # 7. Ingestion of Restricted Payload Rejection
    def test_contract_handles_restricted_payload(self):
        """Ensures restricted payloads are not inserted into the jobs database."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db = DatabaseManager(db_path=Path(tmp_dir) / "test_restricted.db")
            contract = AgentIntegrationContract(db_manager=db)

            restricted_payload = ExtractedJobPayload(
                page_url="https://indeed.com/jobs/view",
                page_title="Attention Required! | Cloudflare",
                job_description="Please solve the challenge below.",
            )

            result = contract.ingest_payload(restricted_payload)
            self.assertFalse(result.success)
            self.assertTrue(result.is_restricted)
            self.assertEqual(len(db.list_jobs()), 0)  # No job inserted


if __name__ == "__main__":
    unittest.main()


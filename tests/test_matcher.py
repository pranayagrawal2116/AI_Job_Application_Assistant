"""Comprehensive unit tests for the Phase 3 Job Matching and Eligibility Engine."""

from pathlib import Path
import tempfile
import unittest

from src.config import config
from src.database.db_manager import DatabaseManager
from src.database.models import Job
from src.matcher.domain_matcher import DomainMatcher
from src.matcher.duration_matcher import DurationMatcher
from src.matcher.education_matcher import EducationMatcher
from src.matcher.eligibility import EligibilityEvaluator, EligibilityState
from src.matcher.experience_matcher import ExperienceMatcher
from src.matcher.explanation import ExplanationGenerator
from src.matcher.job_matcher import JobMatcher
from src.matcher.location_matcher import LocationMatcher
from src.matcher.score_calculator import ScoreCalculator
from src.matcher.skill_matcher import SkillMatcher


class TestJobMatcherEngine(unittest.TestCase):
    """Test suite for Phase 3 Matching and Eligibility Engine."""

    def setUp(self):
        self.candidate = config.candidate_profile
        self.scoring_rules = config.scoring_rules
        self.matcher = JobMatcher(candidate_profile=self.candidate, scoring_rules=self.scoring_rules)

    def _create_fictional_job(
        self,
        title: str = "Machine Learning Intern",
        company: str = "Apex AI Innovations",
        description: str = "Looking for a passionate ML intern to work on computer vision and NLP models.",
        skills: list | None = None,
        location: str = "Remote, India",
        criteria: dict | None = None,
    ) -> Job:
        return Job(
            company_name=company,
            job_title=title,
            job_url=f"https://fictional-career-hub.com/{company.lower().replace(' ', '-')}/{title.lower().replace(' ', '-')}",
            platform="LinkedIn",
            job_description=description,
            required_skills=skills or ["Python", "Machine Learning"],
            location=location,
            eligibility_criteria=criteria or {},
        )

    # 1. Perfect Skill Match
    def test_perfect_skill_match(self):
        """Verifies candidate receives full technical skill points when all demands match confirmed skills."""
        job = self._create_fictional_job(
            skills=["Python", "Machine Learning", "Data Preprocessing", "Data Visualization"]
        )
        skill_matcher = SkillMatcher(self.candidate, self.scoring_rules)
        res = skill_matcher.match(job)

        self.assertEqual(res.score, 25.0)
        self.assertEqual(len(res.missing_skills), 0)
        self.assertIn("Python", res.confirmed_skills)
        self.assertIn("Machine Learning", res.confirmed_skills)

    # 2. Partial Skill Match
    def test_partial_skill_match(self):
        """Verifies partial score when some skills match and others are missing."""
        job = self._create_fictional_job(
            skills=["Python", "Machine Learning", "Kubernetes", "Rust"]
        )
        skill_matcher = SkillMatcher(self.candidate, self.scoring_rules)
        res = skill_matcher.match(job)

        self.assertGreater(res.score, 0.0)
        self.assertLess(res.score, 25.0)
        self.assertIn("Kubernetes", res.missing_skills)
        self.assertIn("Rust", res.missing_skills)
        self.assertIn("Python", res.confirmed_skills)

    # 3. No Skill Match
    def test_no_skill_match(self):
        """Verifies zero technical skill points when required skills have no overlap with candidate competencies."""
        job = self._create_fictional_job(
            skills=["Ruby on Rails", "Elixir", "Cobol", "Fortran"]
        )
        skill_matcher = SkillMatcher(self.candidate, self.scoring_rules)
        res = skill_matcher.match(job)

        self.assertEqual(res.score, 0.0)
        self.assertEqual(len(res.confirmed_skills), 0)
        self.assertEqual(len(res.missing_skills), 4)

    # 4. Domain Relevance
    def test_domain_relevance_tiers(self):
        """Verifies Tier 1 (30 pts), Tier 2 (20 pts), Tier 3 (10 pts), and irrelevant (0 pts)."""
        dm = DomainMatcher(self.scoring_rules)

        # Tier 1
        job1 = self._create_fictional_job(title="Generative AI Intern", description="Work on LLMs and Artificial Intelligence.")
        self.assertEqual(dm.match(job1).score, 30.0)

        # Tier 2
        job2 = self._create_fictional_job(title="Python Developer Intern", description="Building backend APIs and data preprocessing scripts.")
        self.assertEqual(dm.match(job2).score, 20.0)

        # Tier 3
        job3 = self._create_fictional_job(title="Flutter Developer Intern", description="Building mobile UI components.")
        self.assertEqual(dm.match(job3).score, 10.0)

        # Irrelevant
        job4 = self._create_fictional_job(title="Real Estate Sales Associate", description="Manage residential property listings.")
        self.assertEqual(dm.match(job4).score, 0.0)

    # 5. CGPA Above Requirement
    def test_cgpa_above_requirement(self):
        """Verifies candidate (7.6 CGPA) is ELIGIBLE when employer requires 7.0 CGPA."""
        job = self._create_fictional_job(
            description="Minimum 7.0 CGPA required in B.Tech.",
            criteria={"min_cgpa": 7.0},
        )
        evaluator = EligibilityEvaluator(self.candidate)
        res = evaluator.evaluate(job)

        self.assertEqual(res.status, EligibilityState.ELIGIBLE)
        self.assertTrue(res.is_eligible)
        self.assertEqual(len(res.disqualification_reasons), 0)

    # 6. CGPA Below Requirement
    def test_cgpa_below_requirement(self):
        """Verifies candidate (7.6 CGPA) is INELIGIBLE when employer mandates 8.5 CGPA."""
        job = self._create_fictional_job(
            description="Strict academic requirement: minimum 8.5 CGPA cutoff.",
            criteria={"min_cgpa": 8.5},
        )
        evaluator = EligibilityEvaluator(self.candidate)
        res = evaluator.evaluate(job)

        self.assertEqual(res.status, EligibilityState.INELIGIBLE)
        self.assertFalse(res.is_eligible)
        self.assertTrue(any("8.5" in r and "7.6" in r for r in res.disqualification_reasons))

    # 7. Missing CGPA Requirement
    def test_missing_cgpa_requirement(self):
        """Verifies candidate is NOT penalized or disqualified when employer specifies no CGPA requirement."""
        job = self._create_fictional_job(
            description="Open for all enthusiastic engineering students with good problem solving skills.",
        )
        evaluator = EligibilityEvaluator(self.candidate)
        res = evaluator.evaluate(job)

        self.assertEqual(res.status, EligibilityState.ELIGIBLE)
        self.assertTrue(res.is_eligible)

        edu_matcher = EducationMatcher(self.candidate, self.scoring_rules)
        edu_res = edu_matcher.match(job)
        self.assertEqual(edu_res.score, 20.0)  # Full 20 points preserved

    # 8. Graduation Year Eligibility
    def test_graduation_year_eligibility(self):
        """Verifies graduation year 2028 compatibility and rejection of earlier batch restrictions."""
        evaluator = EligibilityEvaluator(self.candidate)

        # Batch 2028 accepted
        job1 = self._create_fictional_job(criteria={"graduation_years": [2027, 2028]})
        self.assertEqual(evaluator.evaluate(job1).status, EligibilityState.ELIGIBLE)

        # Restricted to earlier batch (2024 or 2025 graduates only)
        job2 = self._create_fictional_job(
            description="This hiring drive is strictly for batch of 2024 and 2025 only.",
            criteria={"graduation_years": [2024, 2025]},
        )
        res2 = evaluator.evaluate(job2)
        self.assertEqual(res2.status, EligibilityState.INELIGIBLE)
        self.assertFalse(res2.is_eligible)
        self.assertTrue(any("2028" in r for r in res2.disqualification_reasons))

    # 9. Experience Restrictions
    def test_experience_restrictions(self):
        """Verifies rejection of positions requiring 3+ years experience."""
        evaluator = EligibilityEvaluator(self.candidate)
        job = self._create_fictional_job(description="Requires at least 3+ years of professional ML engineering experience.")
        res = evaluator.evaluate(job)

        self.assertEqual(res.status, EligibilityState.INELIGIBLE)
        self.assertFalse(res.is_eligible)
        self.assertTrue(any("experience" in r.lower() for r in res.disqualification_reasons))

    # 10. Remote Location Compatibility
    def test_remote_location_compatibility(self):
        """Verifies 10 location points for remote / work-from-home jobs."""
        loc_matcher = LocationMatcher(self.scoring_rules)
        job = self._create_fictional_job(location="Remote - Anywhere in India")
        res = loc_matcher.match(job)
        self.assertEqual(res.score, 10.0)

    # 11. India-Only Restrictions
    def test_india_only_restrictions(self):
        """Verifies rejection of non-remote foreign jobs requiring in-person relocation."""
        evaluator = EligibilityEvaluator(self.candidate)
        job = self._create_fictional_job(location="London, United Kingdom (On-site Only)")
        res = evaluator.evaluate(job)

        self.assertEqual(res.status, EligibilityState.INELIGIBLE)
        self.assertFalse(res.is_eligible)
        self.assertTrue(any("London" in r or "outside India" in r for r in res.disqualification_reasons))

    # 12. Unknown Eligibility
    def test_unknown_eligibility(self):
        """Verifies UNKNOWN status when job details are sparse/insufficient."""
        evaluator = EligibilityEvaluator(self.candidate)
        job = Job(
            company_name="Mystery Tech",
            job_title="Intern",
            job_url="https://mystery.com/intern",
            platform="Direct",
            job_description="",
            required_skills=[],
        )
        res = evaluator.evaluate(job)
        self.assertEqual(res.status, EligibilityState.UNKNOWN)
        self.assertTrue(res.is_eligible)  # Default permissive to allow human review

    # 13. Empty Job Descriptions
    def test_empty_job_descriptions(self):
        """Verifies matcher handles empty descriptions without crashing."""
        job = Job(
            company_name="Silent Corp",
            job_title="Data Intern",
            job_url="https://silent.corp/data-intern",
            platform="Direct",
            job_description=None,
            required_skills=None,
        )
        result = self.matcher.evaluate_job(job)
        self.assertIsInstance(result.match_score, float)
        self.assertEqual(result.eligibility_status, EligibilityState.UNKNOWN)

    # 14. Missing Candidate Information
    def test_missing_candidate_information(self):
        """Verifies engine handles sparse candidate profiles safely."""
        sparse_profile = {"education": [{"current_cgpa": 7.0}]}
        matcher = JobMatcher(candidate_profile=sparse_profile, scoring_rules=self.scoring_rules)
        job = self._create_fictional_job()
        res = matcher.evaluate_job(job)
        self.assertIsNotNone(res.match_score)

    # 15. Score Calculation and Weight Validation
    def test_score_calculation_and_weight_validation(self):
        """Verifies max weights sum to 100 and classifications match expected ranges."""
        calculator = ScoreCalculator(self.scoring_rules)
        self.assertEqual(sum(calculator.max_weights.values()), 100.0)

        # Max score
        res_max = calculator.calculate(30, 25, 20, 10, 10, 5)
        self.assertEqual(res_max.total_score, 100.0)
        self.assertEqual(res_max.classification, "Excellent")

        # Good score (75.0)
        res_good = calculator.calculate(25, 20, 15, 8, 5, 2)
        self.assertEqual(res_good.total_score, 75.0)
        self.assertEqual(res_good.classification, "Good")

        # Moderate score (60.0)
        res_mod = calculator.calculate(20, 15, 10, 5, 8, 2)
        self.assertEqual(res_mod.total_score, 60.0)
        self.assertEqual(res_mod.classification, "Moderate")

        # Low score (40.0)
        res_low = calculator.calculate(10, 10, 10, 5, 3, 2)
        self.assertEqual(res_low.total_score, 40.0)
        self.assertEqual(res_low.classification, "Low")

    # 16. Job Matcher Database Integration
    def test_job_matcher_database_integration(self):
        """Verifies that evaluate_and_update_job updates SQLite records correctly."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_matcher.db"
            db = DatabaseManager(db_path=db_path)

            sample_job = self._create_fictional_job(
                title="AI Research Intern",
                company="OpenAI Research India",
                description="Join our team working on generative AI and natural language processing.",
                skills=["Python", "Machine Learning", "Generative AI", "NLP"],
                location="Remote",
            )
            inserted = db.insert_job(sample_job)

            # Evaluate and update in DB
            updated = self.matcher.evaluate_and_update_job(inserted, db=db)

            self.assertGreater(updated.match_score, 85.0)
            self.assertEqual(updated.match_classification, "Excellent")
            self.assertTrue(updated.is_eligible)
            self.assertIn("scoring_rules_version", updated.score_breakdown)

            # Retrieve from DB to confirm persistence
            db_job = db.get_job_by_id(inserted.id)
            self.assertEqual(db_job.match_classification, "Excellent")
            self.assertEqual(db_job.match_score, updated.match_score)
            # Ensure original description was preserved
            self.assertEqual(db_job.job_description, sample_job.job_description)

    # 17. Explanation Generation
    def test_explanation_generation(self):
        """Verifies markdown report generation with matching skills, missing tools, and recommendations."""
        job = self._create_fictional_job(
            title="Data Science Intern",
            skills=["Python", "Machine Learning", "SQL", "Tableau", "AWS"],
        )
        res = self.matcher.evaluate_job(job)
        md = res.explanation.format_text()

        self.assertIn("Match Summary", md)
        self.assertIn("Matching Skills", md)
        self.assertIn("Missing Skills", md)
        self.assertIn("Tableau", md)


if __name__ == "__main__":
    unittest.main()


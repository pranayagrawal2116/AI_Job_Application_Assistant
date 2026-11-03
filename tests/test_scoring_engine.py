"""Unit Tests for 100-Point Scoring Engine and Profile Weightings (Phase 5).

Verifies strict mathematical invariant that all profiles sum to 100 points, deterministic
evaluation, score bounds, non-applicable dimension handling, and profile auto-recommendation.
"""

import unittest

from src.matcher.scoring_profiles import (
    SCORING_PROFILES,
    get_scoring_profile,
    recommend_scoring_profile,
)
from src.matcher.universal_matcher import (
    CandidateFactNormalizer,
    JobRequirementNormalizer,
    UniversalScoringEngine,
)


class TestScoringEngine(unittest.TestCase):
    """Test suite for Phase 5 Universal Scoring Engine."""

    def test_all_scoring_profiles_sum_to_one_hundred_points(self):
        """Mathematical invariant: Every configured scoring profile must sum to exactly 100.0 points."""
        self.assertGreaterEqual(len(SCORING_PROFILES), 10)
        for pid, conf in SCORING_PROFILES.items():
            total = sum(conf.weights.values())
            self.assertAlmostEqual(
                total,
                100.0,
                places=3,
                msg=f"Profile '{pid}' weights do not sum to 100.0 (got {total})",
            )

    def test_deterministic_scoring_for_identical_inputs(self):
        """Repeated scoring runs on identical inputs must produce identical score and dimension points."""
        profile = get_scoring_profile("general_baseline")
        facts = CandidateFactNormalizer.normalize(
            profile_data={
                "skills": {"tech": ["Python", "SQL"]},
                "education": [{"degree": "B.Tech", "major": "Computer Science", "current_cgpa": 7.8}],
                "projects": [{"title": "Chatbot", "description": "AI chatbot"}],
            }
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={
                "job_title": "AI Developer",
                "mandatory_skills": ["Python"],
                "required_degree_levels": ["Bachelor"],
            }
        )

        score_1, conf_1, bd_1 = UniversalScoringEngine.calculate_score(
            scoring_profile=profile,
            skill_ratio=1.0, skill_conf=1.0,
            edu_ratio=1.0, edu_conf=1.0,
            exp_ratio=0.5, exp_conf=0.9,
            cert_ratio=0.0, cert_conf=1.0,
            resp_ratio=0.8,
            loc_ratio=1.0, loc_conf=1.0,
            facts=facts, reqs=reqs,
        )

        score_2, conf_2, bd_2 = UniversalScoringEngine.calculate_score(
            scoring_profile=profile,
            skill_ratio=1.0, skill_conf=1.0,
            edu_ratio=1.0, edu_conf=1.0,
            exp_ratio=0.5, exp_conf=0.9,
            cert_ratio=0.0, cert_conf=1.0,
            resp_ratio=0.8,
            loc_ratio=1.0, loc_conf=1.0,
            facts=facts, reqs=reqs,
        )

        self.assertEqual(score_1, score_2)
        self.assertEqual(conf_1, conf_2)
        for k in bd_1:
            self.assertEqual(bd_1[k].earned_points, bd_2[k].earned_points)

    def test_student_intern_profile_excludes_experience_penalty(self):
        """Student/intern profile reallocates experience weight (0 pts) to coursework and projects with clear explanation."""
        profile = get_scoring_profile("student_intern")
        self.assertEqual(profile.weights["experience"], 0.0)
        self.assertIn("experience", profile.excluded_dimension_reasons)

        facts = CandidateFactNormalizer.normalize(
            profile_data={
                "skills": {"tech": ["Python", "Machine Learning"]},
                "education": [{"degree": "B.Tech in CS & AI", "major": "AI", "current_cgpa": 8.0}],
                "projects": [{"title": "Computer Vision Classifier", "description": "PyTorch model"}],
            }
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={
                "job_title": "AI Research Intern",
                "mandatory_skills": ["Python", "Machine Learning"],
                "required_degree_levels": ["Bachelor"],
            }
        )

        score, conf, bd = UniversalScoringEngine.calculate_score(
            scoring_profile=profile,
            skill_ratio=1.0, skill_conf=1.0,
            edu_ratio=1.0, edu_conf=1.0,
            exp_ratio=0.0, exp_conf=1.0,  # Zero employment experience
            cert_ratio=0.0, cert_conf=1.0,
            resp_ratio=1.0,
            loc_ratio=1.0, loc_conf=1.0,
            facts=facts, reqs=reqs,
        )

        self.assertEqual(bd["experience"].earned_points, 0.0)
        self.assertEqual(bd["experience"].max_points, 0.0)
        self.assertIn("do not penalize", bd["experience"].notes.lower())
        # Overall score can reach 100 for a student if skills, edu, projects, domain, location are satisfied
        self.assertGreaterEqual(score, 90.0)

    def test_score_boundaries(self):
        """Score must never exceed 100.0 and never fall below 0.0."""
        profile = get_scoring_profile("general_baseline")
        facts = CandidateFactNormalizer.normalize({})
        reqs = JobRequirementNormalizer.normalize({})

        # Maximum possible
        max_score, _, _ = UniversalScoringEngine.calculate_score(
            scoring_profile=profile,
            skill_ratio=1.5, skill_conf=1.0,
            edu_ratio=1.5, edu_conf=1.0,
            exp_ratio=1.5, exp_conf=1.0,
            cert_ratio=1.5, cert_conf=1.0,
            resp_ratio=1.5,
            loc_ratio=1.5, loc_conf=1.0,
            facts=facts, reqs=reqs,
        )
        self.assertEqual(max_score, 100.0)

        # Minimum possible
        min_score, _, _ = UniversalScoringEngine.calculate_score(
            scoring_profile=profile,
            skill_ratio=0.0, skill_conf=0.0,
            edu_ratio=0.0, edu_conf=0.0,
            exp_ratio=0.0, exp_conf=0.0,
            cert_ratio=0.0, cert_conf=0.0,
            resp_ratio=0.0,
            loc_ratio=0.0, loc_conf=0.0,
            facts=facts, reqs=reqs,
        )
        self.assertEqual(min_score, 0.0)

    def test_profile_recommendation_logic(self):
        """Recommender selects appropriate profile across industries and experience levels."""
        p_nurse, _ = recommend_scoring_profile(job_industry="Healthcare", job_title="Staff Nurse")
        self.assertEqual(p_nurse, "healthcare_clinical")

        p_lawyer, _ = recommend_scoring_profile(job_industry="Legal", job_title="Corporate Attorney")
        self.assertEqual(p_lawyer, "legal_counsel")

        p_engineer, _ = recommend_scoring_profile(job_industry="Mechanical Engineering", job_title="CAD Design Engineer")
        self.assertEqual(p_engineer, "engineering_technical")

        p_intern, _ = recommend_scoring_profile(candidate_level="student", job_title="Data Science Intern", is_internship=True)
        self.assertEqual(p_intern, "student_intern")

        p_exec, _ = recommend_scoring_profile(candidate_level="senior", job_title="VP of Engineering", years_experience=10.0)
        self.assertEqual(p_exec, "senior_executive")


if __name__ == "__main__":
    unittest.main()

"""Comprehensive Unit Tests for Universal Skill Matching and Anti-Aliasing (Phase 5).

Verifies exact matches, synonym resolution, related domain skill matching, partial matches,
anti-aliasing guards (e.g., Java != JavaScript), and cross-industry competencies.
"""

import unittest

from src.matcher.terminology import (
    are_skills_strictly_distinct,
)
from src.matcher.universal_matcher import (
    CandidateFactNormalizer,
    JobRequirementNormalizer,
    UniversalSkillMatcher,
)


class TestUniversalSkillMatching(unittest.TestCase):
    """Test suite for Phase 5 Universal Skill Matcher."""

    def test_exact_skill_match_verified(self):
        """Verified skill in candidate profile matches required job skill exactly with full confidence."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={"skills": {"technical": ["Python", "Machine Learning"]}}
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={"mandatory_skills": ["Python", "Machine Learning"]}
        )

        assessments, ratio, conf = UniversalSkillMatcher.evaluate(facts, reqs)
        self.assertEqual(len(assessments), 2)
        self.assertEqual(assessments[0].classification, "EXACT_MATCH")
        self.assertEqual(assessments[1].classification, "EXACT_MATCH")
        self.assertEqual(ratio, 1.0)
        self.assertEqual(conf, 1.0)

    def test_synonym_resolution_financial_modeling(self):
        """Spelling variations like 'Financial modelling' match 'Financial modeling' as exact synonyms."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={"skills": {"finance": ["Financial modelling"]}}
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={"mandatory_skills": ["Financial modeling"]}
        )

        assessments, ratio, conf = UniversalSkillMatcher.evaluate(facts, reqs)
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0].classification, "EXACT_MATCH")
        self.assertIn("synonym", assessments[0].candidate_evidence)
        self.assertEqual(ratio, 1.0)

    def test_synonym_resolution_tech_abbreviations(self):
        """Standard tech abbreviations (k8s -> kubernetes, nlp -> natural language processing) resolve to canonical keys."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={"skills": {"tools": ["k8s", "nlp", "py", "postgres"]}}
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={"mandatory_skills": ["Kubernetes", "Natural Language Processing", "Python", "PostgreSQL"]}
        )

        assessments, ratio, conf = UniversalSkillMatcher.evaluate(facts, reqs)
        for sa in assessments:
            self.assertEqual(sa.classification, "EXACT_MATCH", f"Expected EXACT_MATCH for {sa.job_skill}")
        self.assertEqual(ratio, 1.0)

    def test_strict_non_equivalence_java_and_javascript(self):
        """Java and JavaScript are strictly distinct and MUST NEVER match."""
        self.assertTrue(are_skills_strictly_distinct("Java", "JavaScript"))
        self.assertTrue(are_skills_strictly_distinct("javascript", "java"))

        facts = CandidateFactNormalizer.normalize(
            profile_data={"skills": {"tech": ["Java"]}}
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={"mandatory_skills": ["JavaScript"]}
        )

        assessments, ratio, conf = UniversalSkillMatcher.evaluate(facts, reqs)
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0].classification, "MISSING")
        self.assertEqual(ratio, 0.0)

    def test_strict_non_equivalence_c_cpp_csharp(self):
        """C, C++, and C# are distinct programming languages and must never match as synonyms."""
        self.assertTrue(are_skills_strictly_distinct("C", "C++"))
        self.assertTrue(are_skills_strictly_distinct("C", "C#"))
        self.assertTrue(are_skills_strictly_distinct("C++", "C#"))

        facts = CandidateFactNormalizer.normalize(
            profile_data={"skills": {"tech": ["C"]}}
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={"mandatory_skills": ["C++", "C#"]}
        )

        assessments, ratio, conf = UniversalSkillMatcher.evaluate(facts, reqs)
        for sa in assessments:
            self.assertEqual(sa.classification, "MISSING")
        self.assertEqual(ratio, 0.0)

    def test_related_skill_matching_deep_learning_frameworks(self):
        """PyTorch and TensorFlow match as RELATED_MATCH in deep learning taxonomy."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={"skills": {"ml": ["PyTorch"]}}
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={"mandatory_skills": ["TensorFlow"]}
        )

        assessments, ratio, conf = UniversalSkillMatcher.evaluate(facts, reqs)
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0].classification, "RELATED_MATCH")
        self.assertGreater(ratio, 0.0)
        self.assertLess(ratio, 1.0)

    def test_related_skill_matching_cloud_platforms(self):
        """AWS and Azure match as RELATED_MATCH under cloud infrastructure taxonomy."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={"skills": {"cloud": ["AWS"]}}
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={"mandatory_skills": ["Azure"]}
        )

        assessments, ratio, conf = UniversalSkillMatcher.evaluate(facts, reqs)
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0].classification, "RELATED_MATCH")

    def test_partial_match_from_project_corpus(self):
        """Skills mentioned in project deliverables qualify as PARTIAL_MATCH."""
        facts = CandidateFactNormalizer.normalize(
            resume_data={
                "projects": [
                    {"title": "E-Commerce Microservices", "description": "Designed microservices communicating via RabbitMQ messaging queue."}
                ]
            }
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={"mandatory_skills": ["RabbitMQ"]}
        )

        assessments, ratio, conf = UniversalSkillMatcher.evaluate(facts, reqs)
        self.assertEqual(len(assessments), 1)
        self.assertEqual(assessments[0].classification, "PARTIAL_MATCH")
        self.assertIn("E-Commerce Microservices", assessments[0].candidate_evidence)

    def test_unverified_skill_confidence_discount(self):
        """Unverified extracted resume skill carries 0.85 confidence vs 1.0 for user confirmed."""
        facts_unverified = CandidateFactNormalizer.normalize(
            resume_data={"technical_skills": ["Docker"]}
        )
        facts_confirmed = CandidateFactNormalizer.normalize(
            profile_data={"skills": {"tools": ["Docker"]}}
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={"mandatory_skills": ["Docker"]}
        )

        _, ratio_unv, conf_unv = UniversalSkillMatcher.evaluate(facts_unverified, reqs)
        _, ratio_conf, conf_conf = UniversalSkillMatcher.evaluate(facts_confirmed, reqs)

        self.assertEqual(conf_conf, 1.0)
        self.assertAlmostEqual(conf_unv, 0.85, places=2)
        self.assertGreater(ratio_conf, ratio_unv)

    def test_cross_industry_healthcare_competencies(self):
        """Clinical patient care and triage evaluate accurately for healthcare postings."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={"skills": {"clinical": ["Patient Care", "Phlebotomy", "Electronic Health Records"]}}
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={"mandatory_skills": ["Patient Care", "Venipuncture", "EHR"]}
        )

        assessments, ratio, conf = UniversalSkillMatcher.evaluate(facts, reqs)
        self.assertEqual(len(assessments), 3)
        self.assertEqual(assessments[0].classification, "EXACT_MATCH")
        self.assertEqual(assessments[1].classification, "EXACT_MATCH")  # venipuncture synonym phlebotomy
        self.assertEqual(assessments[2].classification, "EXACT_MATCH")  # ehr synonym electronic health records
        self.assertEqual(ratio, 1.0)


if __name__ == "__main__":
    unittest.main()

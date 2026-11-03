"""Unit Tests for Three-State Eligibility Engine (Phase 5).

Verifies strict non-negotiable mandatory qualification checks:
- ELIGIBLE: All assessable mandatory requirements verified.
- INELIGIBLE: Demonstrable failure of confirmed qualification against non-negotiable cutoff.
- UNKNOWN: Missing or ambiguous data cannot verify mandatory condition. Never classify UNKNOWN as ELIGIBLE.
"""

import unittest

from src.matcher.universal_matcher import (
    CandidateFactNormalizer,
    CertificationLicensingEvaluator,
    EducationCompatibilityEvaluator,
    ExperienceEvaluator,
    JobRequirementNormalizer,
    UniversalEligibilityEvaluator,
)
from src.matcher.scoring_profiles import get_scoring_profile


class TestEligibilityEngine(unittest.TestCase):
    """Test suite for Phase 5 Three-State Eligibility Engine."""

    def test_eligible_when_all_mandatory_requirements_verified(self):
        """Candidate satisfying degree, experience, and skills receives ELIGIBLE status."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={
                "education": [{"degree": "Bachelor of Technology", "major": "Computer Science", "current_cgpa": 8.0}],
                "experience": [{"job_title": "Software Engineer", "duration_months": 24}],
                "skills": {"tech": ["Python", "SQL"]},
            }
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={
                "job_title": "Software Engineer",
                "required_degree_levels": ["Bachelor"],
                "min_years_experience": 1.0,
                "min_gpa_or_percentage": 7.0,
                "mandatory_skills": ["Python"],
            }
        )
        profile = get_scoring_profile("experienced_professional")

        edu, _, _ = EducationCompatibilityEvaluator.evaluate(facts, reqs)
        cert, _, _ = CertificationLicensingEvaluator.evaluate(facts, reqs)
        exp, _, _ = ExperienceEvaluator.evaluate(facts, reqs, profile)

        status, reasons = UniversalEligibilityEvaluator.evaluate(facts, reqs, edu, cert, exp)
        self.assertEqual(status, "ELIGIBLE")
        self.assertIn("verified", reasons[0])

    def test_ineligible_when_degree_level_below_mandatory_cutoff(self):
        """Candidate holding Associate/Diploma when Master's is mandatory returns INELIGIBLE."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={
                "education": [{"degree": "Diploma in Mechanical Engineering", "major": "Mechanical", "current_cgpa": 7.5}],
            }
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={
                "required_degree_levels": ["Master"],
            }
        )
        profile = get_scoring_profile("general_baseline")

        edu, _, _ = EducationCompatibilityEvaluator.evaluate(facts, reqs)
        cert, _, _ = CertificationLicensingEvaluator.evaluate(facts, reqs)
        exp, _, _ = ExperienceEvaluator.evaluate(facts, reqs, profile)

        status, reasons = UniversalEligibilityEvaluator.evaluate(facts, reqs, edu, cert, exp)
        self.assertEqual(status, "INELIGIBLE")
        self.assertTrue(any("degree level" in r.lower() for r in reasons))

    def test_ineligible_when_cgpa_below_mandatory_cutoff(self):
        """Candidate CGPA 6.8 against mandatory employer cutoff of 7.5 returns INELIGIBLE."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={
                "education": [{"degree": "B.Tech", "major": "AI & DS", "current_cgpa": 6.8}],
            }
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={
                "required_degree_levels": ["Bachelor"],
                "min_gpa_or_percentage": 7.5,
            }
        )
        profile = get_scoring_profile("fresh_graduate")

        edu, _, _ = EducationCompatibilityEvaluator.evaluate(facts, reqs)
        cert, _, _ = CertificationLicensingEvaluator.evaluate(facts, reqs)
        exp, _, _ = ExperienceEvaluator.evaluate(facts, reqs, profile)

        status, reasons = UniversalEligibilityEvaluator.evaluate(facts, reqs, edu, cert, exp)
        self.assertEqual(status, "INELIGIBLE")
        self.assertTrue(any("cgpa" in r.lower() or "cutoff" in r.lower() for r in reasons))

    def test_unknown_when_mandatory_license_not_mentioned(self):
        """Mandatory nursing license not documented in resume returns UNKNOWN, not INELIGIBLE."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={
                "education": [{"degree": "BS in Nursing", "major": "Nursing"}],
                # No license listed
            }
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={
                "job_title": "Clinical Staff Nurse",
                "licenses_required": ["Registered Nurse"],
            }
        )
        profile = get_scoring_profile("healthcare_clinical")

        edu, _, _ = EducationCompatibilityEvaluator.evaluate(facts, reqs)
        cert, _, _ = CertificationLicensingEvaluator.evaluate(facts, reqs)
        exp, _, _ = ExperienceEvaluator.evaluate(facts, reqs, profile)

        status, reasons = UniversalEligibilityEvaluator.evaluate(facts, reqs, edu, cert, exp)
        self.assertEqual(status, "UNKNOWN")
        self.assertTrue(any("registered nurse" in r.lower() for r in reasons))

    def test_unknown_when_gpa_missing_but_cutoff_mandated(self):
        """Candidate profile omitting CGPA when employer mandates cutoff returns UNKNOWN."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={
                "education": [{"degree": "B.Tech", "major": "Computer Science"}],  # No CGPA field
            }
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={
                "min_gpa_or_percentage": 7.5,
            }
        )
        profile = get_scoring_profile("general_baseline")

        edu, _, _ = EducationCompatibilityEvaluator.evaluate(facts, reqs)
        cert, _, _ = CertificationLicensingEvaluator.evaluate(facts, reqs)
        exp, _, _ = ExperienceEvaluator.evaluate(facts, reqs, profile)

        status, reasons = UniversalEligibilityEvaluator.evaluate(facts, reqs, edu, cert, exp)
        self.assertEqual(status, "UNKNOWN")
        self.assertTrue(any("cgpa" in r.lower() and "missing" in r.lower() for r in reasons))

    def test_preferred_requirements_do_not_cause_ineligibility(self):
        """Missing preferred master's degree or preferred certification does NOT make candidate ineligible."""
        facts = CandidateFactNormalizer.normalize(
            profile_data={
                "education": [{"degree": "Bachelor of Science", "major": "Statistics", "current_cgpa": 8.5}],
                "skills": {"tech": ["Python", "SQL"]},
            }
        )
        reqs = JobRequirementNormalizer.normalize(
            job_data={
                "job_title": "Data Analyst",
                "required_degree_levels": ["Bachelor"],
                "preferred_skills": ["Tableau", "AWS"],  # Candidate lacks these preferred items
                "certifications_required": [],
            }
        )
        profile = get_scoring_profile("fresh_graduate")

        edu, _, _ = EducationCompatibilityEvaluator.evaluate(facts, reqs)
        cert, _, _ = CertificationLicensingEvaluator.evaluate(facts, reqs)
        exp, _, _ = ExperienceEvaluator.evaluate(facts, reqs, profile)

        status, reasons = UniversalEligibilityEvaluator.evaluate(facts, reqs, edu, cert, exp)
        self.assertEqual(status, "ELIGIBLE")


if __name__ == "__main__":
    unittest.main()

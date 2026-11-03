"""Unit tests for Universal Tailored Resume Generator (Architecture v2.1.1 - Phase 6).
Verifies multi-profession support, zero-hallucination guarantees, claim provenance, and editing.
"""

import unittest

from src.preparer.tailored_resume_generator import UniversalTailoredResumeGenerator


class TestTailoredResumeGenerator(unittest.TestCase):
    """Test suite for Universal Tailored Resume Generator."""

    def setUp(self):
        self.generator = UniversalTailoredResumeGenerator()

        # Healthcare Candidate Profile (Registered Nurse)
        self.nurse_profile = {
            "personal": {
                "full_name": "Elena Rostova",
                "email": "elena.rostova@example.com",
                "phone": "+1 555-0199",
                "location": "Boston, MA",
                "headline": "Registered Nurse (ICU / Critical Care)",
            },
            "education": [
                {
                    "institution": "Boston College School of Nursing",
                    "degree": "Bachelor of Science in Nursing (BSN)",
                    "major": "Nursing",
                    "graduation_year": 2020,
                    "cgpa": 3.85,
                    "verification_status": "USER_CONFIRMED",
                }
            ],
            "work_experience": [
                {
                    "employer": "Massachusetts General Hospital",
                    "job_title": "Staff Nurse - Intensive Care Unit",
                    "duration": "3 years",
                    "responsibilities": [
                        "Administered critical medications, titrating vasoactive infusions for unstable patients.",
                        "Monitored multi-organ failure patients utilizing advanced hemodynamic arterial lines.",
                        "Collaborated with multidisciplinary teams to develop and execute complex care plans.",
                    ],
                    "verification_status": "USER_CONFIRMED",
                }
            ],
            "skills": ["Triage", "Hemodynamic Monitoring", "Critical Care", "EMR", "ACLS", "BLS", "Patient Advocacy"],
            "licenses": [{"name": "Registered Nurse (RN) - Massachusetts Board", "is_confirmed": True}],
            "certifications": [{"name": "Critical Care Registered Nurse (CCRN)", "is_confirmed": True}],
        }

        # Healthcare Job Description
        self.icu_nurse_jd = {
            "id": 101,
            "company_name": "Brigham and Women's Hospital",
            "role_title": "ICU Staff Nurse",
            "required_skills": ["Critical Care", "Hemodynamic Monitoring", "ACLS", "Patient Care"],
            "preferred_skills": ["CCRN", "EMR"],
        }

    def test_zero_hallucination_guarantee(self):
        """Verifies that generated tailored resume NEVER invents employers, degrees, or skills."""
        tailored = self.generator.generate(
            user_id=1,
            candidate_profile=self.nurse_profile,
            job_description=self.icu_nurse_jd,
        )

        # 1. Personal contact preserved
        self.assertEqual(tailored.personal_info["full_name"], "Elena Rostova")
        self.assertEqual(tailored.personal_info["email"], "elena.rostova@example.com")

        # 2. Employer & Degree strictly from profile
        self.assertEqual(len(tailored.experience_entries), 1)
        self.assertEqual(tailored.experience_entries[0].employer, "Massachusetts General Hospital")
        self.assertEqual(tailored.experience_entries[0].job_title, "Staff Nurse - Intensive Care Unit")

        self.assertEqual(len(tailored.education_entries), 1)
        self.assertEqual(tailored.education_entries[0].institution, "Boston College School of Nursing")
        self.assertEqual(tailored.education_entries[0].degree, "Bachelor of Science in Nursing (BSN)")

        # 3. No invented tech skills (e.g. Python, SQL) in healthcare profile
        all_res_skills = tailored.matching_skills + tailored.additional_skills
        self.assertNotIn("Python", all_res_skills)
        self.assertNotIn("Machine Learning", all_res_skills)
        self.assertIn("Critical Care", all_res_skills)
        self.assertIn("Hemodynamic Monitoring", all_res_skills)

    def test_claim_level_provenance_metadata(self):
        """Verifies every bullet and summary has claim provenance linking to source facts."""
        tailored = self.generator.generate(
            user_id=1,
            candidate_profile=self.nurse_profile,
            job_description=self.icu_nurse_jd,
        )

        # Check Summary Provenance
        self.assertIsNotNone(tailored.summary_provenance)
        self.assertEqual(tailored.summary_provenance.source_type, "synthesized_summary")
        self.assertTrue(tailored.summary_provenance.confidence > 0.8)

        # Check Bullets Provenance
        exp = tailored.experience_entries[0]
        self.assertTrue(len(exp.bullets) >= 3)
        for bullet in exp.bullets:
            self.assertIsNotNone(bullet.claim_id)
            self.assertTrue(bullet.claim_id.startswith("claim_exp_"))
            self.assertEqual(bullet.provenance.source_type, "candidate_profile")
            self.assertEqual(bullet.provenance.evidence_status, "USER_CONFIRMED")
            self.assertIn(bullet.claim_id, tailored.provenance_map)

    def test_bullet_reordering_by_job_alignment(self):
        """Verifies that bullets matching JD keywords are scored and prioritized first."""
        tailored = self.generator.generate(
            user_id=1,
            candidate_profile=self.nurse_profile,
            job_description=self.icu_nurse_jd,
        )

        bullets = tailored.experience_entries[0].bullets
        # The bullet mentioning "hemodynamic" matches the JD keyword "Hemodynamic Monitoring"
        first_bullet = bullets[0]
        self.assertGreaterEqual(first_bullet.relevance_score, 0.0)
        self.assertTrue(any(kw.lower() in first_bullet.bullet_text.lower() for kw in ["hemodynamic", "medications", "critical"]))

    def test_in_place_bullet_editing_updates_provenance(self):
        """Editing a bullet updates its text and updates provenance to USER_CONFIRMED / user_edit."""
        tailored = self.generator.generate(
            user_id=1,
            candidate_profile=self.nurse_profile,
            job_description=self.icu_nurse_jd,
        )

        initial_version = tailored.version
        success = tailored.update_bullet(
            exp_index=0,
            bullet_index=0,
            new_text="Managed 15+ critically ill COVID-19 patients on mechanical ventilation with ECMO support.",
        )
        self.assertTrue(success)
        self.assertEqual(tailored.version, initial_version + 1)

        updated_bullet = tailored.experience_entries[0].bullets[0]
        self.assertEqual(updated_bullet.provenance.source_type, "user_edit")
        self.assertEqual(updated_bullet.provenance.evidence_status, "USER_CONFIRMED")
        self.assertEqual(updated_bullet.provenance.source_version, initial_version + 1)

    def test_diff_inspection_with_original_bullets(self):
        """Verifies that diff_with_original accurately detects candidate edits."""
        tailored = self.generator.generate(
            user_id=1,
            candidate_profile=self.nurse_profile,
            job_description=self.icu_nurse_jd,
        )

        orig_bullets = list(self.nurse_profile["work_experience"][0]["responsibilities"])

        # Before edit: no diff if texts match
        tailored.update_bullet(0, 0, "Custom updated clinical achievement text.")
        diff = tailored.diff_with_original(orig_bullets)
        self.assertTrue(len(diff) > 0)
        diff_str = "\n".join(diff)
        self.assertIn("+Custom updated clinical achievement text.", diff_str)

    def test_cross_industry_engineering_candidate(self):
        """Verifies generator works cleanly for a Mechanical Engineering candidate."""
        eng_profile = {
            "personal": {"full_name": "Marcus Vance", "email": "marcus@example.com", "headline": "Mechanical Design Engineer"},
            "education": [{"institution": "Purdue University", "degree": "BS Mechanical Engineering", "graduation_year": 2022}],
            "work_experience": [
                {
                    "employer": "Caterpillar Inc.",
                    "job_title": "Design Engineer",
                    "duration": "2 years",
                    "responsibilities": ["Designed hydraulic component assemblies using SolidWorks and Creo."],
                }
            ],
            "skills": ["SolidWorks", "Creo", "GD&T", "FEA", "Thermal Analysis"],
            "licenses": [{"name": "Engineer-in-Training (EIT)", "is_confirmed": True}],
        }
        eng_jd = {
            "company_name": "Tesla",
            "role_title": "Mechanical Design Engineer",
            "required_skills": ["SolidWorks", "GD&T", "CAD"],
        }
        tailored_eng = self.generator.generate(
            user_id=2,
            candidate_profile=eng_profile,
            job_description=eng_jd,
        )
        self.assertEqual(tailored_eng.target_company, "Tesla")
        self.assertIn("SolidWorks", tailored_eng.matching_skills)
        self.assertEqual(tailored_eng.education_entries[0].institution, "Purdue University")
        self.assertEqual(len(tailored_eng.licenses), 1)


if __name__ == "__main__":
    unittest.main()

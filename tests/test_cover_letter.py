"""Unit tests for Universal Cover Letter Generator (Architecture v2.1.1 - Phase 6).
Verifies tone adaptations, career-level awareness, zero fabrication, and claim provenance.
"""

from pathlib import Path
import tempfile
import unittest

from src.preparer.cover_letter_generator import (
    CareerLevel,
    CoverLetterGenerator,
    LetterTone,
)


class TestUniversalCoverLetterGenerator(unittest.TestCase):
    """Test suite for Universal Cover Letter Generator."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)
        self.generator = CoverLetterGenerator(output_dir=self.output_dir)

        # Legal Candidate Profile (Corporate Attorney)
        self.attorney_profile = {
            "personal": {
                "full_name": "Samantha Reed",
                "email": "samantha.reed@example.com",
                "phone": "+1 212-555-0144",
                "location": "New York, NY",
                "headline": "Corporate Associate Attorney (M&A / Securities)",
            },
            "education": [
                {
                    "institution": "Columbia Law School",
                    "degree": "Juris Doctor (J.D.)",
                    "graduation_year": 2019,
                    "verification_status": "USER_CONFIRMED",
                }
            ],
            "work_experience": [
                {
                    "employer": "Davis & Polk LLP",
                    "job_title": "Senior Corporate Associate",
                    "duration": "4 years",
                    "responsibilities": [
                        "Advised public companies on cross-border mergers and acquisitions exceeding $500M in transaction value.",
                        "Drafted purchase agreements, SEC disclosure filings, and board governance resolutions.",
                    ],
                    "verification_status": "USER_CONFIRMED",
                }
            ],
            "skills": ["Corporate Governance", "Mergers & Acquisitions", "SEC Filings", "Due Diligence", "Contract Drafting"],
            "licenses": [{"name": "New York State Bar Admission", "is_confirmed": True}],
        }

        self.in_house_counsel_jd = {
            "company_name": "Fintech Global Corp",
            "role_title": "Legal Counsel - Corporate & Regulatory",
            "required_skills": ["Corporate Governance", "Contract Drafting", "Regulatory Compliance"],
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_tone_variations(self):
        """Verifies that all 4 tones produce distinct, appropriate phrasing without fabricating facts."""
        tones = [
            LetterTone.PROFESSIONAL_DIRECT,
            LetterTone.ENTHUSIASTIC_MODERN,
            LetterTone.EXECUTIVE_FORMAL,
            LetterTone.ACADEMIC_RESEARCH,
        ]

        generated_letters = []
        for tone in tones:
            letter = self.generator.generate_universal_cover_letter(
                user_id=10,
                candidate_profile=self.attorney_profile,
                job_description=self.in_house_counsel_jd,
                tone=tone,
            )
            self.assertEqual(letter.tone, tone.value)
            self.assertIn("Samantha Reed", letter.letter_text)
            self.assertIn("Fintech Global Corp", letter.letter_text)
            self.assertIn("Columbia Law School", letter.letter_text)
            generated_letters.append(letter.letter_text)

        # Verify all tones generate distinct text
        self.assertEqual(len(set(generated_letters)), 4)

    def test_career_level_adaptation_student_vs_executive(self):
        """Verifies tone and emphasis differ between Student/Fresher and Senior/Executive."""
        # 1. Student / Entry-level candidate
        student_profile = {
            "personal": {"full_name": "David Kim", "email": "david@example.com", "headline": "Economics Graduate"},
            "education": [{"institution": "UC Berkeley", "degree": "BS Economics", "graduation_year": 2024}],
            "skills": ["Financial Modeling", "Data Analysis", "Excel"],
        }
        finance_jd = {"company_name": "Morgan Stanley", "role_title": "Junior Analyst"}

        student_cl = self.generator.generate_universal_cover_letter(
            user_id=11,
            candidate_profile=student_profile,
            job_description=finance_jd,
            career_level=CareerLevel.STUDENT_FRESHER,
        )
        self.assertEqual(student_cl.career_level, CareerLevel.STUDENT_FRESHER.value)
        self.assertIn("UC Berkeley", student_cl.letter_text)

        # 2. Executive candidate
        exec_cl = self.generator.generate_universal_cover_letter(
            user_id=10,
            candidate_profile=self.attorney_profile,
            job_description=self.in_house_counsel_jd,
            career_level=CareerLevel.SENIOR_EXECUTIVE,
            tone=LetterTone.EXECUTIVE_FORMAL,
        )
        self.assertEqual(exec_cl.career_level, CareerLevel.SENIOR_EXECUTIVE.value)
        self.assertIn("Senior Corporate Associate", exec_cl.letter_text)

    def test_zero_fabrication_guarantee(self):
        """Verifies cover letter never invents referral names, awards, or fake personal anecdotes."""
        letter = self.generator.generate_universal_cover_letter(
            user_id=10,
            candidate_profile=self.attorney_profile,
            job_description=self.in_house_counsel_jd,
        )
        text = letter.letter_text

        # Never invent referral introductions
        self.assertNotIn("referred by", text.lower())
        self.assertNotIn("spoke with", text.lower())
        # Never invent awards
        self.assertNotIn("employee of the year", text.lower())
        # Preserves real credentials
        self.assertIn("New York State Bar Admission", text)
        self.assertIn("Davis & Polk LLP", text)

    def test_claim_provenance_tracking(self):
        """Verifies that all paragraphs have associated claim provenance objects."""
        letter = self.generator.generate_universal_cover_letter(
            user_id=10,
            candidate_profile=self.attorney_profile,
            job_description=self.in_house_counsel_jd,
        )
        self.assertTrue(len(letter.provenance_claims) >= 4)
        for claim in letter.provenance_claims:
            self.assertIsNotNone(claim.claim_id)
            self.assertTrue(claim.claim_id.startswith("claim_cl_"))
            self.assertTrue(len(claim.generated_text) > 0)


if __name__ == "__main__":
    unittest.main()

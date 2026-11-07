"""Unit tests for Phase B.3 CareerRoleInferencer.

Validates:
1. Multi-domain career role inference (Tech, Finance, Healthcare, Engineering).
2. Zero hardcoding of universal AI/ML defaults across non-tech candidates.
3. Accurate detection and handling of student/fresher candidates without work experience.
4. Evidence attribution (supporting skills, evidence sources) for every suggested role.
5. Location inference from verified candidate profile data.
"""

import unittest
from src.preparer.career_role_inferencer import CareerRoleInferencer, InferredRole


class TestCareerRoleInferencer(unittest.TestCase):
    def setUp(self):
        self.inferencer = CareerRoleInferencer()

    def test_tech_candidate_inference(self):
        profile = {
            "personal_info": {"location": "Bengaluru, Karnataka"},
            "education": [
                {
                    "institution": "Tech University",
                    "degree": "B.Tech",
                    "field_of_study": "Computer Science & Engineering",
                    "graduation_year": 2025,
                }
            ],
            "work_experience": [
                {
                    "employer": "Tech Corp",
                    "job_title": "Software Engineering Intern",
                    "responsibilities": ["Developed backend REST APIs using FastAPI and PostgreSQL."],
                }
            ],
            "technical_skills": ["Python", "FastAPI", "PostgreSQL", "Docker", "Git"],
            "projects": [
                {
                    "name": "E-Commerce Microservices",
                    "description": "Built scalable order processing pipeline in Python.",
                    "technologies": ["Python", "Docker", "Redis"],
                }
            ],
        }

        roles = self.inferencer.infer_roles(profile)
        self.assertGreater(len(roles), 0)

        role_titles = [r.role_title.lower() for r in roles]
        # Should include software/backend engineering
        self.assertTrue(any("software" in t or "backend" in t or "developer" in t for t in role_titles))

        # Check evidence attribution
        for r in roles:
            self.assertIsInstance(r, InferredRole)
            self.assertGreater(len(r.evidence_sources), 0)
            self.assertGreaterEqual(r.confidence, 0.0)
            self.assertLessEqual(r.confidence, 1.0)

    def test_finance_candidate_no_universal_ai_defaults(self):
        profile = {
            "personal_info": {"location": "Mumbai, Maharashtra"},
            "education": [
                {
                    "institution": "Commerce College",
                    "degree": "Bachelor of Commerce",
                    "field_of_study": "Accounting and Finance",
                    "graduation_year": 2024,
                }
            ],
            "work_experience": [
                {
                    "employer": "ABC Accounting Firm",
                    "job_title": "Audit Associate",
                    "responsibilities": ["Financial reporting, ledger reconciliation, tax auditing."],
                }
            ],
            "professional_skills": ["Financial Modeling", "QuickBooks", "Tax Compliance", "Excel", "Auditing"],
            "projects": [
                {
                    "name": "Corporate Tax Strategy Analysis",
                    "description": "Comprehensive audit of tax liabilities for mid-size firms.",
                }
            ],
        }

        roles = self.inferencer.infer_roles(profile)
        self.assertGreater(len(roles), 0)

        role_titles = [r.role_title.lower() for r in roles]
        # Must recommend financial/accounting roles
        self.assertTrue(any("financial" in t or "accountant" in t or "audit" in t for t in role_titles))

        # STRICT CHECK: ZERO AI/ML universal default leakage
        for t in role_titles:
            self.assertNotIn("artificial intelligence", t)
            self.assertNotIn("deep learning", t)
            self.assertNotIn("ml intern", t)

    def test_healthcare_candidate_inference(self):
        profile = {
            "personal_info": {"location": "Delhi, India"},
            "education": [
                {
                    "institution": "Medical Sciences Institute",
                    "degree": "B.Sc Nursing",
                    "field_of_study": "Nursing",
                    "graduation_year": 2023,
                }
            ],
            "work_experience": [
                {
                    "employer": "City General Hospital",
                    "job_title": "Staff Nurse",
                    "responsibilities": ["Patient care, vital signs monitoring, medication administration."],
                }
            ],
            "technical_skills": ["Patient Care", "BLS Certification", "Clinical Documentation", "Triage"],
        }

        roles = self.inferencer.infer_roles(profile)
        self.assertGreater(len(roles), 0)

        role_titles = [r.role_title.lower() for r in roles]
        self.assertTrue(any("nurse" in t or "clinical" in t or "healthcare" in t for t in role_titles))

        # Zero tech/AI leakage
        for t in role_titles:
            self.assertNotIn("software engineer", t)
            self.assertNotIn("python developer", t)

    def test_mechanical_engineering_candidate(self):
        profile = {
            "personal_info": {"location": "Pune, Maharashtra"},
            "education": [
                {
                    "institution": "Engineering College",
                    "degree": "B.E. Mechanical Engineering",
                    "field_of_study": "Mechanical",
                    "graduation_year": 2024,
                }
            ],
            "technical_skills": ["AutoCAD", "SolidWorks", "Thermodynamics", "Finite Element Analysis (FEA)", "ANSYS"],
            "projects": [
                {
                    "name": "Formula Student Chassis Design",
                    "description": "Structural analysis and CAD modeling of vehicle chassis in SolidWorks.",
                }
            ],
        }

        roles = self.inferencer.infer_roles(profile)
        self.assertGreater(len(roles), 0)

        role_titles = [r.role_title.lower() for r in roles]
        self.assertTrue(any("mechanical" in t or "design" in t or "cad" in t for t in role_titles))

    def test_fresher_without_experience_generates_intern_roles(self):
        profile = {
            "personal_info": {"location": "Hyderabad"},
            "education": [
                {
                    "institution": "University College of Engineering",
                    "degree": "Bachelor of Technology",
                    "field_of_study": "Computer Science & Artificial Intelligence",
                    "graduation_year": 2028,
                }
            ],
            "work_experience": [],  # Fresher, no prior jobs
            "technical_skills": ["Python", "Machine Learning", "PyTorch", "Data Analysis"],
            "projects": [
                {
                    "name": "Medical Diagnostic Chatbot",
                    "description": "AI-driven symptom checker with NLP classification.",
                    "technologies": ["Python", "PyTorch", "HuggingFace"],
                }
            ],
        }

        roles = self.inferencer.infer_roles(profile)
        self.assertGreater(len(roles), 0)

        role_titles = [r.role_title.lower() for r in roles]
        # Should detect student/fresher timeline (grad 2028, 0 exp) and prioritize intern / entry-level roles
        self.assertTrue(any("intern" in t or "junior" in t or "entry" in t or "trainee" in t for t in role_titles))

    def test_location_inference(self):
        # Candidate with city in personal_info
        profile = {
            "personal_info": {"location": "Pune, Maharashtra, India"},
        }
        locs = self.inferencer.infer_locations(profile)
        self.assertIn("Remote", locs)
        self.assertIn("Pune", locs)
        self.assertIn("India", locs)

        # Empty location falls back safely without breaking
        empty_profile = {}
        locs_fallback = self.inferencer.infer_locations(empty_profile)
        self.assertIn("Remote", locs_fallback)
        self.assertIn("India", locs_fallback)


if __name__ == "__main__":
    unittest.main()

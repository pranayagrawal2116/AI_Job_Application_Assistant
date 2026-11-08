"""Unit and integration tests for Phase B.4:
1. Dynamic, empirical candidate classification (student, fresher, qualified, experienced).
2. Fair, non-penalizing profile completeness (freshers with projects achieve 100%).
3. Candidate-scoped matching metrics without global catalogue score leakage.
4. Contextual, profession-specific dashboard recommended actions with zero generic AI/ML assumptions.
"""

import os
os.environ.setdefault("APP_ENV", "test")

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from backend.api.routers.dashboard import get_dashboard_summary
from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.models import Job, MatchResult
from src.preparer.career_role_inferencer import CareerRoleInferencer


class TestPhaseB4Dashboard(unittest.TestCase):
    def setUp(self):
        DashboardService._instance = None
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "test_dashboard_b4.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.service = DashboardService.get_instance(db_manager=self.db, storage_base_dir=self.temp_path)
        self.inferencer = CareerRoleInferencer()

    def tearDown(self):
        self.temp_dir.cleanup()
        DashboardService._instance = None

    def test_candidate_classification_categories(self):
        """Empirical classification correctly identifies distinct career stages without fabrication."""
        # 1. Enrolled Student (Future graduation year, minimal experience)
        curr_yr = datetime.now(timezone.utc).year
        student_data = {
            "education": [{"degree": "B.Tech Computer Science", "expected_graduation_year": curr_yr + 2}],
            "work_experience": [{"job_title": "Intern", "duration": "3 months"}],
        }
        self.assertEqual(self.inferencer.classify_candidate(student_data), "student")

        # 2. Fresher (Graduated recently with 0 full-time experience)
        fresher_data = {
            "education": [{"degree": "B.Sc Mathematics", "graduation_year": curr_yr}],
            "work_experience": [],
            "projects": [{"title": "Data Analysis Study"}],
        }
        self.assertEqual(self.inferencer.classify_candidate(fresher_data), "fresher")

        # 3. Professionally Qualified (Statutory certification / ACCA / CPA)
        acca_data = {
            "education": [{"degree": "BBA Accounting", "graduation_year": curr_yr - 3}],
            "certifications": [{"name": "ACCA Member"}],
            "work_experience": [{"job_title": "Tax Associate", "duration": "18 months"}],
        }
        self.assertEqual(self.inferencer.classify_candidate(acca_data), "professionally_qualified")

        # 4. Experienced Professional (>= 12 months experience or senior title)
        senior_data = {
            "education": [{"degree": "B.E. Mechanical", "graduation_year": 2018}],
            "work_experience": [{"job_title": "Senior Design Engineer", "duration": "5 years"}],
        }
        self.assertEqual(self.inferencer.classify_candidate(senior_data), "experienced_professional")

        # 5. Empty / General Profile
        empty_data = {}
        self.assertEqual(self.inferencer.classify_candidate(empty_data), "general_candidate")

    def test_fair_completeness_scoring_no_fresher_penalty(self):
        """Students and freshers with projects achieve 100% completeness without employment history."""
        curr_yr = datetime.now(timezone.utc).year
        student_profile = {
            "personal": {"full_name": "Alex Student", "email": "alex@example.com", "phone": "+1234567890"},
            "education": [{"degree": "B.Tech CSE", "institution": "Tech University", "expected_graduation_year": curr_yr + 2}],
            "technical_skills": ["Python", "Flutter", "FastAPI"],
            "projects": [
                {"title": "Medical Chatbot", "description": "Healthcare AI assistant"},
                {"title": "Open Source App", "description": "Mobile Flutter app"},
            ],
            "work_experience": [],  # Zero employment history
        }

        res = self.inferencer.calculate_profile_completeness(student_profile, resumes_count=1)
        self.assertEqual(res["candidate_category"], "student")
        self.assertEqual(res["completeness_score"], 100, "Fresher with projects must achieve 100% completeness")
        self.assertEqual(res["evidence_breakdown"]["career_evidence"], 20)
        self.assertTrue(res["is_application_ready"])

    def test_candidate_scoped_matching_metrics_isolation(self):
        """Candidate matching metrics strictly query user-scoped MatchResults, never global catalog scores."""
        # Create Candidate A and Candidate B
        user_a = self.service.register_candidate("cand.a@example.com", "Pass123!", "Candidate A")
        user_b = self.service.register_candidate("cand.b@example.com", "Pass123!", "Candidate B")

        # Add 5 global catalog jobs
        job_ids = []
        for i in range(5):
            job = Job(
                company_name=f"Company {i}",
                job_title=f"Role {i}",
                job_description="Sample job description",
                job_url=f"https://example.com/jobs/{i}",
                platform="Direct",
                match_score=95.0,  # Global catalogue score!
                is_eligible=True,   # Global catalogue eligibility!
            )
            saved = self.db.add_job(job)
            job_ids.append(saved.id)

        # Candidate A evaluates 2 jobs: 1 eligible (score 85), 1 ineligible (score 40)
        mr1 = MatchResult(
            id=1,
            user_id=user_a.id,
            job_id=job_ids[0],
            match_score=85.0,
            match_classification="Good match",
            eligibility_status="ELIGIBLE",
            score_breakdown={"domain": 25},
            explanation="Matches qualifications.",
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )
        mr2 = MatchResult(
            id=2,
            user_id=user_a.id,
            job_id=job_ids[1],
            match_score=40.0,
            match_classification="Low match",
            eligibility_status="INELIGIBLE",
            score_breakdown={"domain": 10},
            explanation="Missing requirements.",
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )
        self.db.save_match_result(mr1)
        self.db.save_match_result(mr2)

        # Metrics for Candidate A
        metrics_a = self.db.get_candidate_matching_metrics(user_a.id)
        self.assertEqual(metrics_a["total_catalog_jobs"], 5)
        self.assertEqual(metrics_a["evaluated_matches_count"], 2)
        self.assertEqual(metrics_a["eligible_matches_count"], 1)

        # Metrics for Candidate B (Unevaluated)
        metrics_b = self.db.get_candidate_matching_metrics(user_b.id)
        self.assertEqual(metrics_b["total_catalog_jobs"], 5)
        self.assertEqual(metrics_b["evaluated_matches_count"], 0, "Candidate B has zero evaluations")
        self.assertEqual(metrics_b["eligible_matches_count"], 0, "Candidate B must NOT inherit global eligibility")

    def test_dashboard_recommendations_profession_specific(self):
        """Dashboard recommends accounting roles for ACCA candidates without generic AI/ML defaults."""
        user = self.service.register_candidate("acca.prof@example.com", "Pass123!", "Priyanka ACCA")
        _, sess = self.service.login_candidate("acca.prof@example.com", "Pass123!")

        # Candidate profile with ACCA qualifications
        acca_profile = {
            "personal": {"full_name": "Priyanka ACCA", "email": "acca.prof@example.com", "phone": "+4412345678"},
            "education": [{"degree": "BBA Finance", "institution": "Symbiosis University"}],
            "certifications": [{"name": "ACCA Member"}],
            "professional_skills": ["UK Taxation", "Internal Audit", "Reconciliation"],
            "technical_skills": ["Digita", "Xero", "Excel"],
            "work_experience": [{"job_title": "Tax Associate", "duration": "24 months"}],
        }
        self.db.save_user_candidate_profile(user.id, acca_profile)

        # Upload dummy resume record
        self.db.create_user_resume(
            user_id=user.id,
            original_filename="acca_resume.pdf",
            storage_filename="acca_resume.pdf",
            file_format="pdf",
            file_size_bytes=1024,
            file_hash="dummyhash123",
            is_primary=True,
        )

        # Invoke summary endpoint
        summary = get_dashboard_summary((user.id, sess))

        rec = summary["recommended_action"]
        self.assertNotIn("AI/ML", rec["description"], "Must not suggest AI/ML roles for finance/accounting candidate")
        self.assertNotIn("internships and AI/ML", rec["description"])

        # Check category and completeness
        self.assertEqual(summary["candidate_category"], "professionally_qualified")
        self.assertEqual(summary["profile_completeness"], 100)

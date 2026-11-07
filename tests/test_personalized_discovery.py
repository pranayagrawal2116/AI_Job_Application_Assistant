"""Unit and integration tests for Phase B.3 Personalized Discovery & Matching Engine.

Validates:
1. SQLite discovery_runs lifecycle, locking, and status transitions.
2. Duplicate active discovery execution prevention.
3. Candidate-scoped match results overlay on GET /api/jobs.
4. Deep 100-point job match explanation endpoint.
5. Discovery preferences updates and persistence.
"""

import os
os.environ.setdefault("APP_ENV", "test")

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.api.main import app
from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.models import Job
from src.security.session_manager import SessionManager
from tests.fixtures.synthetic_personas import generate_persona_pdf


class TestPersonalizedDiscovery(unittest.TestCase):
    def setUp(self):
        DashboardService._instance = None
        SessionManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_personalized_discovery.db"
        self.db = DatabaseManager(db_path=self.db_path)

        # Patch DashboardService db instance
        self.service = DashboardService.get_instance(db_manager=self.db, storage_base_dir=self.temp_dir.name)

        # Create a test user and login session via auth_manager
        user = self.service.register_candidate(
            email="candidate.discovery@example.com",
            password="SecurePassword123!",
            full_name="Alex Discovery",
            profession_industry="Technology",
        )
        self.user_id = user.id
        _, session = self.service.login_candidate(
            email="candidate.discovery@example.com",
            password="SecurePassword123!",
            client_ip="127.0.0.1",
        )
        self.session_id = session.session_id
        self.headers = {"Authorization": f"Bearer {self.session_id}"}

        # Create candidate profile
        self.profile_data = {
            "personal_info": {
                "full_name": "Alex Discovery",
                "email": "candidate.discovery@example.com",
                "location": "Bengaluru, Karnataka",
            },
            "education": [
                {
                    "institution": "National Institute of Technology",
                    "degree": "B.Tech Computer Science",
                    "graduation_year": 2025,
                    "cgpa": 8.4,
                    "provenance": "USER_CONFIRMED",
                }
            ],
            "technical_skills": ["Python", "FastAPI", "Machine Learning", "Docker", "SQL"],
            "search_preferences": {
                "target_roles": ["Python Developer", "Machine Learning Intern"],
                "target_locations": ["Remote", "Bengaluru"],
                "auto_discover_enabled": True,
            },
        }
        self.db.save_user_candidate_profile(self.user_id, self.profile_data)

        self.client = TestClient(app)
        self.client.cookies.set("session_id", self.session_id)

    def tearDown(self):
        DashboardService._instance = None
        SessionManager.reset_instance()
        self.temp_dir.cleanup()

    def test_discovery_run_lifecycle_and_locking(self):
        """Tests creation, active-check locking, and status completion of discovery runs."""
        # Initial state: no active run
        active = self.db.get_active_discovery_run(self.user_id)
        self.assertIsNone(active)

        # Create a run in PENDING status
        run_rec = self.db.create_discovery_run(
            user_id=self.user_id,
            target_roles=["Python Developer"],
            target_locations=["Remote"],
        )
        self.assertIsInstance(run_rec, dict)
        run_id = run_rec["id"]

        # Active check should now find the run
        active = self.db.get_active_discovery_run(self.user_id)
        self.assertIsNotNone(active)
        self.assertEqual(active["id"], run_id)
        self.assertEqual(active["status"], "PENDING")

        # Update to RUNNING
        updated = self.db.update_discovery_run(
            run_id=run_id,
            status="RUNNING",
            new_jobs_count=12,
        )
        self.assertTrue(updated)

        active = self.db.get_active_discovery_run(self.user_id)
        self.assertEqual(active["status"], "RUNNING")
        self.assertEqual(active["new_jobs_count"], 12)

        # Complete run
        completed = self.db.update_discovery_run(
            run_id=run_id,
            status="COMPLETED",
            new_jobs_count=15,
            error_message=None,
        )
        self.assertTrue(completed)

        # Active run should now be None
        active_after = self.db.get_active_discovery_run(self.user_id)
        self.assertIsNone(active_after)

        # Latest run should return the completed run
        latest = self.db.get_latest_discovery_run(self.user_id)
        self.assertIsNotNone(latest)
        self.assertEqual(latest["id"], run_id)
        self.assertEqual(latest["status"], "COMPLETED")

    def test_api_trigger_discovery_and_active_locking(self):
        """Tests /api/discovery/trigger returns started and locks duplicate trigger."""
        with patch.object(self.service, "run_candidate_discovery") as mock_disc:
            mock_disc.return_value = {"status": "completed", "jobs_discovered": 5, "matches_evaluated": 5}

            # First trigger (synchronous fallback when no BackgroundTasks runner is attached)
            res = self.client.post("/api/discovery/trigger", json={"roles": ["Python Developer"]}, headers=self.headers)
            self.assertEqual(res.status_code, 200)

            # Now simulate an active run in DB
            self.db.create_discovery_run(
                user_id=self.user_id,
                target_roles=["Python Developer"],
                target_locations=["Remote"],
            )

            # Second trigger should detect active run lock
            res2 = self.client.post("/api/discovery/trigger", json={"roles": ["Python Developer"]}, headers=self.headers)
            self.assertEqual(res2.status_code, 200)
            data2 = res2.json()
            self.assertEqual(data2["status"], "already_running")
            self.assertIn("already in progress", data2["message"])

    def test_api_discovery_status_and_suggested_roles(self):
        """Tests /api/discovery/status and /api/discovery/suggested-roles."""
        res = self.client.get("/api/discovery/status", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("is_running", data)
        self.assertIn("target_roles", data)
        self.assertIn("target_locations", data)
        self.assertIn("suggested_roles", data)

        res_roles = self.client.get("/api/discovery/suggested-roles", headers=self.headers)
        self.assertEqual(res_roles.status_code, 200)
        roles_data = res_roles.json()
        self.assertIn("suggested_roles", roles_data)
        self.assertIn("suggested_locations", roles_data)
        # Should have inferred roles for Alex Discovery (B.Tech CS + Python/ML)
        role_titles = [r["role_title"].lower() for r in roles_data["suggested_roles"]]
        self.assertTrue(any("python" in t or "software" in t or "data" in t for t in role_titles))

    def test_api_discovery_preferences_update(self):
        """Tests updating candidate search preferences via POST /api/discovery/preferences."""
        payload = {
            "target_roles": ["Full Stack Developer", "Backend Engineer"],
            "target_locations": ["Remote", "Bengaluru", "Pune"],
            "auto_discover_enabled": True,
        }
        res = self.client.post("/api/discovery/preferences", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("preferences", data)
        self.assertEqual(data["preferences"]["target_roles"], payload["target_roles"])

        # Verify DB persisted
        prof = self.db.get_user_candidate_profile(self.user_id)
        saved_prefs = prof["profile_data"]["search_preferences"]
        self.assertEqual(saved_prefs["target_roles"], payload["target_roles"])
        self.assertEqual(saved_prefs["target_locations"], payload["target_locations"])

    def test_jobs_personalized_matching_overlay(self):
        """Tests that GET /api/jobs overlays candidate-specific MatchResults rather than global scores."""
        # Ingest a catalog job
        job_obj = Job(
            platform="LinkedIn",
            company_name="TestCorp AI",
            job_title="Python Backend Engineer",
            job_description="We are seeking a Python engineer with FastAPI and Docker experience.",
            job_url="https://testcorp.ai/careers/python-engineer",
            location="Remote",
            match_score=45.0,  # Generic or stale global catalog score
            match_classification="Moderate match",
            is_eligible=True,
            required_skills="Python,FastAPI,Docker,PostgreSQL",
        )
        saved_job = self.db.insert_job(job_obj)
        job_id = saved_job.id

        # Save a verifiable uploaded resume for user
        pdf_bytes = generate_persona_pdf("backend_engineer")
        ok, msg, res_rec = self.service.upload_user_resume(
            user_id=self.user_id,
            file_bytes=pdf_bytes,
            original_filename="alex_resume.pdf",
            set_as_primary=True,
        )
        self.assertTrue(ok)
        resume_id = res_rec["id"]

        # Run candidate-specific match evaluation
        match_result = self.service.run_match_evaluation(
            user_id=self.user_id,
            resume_id=resume_id,
            job_id=job_id,
            scoring_profile_id="student_intern",
        )
        self.assertIsNotNone(match_result)
        candidate_score = match_result.match_score

        # Now query GET /api/jobs
        res = self.client.get("/api/jobs", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        jobs = res.json()
        self.assertGreaterEqual(len(jobs), 1)

        target_job = next(j for j in jobs if j["id"] == job_id)
        # Personalized match score should override the catalog's 45.0
        self.assertEqual(target_job["match_score"], round(candidate_score, 1))
        self.assertIn("matching_skills", target_job)
        self.assertTrue(len(target_job["matching_skills"]) > 0)

        # Test match explanation endpoint
        res_exp = self.client.get(f"/api/jobs/{job_id}/match-explanation", headers=self.headers)
        self.assertEqual(res_exp.status_code, 200)
        exp_data = res_exp.json()
        self.assertEqual(exp_data["job_id"], job_id)
        self.assertEqual(exp_data["match_score"], round(candidate_score, 1))
        self.assertIn("score_breakdown", exp_data)
        self.assertIn("explanation", exp_data)


if __name__ == "__main__":
    unittest.main()

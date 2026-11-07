"""Unit and integration tests for Phase B.3.3:
1. Startup recovery of interrupted discovery runs during FastAPI lifespan.
2. Candidate-specific match evaluation for duplicate jobs without score reuse or leakage.
3. Discovery response metrics and contract alignment.
"""

import os
os.environ.setdefault("APP_ENV", "test")

import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.api.main import app, lifespan
from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.models import Job
from src.security.session_manager import SessionManager
from src.scraper.discovery.search_coordinator import DiscoverySummary
from tests.fixtures.synthetic_personas import generate_persona_pdf, generate_two_column_acca_pdf


class TestPhaseB33RecoveryAndMatching(unittest.TestCase):
    def setUp(self):
        DashboardService._instance = None
        SessionManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_phase_b_3_3.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.service = DashboardService.get_instance(db_manager=self.db, storage_base_dir=self.temp_dir.name)

        # Candidate A (CSE / Tech)
        self.user_a = self.service.register_candidate(
            email="candidate.a@example.com",
            password="Password123!",
            full_name="Candidate A Tech",
            profession_industry="Technology",
        )
        _, self.session_a = self.service.login_candidate(
            email="candidate.a@example.com",
            password="Password123!",
            client_ip="127.0.0.1",
        )

        # Upload CSE resume for Candidate A
        cse_pdf = generate_persona_pdf("cs_mobile_ai_student")
        ok_a, _, self.resume_a = self.service.upload_user_resume(
            user_id=self.user_a.id,
            file_bytes=cse_pdf,
            original_filename="candidate_a_cse.pdf",
            set_as_primary=True,
        )
        self.assertTrue(ok_a)

        # Candidate B (ACCA / Finance)
        self.user_b = self.service.register_candidate(
            email="candidate.b@example.com",
            password="Password123!",
            full_name="Candidate B Finance",
            profession_industry="Finance",
        )
        _, self.session_b = self.service.login_candidate(
            email="candidate.b@example.com",
            password="Password123!",
            client_ip="127.0.0.1",
        )

        # Upload ACCA resume for Candidate B
        acca_pdf = generate_two_column_acca_pdf()
        ok_b, _, self.resume_b = self.service.upload_user_resume(
            user_id=self.user_b.id,
            file_bytes=acca_pdf,
            original_filename="candidate_b_acca.pdf",
            set_as_primary=True,
        )
        self.assertTrue(ok_b)

    def tearDown(self):
        DashboardService._instance = None
        SessionManager.reset_instance()
        self.temp_dir.cleanup()

    def test_fastapi_lifespan_startup_recovery(self):
        """Verifies that FastAPI lifespan startup recovers interrupted PENDING and RUNNING runs across multiple users."""
        # 1. First, create a completed run for user_a that should remain unchanged
        run_completed = self.db.create_discovery_run(self.user_a.id, ["Data Analyst"], ["Remote"])
        self.db.update_discovery_run(run_completed["id"], status="COMPLETED", total_discovered=10, new_jobs_saved=5)

        # 2. Now create stale runs before server starts
        run_a = self.db.create_discovery_run(self.user_a.id, ["Software Engineer"], ["Remote"])
        self.db.update_discovery_run(run_a["id"], status="RUNNING")

        run_b = self.db.create_discovery_run(self.user_b.id, ["Tax Associate"], ["London"])
        # leaves run_b in PENDING

        # Verify active run locks exist
        self.assertIsNotNone(self.db.get_active_discovery_run(self.user_a.id))
        self.assertIsNotNone(self.db.get_active_discovery_run(self.user_b.id))

        # Simulate FastAPI Lifespan Startup
        async def run_lifespan():
            async with lifespan(app):
                pass

        asyncio.run(run_lifespan())

        # Verify run_a is now FAILED with completion timestamp and reason
        updated_a = self.db.get_discovery_run(run_a["id"], user_id=self.user_a.id)
        self.assertEqual(updated_a["status"], "FAILED")
        self.assertIn("Interrupted by server restart", updated_a["error_message"])
        self.assertIsNotNone(updated_a["completed_at"])

        # Verify run_b is now FAILED
        updated_b = self.db.get_discovery_run(run_b["id"], user_id=self.user_b.id)
        self.assertEqual(updated_b["status"], "FAILED")
        self.assertIsNotNone(updated_b["completed_at"])

        # Verify completed run remains COMPLETED
        updated_comp = self.db.get_discovery_run(run_completed["id"], user_id=self.user_a.id)
        self.assertEqual(updated_comp["status"], "COMPLETED")
        self.assertEqual(updated_comp["new_jobs_saved"], 5)

        # Verify both candidates can now immediately trigger a new run without lock conflict
        new_run_a = self.db.create_discovery_run(self.user_a.id, ["Software Engineer"], ["Remote"])
        self.assertIsNotNone(new_run_a)
        self.assertEqual(new_run_a["status"], "PENDING")

        new_run_b = self.db.create_discovery_run(self.user_b.id, ["Tax Associate"], ["London"])
        self.assertIsNotNone(new_run_b)
        self.assertEqual(new_run_b["status"], "PENDING")

    def test_duplicate_job_candidate_specific_evaluation(self):
        """Verifies that duplicate catalog jobs encountered in a second candidate's run receive candidate-specific matching."""
        # 1. Candidate A adds a Software Engineer job to catalog
        job = Job(
            company_name="Apex Tech Corp",
            job_title="Software Engineer - Python & Mobile",
            job_description="Seeking a software developer with Python, Flutter, Dart, REST APIs, and Mobile development experience.",
            job_url="https://apextech.example.com/jobs/101",
            location="Remote",
            platform="LinkedIn",
        )
        saved_job = self.db.add_job(job)
        job_id = saved_job.id

        # 2. Evaluate Candidate A on Job 1
        res_a = self.service.run_match_evaluation(
            user_id=self.user_a.id,
            resume_id=self.resume_a["id"],
            job_id=job_id,
        )
        self.assertIsNotNone(res_a)
        match_a = self.db.get_latest_match_result(user_id=self.user_a.id, job_id=job_id)
        self.assertIsNotNone(match_a)
        self.assertGreater(match_a.match_score, 50.0, "Tech candidate should match tech job well")

        # 3. Candidate B runs discovery and encounters the exact same job listing
        # Mock SearchCoordinator to return this job as a duplicate
        summary = DiscoverySummary()
        summary.total_discovered = 1
        summary.new_jobs_saved = 0
        summary.duplicates_skipped = 1
        summary.duplicate_job_ids = [job_id]
        summary.platform_breakdown = {"LinkedIn": 1}

        with patch.object(self.service.coordinator, "run_discovery", return_value=summary):
            client = TestClient(app)
            client.cookies.set("session_id", self.session_b.session_id)
            headers = {"Authorization": f"Bearer {self.session_b.session_id}"}

            # Trigger discovery for Candidate B
            res = client.post("/api/jobs/discovery", json={"roles": ["Software Engineer"]}, headers=headers)
            self.assertEqual(res.status_code, 200)
            data = res.json()
            run_id = data["run_id"]

            # Wait briefly for thread execution
            import time
            time.sleep(0.5)

            # Poll run status
            run_res = client.get(f"/api/jobs/discovery/{run_id}", headers=headers)
            self.assertEqual(run_res.status_code, 200)
            run_data = run_res.json()
            self.assertEqual(run_data["duplicates_skipped"], 1)
            self.assertEqual(run_data["total_discovered"], 1)
            self.assertEqual(run_data["new_jobs_saved"], 0)

            # 4. Verify Candidate B received a personalized match evaluation for Job 1
            match_b = self.db.get_latest_match_result(user_id=self.user_b.id, job_id=job_id)
            self.assertIsNotNone(match_b, "Candidate B must receive their own evaluation for the duplicate job")

            # 5. Verify Candidate B's score is distinct and strictly lower than Candidate A
            self.assertNotEqual(match_a.match_score, match_b.match_score)
            self.assertLess(match_b.match_score, match_a.match_score)
            self.assertEqual(match_b.user_id, self.user_b.id)
            self.assertEqual(match_a.user_id, self.user_a.id)

    def test_discovery_metrics_contract(self):
        """Verifies the unified DiscoveryRun response contract across completed, partial, duplicate, and empty runs."""
        client = TestClient(app)
        client.cookies.set("session_id", self.session_a.session_id)
        headers = {"Authorization": f"Bearer {self.session_a.session_id}"}

        # Case 1: Completed run with metrics
        run1 = self.db.create_discovery_run(self.user_a.id, ["AI Engineer"], ["Remote"])
        self.db.update_discovery_run(
            run_id=run1["id"],
            status="COMPLETED",
            total_discovered=12,
            new_jobs_saved=8,
            duplicates_skipped=4,
            restricted_count=0,
            source_outcomes={"LinkedIn": 6, "Internshala": 6},
        )

        res = client.get(f"/api/jobs/discovery/{run1['id']}", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        # Contract checks
        self.assertEqual(data["run_id"], run1["id"])
        self.assertEqual(data["id"], run1["id"])
        self.assertEqual(data["status"], "COMPLETED")
        self.assertEqual(data["total_discovered"], 12)
        self.assertEqual(data["jobs_found"], 12)
        self.assertEqual(data["new_jobs_saved"], 8)
        self.assertEqual(data["jobs_saved"], 8)
        self.assertEqual(data["duplicates_skipped"], 4)
        self.assertEqual(data["restricted_count"], 0)
        self.assertEqual(data["target_roles"], ["AI Engineer"])
        self.assertEqual(data["target_locations"], ["Remote"])
        self.assertEqual(data["source_outcomes"]["LinkedIn"], 6)

        # Case 2: Partial run with restricted incidents
        run2 = self.db.create_discovery_run(self.user_a.id, ["Python Dev"], ["India"])
        self.db.update_discovery_run(
            run_id=run2["id"],
            status="PARTIAL",
            total_discovered=5,
            new_jobs_saved=3,
            duplicates_skipped=1,
            restricted_count=2,
            source_outcomes={"Indeed": 3},
        )
        res2 = client.get(f"/api/jobs/discovery/{run2['id']}", headers=headers)
        data2 = res2.json()
        self.assertEqual(data2["status"], "PARTIAL")
        self.assertEqual(data2["total_discovered"], 5)
        self.assertEqual(data2["new_jobs_saved"], 3)
        self.assertEqual(data2["restricted_count"], 2)

        # Case 3: Failed run
        run3 = self.db.create_discovery_run(self.user_a.id, ["Data Engineer"], ["Remote"])
        self.db.update_discovery_run(
            run_id=run3["id"],
            status="FAILED",
            error_message="Network timeout connecting to provider",
        )
        res3 = client.get(f"/api/jobs/discovery/{run3['id']}", headers=headers)
        data3 = res3.json()
        self.assertEqual(data3["status"], "FAILED")
        self.assertEqual(data3["error_message"], "Network timeout connecting to provider")

        # Case 4: Latest discovery run status endpoint
        latest_res = client.get("/api/jobs/discovery/latest", headers=headers)
        self.assertEqual(latest_res.status_code, 200)
        latest_data = latest_res.json()
        self.assertTrue(latest_data["has_run"])
        self.assertEqual(latest_data["run"]["id"], run3["id"])

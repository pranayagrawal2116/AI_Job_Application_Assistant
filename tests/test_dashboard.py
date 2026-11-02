"""Unit tests for Phase 6 Streamlit Dashboard Services, Metrics, Analytics, and Governance."""

from datetime import datetime
from pathlib import Path
import tempfile
import unittest

import pandas as pd
import plotly.graph_objects as go

from dashboard.services.analytics_service import AnalyticsService
from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.models import ApplicationStatus, Job


class TestDashboardArchitecture(unittest.TestCase):
    """Test suite verifying dashboard data layer, analytics engine, and human governance."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_dashboard.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.service = DashboardService(db_manager=self.db)
        self.analytics = AnalyticsService(db_manager=self.db)

        # Seed test jobs with varying scores and statuses
        self.j1 = self.db.add_job(
            Job(
                company_name="Alpha Brain AI",
                job_title="AI Research Intern",
                job_url="https://alpha.ai/jobs/1",
                platform="Internshala",
                location="Pune",
                stipend="₹25,000 /month",
                match_score=92.0,
                match_classification="Excellent",
                is_eligible=True,
                job_description="Python, PyTorch, Deep Learning, computer vision models.",
            )
        )
        self.j2 = self.db.add_job(
            Job(
                company_name="Beta Neural Corp",
                job_title="Machine Learning Intern",
                job_url="https://beta.ai/jobs/2",
                platform="LinkedIn",
                location="Remote",
                stipend="₹30,000 /month",
                match_score=78.0,
                match_classification="Good",
                is_eligible=True,
                job_description="Python, Scikit-learn, Pandas, NLP pipelines.",
            )
        )
        self.j3 = self.db.add_job(
            Job(
                company_name="Gamma Analytics",
                job_title="Data Science Intern",
                job_url="https://gamma.ai/jobs/3",
                platform="Direct",
                location="Paris, France",
                stipend="Not Disclosed",
                match_score=42.0,
                match_classification="Low",
                is_eligible=False,
                job_description="French work authorization strictly required. Machine learning.",
            )
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Metric Calculation Tests
    def test_metrics_calculation(self):
        metrics = self.service.get_metrics()
        self.assertEqual(metrics["total_discovered"], 3)
        self.assertEqual(metrics["eligible_count"], 2)
        self.assertEqual(metrics["ineligible_count"], 1)
        self.assertEqual(metrics["excellent_matches"], 1)
        self.assertEqual(metrics["good_matches"], 1)
        self.assertEqual(metrics["low_matches"], 1)
        self.assertEqual(metrics["shortlisted_count"], 0)

    # 2. DataFrame Retrieval & Joins
    def test_get_all_jobs_df(self):
        df = self.service.get_all_jobs_df()
        self.assertFalse(df.empty)
        self.assertEqual(len(df), 3)
        self.assertIn("job_title", df.columns)
        self.assertIn("match_score", df.columns)
        self.assertIn("application_status", df.columns)
        self.assertTrue(all(df["application_status"] == ApplicationStatus.DISCOVERED.value))

    # 3. Shortlist Management
    def test_toggle_shortlist(self):
        # Shortlist job 1
        succ, msg = self.service.toggle_shortlist(self.j1.id, notes="Priority opportunity")
        self.assertTrue(succ)
        app = self.db.get_application_by_job_id(self.j1.id)
        stat_val = app.status.value if hasattr(app.status, "value") else str(app.status)
        self.assertEqual(stat_val, ApplicationStatus.SHORTLISTED.value)
        self.assertEqual(app.notes, "Priority opportunity")

        # Verify metrics updated
        metrics = self.service.get_metrics()
        self.assertEqual(metrics["shortlisted_count"], 1)

        # Toggle back
        succ2, _ = self.service.toggle_shortlist(self.j1.id)
        self.assertTrue(succ2)
        app2 = self.db.get_application_by_job_id(self.j1.id)
        stat2_val = app2.status.value if hasattr(app2.status, "value") else str(app2.status)
        self.assertEqual(stat2_val, ApplicationStatus.UNDER_REVIEW.value)

    # 4. Strict Human-in-the-Loop Safeguard on Submission
    def test_applied_status_human_governance(self):
        # First transition to Awaiting Approval
        self.service.update_application_status(self.j1.id, ApplicationStatus.UNDER_REVIEW.value)
        self.service.update_application_status(self.j1.id, ApplicationStatus.SHORTLISTED.value)
        self.service.update_application_status(self.j1.id, ApplicationStatus.APPLICATION_PREPARED.value)
        self.service.update_application_status(self.j1.id, ApplicationStatus.AWAITING_APPROVAL.value)

        # Attempt to mark as Applied without approver name -> must fail
        succ_no_name, msg1 = self.service.update_application_status(
            self.j1.id, ApplicationStatus.APPLIED.value, approver_name=""
        )
        self.assertFalse(succ_no_name)
        self.assertIn("Human approver name is mandatory", msg1)

        # Attempt to mark as Applied with automated bot name -> must fail
        succ_bot, msg2 = self.service.update_application_status(
            self.j1.id, ApplicationStatus.APPLIED.value, approver_name="auto_apply_bot"
        )
        self.assertFalse(succ_bot)
        self.assertIn("Approval rejected", msg2)

        # Mark as Applied with verified human approver -> must succeed
        succ_valid, msg3 = self.service.update_application_status(
            self.j1.id, ApplicationStatus.APPLIED.value, approver_name="Candidate Pranay"
        )
        self.assertTrue(succ_valid)
        app = self.db.get_application_by_job_id(self.j1.id)
        stat_val = app.status.value if hasattr(app.status, "value") else str(app.status)
        self.assertEqual(stat_val, ApplicationStatus.APPLIED.value)

    # 5. Candidate Profile Persistence
    def test_candidate_profile_persistence(self):
        new_prof = {
            "personal": {"full_name": "Pranay"},
            "education": [{"institution": "MIT WPU", "current_cgpa": 7.6, "expected_graduation_year": 2028}],
            "technical_skills": {"programming_languages": ["Python", "Dart"]},
        }
        succ, msg = self.service.save_candidate_profile(new_prof)
        self.assertTrue(succ)
        rec = self.db.get_latest_candidate_profile()
        self.assertIsNotNone(rec)
        self.assertEqual(rec.profile_data["education"][0]["current_cgpa"], 7.6)

    # 6. Analytics Visualizations & Skill Gap
    def test_analytics_charts_and_gap_analysis(self):
        df = self.service.get_all_jobs_df()
        fig_score = self.analytics.get_score_distribution_chart(df)
        self.assertIsInstance(fig_score, go.Figure)

        fig_elig = self.analytics.get_eligibility_pie_chart(df)
        self.assertIsInstance(fig_elig, go.Figure)

        fig_loc = self.analytics.get_location_distribution_chart(df)
        self.assertIsInstance(fig_loc, go.Figure)

        fig_plat = self.analytics.get_platform_distribution_chart(df)
        self.assertIsInstance(fig_plat, go.Figure)

        # Skill demand and missing gap
        df_demand, df_missing = self.analytics.get_skills_demand_analysis(df)
        self.assertFalse(df_demand.empty)
        # Python is present in descriptions
        self.assertIn("Python", df_demand["Skill"].values)

        fig_funnel = self.analytics.get_application_funnel_chart(self.service.get_metrics())
        self.assertIsInstance(fig_funnel, go.Figure)

    # 7. Backup and CSV Export
    def test_backup_and_csv_export(self):
        csv_path = self.service.export_jobs_to_csv()
        self.assertTrue(Path(csv_path).exists())

        backup_path = self.service.backup_database()
        self.assertTrue(Path(backup_path).exists())


if __name__ == "__main__":
    unittest.main()

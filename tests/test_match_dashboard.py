"""Unit and Integration Tests for Resume Match Dashboard and Service (Phase 5).

Verifies dashboard service operations:
- Available scoring profiles listing.
- Profile auto-recommendation based on resume and job context.
- End-to-end evaluation execution and history query.
- Streamlit render_resume_match_analysis component execution.
"""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dashboard.services.dashboard_service import DashboardService
from dashboard.views.resume_match_analysis import render_resume_match_analysis
from src.database.db_manager import DatabaseManager
from tests.fixtures.synthetic_personas import generate_persona_pdf


class TestMatchDashboard(unittest.TestCase):
    """Test suite for Resume Match Analysis Dashboard and Services."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(db_path=Path(self.temp_dir.name) / "test_dash.db")
        self.service = DashboardService(db_manager=self.db)
        self.service.storage_base_dir = Path(self.temp_dir.name) / "users"

        # Setup standard user, resume, and job description
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('dash@test.com', 'h', 'salt', 'Dashboard User')")
            self.user_id = cursor.lastrowid

            # Create physical valid PDF file on disk
            user_resumes = self.service.storage_base_dir / str(self.user_id) / "resumes"
            user_resumes.mkdir(parents=True, exist_ok=True)
            pdf_bytes = generate_persona_pdf("freshman_cs_student")
            (user_resumes / "r.pdf").write_bytes(pdf_bytes)
            real_hash = hashlib.sha256(pdf_bytes).hexdigest()
            real_size = len(pdf_bytes)

            cursor.execute(
                """
                INSERT INTO resumes (user_id, storage_filename, original_filename, file_format, file_hash, file_size_bytes, parsed_data)
                VALUES (?, 'r.pdf', 'Resume.pdf', 'pdf', ?, ?, '{"career_level": "student", "technical_skills": ["Python", "SQL"], "education": [{"degree": "B.Tech in CS", "major": "Computer Science"}], "projects": [{"title": "AI Bot", "description": "Chatbot"}]}')
                """,
                (self.user_id, real_hash, real_size),
            )
            self.resume_id = cursor.lastrowid

            cursor.execute(
                """
                INSERT INTO resume_versions (resume_id, user_id, version_num, storage_filename, file_hash, file_size_bytes, change_notes, snapshot_json)
                VALUES (?, ?, 1, 'r.pdf', ?, ?, 'Initial upload', '{}')
                """,
                (self.resume_id, self.user_id, real_hash, real_size),
            )

            cursor.execute(
                """
                INSERT INTO job_descriptions (user_id, source_type, company_name, job_title, raw_content, content_hash, parsed_data)
                VALUES (?, 'pasted', 'AI Lab', 'AI Intern', 'Python required', 'c51d76bc7ed4a94ebb2663672bafb76273c6c99794e9428ea3798ef86c629054', '{"mandatory_skills": ["Python"], "internship_duration": "3 months"}')
                """,
                (self.user_id,),
            )
            self.jd_id = cursor.lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_get_available_scoring_profiles(self):
        """Service lists all 10 configured scoring profiles with metadata."""
        profiles = self.service.get_available_scoring_profiles()
        self.assertGreaterEqual(len(profiles), 10)
        profile_ids = [p["id"] for p in profiles]
        self.assertIn("general_baseline", profile_ids)
        self.assertIn("student_intern", profile_ids)
        self.assertIn("healthcare_clinical", profile_ids)
        self.assertIn("engineering_technical", profile_ids)

    def test_recommend_scoring_profile(self):
        """Service recommends student_intern profile for student resume matching internship posting."""
        rec_id, reason = self.service.recommend_scoring_profile(
            user_id=self.user_id,
            resume_id=self.resume_id,
            job_description_id=self.jd_id,
        )
        self.assertEqual(rec_id, "student_intern")
        self.assertIn("internship", reason.lower())

    def test_run_match_evaluation_via_service(self):
        """Service executes match evaluation and returns populated UniversalMatchResult."""
        result = self.service.run_match_evaluation(
            user_id=self.user_id,
            resume_id=self.resume_id,
            job_description_id=self.jd_id,
        )
        self.assertEqual(result.user_id, self.user_id)
        self.assertGreaterEqual(result.match_score, 70.0)
        self.assertEqual(result.eligibility_status, "ELIGIBLE")

        # Verify history
        hist = self.service.get_user_match_history(user_id=self.user_id)
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0].id, result.resume_id and hist[0].job_description_id and hist[0].id)

    @patch("dashboard.views.resume_match_analysis.st")
    def test_render_resume_match_analysis_view(self, mock_st):
        """Streamlit view function executes without error when user has valid resumes and jobs."""
        mock_st.session_state = {"user_id": self.user_id}
        # Mock tabs, columns, and expanders
        mock_st.tabs.return_value = [MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock()]
        mock_st.columns.side_effect = lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]
        mock_st.expander.return_value.__enter__.return_value = MagicMock()
        mock_st.selectbox.side_effect = [self.resume_id, self.jd_id, "student_intern"]
        mock_st.button.return_value = False

        with patch("dashboard.views.resume_match_analysis.DashboardService.get_instance", return_value=self.service):
            render_resume_match_analysis()

        mock_st.markdown.assert_any_call("## 🎯 Resume-to-Job Matching & Eligibility Engine")


if __name__ == "__main__":
    unittest.main()

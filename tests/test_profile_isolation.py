"""Tests for Multi-User Candidate Profile Isolation (Phase 6 Preflight Milestone 6.0).
Verifies that candidate profiles are strictly isolated per user account,
with no cross-user leakage or legacy single-user fallback.
"""

from pathlib import Path
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import ValidationError
from src.security.auth import AuthManager


class TestProfileIsolation(unittest.TestCase):
    """Test suite for multi-user profile isolation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_isolation.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.auth = AuthManager(db_manager=self.db)

        # Create two distinct test users
        self.user_a = self.auth.register(
            email="alice@example.com",
            password="AliceSecurePassword123!",
            full_name="Alice Smith",
            profession_industry="Healthcare",
        )
        self.user_b = self.auth.register(
            email="bob@example.com",
            password="BobSecurePassword123!",
            full_name="Bob Jones",
            profession_industry="Engineering",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_new_accounts_start_with_empty_profile(self):
        """Newly created accounts must have no active candidate profile and no fallback."""
        prof_a = self.db.get_user_candidate_profile(self.user_a.id)
        prof_b = self.db.get_user_candidate_profile(self.user_b.id)

        self.assertIsNone(prof_a, "User A should start with no candidate profile.")
        self.assertIsNone(prof_b, "User B should start with no candidate profile.")

        hist_a = self.db.get_user_candidate_profile_history(self.user_a.id)
        hist_b = self.db.get_user_candidate_profile_history(self.user_b.id)
        self.assertEqual(len(hist_a), 0)
        self.assertEqual(len(hist_b), 0)

    def test_user_a_save_does_not_leak_to_user_b(self):
        """Saving a profile for User A must never make it visible or active for User B."""
        profile_data_a = {
            "personal": {
                "full_name": "Alice Smith",
                "email": "alice@example.com",
                "headline": "Registered Nurse",
            },
            "skills": ["Patient Care", "Triage", "EMR"],
            "licenses": [{"name": "Registered Nurse (RN)", "is_confirmed": True}],
        }

        saved_a = self.db.save_user_candidate_profile(self.user_a.id, profile_data_a)
        self.assertIsNotNone(saved_a)
        self.assertEqual(saved_a["user_id"], self.user_a.id)

        # Verify User A has the profile
        retrieved_a = self.db.get_user_candidate_profile(self.user_a.id)
        self.assertIsNotNone(retrieved_a)
        self.assertEqual(retrieved_a["profile_data"]["personal"]["headline"], "Registered Nurse")

        # Verify User B STILL has no profile
        retrieved_b = self.db.get_user_candidate_profile(self.user_b.id)
        self.assertIsNone(retrieved_b, "User B must not receive User A's profile!")

        # Verify history isolation
        hist_a = self.db.get_user_candidate_profile_history(self.user_a.id)
        hist_b = self.db.get_user_candidate_profile_history(self.user_b.id)
        self.assertEqual(len(hist_a), 1)
        self.assertEqual(len(hist_b), 0)

    def test_user_b_independent_profile_and_history(self):
        """User B can save an entirely independent profile with their own version lineage."""
        profile_data_a = {
            "personal": {"full_name": "Alice Smith", "headline": "Registered Nurse"},
            "skills": ["Patient Care"],
        }
        self.db.save_user_candidate_profile(self.user_a.id, profile_data_a)

        profile_data_b = {
            "personal": {
                "full_name": "Bob Jones",
                "email": "bob@example.com",
                "headline": "Mechanical Engineer",
            },
            "skills": ["SolidWorks", "Thermodynamics", "FEA"],
            "licenses": [{"name": "Professional Engineer (PE)", "is_confirmed": True}],
        }

        saved_b = self.db.save_user_candidate_profile(self.user_b.id, profile_data_b)
        self.assertIsNotNone(saved_b)
        self.assertEqual(saved_b["user_id"], self.user_b.id)

        # Verify User B profile
        retrieved_b = self.db.get_user_candidate_profile(self.user_b.id)
        self.assertEqual(retrieved_b["profile_data"]["personal"]["headline"], "Mechanical Engineer")
        self.assertIn("SolidWorks", retrieved_b["profile_data"]["skills"])

        # Verify User A profile is unaffected
        retrieved_a = self.db.get_user_candidate_profile(self.user_a.id)
        self.assertEqual(retrieved_a["profile_data"]["personal"]["headline"], "Registered Nurse")
        self.assertNotIn("SolidWorks", retrieved_a["profile_data"].get("skills", []))

    def test_empty_profile_data_raises_validation_error(self):
        """Attempting to save an empty profile raises ValidationError and does not record."""
        with self.assertRaises(ValidationError):
            self.db.save_user_candidate_profile(self.user_a.id, {})

    def test_dashboard_service_save_scoped_by_user(self):
        """DashboardService.save_candidate_profile with user_id persists to that user only."""
        from dashboard.services.dashboard_service import DashboardService
        service = DashboardService.get_instance()
        service.db = self.db

        prof_data = {
            "personal": {"full_name": "Alice Updated", "email": "alice@example.com"},
            "skills": ["Pediatrics", "Critical Care"],
        }
        succ, msg = service.save_candidate_profile(prof_data, user_id=self.user_a.id)
        self.assertTrue(succ)

        retrieved_a = self.db.get_user_candidate_profile(self.user_a.id)
        self.assertEqual(retrieved_a["profile_data"]["personal"]["full_name"], "Alice Updated")

        retrieved_b = self.db.get_user_candidate_profile(self.user_b.id)
        self.assertIsNone(retrieved_b, "User B profile must remain None.")


if __name__ == "__main__":
    unittest.main()

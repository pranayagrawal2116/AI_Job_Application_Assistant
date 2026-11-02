"""Unit tests for configuration loading, candidate profile integrity, and safety settings."""

import json
import sqlite3
import unittest
from pathlib import Path
import yaml

from src.config import BASE_DIR, CONFIG_DIR, DATA_DIR, AppConfig, load_json, load_yaml


class TestConfiguration(unittest.TestCase):
    """Verifies that all Phase 1 configuration and profile files are valid and complete."""

    def setUp(self):
        self.config = AppConfig()

    def test_config_yaml_loading(self):
        """Checks config.yaml loads with mandatory safety safeguards."""
        config_data = self.config.app
        self.assertEqual(config_data.get("name"), "AI Job Application Assistant")

        safety = self.config._app_config.get("safety_and_compliance", {})
        self.assertTrue(safety.get("require_manual_submission_approval"))
        self.assertFalse(safety.get("allow_automated_submission"))
        self.assertTrue(safety.get("stop_before_submission"))

    def test_scoring_rules_100_points(self):
        """Verifies that matching weights sum exactly to 100 points."""
        weights = self.config.scoring_rules.get("weights", {})
        total_points = sum(w.get("max_points", 0) for w in weights.values())
        self.assertEqual(total_points, 100, f"Expected 100 total points, got {total_points}")

        # Check individual weights
        self.assertEqual(weights["domain_relevance"]["max_points"], 30)
        self.assertEqual(weights["technical_skills"]["max_points"], 25)
        self.assertEqual(weights["educational_eligibility"]["max_points"], 20)
        self.assertEqual(weights["experience_compatibility"]["max_points"], 10)
        self.assertEqual(weights["location_preference"]["max_points"], 10)
        self.assertEqual(weights["duration_compatibility"]["max_points"], 5)

    def test_candidate_profile_integrity(self):
        """Verifies candidate profile values match user provided specification exactly."""
        candidate = self.config.candidate_profile
        edu = candidate.get("education", [])
        self.assertTrue(len(edu) > 0)
        self.assertEqual(edu[0]["institution"], "MIT World Peace University")
        self.assertIn("AI & Data Science", edu[0]["major"])
        self.assertEqual(edu[0]["expected_graduation_year"], 2028)
        self.assertEqual(edu[0]["current_cgpa"], 7.6)

        # Ensure no fabricated experience
        self.assertEqual(candidate.get("work_experience"), [])
        self.assertIn("Fresher", candidate.get("experience_level"))

        # Verify exact projects
        projects = [p["name"] for p in candidate.get("projects", [])]
        self.assertIn("Hospital Management Application", projects)
        self.assertIn("Factory Management Application", projects)
        self.assertIn("Diabetes Risk Prediction using Machine Learning", projects)

    def test_target_roles(self):
        """Checks all target roles are defined in preferences."""
        roles = self.config.target_preferences.get("target_roles", [])
        expected_roles = [
            "AI Intern",
            "Machine Learning Intern",
            "Data Science Intern",
            "Python Developer Intern",
            "Deep Learning Intern",
            "Generative AI Intern",
            "NLP Intern",
            "Computer Vision Intern",
        ]
        for role in expected_roles:
            self.assertIn(role, roles)

    def test_sqlite_schema_validity(self):
        """Verifies the SQLite schema file parses and creates an in-memory database cleanly."""
        schema_path = BASE_DIR / "src" / "database" / "schema.sql"
        self.assertTrue(schema_path.is_file())
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.executescript(schema_sql)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()

        self.assertIn("jobs", tables)
        self.assertIn("application_logs", tables)


if __name__ == "__main__":
    unittest.main()


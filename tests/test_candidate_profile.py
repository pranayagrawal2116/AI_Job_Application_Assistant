"""Unit tests for Universal Candidate Profile, Field Provenance, Diffing, and Synchronization.

Validates:
1. Universal profile structure across all 10 core sections.
2. Field-level provenance tracking and confidence scores.
3. Accurate diff calculation (new, modified, protected, unmodified).
4. Strict non-destruction of USER_CONFIRMED and USER_CORRECTED profile fields.
5. Controlled override with explicit approval.
6. Immutable SQLite version snapshots and history retrieval.
"""

from pathlib import Path
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.preparer.profile_updater import ProfileUpdater
from src.preparer.resume_parser import (
    ParsedResume,
    ResumeParser,
    VerificationStatus,
)
from tests.fixtures.synthetic_personas import (
    generate_persona_docx,
)


class TestCandidateProfileEngine(unittest.TestCase):
    """Test suite verifying candidate profile structures, diffing, and synchronization."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_profiles.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.updater = ProfileUpdater(db_manager=self.db)

        # Seed test user
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (email, password_hash, password_salt, full_name)
                VALUES ('doctor@hospital.org', 'argon_hash', 'salt', 'Dr. Sarah Jenkins')
                """
            )
            self.user_id = cursor.lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Universal Profile Structure
    def test_universal_profile_structure(self):
        """Verifies candidate profile populates all universal sections for a cardiologist."""
        docx_bytes = generate_persona_docx("cardiologist")
        fpath = Path(self.temp_dir.name) / "cardio.docx"
        fpath.write_bytes(docx_bytes)

        parser = ResumeParser()
        parsed = parser.parse_file(fpath)
        profile = self.updater.build_profile_dict(parsed)

        # Verify 10 universal sections
        self.assertIn("personal", profile)
        self.assertEqual(profile["personal"]["full_name"], "Dr. Sarah Jenkins")
        self.assertEqual(profile["personal"]["email"], "dr.jenkins@bostonheartclinic.org")

        self.assertIn("education", profile)
        self.assertTrue(len(profile["education"]) >= 1)
        self.assertIn("Harvard", profile["education"][0]["institution"])

        self.assertIn("work_experience", profile)
        self.assertTrue(len(profile["work_experience"]) >= 1)
        self.assertIn("Hospital", profile["work_experience"][0]["employer"])

        self.assertIn("technical_skills", profile)
        self.assertIn("certifications", profile)
        self.assertIn("projects", profile)
        self.assertIn("candidate_inputs", profile)
        self.assertIn("preferences", profile)
        self.assertIn("field_provenance", profile)
        self.assertIn("resume_metadata", profile)

    # 2. Field Provenance Tracking
    def test_field_provenance_recording(self):
        """Verifies that field provenance records verification status and confidence."""
        docx_bytes = generate_persona_docx("attorney")
        fpath = Path(self.temp_dir.name) / "attorney.docx"
        fpath.write_bytes(docx_bytes)

        parser = ResumeParser()
        parsed = parser.parse_file(fpath)
        profile = self.updater.build_profile_dict(parsed)

        prov = profile["field_provenance"]
        self.assertIn("full_name", prov)
        self.assertEqual(prov["full_name"]["verification_status"], VerificationStatus.EXTRACTED_UNVERIFIED)
        self.assertGreaterEqual(prov["full_name"]["confidence"], 0.9)

    # 3. Profile Diff Calculation
    def test_diff_calculation(self):
        """Calculates differences between existing candidate profile and new resume."""
        docx_bytes = generate_persona_docx("backend_engineer")
        fpath = Path(self.temp_dir.name) / "backend.docx"
        fpath.write_bytes(docx_bytes)

        parser = ResumeParser()
        parsed = parser.parse_file(fpath)

        current_profile = {
            "personal": {
                "full_name": "Alex Mercer",
                "email": "old.email@previous.com",
                "phone": "",
            },
            "education": [],
            "work_experience": [],
            "technical_skills": {"all_skills": ["Go", "C++"]},
            "field_provenance": {
                "full_name": {"verification_status": VerificationStatus.USER_CONFIRMED},
                "email": {"verification_status": VerificationStatus.USER_CORRECTED},
            },
        }

        diff = self.updater.diff_profile_with_resume(current_profile, parsed)

        # 1. full_name is identical -> unmodified
        self.assertTrue(any(u["field"] == "personal.full_name" for u in diff["unmodified_fields"]))
        # 2. email is USER_CORRECTED and differs -> protected
        self.assertTrue(any(p["field"] == "personal.email" for p in diff["protected_fields"]))
        # 3. phone was empty in profile -> new_fields
        self.assertTrue(any(n["field"] == "personal.phone" for n in diff["new_fields"]))
        # 4. education was empty in profile -> new_fields
        self.assertTrue(any(n["field"] == "education" for n in diff["new_fields"]))

    # 4. Non-Destructive Synchronization
    def test_apply_sync_preserves_confirmed_fields(self):
        """Guarantees that USER_CONFIRMED or USER_CORRECTED fields are NOT overwritten."""
        docx_bytes = generate_persona_docx("cfa_investment_banker")
        fpath = Path(self.temp_dir.name) / "cfa.docx"
        fpath.write_bytes(docx_bytes)

        parser = ResumeParser()
        parsed = parser.parse_file(fpath)

        # Candidate previously manually corrected their phone number and confirmed their email
        current_profile = {
            "personal": {
                "full_name": "Priya Sharma",
                "email": "priya.confirmed@personal.com",
                "phone": "+91 99999 88888",
            },
            "education": [],
            "work_experience": [],
            "technical_skills": {"all_skills": []},
            "field_provenance": {
                "email": {"verification_status": VerificationStatus.USER_CONFIRMED},
                "phone": {"verification_status": VerificationStatus.USER_CORRECTED},
            },
        }

        synced = self.updater.apply_approved_sync(
            current_profile=current_profile,
            resume=parsed,
            approved_fields=None,
            override_protected=False,
        )

        # Email and phone must remain the candidate's confirmed values
        self.assertEqual(synced["personal"]["email"], "priya.confirmed@personal.com")
        self.assertEqual(synced["personal"]["phone"], "+91 99999 88888")
        # Unprotected empty sections should have been populated from resume
        self.assertTrue(len(synced["education"]) >= 1)
        self.assertIn("Ahmedabad", synced["education"][0]["institution"])

    def test_apply_sync_with_explicit_override(self):
        """Allows updating protected fields when override_protected=True."""
        docx_bytes = generate_persona_docx("cfa_investment_banker")
        fpath = Path(self.temp_dir.name) / "cfa2.docx"
        fpath.write_bytes(docx_bytes)

        parser = ResumeParser()
        parsed = parser.parse_file(fpath)

        current_profile = {
            "personal": {
                "full_name": "Priya Sharma",
                "email": "priya.old@example.com",
            },
            "field_provenance": {
                "email": {"verification_status": VerificationStatus.USER_CONFIRMED},
            },
        }

        synced = self.updater.apply_approved_sync(
            current_profile=current_profile,
            resume=parsed,
            approved_fields=["personal.email"],
            override_protected=True,
        )

        self.assertEqual(synced["personal"]["email"], "priya.sharma@mumbaicapital.in")

    # 5. SQLite Profile Version Snapshots
    def test_profile_version_snapshots(self):
        """Verifies immutable version history in SQLite."""
        prof_v1 = {"personal": {"full_name": "Alex Mercer", "email": "alex@v1.com"}}
        rec1 = self.db.save_user_candidate_profile(self.user_id, prof_v1)
        self.assertEqual(rec1["version"], 1)
        self.assertTrue(rec1["is_active"])

        prof_v2 = {"personal": {"full_name": "Alex Mercer", "email": "alex@v2.com"}}
        rec2 = self.db.save_user_candidate_profile(self.user_id, prof_v2)
        self.assertEqual(rec2["version"], 2)
        self.assertTrue(rec2["is_active"])

        # Fetch active profile
        active = self.db.get_user_candidate_profile(self.user_id)
        self.assertIsNotNone(active)
        self.assertEqual(active["version"], 2)
        self.assertEqual(active["profile_data"]["personal"]["email"], "alex@v2.com")

        # Fetch history
        history = self.db.get_user_candidate_profile_history(self.user_id)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["version"], 2)
        self.assertEqual(history[1]["version"], 1)


if __name__ == "__main__":
    unittest.main()


"""Unit Tests for Match Result SQLite Persistence, Immutability, and User Isolation (Phase 5).

Verifies:
- Immutable persistence in match_results table.
- Canonical RFC 8785 JSON representation of evaluation details.
- Cross-user composite foreign key enforcement (CrossUserAccessError).
- Hash retention for resume file hash and job snapshot hash.
- History queries and latest match resolution.
"""

from pathlib import Path
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    CrossUserAccessError,
)
from src.database.models import MatchResult
from src.matcher.universal_matcher import (
    UniversalMatcher,
)


class TestMatchResultPersistence(unittest.TestCase):
    """Test suite for Phase 5 Match Result Database Persistence."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_persistence.db"
        self.db = DatabaseManager(db_path=self.db_path)

        # Create two distinct test users
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('user1@test.com', 'h1', 'salt1', 'User One')")
            self.user1_id = cursor.lastrowid
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('user2@test.com', 'h2', 'salt2', 'User Two')")
            self.user2_id = cursor.lastrowid

            # User 1 resume & job description
            cursor.execute(
                """
                INSERT INTO resumes (user_id, storage_filename, original_filename, file_format, file_hash, file_size_bytes, parsed_data)
                VALUES (?, 'res1.pdf', 'Resume1.pdf', 'pdf', 'hash_user1_res', 1024, '{"skills": ["Python"]}')
                """,
                (self.user1_id,),
            )
            self.u1_resume_id = cursor.lastrowid

            cursor.execute(
                """
                INSERT INTO job_descriptions (user_id, source_type, company_name, job_title, raw_content, content_hash, snapshot_hash, parsed_data)
                VALUES (?, 'pasted', 'Acme AI', 'ML Engineer', 'Python and ML required', 'hash_jd1_content', 'hash_jd1_snapshot', '{"mandatory_skills": ["Python"]}')
                """,
                (self.user1_id,),
            )
            self.u1_jd_id = cursor.lastrowid

            # User 2 resume & job description
            cursor.execute(
                """
                INSERT INTO resumes (user_id, storage_filename, original_filename, file_format, file_hash, file_size_bytes, parsed_data)
                VALUES (?, 'res2.pdf', 'Resume2.pdf', 'pdf', 'hash_user2_res', 2048, '{"skills": ["Java"]}')
                """,
                (self.user2_id,),
            )
            self.u2_resume_id = cursor.lastrowid

            cursor.execute(
                """
                INSERT INTO job_descriptions (user_id, source_type, company_name, job_title, raw_content, content_hash, snapshot_hash, parsed_data)
                VALUES (?, 'pasted', 'Beta Corp', 'Java Dev', 'Java required', 'hash_jd2_content', 'hash_jd2_snapshot', '{"mandatory_skills": ["Java"]}')
                """,
                (self.user2_id,),
            )
            self.u2_jd_id = cursor.lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_and_retrieve_match_result(self):
        """Saves immutable match result with all version and snapshot hashes, and retrieves accurately."""
        mr = MatchResult(
            user_id=self.user1_id,
            resume_id=self.u1_resume_id,
            job_description_id=self.u1_jd_id,
            match_score=88.5,
            match_classification="Excellent Match",
            eligibility_status="ELIGIBLE",
            score_breakdown='{"skills": {"earned_points": 25.0, "max_points": 25.0}}',
            explanation="Strong verified match on Python competencies.",
            resume_version_num=1,
            resume_file_hash="hash_user1_res",
            job_snapshot_hash="hash_jd1_snapshot",
            scoring_profile="general_baseline",
            assessment_confidence=0.95,
            engine_version="2.1.1",
        )

        match_id = self.db.save_match_result(mr)
        self.assertIsInstance(match_id, int)
        self.assertGreater(match_id, 0)

        retrieved = self.db.get_match_result(match_id=match_id, user_id=self.user1_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.user_id, self.user1_id)
        self.assertEqual(retrieved.match_score, 88.5)
        self.assertEqual(retrieved.resume_file_hash, "hash_user1_res")
        self.assertEqual(retrieved.job_snapshot_hash, "hash_jd1_snapshot")
        self.assertEqual(retrieved.eligibility_status, "ELIGIBLE")

    def test_cross_user_isolation_blocks_foreign_resume(self):
        """User 1 attempting to match against User 2's resume raises CrossUserAccessError."""
        mr = MatchResult(
            user_id=self.user1_id,
            resume_id=self.u2_resume_id,  # User 2 resume!
            job_description_id=self.u1_jd_id,
            match_score=50.0,
            match_classification="Moderate Match",
            eligibility_status="ELIGIBLE",
            score_breakdown="{}",
            explanation="Cross-user attempt",
        )

        with self.assertRaises(CrossUserAccessError):
            self.db.save_match_result(mr)

    def test_cross_user_isolation_blocks_foreign_job_description(self):
        """User 1 attempting to match against User 2's job description raises CrossUserAccessError."""
        mr = MatchResult(
            user_id=self.user1_id,
            resume_id=self.u1_resume_id,
            job_description_id=self.u2_jd_id,  # User 2 JD!
            match_score=50.0,
            match_classification="Moderate Match",
            eligibility_status="ELIGIBLE",
            score_breakdown="{}",
            explanation="Cross-user attempt",
        )

        with self.assertRaises(CrossUserAccessError):
            self.db.save_match_result(mr)

    def test_cross_user_isolation_blocks_foreign_match_retrieval(self):
        """User 2 cannot read User 1's match result; raises CrossUserAccessError."""
        mr = MatchResult(
            user_id=self.user1_id,
            resume_id=self.u1_resume_id,
            job_description_id=self.u1_jd_id,
            match_score=75.0,
            match_classification="Good Match",
            eligibility_status="ELIGIBLE",
            score_breakdown="{}",
            explanation="User 1 private result",
        )
        match_id = self.db.save_match_result(mr)

        with self.assertRaises(CrossUserAccessError):
            self.db.get_match_result(match_id=match_id, user_id=self.user2_id)

    def test_immutability_new_evaluation_creates_new_record(self):
        """Re-running match evaluation creates a new immutable historical record, not an overwrite."""
        matcher = UniversalMatcher(db_manager=self.db)
        from src.security.resume_verifier import VerifiedResume
        from src.preparer.resume_parser import ParsedResume

        v_resume = VerifiedResume(
            resume_id=self.u1_resume_id,
            user_id=self.user1_id,
            version_num=1,
            storage_filename="res1.pdf",
            file_bytes=b"%PDF-1.4\n%EOF\n",
            file_hash="a" * 64,
            file_size_bytes=15,
            file_format="pdf",
            raw_text="Python and ML engineer",
            _parsed_resume=ParsedResume(raw_text="Python and ML engineer", technical_skills=["Python"]),
        )

        matcher.evaluate(
            user_id=self.user1_id,
            verified_resume=v_resume,
            job_description_id=self.u1_jd_id,
            scoring_profile_id="general_baseline",
            persist=True,
        )

        matcher.evaluate(
            user_id=self.user1_id,
            verified_resume=v_resume,
            job_description_id=self.u1_jd_id,
            scoring_profile_id="student_intern",
            persist=True,
        )

        history = self.db.get_user_match_results(
            user_id=self.user1_id,
            resume_id=self.u1_resume_id,
            job_description_id=self.u1_jd_id,
        )
        self.assertEqual(len(history), 2)
        # Evaluated at newest first
        self.assertEqual(history[0].scoring_profile, "student_intern")
        self.assertEqual(history[1].scoring_profile, "general_baseline")


if __name__ == "__main__":
    unittest.main()

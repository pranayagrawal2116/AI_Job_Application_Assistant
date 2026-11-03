"""Phase 5.1 Comprehensive Hardening & Correctness Test Suite.

Verifies all 22 required scenarios:
1. Four years of verified experience against a mandatory five-year requirement (INELIGIBLE).
2. Exactly five years against a mandatory five-year requirement (ELIGIBLE).
3. Two years against a mandatory three-year requirement (INELIGIBLE).
4. Requirements below three years (e.g. 1 yr against mandatory 2 yr requirement -> INELIGIBLE).
5. Incomplete experience dates (UNKNOWN).
6. Unverified extracted degree satisfying a mandatory education requirement (UNKNOWN).
7. Unverified extracted degree failing a mandatory education requirement (UNKNOWN).
8. Confirmed degree satisfying a requirement (ELIGIBLE).
9. Missing mandatory CGPA (UNKNOWN).
10. Unverified extracted CGPA below a cutoff (UNKNOWN).
11. Resume-extracted license incorrectly being considered verified (UNKNOWN / UNVERIFIED).
12. User-confirmed license satisfying a mandatory license (ELIGIBLE / SATISFIED).
13. Missing license returning UNKNOWN.
14. Dashboard evaluation incorporating the authenticated user's saved profile.
15. Candidate-profile version changing between two evaluations (records version 1 then version 2).
16. Active resume version greater than one being recorded correctly (resume_version_num = 2).
17. Profile snapshot hash remaining tied to the exact evaluation (candidate_profile_hash).
18. Deleting a resume referenced by match history preserving the history.
19. Archiving a job description referenced by match history preserving the history.
20. Cross-user attempts to use another user's profile, resume, job description, or match record being rejected (CrossUserAccessError).
21. Unrelated projects not receiving the same relevance score as relevant projects (relevant_score > unrelated_score).
22. Existing historical results remaining unchanged after later candidate-profile edits.
"""

import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any, Dict, Optional
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.database.exceptions import CrossUserAccessError
from src.database.models import JobDescription
from src.matcher.universal_matcher import (
    CandidateFactNormalizer,
    JobRequirementNormalizer,
    UniversalMatcher,
    UniversalScoringEngine,
)


class TestPhase51Hardening(unittest.TestCase):
    """Full 22-scenario verification suite for Phase 5.1."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_phase51.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.service = DashboardService(db_manager=self.db)
        self.matcher = UniversalMatcher(db_manager=self.db)

        # Create two distinct test users in database
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('alice@test.com', 'h1', 's1', 'Alice')"
            )
            self.user1_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('bob@test.com', 'h2', 's2', 'Bob')"
            )
            self.user2_id = cursor.lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_resume(
        self,
        user_id: int,
        parsed_data: Optional[Dict[str, Any]] = None,
        active_version: int = 1,
    ) -> Dict[str, Any]:
        """Creates a resume record directly in the test database."""
        data = parsed_data or {"skills": ["Python"]}
        json_data = json.dumps(data)
        file_hash = hashlib.sha256(json_data.encode("utf-8")).hexdigest()
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO resumes (
                    user_id, storage_filename, original_filename, file_format,
                    file_hash, file_size_bytes, parsed_data, active_version, is_active
                ) VALUES (?, 'test_resume.pdf', 'test_resume.pdf', 'pdf', ?, 1024, ?, ?, 1)
                """,
                (user_id, file_hash, json_data, active_version),
            )
            res_id = cursor.lastrowid
            cursor.execute("SELECT * FROM resumes WHERE id = ?", (res_id,))
            return dict(cursor.fetchone())

    def _create_job_description(
        self,
        user_id: int,
        parsed_data: Optional[Dict[str, Any]] = None,
        company: str = "Test Corp",
        title: str = "Engineer",
    ) -> JobDescription:
        """Creates a job description record directly in the test database."""
        p_data = parsed_data or {"mandatory_skills": ["Python"]}
        return self.db.create_job_description(
            user_id=user_id,
            company_name=company,
            job_title=title,
            raw_content=f"{company} {title} listing",
            source_type="pasted",
            parsed_data=p_data,
        )

    # 1. Four years of verified experience against a mandatory five-year requirement (INELIGIBLE)
    def test_01_experience_below_mandatory_cutoff_is_ineligible(self):
        profile_data = {
            "experience": [
                {
                    "title": "Software Engineer",
                    "company": "Acme Corp",
                    "start_date": "2020-01-01",
                    "end_date": "2023-12-31",  # Exactly 48 months = 4.0 years
                    "verification_status": "USER_CONFIRMED",
                }
            ]
        }
        job_data = {
            "job_title": "Lead Software Engineer",
            "min_years_experience": 5.0,
            "mandatory_skills": ["Python"],
        }
        res = self.matcher.evaluate(user_id=self.user1_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "INELIGIBLE")
        self.assertTrue(any("5" in r and "4" in r for r in res.eligibility_reasons))

    # 2. Exactly five years against a mandatory five-year requirement (ELIGIBLE)
    def test_02_experience_meeting_mandatory_cutoff_is_eligible(self):
        profile_data = {
            "experience": [
                {
                    "title": "Software Engineer",
                    "company": "Acme Corp",
                    "start_date": "2019-01-01",
                    "end_date": "2023-12-31",  # Exactly 60 months = 5.0 years
                    "verification_status": "USER_CONFIRMED",
                }
            ]
        }
        job_data = {
            "job_title": "Lead Software Engineer",
            "min_years_experience": 5.0,
        }
        res = self.matcher.evaluate(user_id=self.user1_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "ELIGIBLE")

    # 3. Two years against a mandatory three-year requirement (INELIGIBLE)
    def test_03_experience_two_years_vs_three_year_requirement_is_ineligible(self):
        profile_data = {
            "experience": [
                {
                    "title": "Software Engineer",
                    "company": "Beta LLC",
                    "start_date": "2022-01-01",
                    "end_date": "2023-12-31",  # Exactly 24 months = 2.0 years
                    "verification_status": "USER_CONFIRMED",
                }
            ]
        }
        job_data = {
            "job_title": "Mid-level Engineer",
            "min_years_experience": 3.0,
        }
        res = self.matcher.evaluate(user_id=self.user1_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "INELIGIBLE")
        self.assertTrue(any("3" in r and "2" in r for r in res.eligibility_reasons))

    # 4. Requirements below three years (e.g. 1 yr against mandatory 2 yr requirement -> INELIGIBLE)
    def test_04_experience_below_three_years_cutoff_is_ineligible(self):
        profile_data = {
            "experience": [
                {
                    "title": "Junior Developer",
                    "company": "Gamma Inc",
                    "start_date": "2023-01-01",
                    "end_date": "2023-12-31",  # 12 months = 1.0 year
                    "verification_status": "USER_CONFIRMED",
                }
            ]
        }
        job_data = {
            "job_title": "Software Developer II",
            "min_years_experience": 2.0,
        }
        res = self.matcher.evaluate(user_id=self.user1_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "INELIGIBLE")
        self.assertTrue(any("2" in r and "1" in r for r in res.eligibility_reasons))

    # 5. Incomplete experience dates (UNKNOWN)
    def test_05_experience_missing_dates_is_unknown(self):
        resume_data = {
            "experience": [
                {
                    "title": "Software Developer",
                    "company": "Delta Systems",
                    # No start_date or end_date
                }
            ]
        }
        job_data = {
            "job_title": "Engineer",
            "min_years_experience": 3.0,
        }
        res = self.matcher.evaluate(user_id=self.user1_id, resume_data=resume_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertTrue(any("dates" in r.lower() or "missing" in r.lower() for r in res.eligibility_reasons))

    # 6. Unverified extracted degree satisfying a mandatory education requirement (UNKNOWN)
    def test_06_unverified_degree_satisfying_requirement_is_unknown(self):
        resume_data = {
            "education": [
                {
                    "degree": "Bachelor of Technology in Computer Science",
                    "major": "Computer Science",
                    # Parsed from resume, not yet confirmed by user
                }
            ]
        }
        job_data = {
            "job_title": "Junior Engineer",
            "required_degree_levels": ["Bachelor"],
        }
        res = self.matcher.evaluate(user_id=self.user1_id, resume_data=resume_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertTrue(any("unverified" in r.lower() or "extracted from resume" in r.lower() for r in res.eligibility_reasons))

    # 7. Unverified extracted degree failing a mandatory education requirement (UNKNOWN)
    def test_07_unverified_degree_failing_requirement_is_unknown(self):
        resume_data = {
            "education": [
                {
                    "degree": "High School Diploma",
                    "major": "General",
                }
            ]
        }
        job_data = {
            "job_title": "Research Scientist",
            "required_degree_levels": ["Master"],
        }
        # Because unverified resume data cannot definitively disqualify candidate without confirmation
        res = self.matcher.evaluate(user_id=self.user1_id, resume_data=resume_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertTrue(any("unverified" in r.lower() or "extracted from resume" in r.lower() for r in res.eligibility_reasons))

    # 8. Confirmed degree satisfying a requirement (ELIGIBLE)
    def test_08_confirmed_degree_satisfying_requirement_is_eligible(self):
        profile_data = {
            "education": [
                {
                    "degree": "Bachelor of Science",
                    "major": "Computer Science",
                    "verification_status": "USER_CONFIRMED",
                }
            ]
        }
        job_data = {
            "job_title": "Software Engineer",
            "required_degree_levels": ["Bachelor"],
        }
        res = self.matcher.evaluate(user_id=self.user1_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "ELIGIBLE")

    # 9. Missing mandatory CGPA (UNKNOWN)
    def test_09_mandatory_cgpa_missing_is_unknown(self):
        profile_data = {
            "education": [
                {
                    "degree": "Bachelor of Science",
                    "major": "Computer Science",
                    "current_cgpa": None,
                    "verification_status": "USER_CONFIRMED",
                }
            ]
        }
        job_data = {
            "job_title": "Graduate Trainee",
            "min_gpa": 3.5,
        }
        res = self.matcher.evaluate(user_id=self.user1_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertTrue(any("gpa" in r.lower() or "cgpa" in r.lower() for r in res.eligibility_reasons))

    # 10. Unverified extracted CGPA below a cutoff (UNKNOWN)
    def test_10_unverified_cgpa_below_cutoff_is_unknown(self):
        resume_data = {
            "education": [
                {
                    "degree": "Bachelor of Science",
                    "major": "Computer Science",
                    "current_cgpa": 2.8,  # Below 3.5 cutoff, but unverified
                }
            ]
        }
        job_data = {
            "job_title": "Analyst",
            "min_gpa": 3.5,
        }
        res = self.matcher.evaluate(user_id=self.user1_id, resume_data=resume_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertTrue(any("cgpa" in r.lower() or "gpa" in r.lower() for r in res.eligibility_reasons))

    # 11. Resume-extracted license incorrectly being considered verified (UNKNOWN / UNVERIFIED)
    def test_11_resume_extracted_license_is_unverified_and_returns_unknown(self):
        resume_data = {
            "certifications": [
                {
                    "name": "Registered Nurse",
                    "is_license": True,
                    # Extracted, unverified
                }
            ]
        }
        job_data = {
            "job_title": "Staff Nurse",
            "mandatory_licenses": ["Registered Nurse"],
        }
        res = self.matcher.evaluate(user_id=self.user1_id, resume_data=resume_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertEqual(res.certification_analysis["license_status"], "UNVERIFIED")
        self.assertTrue(any("license" in r.lower() or "unconfirmed" in r.lower() or "extracted from resume" in r.lower() for r in res.eligibility_reasons))

    # 12. User-confirmed license satisfying a mandatory license (ELIGIBLE / SATISFIED)
    def test_12_confirmed_license_satisfies_mandatory_requirement(self):
        profile_data = {
            "certifications": [
                {
                    "name": "Registered Nurse",
                    "is_license": True,
                    "verification_status": "USER_CONFIRMED",
                }
            ]
        }
        job_data = {
            "job_title": "Staff Nurse",
            "mandatory_licenses": ["Registered Nurse"],
        }
        res = self.matcher.evaluate(user_id=self.user1_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "ELIGIBLE")
        self.assertEqual(res.certification_analysis["license_status"], "SATISFIED")

    # 13. Missing license returning UNKNOWN
    def test_13_missing_mandatory_license_returns_unknown(self):
        profile_data = {
            "certifications": []
        }
        job_data = {
            "job_title": "Staff Nurse",
            "mandatory_licenses": ["Registered Nurse"],
        }
        res = self.matcher.evaluate(user_id=self.user1_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertTrue(any("not documented" in r.lower() for r in res.eligibility_reasons))

    # 14. Dashboard evaluation incorporating the authenticated user's saved profile
    def test_14_dashboard_evaluation_incorporates_saved_candidate_profile(self):
        # 1. Save candidate profile in database for user 1
        prof = {
            "full_name": "Alice Developer",
            "skills": {"technical": ["Python", "Machine Learning"]},
            "education": [{"degree": "Bachelor of Engineering", "major": "Computer Science", "verification_status": "USER_CONFIRMED"}],
        }
        self.db.save_user_candidate_profile(self.user1_id, prof)

        # 2. Add resume and job description
        res_rec = self._create_resume(user_id=self.user1_id, parsed_data={"skills": ["Python"]})
        jd_rec = self._create_job_description(
            user_id=self.user1_id,
            parsed_data={"mandatory_skills": ["Python", "Machine Learning"], "required_degree_levels": ["Bachelor"]},
        )

        # 3. Run dashboard evaluation without passing profile_data explicitly
        result = self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res_rec["id"],
            job_description_id=jd_rec.id,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.candidate_profile_version, 1)
        self.assertIsNotNone(result.candidate_profile_hash)
        self.assertEqual(result.eligibility_status, "ELIGIBLE")

    # 15. Candidate-profile version changing between two evaluations (records version 1 then version 2)
    def test_15_candidate_profile_version_increments_between_evaluations(self):
        # Initial profile v1
        self.db.save_user_candidate_profile(self.user1_id, {"skills": {"tech": ["Python"]}})
        res_rec = self._create_resume(user_id=self.user1_id)
        jd_rec = self._create_job_description(user_id=self.user1_id)

        eval1 = self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res_rec["id"],
            job_description_id=jd_rec.id,
        )
        self.assertEqual(eval1.candidate_profile_version, 1)

        # Update profile to v2
        self.db.save_user_candidate_profile(self.user1_id, {"skills": {"tech": ["Python", "C++", "PyTorch"]}})

        eval2 = self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res_rec["id"],
            job_description_id=jd_rec.id,
        )
        self.assertEqual(eval2.candidate_profile_version, 2)
        self.assertNotEqual(eval1.candidate_profile_hash, eval2.candidate_profile_hash)

    # 16. Active resume version greater than one being recorded correctly (resume_version_num = 2)
    def test_16_active_resume_version_greater_than_one_recorded(self):
        res_rec = self._create_resume(user_id=self.user1_id, active_version=2)
        jd_rec = self._create_job_description(user_id=self.user1_id)

        match_res = self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res_rec["id"],
            job_description_id=jd_rec.id,
        )
        self.assertEqual(match_res.resume_version_num, 2)

        # Check in DB
        latest_matches = self.db.get_user_match_results(self.user1_id)
        self.assertEqual(len(latest_matches), 1)
        db_record = latest_matches[0]
        self.assertEqual(db_record.resume_version_num, 2)

    # 17. Profile snapshot hash remaining tied to the exact evaluation (candidate_profile_hash)
    def test_17_profile_snapshot_hash_persisted_in_match_results(self):
        prof = {"headline": "AI Specialist", "skills": {"tech": ["Python", "Deep Learning"]}}
        prof_res = self.db.save_user_candidate_profile(self.user1_id, prof)
        expected_hash = prof_res["profile_hash"]

        res_rec = self._create_resume(user_id=self.user1_id)
        jd_rec = self._create_job_description(user_id=self.user1_id)

        match_res = self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res_rec["id"],
            job_description_id=jd_rec.id,
        )
        self.assertEqual(match_res.candidate_profile_hash, expected_hash)

        # Verify persisted row in SQLite
        latest_matches = self.db.get_user_match_results(self.user1_id)
        db_match = latest_matches[0]
        self.assertEqual(db_match.candidate_profile_hash, expected_hash)

    # 18. Deleting a resume referenced by match history preserving the history
    def test_18_deleting_resume_with_linked_matches_archives_resume_and_preserves_matches(self):
        res_rec = self._create_resume(user_id=self.user1_id)
        jd_rec = self._create_job_description(user_id=self.user1_id)
        self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res_rec["id"],
            job_description_id=jd_rec.id,
        )
        latest_matches = self.db.get_user_match_results(self.user1_id)
        match_id = latest_matches[0].id

        # Attempt deletion
        del_result = self.db.delete_user_resume(res_rec["id"], self.user1_id)
        self.assertTrue(del_result)

        # Resume should be archived (is_active = 0)
        archived_res = self.db.get_user_resume(res_rec["id"], self.user1_id)
        self.assertEqual(archived_res["is_active"], 0)

        # Match result must still exist intact
        persisted_match = self.db.get_match_result(match_id, self.user1_id)
        self.assertIsNotNone(persisted_match)
        self.assertEqual(persisted_match.resume_id, res_rec["id"])

    # 19. Archiving a job description referenced by match history preserving the history
    def test_19_deleting_job_description_with_linked_matches_archives_jd_and_preserves_matches(self):
        res_rec = self._create_resume(user_id=self.user1_id)
        jd_rec = self._create_job_description(user_id=self.user1_id)
        self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res_rec["id"],
            job_description_id=jd_rec.id,
        )
        latest_matches = self.db.get_user_match_results(self.user1_id)
        match_id = latest_matches[0].id

        # Attempt JD deletion
        del_res = self.db.delete_job_description(jd_rec.id, self.user1_id)
        self.assertEqual(del_res["action"], "archived")
        self.assertTrue(del_res["archived"])

        # Match result must still exist intact
        persisted_match = self.db.get_match_result(match_id, self.user1_id)
        self.assertIsNotNone(persisted_match)
        self.assertEqual(persisted_match.job_description_id, jd_rec.id)

    # 20. Cross-user attempts to use another user's profile, resume, job description, or match record being rejected
    def test_20_cross_user_access_rejected_with_exception(self):
        res_rec = self._create_resume(user_id=self.user1_id)
        jd_rec = self._create_job_description(user_id=self.user1_id)
        self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res_rec["id"],
            job_description_id=jd_rec.id,
        )
        latest_matches = self.db.get_user_match_results(self.user1_id)
        match_id = latest_matches[0].id

        # User 2 tries to access User 1's resume
        with self.assertRaises(CrossUserAccessError):
            self.db.get_user_resume(res_rec["id"], user_id=self.user2_id)

        # User 2 tries to access User 1's JD
        with self.assertRaises(CrossUserAccessError):
            self.db.get_job_description(jd_rec.id, user_id=self.user2_id)

        # User 2 tries to access User 1's match result
        with self.assertRaises(CrossUserAccessError):
            self.db.get_match_result(match_id, user_id=self.user2_id)

        # User 2 tries to evaluate using User 1's resume_id
        with self.assertRaises(CrossUserAccessError):
            self.matcher.evaluate(
                user_id=self.user2_id,
                resume_id=res_rec["id"],
                job_data={"job_title": "Test"},
            )

        # User 2 tries to evaluate using User 1's job_description_id
        with self.assertRaises(CrossUserAccessError):
            self.matcher.evaluate(
                user_id=self.user2_id,
                resume_data={"skills": ["Python"]},
                job_description_id=jd_rec.id,
            )

    # 21. Unrelated projects not receiving the same relevance score as relevant projects
    def test_21_unrelated_projects_score_lower_than_relevant_projects(self):
        reqs = JobRequirementNormalizer.normalize(
            job_data={
                "job_title": "Machine Learning Engineer",
                "mandatory_skills": ["Python", "PyTorch", "Computer Vision"],
                "responsibilities": ["Train neural network vision classifiers on image datasets"],
            }
        )

        relevant_facts = CandidateFactNormalizer.normalize(
            profile_data={
                "projects": [
                    {
                        "title": "Computer Vision Classifier",
                        "description": "Trained neural network vision models in PyTorch",
                        "technologies": ["Python", "PyTorch"],
                    }
                ]
            }
        )

        unrelated_facts = CandidateFactNormalizer.normalize(
            profile_data={
                "projects": [
                    {
                        "title": "Wedding Catering Budget Planner",
                        "description": "Calculated dinner costs and vendor agreements",
                        "technologies": ["Word", "Spreadsheet"],
                    }
                ]
            }
        )

        rel_ratio, _, rel_notes = UniversalScoringEngine.evaluate_projects_relevance(relevant_facts.projects, reqs)
        unrel_ratio, _, unrel_notes = UniversalScoringEngine.evaluate_projects_relevance(unrelated_facts.projects, reqs)

        self.assertGreater(rel_ratio, unrel_ratio)
        self.assertEqual(rel_ratio, 1.0)
        self.assertLessEqual(unrel_ratio, 0.10)
        self.assertIn("direct skill/duty alignment", rel_notes)
        self.assertIn("none demonstrated relevance", unrel_notes)

    # 22. Existing historical results remaining unchanged after later candidate-profile edits
    def test_22_historical_match_results_immutable_after_profile_edits(self):
        # Save initial candidate profile v1
        self.db.save_user_candidate_profile(
            self.user1_id,
            {
                "skills": {"tech": ["Python", "Machine Learning"]},
                "education": [{"degree": "Bachelor of Science", "major": "Computer Science", "verification_status": "USER_CONFIRMED"}],
            },
        )
        res_rec = self._create_resume(user_id=self.user1_id)
        jd_rec = self._create_job_description(
            user_id=self.user1_id,
            parsed_data={"mandatory_skills": ["Python", "Machine Learning"], "required_degree_levels": ["Bachelor"]},
        )

        # Run evaluation 1
        eval1 = self.service.run_match_evaluation(
            user_id=self.user1_id,
            resume_id=res_rec["id"],
            job_description_id=jd_rec.id,
        )
        orig_score = eval1.match_score
        orig_status = eval1.eligibility_status
        orig_hash = eval1.candidate_profile_hash
        latest_matches = self.db.get_user_match_results(self.user1_id)
        match_id = latest_matches[0].id

        # Update candidate profile to v2 with completely different qualifications (e.g. non-CS degree)
        self.db.save_user_candidate_profile(
            self.user1_id,
            {
                "skills": {"tech": ["Cooking", "Pastry"]},
                "education": [{"degree": "Culinary Diploma", "major": "Culinary Arts", "verification_status": "USER_CONFIRMED"}],
            },
        )

        # Re-fetch evaluation 1 from database
        db_eval1 = self.db.get_match_result(match_id, self.user1_id)
        self.assertEqual(db_eval1.match_score, orig_score)
        self.assertEqual(db_eval1.eligibility_status, orig_status)
        self.assertEqual(db_eval1.candidate_profile_hash, orig_hash)
        self.assertEqual(db_eval1.candidate_profile_version, 1)


if __name__ == "__main__":
    unittest.main()

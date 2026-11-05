"""Phase 5.1.1 Candidate Profile & Matching Pipeline Integration Test Suite.

Exhaustively verifies:
1. Actual candidate profile skill ingestion (categorized technical_skills, professional_skills,
   soft_skills, tools_and_software, languages, deduplication, and confirmed profile skills
   matched even when absent from resume).
2. Explicit user-confirmation semantics (empty provenance stays unverified, EXTRACTED_UNVERIFIED,
   manually confirmed education/CGPA/employment/skills/licenses, and non-overwriting sync).
3. Experience date preservation through pipeline (ResumeParser -> ProfileUpdater ->
   CandidateFactNormalizer -> UniversalEligibilityEvaluator, range splitting, and overlap merging).
4. Mixed verified/unverified experience eligibility (12m conf + 6m unverified vs 24m -> UNKNOWN;
   confirmed >= cutoff -> ELIGIBLE; confirmed complete shortfall -> INELIGIBLE;
   incomplete history -> UNKNOWN).
5. End-to-end database persistence and audit hash tracking.
"""

import hashlib
from pathlib import Path
import tempfile
import unittest

from dashboard.services.dashboard_service import DashboardService
from src.database.db_manager import DatabaseManager
from src.matcher.terminology import split_date_range
from src.matcher.universal_matcher import (
    CandidateFactNormalizer,
    UniversalMatcher,
)
from src.preparer.profile_updater import ProfileUpdater
from src.preparer.resume_parser import (
    ExperienceEntry,
    EducationEntry,
    ParsedResume,
)
from tests.fixtures.synthetic_personas import generate_persona_pdf


class TestProfileAndMatchingPipeline(unittest.TestCase):
    """Full integration tests for Candidate Profile data structures, confirmation semantics, and matching."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_base = Path(self.temp_dir.name) / "users"
        self.db_path = Path(self.temp_dir.name) / "test_pipeline.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.service = DashboardService(db_manager=self.db, storage_base_dir=self.storage_base)
        self.matcher = UniversalMatcher(db_manager=self.db)

        # Setup test user
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('tester@domain.com', 'h1', 's1', 'Test Candidate')"
            )
            self.user_id = cursor.lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    # =========================================================================
    # 1. ACTUAL CANDIDATE PROFILE SKILL INGESTION
    # =========================================================================

    def test_01_actual_profile_editor_skill_structures_ingested(self):
        """Verifies skills from categorized technical_skills dict, professional_skills, tools, and languages."""
        profile_data = {
            "technical_skills": {
                "programming_languages": ["Python", "Dart", "C++"],
                "mobile_development": ["Flutter"],
                "databases": ["PostgreSQL", "SQLite"],
                "all_skills": ["Python", "Dart", "C++", "Flutter", "PostgreSQL", "SQLite", "Git"],
            },
            "professional_skills": ["Agile Project Management", "System Architecture"],
            "soft_skills": ["Cross-functional Teamwork", "Communication"],
            "tools_and_software": ["Docker", "Kubernetes", "VS Code"],
            "languages": ["English", "Hindi"],
            "field_provenance": {
                "technical_skills": {"verification_status": "USER_CONFIRMED"},
                "professional_skills": {"verification_status": "USER_CONFIRMED"},
                "tools_and_software": {"verification_status": "USER_CONFIRMED"},
            },
        }

        facts = CandidateFactNormalizer.normalize(profile_data=profile_data)

        # Verify all categorized skills are normalized into facts.skills
        self.assertIn("python", facts.skills)
        self.assertIn("flutter", facts.skills)
        self.assertIn("postgresql", facts.skills)
        self.assertIn("docker", facts.skills)
        self.assertIn("agile project management", facts.skills)
        self.assertIn("cross-functional teamwork", facts.skills)
        self.assertIn("english", facts.skills)

        # Verify confirmed skills retain USER_CONFIRMED status
        self.assertEqual(facts.skills["python"].verification_status, "USER_CONFIRMED")
        self.assertTrue(facts.skills["python"].is_confirmed)
        self.assertEqual(facts.skills["flutter"].verification_status, "USER_CONFIRMED")
        self.assertEqual(facts.skills["docker"].verification_status, "USER_CONFIRMED")

    def test_02_deduplicated_skills_preserve_highest_confirmation_and_provenance(self):
        """When a skill appears in multiple sections or resume, user-confirmed profile status wins."""
        profile_data = {
            "technical_skills": {
                "programming_languages": ["Python"],
                "all_skills": ["Python"],
            },
            "field_provenance": {
                "technical_skills": {"verification_status": "USER_CONFIRMED"},
            },
        }
        resume_data = {
            "technical_skills": ["Python", "Unverified Skill"],
        }

        facts = CandidateFactNormalizer.normalize(resume_data=resume_data, profile_data=profile_data)

        # Python appears in profile (confirmed) and resume (unverified)
        self.assertIn("python", facts.skills)
        self.assertEqual(facts.skills["python"].verification_status, "USER_CONFIRMED")
        self.assertTrue(facts.skills["python"].is_confirmed)
        self.assertIn("profile.technical_skills", facts.skills["python"].provenance_field)

        # Unverified skill remains EXTRACTED_UNVERIFIED
        self.assertIn("unverified skill", facts.skills)
        self.assertEqual(facts.skills["unverified skill"].verification_status, "EXTRACTED_UNVERIFIED")
        self.assertFalse(facts.skills["unverified skill"].is_confirmed)

    def test_03_confirmed_profile_skills_evaluated_even_when_absent_from_resume(self):
        """Candidate-confirmed skills in profile must match job requirements even if not in selected resume."""
        profile_data = {
            "technical_skills": {
                "all_skills": ["Python", "Docker", "PyTorch"],
            },
            "field_provenance": {
                "technical_skills": {"verification_status": "USER_CONFIRMED"},
            },
            "education": [{"degree": "Bachelor of Science", "major": "Computer Science", "verification_status": "USER_CONFIRMED"}],
        }
        # Selected resume has ONLY basic skills, omitting PyTorch and Docker
        resume_data = {
            "technical_skills": ["Python"],
        }
        job_data = {
            "job_title": "ML Engineer",
            "mandatory_skills": ["Python", "Docker", "PyTorch"],
            "required_degree_levels": ["Bachelor"],
        }

        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data=resume_data,
            profile_data=profile_data,
            job_data=job_data,
            persist=False,
        )

        # PyTorch and Docker from confirmed profile must match the job requirement
        matched_job_skills = [sa.job_skill for sa in res.skills_assessment if sa.classification == "EXACT_MATCH"]
        self.assertIn("Python", matched_job_skills)
        self.assertIn("Docker", matched_job_skills)
        self.assertIn("PyTorch", matched_job_skills)
        self.assertEqual(res.eligibility_status, "ELIGIBLE")

    # =========================================================================
    # 2. EXPLICIT USER-CONFIRMATION SEMANTICS
    # =========================================================================

    def test_04_imported_profile_with_empty_provenance_stays_unverified(self):
        """Imported profile with empty field_provenance dictionary must not be auto-verified."""
        profile_data = {
            "education": [{"degree": "Bachelor of Engineering", "major": "CS"}],
            "field_provenance": {},  # Explicitly empty provenance
        }
        job_data = {
            "job_title": "Software Engineer",
            "required_degree_levels": ["Bachelor"],
        }

        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data=profile_data,
            job_data=job_data,
            persist=False,
        )

        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertTrue(any("unverified" in r.lower() for r in res.eligibility_reasons))

    def test_05_imported_profile_with_extracted_unverified_provenance_stays_unverified(self):
        """Profile with EXTRACTED_UNVERIFIED provenance returns UNKNOWN for mandatory criteria."""
        profile_data = {
            "education": [{"degree": "Bachelor of Technology", "major": "IT", "verification_status": "EXTRACTED_UNVERIFIED"}],
            "field_provenance": {
                "education": {"verification_status": "EXTRACTED_UNVERIFIED"},
            },
        }
        job_data = {
            "job_title": "IT Analyst",
            "required_degree_levels": ["Bachelor"],
        }

        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data=profile_data,
            job_data=job_data,
            persist=False,
        )

        self.assertEqual(res.eligibility_status, "UNKNOWN")

    def test_06_manually_confirmed_education_satisfies_requirement(self):
        """Manually confirmed education entry satisfies mandatory degree requirement (ELIGIBLE)."""
        profile_data = {
            "education": [
                {
                    "degree": "Bachelor of Science in Computer Science",
                    "major": "Computer Science",
                    "verification_status": "USER_CONFIRMED",
                }
            ],
            "field_provenance": {
                "education": {"verification_status": "USER_CONFIRMED"},
            },
        }
        job_data = {
            "job_title": "Developer",
            "required_degree_levels": ["Bachelor"],
        }

        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data=profile_data,
            job_data=job_data,
            persist=False,
        )

        self.assertEqual(res.eligibility_status, "ELIGIBLE")

    def test_07_manually_confirmed_cgpa_satisfies_cutoff(self):
        """Manually confirmed CGPA evaluated against employer cutoff."""
        profile_data = {
            "education": [
                {
                    "degree": "B.Tech",
                    "major": "CS",
                    "current_cgpa": 8.5,
                    "verification_status": "USER_CONFIRMED",
                }
            ],
            "field_provenance": {
                "education": {"verification_status": "USER_CONFIRMED"},
                "current_cgpa": {"verification_status": "USER_CONFIRMED"},
            },
        }
        job_data = {
            "job_title": "Junior Engineer",
            "min_gpa": 7.5,
            "required_degree_levels": ["Bachelor"],
        }

        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data=profile_data,
            job_data=job_data,
            persist=False,
        )

        self.assertEqual(res.eligibility_status, "ELIGIBLE")

    def test_08_statutory_license_confirmed_vs_unverified(self):
        """User-confirmed statutory license returns SATISFIED/ELIGIBLE; unverified returns UNVERIFIED/UNKNOWN."""
        job_data = {
            "job_title": "Staff Nurse",
            "mandatory_licenses": ["Registered Nurse"],
        }

        # 1. Confirmed license
        conf_profile = {
            "certifications": [
                {
                    "name": "Registered Nurse",
                    "is_license": True,
                    "verification_status": "USER_CONFIRMED",
                }
            ],
            "field_provenance": {"certifications": {"verification_status": "USER_CONFIRMED"}},
        }
        res_conf = self.matcher.evaluate(user_id=self.user_id, profile_data=conf_profile, job_data=job_data, persist=False)
        self.assertEqual(res_conf.eligibility_status, "ELIGIBLE")
        self.assertEqual(res_conf.certification_analysis["license_status"], "SATISFIED")

        # 2. Unverified license from resume
        unconf_profile = {
            "certifications": [
                {
                    "name": "Registered Nurse",
                    "is_license": True,
                    "verification_status": "EXTRACTED_UNVERIFIED",
                }
            ],
            "field_provenance": {"certifications": {"verification_status": "EXTRACTED_UNVERIFIED"}},
        }
        res_unconf = self.matcher.evaluate(user_id=self.user_id, profile_data=unconf_profile, job_data=job_data, persist=False)
        self.assertEqual(res_unconf.eligibility_status, "UNKNOWN")
        self.assertEqual(res_unconf.certification_analysis["license_status"], "UNVERIFIED")

    def test_09_resume_sync_does_not_overwrite_confirmed_fields(self):
        """Later resume synchronization protects candidate's confirmed education and certifications."""
        updater = ProfileUpdater(db_manager=self.db)
        existing_profile = {
            "personal": {"full_name": "Alice Confirmed"},
            "education": [{"degree": "Confirmed B.Tech", "institution": "IIT", "current_cgpa": 9.0}],
            "certifications": [{"name": "Confirmed PMP", "verification_status": "USER_CONFIRMED"}],
            "field_provenance": {
                "education": {"verification_status": "USER_CONFIRMED"},
                "certifications": {"verification_status": "USER_CONFIRMED"},
            },
        }

        incoming_resume = ParsedResume(
            full_name="Alice Different",
            education=[EducationEntry(institution="Different University", degree="Different Degree")],
            certifications=[],
        )

        diff = updater.diff_profile_with_resume(existing_profile, incoming_resume)

        # Confirmed education and certifications must be classified as protected
        protected_names = [p["field"] for p in diff["protected_fields"]]
        self.assertIn("education", protected_names)
        self.assertIn("certifications", protected_names)

        # Applying sync without override preserves confirmed fields
        synced = updater.apply_approved_sync(existing_profile, incoming_resume, override_protected=False)
        self.assertEqual(synced["education"][0]["degree"], "Confirmed B.Tech")
        self.assertEqual(synced["certifications"][0]["name"], "Confirmed PMP")

    # =========================================================================
    # 3. EXPERIENCE DATE PRESERVATION THROUGH COMPLETE PIPELINE
    # =========================================================================

    def test_10_date_range_splitting_and_preservation(self):
        """Tests terminology.split_date_range across all standard date range formats."""
        # 1. Month Year - Month Year
        s1, e1 = split_date_range("Jan 2020 - Dec 2023")
        self.assertEqual(s1, "Jan 2020")
        self.assertEqual(e1, "Dec 2023")

        # 2. Month Year - Present
        s2, e2 = split_date_range("Jan 2020 - Present")
        self.assertEqual(s2, "Jan 2020")
        self.assertEqual(e2, "Present")

        # 3. YYYY-MM to YYYY-MM
        s3, e3 = split_date_range("2020-01 to 2024-01")
        self.assertEqual(s3, "2020-01")
        self.assertEqual(e3, "2024-01")

        # 4. YYYY-MM-DD to YYYY-MM-DD
        s4, e4 = split_date_range("2020-01-01 to 2024-01-01")
        self.assertEqual(s4, "2020-01-01")
        self.assertEqual(e4, "2024-01-01")

        # 5. En-dash and Em-dash
        s5, e5 = split_date_range("2021-06 – 2023-08")
        self.assertEqual(s5, "2021-06")
        self.assertEqual(e5, "2023-08")

    def test_11_profile_updater_build_profile_dict_preserves_experience_fields(self):
        """ProfileUpdater.build_profile_dict preserves start_date, end_date, is_current, duration, and duration_months."""
        updater = ProfileUpdater(db_manager=self.db)
        parsed = ParsedResume(
            work_experience=[
                ExperienceEntry(
                    employer="Tech Solutions",
                    job_title="Software Engineer",
                    start_date="2021-01",
                    end_date="2023-01",
                    duration="Jan 2021 - Jan 2023",
                    duration_months=24,
                    is_current=False,
                    responsibilities=["Built microservices"],
                )
            ]
        )

        p_dict = updater.build_profile_dict(parsed)
        exp_entry = p_dict["work_experience"][0]

        self.assertEqual(exp_entry["employer"], "Tech Solutions")
        self.assertEqual(exp_entry["job_title"], "Software Engineer")
        self.assertEqual(exp_entry["start_date"], "2021-01")
        self.assertEqual(exp_entry["end_date"], "2023-01")
        self.assertEqual(exp_entry["duration"], "Jan 2021 - Jan 2023")
        self.assertEqual(exp_entry["duration_months"], 24)
        self.assertFalse(exp_entry["is_current"])

    def test_12_overlapping_experience_intervals_merged_without_double_counting(self):
        """Overlapping concurrent roles are merged to calculate true non-overlapping experience duration."""
        profile_data = {
            "work_experience": [
                {
                    "job_title": "Primary Developer",
                    "start_date": "2022-01-01",
                    "end_date": "2022-12-31",  # 12 months (2022)
                    "verification_status": "USER_CONFIRMED",
                },
                {
                    "job_title": "Concurrent Part-time Dev",
                    "start_date": "2022-06-01",
                    "end_date": "2023-05-31",  # 12 months (overlaps June-Dec 2022, extends to May 2023)
                    "verification_status": "USER_CONFIRMED",
                },
            ],
            "field_provenance": {"work_experience": {"verification_status": "USER_CONFIRMED"}},
        }

        facts = CandidateFactNormalizer.normalize(profile_data=profile_data)

        # Jan 2022 to May 2023 = 17 non-overlapping months (NOT 12 + 12 = 24 months)
        self.assertEqual(facts.total_experience_months, 17)
        self.assertEqual(facts.confirmed_experience_months, 17)

    # =========================================================================
    # 4. MIXED VERIFIED/UNVERIFIED EXPERIENCE ELIGIBILITY
    # =========================================================================

    def test_13_mixed_experience_shortfall_returns_unknown_not_ineligible(self):
        """12 months confirmed + 6 months unverified vs 24 months required returns UNKNOWN."""
        profile_data = {
            "work_experience": [
                {
                    "employer": "Confirmed Employer",
                    "job_title": "Software Engineer",
                    "start_date": "2022-01-01",
                    "end_date": "2022-12-31",  # 12 months = 1.0 yr confirmed
                    "verification_status": "USER_CONFIRMED",
                },
                {
                    "employer": "Unverified Employer",
                    "job_title": "Junior Developer",
                    "start_date": "2023-01-01",
                    "end_date": "2023-06-30",  # 6 months = 0.5 yr unverified
                    "verification_status": "EXTRACTED_UNVERIFIED",
                },
            ],
            # Total documented = 18 months; employer minimum = 24 months
        }
        job_data = {
            "job_title": "Mid-level Engineer",
            "min_years_experience": 2.0,  # 24 months
        }

        res = self.matcher.evaluate(user_id=self.user_id, profile_data=profile_data, job_data=job_data, persist=False)

        # Because part of the experience remains unverified, outcome is UNKNOWN, not INELIGIBLE
        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertTrue(any("unverified experience requires candidate confirmation" in r.lower() for r in res.eligibility_reasons))

    def test_14_confirmed_experience_meeting_minimum_returns_eligible(self):
        """24 months confirmed + 6 months unverified vs 24 months required returns ELIGIBLE."""
        profile_data = {
            "work_experience": [
                {
                    "employer": "Confirmed Corp",
                    "job_title": "Developer",
                    "start_date": "2021-01-01",
                    "end_date": "2022-12-31",  # 24 months = 2.0 yrs confirmed
                    "verification_status": "USER_CONFIRMED",
                },
                {
                    "employer": "Unverified Co",
                    "job_title": "Freelance",
                    "start_date": "2023-01-01",
                    "end_date": "2023-06-30",  # 6 months unverified
                    "verification_status": "EXTRACTED_UNVERIFIED",
                },
            ]
        }
        job_data = {
            "job_title": "Developer II",
            "min_years_experience": 2.0,
        }

        res = self.matcher.evaluate(user_id=self.user_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "ELIGIBLE")

    def test_15_confirmed_complete_history_demonstrably_below_minimum_returns_ineligible(self):
        """12 months confirmed experience with complete history confirmed returns INELIGIBLE against 2.0 yrs."""
        profile_data = {
            "work_experience": [
                {
                    "employer": "Confirmed Corp",
                    "job_title": "Junior Developer",
                    "start_date": "2023-01-01",
                    "end_date": "2023-12-31",  # 12 months = 1.0 yr confirmed
                    "verification_status": "USER_CONFIRMED",
                }
            ],
            "employment_history_complete": True,
        }
        job_data = {
            "job_title": "Mid-level Engineer",
            "min_years_experience": 2.0,
        }

        res = self.matcher.evaluate(user_id=self.user_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "INELIGIBLE")
        self.assertTrue(any("demonstrably below" in r.lower() for r in res.eligibility_reasons))

    def test_16_incomplete_history_shortfall_returns_unknown(self):
        """12 months confirmed experience with employment_history_complete=False returns UNKNOWN against 2.0 yrs."""
        profile_data = {
            "work_experience": [
                {
                    "employer": "Confirmed Corp",
                    "job_title": "Junior Developer",
                    "start_date": "2023-01-01",
                    "end_date": "2023-12-31",  # 12 months = 1.0 yr confirmed
                    "verification_status": "USER_CONFIRMED",
                }
            ],
            "employment_history_complete": False,  # Candidate explicitly indicates unlisted experience exists
        }
        job_data = {
            "job_title": "Mid-level Engineer",
            "min_years_experience": 2.0,
        }

        res = self.matcher.evaluate(user_id=self.user_id, profile_data=profile_data, job_data=job_data, persist=False)
        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertTrue(any("incomplete" in r.lower() for r in res.eligibility_reasons))

    # =========================================================================
    # 5. REAL DASHBOARD EVALUATION & AUDIT SNAPSHOT INTEGRATION
    # =========================================================================

    def test_17_real_dashboard_evaluation_records_candidate_profile_hash_and_version(self):
        """End-to-end integration: saving profile in DB and running match records exact hash and version."""
        # 1. Save profile via DB manager using actual Profile Editor format
        editor_profile = {
            "personal": {"full_name": "Test Candidate", "email": "tester@domain.com"},
            "education": [{"degree": "Bachelor of Technology", "major": "Computer Science", "verification_status": "USER_CONFIRMED"}],
            "technical_skills": {
                "programming_languages": ["Python", "SQL"],
                "all_skills": ["Python", "SQL", "Docker"],
            },
            "field_provenance": {
                "education": {"verification_status": "USER_CONFIRMED"},
                "technical_skills": {"verification_status": "USER_CONFIRMED"},
            },
            "is_user_confirmed": True,
        }
        self.db.save_user_candidate_profile(user_id=self.user_id, profile_data=editor_profile)

        # 2. Add resume and job description
        user_res_dir = self.service.storage_base_dir / str(self.user_id) / "resumes"
        user_res_dir.mkdir(parents=True, exist_ok=True)
        pdf_bytes = generate_persona_pdf("backend_engineer")
        (user_res_dir / "r.pdf").write_bytes(pdf_bytes)
        file_hash = hashlib.sha256(pdf_bytes).hexdigest()
        file_size = len(pdf_bytes)

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO resumes (user_id, storage_filename, original_filename, file_format, file_hash, file_size_bytes, parsed_data, active_version, is_active)
                VALUES (?, 'r.pdf', 'r.pdf', 'pdf', ?, ?, '{"skills":["Python"]}', 1, 1)
                """,
                (self.user_id, file_hash, file_size),
            )
            res_id = cursor.lastrowid

            cursor.execute(
                """
                INSERT INTO resume_versions (resume_id, user_id, version_num, storage_filename, file_hash, file_size_bytes, change_notes, snapshot_json)
                VALUES (?, ?, 1, 'r.pdf', ?, ?, 'Initial upload', '{}')
                """,
                (res_id, self.user_id, file_hash, file_size),
            )

            cursor.execute(
                """
                INSERT INTO job_descriptions (user_id, source_type, company_name, job_title, raw_content, content_hash, parsed_data)
                VALUES (?, 'pasted', 'TestCorp', 'Backend Dev', 'Content', 'hash_jd', '{"mandatory_skills":["Python"],"required_degree_levels":["Bachelor"]}')
                """,
                (self.user_id,),
            )
            jd_id = cursor.lastrowid

        # 3. Run dashboard evaluation
        result = self.service.run_match_evaluation(user_id=self.user_id, resume_id=res_id, job_description_id=jd_id)

        self.assertIsNotNone(result)
        self.assertEqual(result.candidate_profile_version, 1)
        self.assertIsNotNone(result.candidate_profile_hash)
        self.assertEqual(result.eligibility_status, "ELIGIBLE")

        # 4. Check database match_results table for persisted candidate_profile_hash
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT candidate_profile_version, candidate_profile_hash FROM match_results WHERE user_id = ?", (self.user_id,))
            row = cursor.fetchone()
            self.assertEqual(row["candidate_profile_version"], 1)
            self.assertEqual(row["candidate_profile_hash"], result.candidate_profile_hash)


if __name__ == "__main__":
    unittest.main()

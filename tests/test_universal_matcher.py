"""End-to-End Tests for Universal Resume-to-Job Matching Engine (Phase 5).

Covers all 45 mandatory scenarios from Phase 5 specification:
- Multi-industry matching: Tech, Healthcare, Finance, Law, Engineering, Management, Marketing, Sales, Creative, Education.
- Career situations: Student/Intern, Fresher, Experienced, Senior/Executive, Career Changer, Freelance, Career Gaps, Missing Dates.
- Three-state eligibility: ELIGIBLE, INELIGIBLE, UNKNOWN.
- Zero-hallucination policy and deterministic scoring.
"""

from pathlib import Path
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import CrossUserAccessError
from src.matcher.universal_matcher import UniversalMatcher


class TestUniversalMatcherScenarios(unittest.TestCase):
    """Exhaustive test suite covering all 45 universal matching engine scenarios."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(db_path=Path(self.temp_dir.name) / "test_matcher.db")
        self.matcher = UniversalMatcher(db_manager=self.db)

        # Setup standard test user
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('tester@domain.com', 'hash', 'salt1', 'Universal Tester')")
            self.user_id = cursor.lastrowid
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('other@domain.com', 'hash', 'salt2', 'Other User')")
            self.other_user_id = cursor.lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    # Scenario 1: CS fresher vs Software Developer Intern
    def test_01_cs_fresher_vs_software_intern(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={
                "career_level": "student",
                "education": [{"degree": "B.Tech", "major": "Computer Science", "current_cgpa": 8.1}],
                "skills": {"tech": ["Python", "Data Structures", "Git"]},
                "projects": [{"title": "Web App", "description": "Flask app with REST API", "technologies": ["Python", "Git"]}],
            },
            job_data={
                "job_title": "Software Developer Intern",
                "mandatory_skills": ["Python", "Git"],
                "required_degree_levels": ["Bachelor"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "ELIGIBLE")
        self.assertGreaterEqual(res.match_score, 85.0)
        self.assertEqual(res.scoring_profile, "student_intern")

    # Scenario 2: Experienced software engineer vs Senior Engineer
    def test_02_experienced_software_engineer_vs_senior_engineer(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={
                "career_level": "senior",
                "education": [{"degree": "B.S. in Computer Science", "major": "Computer Science"}],
                "experience": [{"job_title": "Senior Engineer", "duration_months": 84, "start_date": "2017-01", "end_date": "2024-01", "responsibilities": ["Lead architecture"]}],
                "skills": {"tech": ["Python", "System Design", "Kubernetes", "AWS"]},
            },
            job_data={
                "job_title": "Senior Software Engineer",
                "min_years_experience": 5.0,
                "mandatory_skills": ["Python", "System Design", "AWS"],
                "required_degree_levels": ["Bachelor"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "ELIGIBLE")
        self.assertGreaterEqual(res.match_score, 85.0)

    # Scenario 3: Registered nurse vs Clinical Nurse role
    def test_03_registered_nurse_vs_clinical_nurse(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={
                "education": [{"degree": "Bachelor of Science in Nursing", "major": "Nursing"}],
                "certifications": [{"name": "Registered Nurse License", "issuing_organization": "State Board of Nursing"}],
                "experience": [{"job_title": "Staff Nurse", "duration_months": 36, "start_date": "2020-01", "end_date": "2023-01", "responsibilities": ["Triage", "Patient Care"]}],
                "skills": {"tech": ["Patient Care", "Phlebotomy", "BLS", "EHR"]},
            },
            job_data={
                "job_title": "Clinical Staff Nurse",
                "industry": "Healthcare",
                "licenses_required": ["Registered Nurse"],
                "mandatory_skills": ["Patient Care", "EHR"],
                "required_degree_levels": ["Bachelor"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "ELIGIBLE")
        self.assertEqual(res.scoring_profile, "healthcare_clinical")
        self.assertGreaterEqual(res.match_score, 85.0)

    # Scenario 4: Medical doctor vs Hospital Medical Officer
    def test_04_medical_doctor_vs_medical_officer(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={
                "education": [{"degree": "MBBS", "major": "Medicine"}],
                "certifications": [{"name": "Medical License"}],
                "experience": [{"job_title": "Resident Medical Officer", "duration_months": 24, "start_date": "2021-01", "end_date": "2023-01"}],
                "skills": {"tech": ["Clinical Diagnosis", "Patient Care", "Pharmacology"]},
            },
            job_data={
                "job_title": "Hospital Medical Officer",
                "industry": "Healthcare",
                "licenses_required": ["Medical License"],
                "required_degree_levels": ["MBBS"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "ELIGIBLE")

    # Scenario 5: Accountant vs Accountant role
    def test_05_accountant_vs_accountant_role(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={
                "education": [{"degree": "Bachelor of Commerce", "major": "Accounting"}],
                "certifications": [{"name": "CPA License"}],
                "experience": [{"job_title": "Accountant", "duration_months": 36, "start_date": "2020-01", "end_date": "2023-01"}],
                "skills": {"tech": ["GAAP", "General Ledger", "Financial Reporting", "Tax Compliance"]},
            },
            job_data={
                "job_title": "Senior Accountant",
                "industry": "Finance",
                "mandatory_skills": ["GAAP", "General Ledger"],
                "required_degree_levels": ["Bachelor"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "ELIGIBLE")
        self.assertGreaterEqual(res.match_score, 80.0)

    # Scenario 6: Financial analyst vs Financial Analyst
    def test_06_financial_analyst(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={
                "education": [{"degree": "BS in Finance", "major": "Finance"}],
                "technical_skills": ["Financial modelling", "Valuation", "Excel"],
            },
            job_data={
                "job_title": "Financial Analyst",
                "industry": "Finance",
                "mandatory_skills": ["Financial modeling", "Valuation"],
            },
            persist=False,
        )
        self.assertGreaterEqual(res.match_score, 70.0)

    # Scenario 7: Mechanical engineer vs Design Engineer
    def test_07_mechanical_engineer(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={
                "education": [{"degree": "B.E. Mechanical Engineering", "major": "Mechanical"}],
                "skills": {"tech": ["AutoCAD", "SolidWorks", "FEA", "Thermodynamics"]},
            },
            job_data={
                "job_title": "CAD Design Engineer",
                "industry": "Mechanical Engineering",
                "mandatory_skills": ["SolidWorks", "AutoCAD"],
                "required_degree_levels": ["Bachelor"],
            },
            persist=False,
        )
        self.assertEqual(res.scoring_profile, "engineering_technical")
        self.assertEqual(res.eligibility_status, "ELIGIBLE")

    # Scenario 8: Civil engineer vs Site Engineer
    def test_08_civil_engineer(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={
                "education": [{"degree": "B.Tech Civil Engineering", "major": "Civil"}],
                "technical_skills": ["AutoCAD", "Structural Analysis", "Site Inspection"],
            },
            job_data={
                "job_title": "Civil Site Engineer",
                "industry": "Civil Engineering",
                "mandatory_skills": ["AutoCAD", "Structural Analysis"],
            },
            persist=False,
        )
        self.assertEqual(res.scoring_profile, "engineering_technical")

    # Scenario 9: Lawyer vs Legal Associate
    def test_09_lawyer_vs_legal_associate(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={
                "education": [{"degree": "Juris Doctor", "major": "Law"}],
                "certifications": [{"name": "Bar Admission", "issuing_organization": "State Bar"}],
                "skills": {"tech": ["Legal Research", "Contract Drafting", "Westlaw"]},
            },
            job_data={
                "job_title": "Legal Associate",
                "industry": "Legal",
                "licenses_required": ["Bar Admission"],
                "mandatory_skills": ["Legal Research", "Contract Drafting"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "ELIGIBLE")
        self.assertEqual(res.scoring_profile, "legal_counsel")

    # Scenario 10: Marketing manager vs Marketing Manager
    def test_10_marketing_manager(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={
                "work_experience": [{"job_title": "Marketing Lead", "duration_months": 48}],
                "technical_skills": ["SEO", "SEM", "Google Analytics", "Content Strategy"],
            },
            job_data={
                "job_title": "Marketing Manager",
                "mandatory_skills": ["SEO", "Google Analytics"],
            },
            persist=False,
        )
        self.assertGreaterEqual(res.match_score, 75.0)

    # Scenario 11: Sales professional vs Sales Executive
    def test_11_sales_professional(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={
                "technical_skills": ["B2B Sales", "CRM", "Lead Generation", "Pipeline Management"],
            },
            job_data={
                "job_title": "Sales Executive",
                "mandatory_skills": ["B2B Sales", "CRM"],
            },
            persist=False,
        )
        self.assertGreaterEqual(res.match_score, 70.0)

    # Scenario 12: Teacher vs Teaching role
    def test_12_teacher_vs_teaching_role(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={
                "education": [{"degree": "Bachelor of Education", "major": "Education"}],
                "certifications": [{"name": "State Teaching Credential"}],
                "skills": {"tech": ["Curriculum Design", "Classroom Management"]},
            },
            job_data={
                "job_title": "Secondary School Teacher",
                "licenses_required": ["Teaching Credential"],
                "mandatory_skills": ["Curriculum Design"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "ELIGIBLE")

    # Scenario 13: Graphic designer vs Designer
    def test_13_graphic_designer(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={
                "technical_skills": ["Figma", "Adobe Photoshop", "Illustrator", "UI/UX Design"],
                "projects": [{"title": "Brand Design System", "description": "Figma design system"}],
            },
            job_data={
                "job_title": "UI/UX Designer",
                "mandatory_skills": ["Figma", "UI/UX Design"],
            },
            persist=False,
        )
        self.assertGreaterEqual(res.match_score, 75.0)

    # Scenario 14: Experienced executive vs Management role
    def test_14_experienced_executive(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={
                "career_level": "senior",
                "experience": [{"job_title": "VP Engineering", "duration_months": 120, "start_date": "2014-01", "end_date": "2024-01", "responsibilities": ["P&L", "Strategic Roadmap"]}],
                "skills": {"tech": ["Team Leadership", "Budget Management", "Stakeholder Management"]},
            },
            job_data={
                "job_title": "Director of Engineering",
                "min_years_experience": 8.0,
                "mandatory_skills": ["Team Leadership", "Budget Management"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "ELIGIBLE")
        self.assertEqual(res.scoring_profile, "senior_executive")

    # Scenario 15: Candidate changing career fields
    def test_15_career_changer(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={
                "career_level": "career_changer",
                "technical_skills": ["Python", "SQL", "Data Analysis"],
                "projects": [{"title": "Data Pipeline", "description": "ETL pipeline"}],
            },
            job_data={
                "job_title": "Junior Data Analyst",
                "mandatory_skills": ["Python", "SQL"],
            },
            scoring_profile_id="career_changer",
            persist=False,
        )
        self.assertEqual(res.scoring_profile, "career_changer")
        self.assertGreaterEqual(res.match_score, 70.0)

    # Scenario 16: Candidate with career gaps (non-penalized)
    def test_16_career_gaps_not_penalized(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={
                "experience": [
                    {"job_title": "Developer", "duration_months": 24, "start_date": "2019-01", "end_date": "2021-01"},
                    # 1 year gap
                    {"job_title": "Senior Developer", "duration_months": 24, "start_date": "2022-01", "end_date": "2024-01"},
                ],
                "skills": {"tech": ["Python", "Docker"]},
            },
            job_data={
                "job_title": "Developer",
                "min_years_experience": 3.0,
                "mandatory_skills": ["Python"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "ELIGIBLE")
        self.assertGreaterEqual(res.match_score, 75.0)

    # Scenario 17: Candidate with incomplete education data
    def test_17_incomplete_education_data(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={
                "education": [],  # Empty
                "technical_skills": ["Python"],
            },
            job_data={
                "job_title": "Software Developer",
                "required_degree_levels": ["Bachelor"],
                "mandatory_skills": ["Python"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "UNKNOWN")

    # Scenario 18: Candidate with missing experience dates
    def test_18_missing_experience_dates(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={
                "work_experience": [{"job_title": "Software Engineer", "employer": "TechCorp"}],  # No dates
                "technical_skills": ["Python"],
            },
            job_data={
                "job_title": "Lead Software Engineer",
                "min_years_experience": 5.0,
                "mandatory_skills": ["Python"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "UNKNOWN")
        self.assertTrue(res.experience_analysis.get("experience_dates_missing"))

    # Scenario 19: Candidate with unverified licenses
    def test_19_unverified_licenses(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={
                "technical_skills": ["Patient Care"],
            },
            job_data={
                "job_title": "Clinical Nurse",
                "licenses_required": ["Registered Nurse"],
            },
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "UNKNOWN")

    # Scenario 20: Candidate with no salary expectations
    def test_20_no_salary_expectations_evaluated_smoothly(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python"]},
            job_data={"job_title": "Developer", "mandatory_skills": ["Python"]},
            persist=False,
        )
        self.assertIsInstance(res.match_score, float)

    # Scenario 21: Candidate whose skills partially match
    def test_21_partial_skills_match(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python"]},
            job_data={"job_title": "Full Stack Dev", "mandatory_skills": ["Python", "Rust", "Kubernetes"]},
            persist=False,
        )
        self.assertGreater(res.match_score, 0.0)
        self.assertLess(res.match_score, 80.0)

    # Scenario 22: Candidate with exact skills
    def test_22_exact_skills(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python", "PostgreSQL", "Docker"]},
            job_data={"job_title": "Backend Dev", "mandatory_skills": ["Python", "PostgreSQL", "Docker"]},
            persist=False,
        )
        exacts = [sa for sa in res.skills_assessment if sa.classification == "EXACT_MATCH"]
        self.assertEqual(len(exacts), 3)

    # Scenario 23: Candidate with similar but non-equivalent skills (Java vs JavaScript)
    def test_23_non_equivalent_skills(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Java"]},
            job_data={"job_title": "Frontend Dev", "mandatory_skills": ["JavaScript"]},
            persist=False,
        )
        missings = [sa for sa in res.skills_assessment if sa.classification == "MISSING"]
        self.assertEqual(len(missings), 1)

    # Scenario 24: Job with mandatory education requirements satisfied
    def test_24_mandatory_education_satisfied(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"education": [{"degree": "Master of Science", "major": "Computer Science"}]},
            job_data={"required_degree_levels": ["Bachelor"]},
            persist=False,
        )
        self.assertEqual(res.education_analysis.get("status"), "SATISFIED")

    # Scenario 25: Job with preferred education requirements
    def test_25_preferred_education(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={"education": [{"degree": "Bachelor of Technology", "major": "Information Technology"}]},
            job_data={"required_degree_levels": ["Bachelor"], "preferred_fields_of_study": ["Computer Science"]},
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "ELIGIBLE")

    # Scenario 26: Job with no education requirements
    def test_26_no_education_requirements(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python"]},
            job_data={"job_title": "Programmer", "mandatory_skills": ["Python"]},
            persist=False,
        )
        self.assertEqual(res.education_analysis.get("status"), "SATISFIED")

    # Scenario 27: Job with missing experience requirements
    def test_27_missing_experience_requirements(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python"]},
            job_data={"job_title": "Developer", "mandatory_skills": ["Python"]},
            persist=False,
        )
        self.assertEqual(res.experience_analysis.get("status"), "SATISFIED")

    # Scenario 28: Job with ambiguous mandatory language
    def test_28_ambiguous_mandatory_language(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python"]},
            job_data={"job_title": "Dev", "mandatory_skills": ["Passion for coding", "Python"]},
            persist=False,
        )
        self.assertGreaterEqual(res.match_score, 40.0)

    # Scenario 29: Job with mandatory professional license
    def test_29_mandatory_license_present(self):
        # 1. Resume-extracted unverified license must not be considered verified
        res_unverified = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"certifications": [{"name": "Bar Admission"}]},
            job_data={"job_title": "Counsel", "licenses_required": ["Bar Admission"]},
            persist=False,
        )
        self.assertEqual(res_unverified.certification_analysis.get("license_status"), "UNVERIFIED")
        self.assertEqual(res_unverified.eligibility_status, "UNKNOWN")

        # 2. User-confirmed license in candidate profile satisfies mandatory requirement
        res_confirmed = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={"certifications": [{"name": "Bar Admission"}]},
            job_data={"job_title": "Counsel", "licenses_required": ["Bar Admission"]},
            persist=False,
        )
        self.assertEqual(res_confirmed.certification_analysis.get("license_status"), "SATISFIED")
        self.assertEqual(res_confirmed.eligibility_status, "ELIGIBLE")

    # Scenario 30: Job with undisclosed compensation
    def test_30_undisclosed_compensation(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python"]},
            job_data={"job_title": "Dev", "mandatory_skills": ["Python"], "compensation_disclosed": False},
            persist=False,
        )
        self.assertIsInstance(res.match_score, float)

    # Scenario 31: Remote job
    def test_31_remote_job(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"location": "Pune, India"},
            job_data={"location": "Remote, Global", "work_arrangement": "Remote"},
            persist=False,
        )
        self.assertEqual(res.dimension_breakdown["location_arrangement"].earned_points, res.dimension_breakdown["location_arrangement"].max_points)

    # Scenario 32: Hybrid job
    def test_32_hybrid_job_matching_location(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"location": "Pune, Maharashtra"},
            job_data={"location": "Pune, India", "work_arrangement": "Hybrid"},
            persist=False,
        )
        self.assertEqual(res.dimension_breakdown["location_arrangement"].earned_points, res.dimension_breakdown["location_arrangement"].max_points)

    # Scenario 33: On-site job
    def test_33_onsite_job_mismatched_location(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"location": "Bengaluru, India"},
            job_data={"location": "Tokyo, Japan", "work_arrangement": "On-site"},
            persist=False,
        )
        self.assertLess(res.dimension_breakdown["location_arrangement"].earned_points, res.dimension_breakdown["location_arrangement"].max_points)

    # Scenario 34: Missing candidate location
    def test_34_missing_candidate_location(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"location": None},
            job_data={"location": "London, UK", "work_arrangement": "On-site"},
            persist=False,
        )
        self.assertEqual(res.dimension_breakdown["location_arrangement"].coverage_confidence, 0.5)

    # Scenario 35: Incomplete job description
    def test_35_incomplete_job_description(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python"]},
            job_data={"job_title": "Developer"},  # Almost empty
            persist=False,
        )
        self.assertIsInstance(res.match_score, float)

    # Scenario 36: Cross-user matching attempt
    def test_36_cross_user_matching_attempt_rejected(self):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO resumes (user_id, storage_filename, original_filename, file_format, file_hash, file_size_bytes) VALUES (?, 'r.pdf', 'r.pdf', 'pdf', 'h', 100)", (self.other_user_id,))
            foreign_res_id = cursor.lastrowid
            cursor.execute("INSERT INTO job_descriptions (user_id, source_type, company_name, job_title, raw_content, content_hash) VALUES (?, 'pasted', 'C', 'T', 'raw', 'h')", (self.user_id,))
            my_jd_id = cursor.lastrowid

        with self.assertRaises(CrossUserAccessError):
            self.matcher.evaluate(
                user_id=self.user_id,
                resume_id=foreign_res_id,
                job_description_id=my_jd_id,
                persist=True,
            )

    # Scenario 37: Resume version changed after previous match
    def test_37_resume_version_change_tracked(self):
        res_v1 = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"raw_text": "Resume content version 1"},
            job_data={"job_title": "Dev"},
            resume_version_num=1,
            persist=False,
        )
        res_v2 = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"raw_text": "Resume content version 2 with added Python"},
            job_data={"job_title": "Dev"},
            resume_version_num=2,
            persist=False,
        )
        self.assertNotEqual(res_v1.resume_file_hash, res_v2.resume_file_hash)
        self.assertEqual(res_v2.resume_version_num, 2)

    # Scenario 38: Job snapshot changed after previous match
    def test_38_job_snapshot_change_tracked(self):
        res_j1 = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python"]},
            job_data={"job_title": "Dev", "snapshot_hash": "hash_jd_snap_1"},
            persist=False,
        )
        res_j2 = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python"]},
            job_data={"job_title": "Dev", "snapshot_hash": "hash_jd_snap_2"},
            persist=False,
        )
        self.assertNotEqual(res_j1.job_snapshot_hash, res_j2.job_snapshot_hash)

    # Scenario 39: Deterministic repeated scoring
    def test_39_deterministic_repeated_scoring(self):
        input_resume = {"technical_skills": ["Python", "SQL"], "education": [{"degree": "B.Tech", "current_cgpa": 7.6}]}
        input_job = {"job_title": "Data Analyst", "mandatory_skills": ["Python", "SQL"]}

        r1 = self.matcher.evaluate(user_id=self.user_id, resume_data=input_resume, job_data=input_job, persist=False)
        r2 = self.matcher.evaluate(user_id=self.user_id, resume_data=input_resume, job_data=input_job, persist=False)
        self.assertEqual(r1.match_score, r2.match_score)
        self.assertEqual(r1.assessment_confidence, r2.assessment_confidence)

    # Scenario 40: Immutable historical evaluation (2 rows created on repeat)
    def test_40_immutable_historical_evaluation(self):
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO resumes (user_id, storage_filename, original_filename, file_format, file_hash, file_size_bytes) VALUES (?, 'r.pdf', 'r.pdf', 'pdf', 'h1', 100)", (self.user_id,))
            rid = cursor.lastrowid
            h2 = "d7439bee24773bcbfa2d0a97947ee36227b10d1022b1a55847e928965bb6bfde"
            cursor.execute("INSERT INTO job_descriptions (user_id, source_type, company_name, job_title, raw_content, content_hash) VALUES (?, 'pasted', 'C', 'T', 'raw', ?)", (self.user_id, h2))
            jdid = cursor.lastrowid

        from src.security.resume_verifier import VerifiedResume
        from src.preparer.resume_parser import ParsedResume

        v_resume = VerifiedResume(
            resume_id=rid,
            user_id=self.user_id,
            version_num=1,
            storage_filename="r.pdf",
            file_bytes=b"%PDF-1.4\n%EOF\n",
            file_hash="a" * 64,
            file_size_bytes=15,
            file_format="pdf",
            raw_text="Test resume",
            _parsed_resume=ParsedResume(raw_text="Test resume"),
        )

        self.matcher.evaluate(user_id=self.user_id, verified_resume=v_resume, job_description_id=jdid, persist=True)
        self.matcher.evaluate(user_id=self.user_id, verified_resume=v_resume, job_description_id=jdid, persist=True)

        history = self.db.get_user_match_results(user_id=self.user_id, resume_id=rid, job_description_id=jdid)
        self.assertEqual(len(history), 2)

    # Scenario 41: Missing data must produce UNKNOWN rather than fabricated ELIGIBLE
    def test_41_missing_data_produces_unknown(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": []},
            job_data={"job_title": "Doctor", "licenses_required": ["Medical License"]},
            persist=False,
        )
        self.assertEqual(res.eligibility_status, "UNKNOWN")

    # Scenario 42: Candidate-confirmed information changes the next evaluation
    def test_42_candidate_confirmed_changes_evaluation(self):
        unconfirmed = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Python"]},  # Unconfirmed
            job_data={"job_title": "Dev", "mandatory_skills": ["Python"]},
            persist=False,
        )
        confirmed = self.matcher.evaluate(
            user_id=self.user_id,
            profile_data={"skills": {"tech": ["Python"]}},  # User confirmed
            job_data={"job_title": "Dev", "mandatory_skills": ["Python"]},
            persist=False,
        )
        self.assertGreater(confirmed.assessment_confidence, unconfirmed.assessment_confidence)

    # Scenario 43: Unverified resume extraction does not become verified evidence
    def test_43_unverified_extraction_preserves_status(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"technical_skills": ["Docker"]},
            job_data={"job_title": "Dev", "mandatory_skills": ["Docker"]},
            persist=False,
        )
        sa = res.skills_assessment[0]
        self.assertIn("EXTRACTED_UNVERIFIED", sa.candidate_evidence)

    # Scenario 44: Applicable scoring profiles produce valid totals out of 100
    def test_44_scoring_profiles_produce_valid_totals(self):
        for pid in ("general_baseline", "student_intern", "experienced_professional", "healthcare_clinical"):
            res = self.matcher.evaluate(
                user_id=self.user_id,
                resume_data={"technical_skills": ["Python"]},
                job_data={"job_title": "Dev", "mandatory_skills": ["Python"]},
                scoring_profile_id=pid,
                persist=False,
            )
            self.assertGreaterEqual(res.match_score, 0.0)
            self.assertLessEqual(res.match_score, 100.0)

    # Scenario 45: Non-applicable dimensions are explained
    def test_45_non_applicable_dimensions_explained(self):
        res = self.matcher.evaluate(
            user_id=self.user_id,
            resume_data={"career_level": "student", "technical_skills": ["Python"]},
            job_data={"job_title": "AI Intern", "mandatory_skills": ["Python"]},
            scoring_profile_id="student_intern",
            persist=False,
        )
        exp_dim = res.dimension_breakdown["experience"]
        self.assertEqual(exp_dim.max_points, 0.0)
        self.assertTrue(len(exp_dim.notes) > 0)


if __name__ == "__main__":
    unittest.main()

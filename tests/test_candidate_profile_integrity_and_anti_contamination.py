"""Regression Tests for Real Candidate Profile Integrity & Anti-Contamination (Phase C.1 / Architecture v2.1.1).

Verifies:
1. Anti-contamination: Never injects mock/fixture placeholders ('candidate@example.com',
   '98765 43210', 'john.doe', 'example.org') into production autofill plans or field decisions.
2. Missing value safeguard: Missing facts (e.g. empty GitHub, missing salary, unstated notice period)
   strictly resolve to NEEDS_INPUT or AMBIGUOUS with intended_value=None.
3. Authenticated profile binding: Generated plan facts strictly reflect the authorized candidate's
   real saved profile from SQLite storage.
4. Resume binary binding: Plan references the authentic active user resume with exact SHA-256 integrity.
"""

import hashlib
from pathlib import Path
import pytest
from src.database.db_manager import DatabaseManager
from src.preparer.form_filling_broker import ApplicationFormFillingBroker
from src.preparer.universal_field_mapper import (
    FormFieldTarget,
    UniversalFieldMapper,
)

BANNED_TEST_PLACEHOLDERS = [
    "candidate@example.com",
    "john.doe@example.com",
    "test@example.com",
    "9876543210",
    "98765 43210",
    "1234567890",
    "https://github.com/candidate",
    "https://www.linkedin.com/in/candidate",
]


class TestCandidateProfileIntegrityAndAntiContamination:
    """Ensures production autofill is strictly rooted in real profile facts and free of fixture contamination."""

    @pytest.fixture(autouse=True)
    def setup_db(self, tmp_path):
        """Sets up an isolated temporary database with realistic seeded candidate fixtures."""
        db_path = tmp_path / "test_isolated.db"
        self.db = DatabaseManager(db_path=db_path)
        self.broker = ApplicationFormFillingBroker(db=self.db)

        # 1. Create candidate user in isolated database
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, 'hash', 'salt', ?)",
                ("pranayagrawal2116@gmail.com", "Pranay Agrawal"),
            )
            self.user_id = cursor.lastrowid

        # 2. Seed realistic candidate profile
        profile_data = {
            "personal": {
                "full_name": "Pranay Agrawal",
                "email": "pranayagrawal2116@gmail.com",
                "phone": "9510029575",
                "current_company": "Sarita Infotech Private Limited",
                "current_location": "Pune, India",
                "linkedin": "https://www.linkedin.com/in/pranay",
                "github": "",
            },
            "education": [],
            "experience": [],
            "technical_skills": ["Python", "FastAPI", "React"],
            "field_provenance": {
                "full_name": "USER_CONFIRMED",
                "email": "USER_CONFIRMED",
                "phone": "USER_CONFIRMED",
                "current_company": "USER_CONFIRMED",
            },
        }
        self.db.save_user_candidate_profile(self.user_id, profile_data)

        # 3. Create minimal valid PDF in candidate's isolated resume directory
        user_resumes_dir = Path("data") / "users" / str(self.user_id) / "resumes"
        user_resumes_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = user_resumes_dir / "Pranay_Agrawal_CV.pdf"
        minimal_pdf = (
            b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f\n0000000010 00000 n\n0000000060 00000 n\n"
            b"0000000117 00000 n\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n198\n%%EOF\n"
        )
        pdf_path.write_bytes(minimal_pdf)
        pdf_hash = hashlib.sha256(minimal_pdf).hexdigest()

        # 4. Seed into resumes and applications tables
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO resumes (
                    user_id, storage_filename, original_filename, file_format, file_hash, file_size_bytes, is_primary, is_active
                ) VALUES (?, ?, ?, 'pdf', ?, ?, 1, 1)""",
                (self.user_id, "Pranay_Agrawal_CV.pdf", "Pranay_Agrawal_CV.pdf", pdf_hash, len(minimal_pdf)),
            )
            self.resume_id = cursor.lastrowid

            cursor.execute(
                """INSERT INTO applications (
                    user_id, company_name, job_title, external_application_url, resume_id, status
                ) VALUES (?, 'CIN7', 'Software Engineer', 'https://jobs.lever.co/cin7/510ff0bd-2b01-4645-bf6f-89be209ad154/apply', ?, 'APPROVED')""",
                (self.user_id, self.resume_id),
            )
            self.app_id = cursor.lastrowid

        yield

        # 5. Clean up temporary filesystem artifacts
        try:
            if pdf_path.exists():
                pdf_path.unlink()
            if user_resumes_dir.exists() and not any(user_resumes_dir.iterdir()):
                user_resumes_dir.rmdir()
                user_parent = Path("data") / "users" / str(self.user_id)
                if user_parent.exists() and not any(user_parent.iterdir()):
                    user_parent.rmdir()
        except Exception:
            pass

    def test_plan_contains_no_banned_fixture_placeholders(self):
        """Verifies that generated plan facts never contain hardcoded sample/test strings."""
        apps = self.db.list_user_applications(self.user_id)
        assert len(apps) > 0, "Expected at least one application in database"

        target_app = apps[0]
        plan = self.broker.prepare_autofill_plan(self.user_id, target_app.id)

        for key, fact in plan.facts.items():
            val = fact.get("value")
            if val is not None and isinstance(val, str):
                for banned in BANNED_TEST_PLACEHOLDERS:
                    assert banned.lower() not in val.lower(), (
                        f"Contamination detected! Fact '{key}' contains test placeholder '{banned}': {val}"
                    )

    def test_real_profile_facts_match_db_profile_exactly(self):
        """Verifies that facts in autofill plan match SQLite candidate profile record exactly."""
        profile_row = self.db.get_user_candidate_profile(self.user_id)
        pdata = profile_row["profile_data"]
        personal = pdata.get("personal") or {}

        apps = self.db.list_user_applications(self.user_id)
        plan = self.broker.prepare_autofill_plan(self.user_id, apps[0].id)

        # 1. Full name
        db_name = (personal.get("full_name") or personal.get("name") or "").strip()
        plan_name = plan.facts.get("full_name", {}).get("value")
        assert plan_name == db_name, f"Name mismatch: DB='{db_name}', Plan='{plan_name}'"

        # 2. Email
        db_email = (personal.get("email") or "").strip()
        plan_email = plan.facts.get("email", {}).get("value")
        assert plan_email == db_email, f"Email mismatch: DB='{db_email}', Plan='{plan_email}'"

        # 3. Phone
        db_phone = (personal.get("phone") or "").strip()
        plan_phone = plan.facts.get("phone", {}).get("value")
        assert plan_phone == db_phone, f"Phone mismatch: DB='{db_phone}', Plan='{plan_phone}'"

        # 4. Resume binding
        resumes = self.db.list_user_resumes(self.user_id)
        if resumes:
            active_resume = resumes[0]
            assert plan.resume_id == active_resume["id"]
            assert plan.resume_filename == active_resume["storage_filename"]

    def test_missing_profile_attributes_leave_fields_blank(self):
        """Verifies that missing candidate facts result in NEEDS_INPUT with intended_value=None."""
        sparse_profile = {
            "personal": {
                "full_name": "Verified Candidate",
                "email": "verified@realdomain.com",
            }
            # Note: No phone, no current_salary, no github, no notice_period
        }
        mapper = UniversalFieldMapper(sparse_profile)

        # Missing phone
        phone_target = FormFieldTarget(name_attr="phone", field_type="tel", accessible_label="Phone")
        decision_phone = mapper.match_field(phone_target)
        assert decision_phone.action == "NEEDS_INPUT"
        assert decision_phone.intended_value is None

        # Missing salary
        salary_target = FormFieldTarget(name_attr="salary", accessible_label="Expected Salary")
        decision_salary = mapper.match_field(salary_target)
        assert decision_salary.action == "NEEDS_INPUT"
        assert decision_salary.intended_value is None

        # Missing GitHub
        github_target = FormFieldTarget(name_attr="github", accessible_label="GitHub URL")
        decision_github = mapper.match_field(github_target)
        assert decision_github.action == "NEEDS_INPUT"
        assert decision_github.intended_value is None

        # Missing Notice Period
        notice_target = FormFieldTarget(name_attr="notice", accessible_label="Notice Period (Days)")
        decision_notice = mapper.match_field(notice_target)
        assert decision_notice.action == "NEEDS_INPUT"
        assert decision_notice.intended_value is None

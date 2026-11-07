"""Phase B.3.2 Acceptance and Regression Test Suite.

Validates:
1. Universal resume parsing and acceptance on synthetic ACCA and CSE personas.
2. In-memory role inference across all 17 synthetic personas with zero hallucinated intern titles on senior roles.
3. Multi-tenant profile synchronization isolation without cross-candidate preference contamination.
4. Atomic discovery locking with DuplicateDiscoveryRunError and tenant isolation.
5. Recovery of interrupted discovery runs upon server startup.
6. Job deduplication with location differentiation.
"""

import os
import pytest
import sqlite3
import tempfile
from typing import Dict, Any

from src.database.db_manager import DatabaseManager
from src.database.models import Job
from src.database.exceptions import DuplicateDiscoveryRunError
from src.preparer.resume_parser import ResumeParser
from src.preparer.profile_updater import ProfileUpdater
from src.preparer.career_role_inferencer import CareerRoleInferencer
from tests.fixtures.synthetic_personas import (
    PERSONA_DEFINITIONS,
    generate_persona_pdf,
    generate_two_column_acca_pdf,
)


@pytest.fixture
def temp_db():
    """Provides a temporary, isolated SQLite DatabaseManager instance."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(db_path=path)
    yield db
    try:
        os.remove(path)
    except OSError:
        pass


def create_test_user(db: DatabaseManager, email: str, name: str) -> int:
    """Helper to insert an authenticated test user into database."""
    with db.transaction() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (email, password_hash, password_salt, full_name)
            VALUES (?, 'testhash', 'testsalt', ?)
            """,
            (email, name),
        )
        return cursor.lastrowid


class TestResumeAcceptanceSynthetic:
    """Acceptance tests verifying parsing and inference on synthetic ACCA and CSE resumes."""

    def test_synthetic_acca_resume_acceptance(self):
        """Validates two-column synthetic ACCA/Finance resume parsing and role inference."""
        pdf_bytes = generate_two_column_acca_pdf()
        parser = ResumeParser()
        parsed = parser.parse_bytes(pdf_bytes, file_format="pdf")

        # Basic identity & contact extraction
        assert parsed.full_name, "Candidate name must be extracted"
        assert parsed.email, "Candidate email must be extracted"
        assert parsed.phone, "Candidate phone must be extracted"

        # Education & certifications
        degrees = [e.degree.lower() for e in parsed.education]
        assert any("bba" in d or "bachelor" in d for d in degrees), "BBA degree must be extracted"

        # Check BBA CGPA
        bba_edu = next((e for e in parsed.education if "bba" in e.degree.lower() or "bachelor" in e.degree.lower()), None)
        assert bba_edu is not None
        assert bba_edu.cgpa is not None and abs(bba_edu.cgpa - 7.69) < 0.05, f"BBA CGPA should be ~7.69, got {bba_edu.cgpa}"

        # Professional qualification
        cert_names = [c.name.lower() for c in parsed.certifications] + [q.name.lower() for q in parsed.professional_qualifications]
        has_acca_cert = any("acca" in c for c in cert_names)
        assert has_acca_cert, "ACCA Member qualification must be recognized"

        # Work Experience / ACCA PER
        assert len(parsed.work_experience) >= 2, f"Expected multiple work roles, got {len(parsed.work_experience)}"

        # Skills & tools
        all_skills = [s.lower() for s in parsed.technical_skills + parsed.professional_skills + parsed.tools_and_software]
        assert any("tax" in s or "audit" in s or "accounting" in s or "vat" in s for s in all_skills), "Accounting/Tax domain skills must be extracted"

        # Career Role Inference
        inferencer = CareerRoleInferencer()
        inferred = inferencer.infer_roles_from_resume(parsed.to_dict())
        role_titles = inferred.suggested_roles

        assert any("tax" in r.lower() or "account" in r.lower() or "audit" in r.lower() for r in role_titles), (
            f"Inferred roles must align with finance/accounting, got {role_titles}"
        )
        # Ensure no "Intern" title hallucination for ACCA Member
        assert not any("intern" in r.lower() for r in role_titles), (
            f"ACCA Member must not receive intern role suggestions, got {role_titles}"
        )

    def test_synthetic_cse_resume_acceptance(self):
        """Validates synthetic CSE / AI & Mobile candidate parsing and role inference."""
        pdf_bytes = generate_persona_pdf("cs_mobile_ai_student")
        parser = ResumeParser()
        parsed = parser.parse_bytes(pdf_bytes, file_format="pdf")

        assert parsed.full_name, "Candidate name must be extracted"
        assert parsed.email, "Candidate email must be extracted"
        assert parsed.education, "Education must be extracted"

        # Skills
        all_skills = [s.lower() for s in parsed.technical_skills + parsed.tools_and_software]
        assert any("python" in s or "flutter" in s or "dart" in s for s in all_skills), (
            f"Expected tech skills (Python/Flutter/Dart), got {all_skills}"
        )

        # Career Role Inference
        inferencer = CareerRoleInferencer()
        inferred = inferencer.infer_roles_from_resume(parsed.to_dict())
        role_titles = inferred.suggested_roles

        assert any("software" in r.lower() or "engineer" in r.lower() or "developer" in r.lower() or "project manager" in r.lower() for r in role_titles), (
            f"Inferred roles must align with tech/software, got {role_titles}"
        )


class TestPersonaRoleInferenceNoInternHallucination:
    """Verifies that senior or qualified personas across all 17 domains never get intern titles."""

    @pytest.mark.parametrize("persona_key", [
        "cardiologist",
        "attorney",
        "cfa_investment_banker",
        "cpa_auditor",
        "supply_chain_director",
        "hotel_gm",
        "enterprise_sales",
        "backend_engineer",
        "stem_educator",
        "biotech_scientist",
        "creative_director",
    ])
    def test_senior_personas_never_assigned_intern(self, persona_key: str):
        persona_data = PERSONA_DEFINITIONS[persona_key]
        inferencer = CareerRoleInferencer()
        inferred = inferencer.infer_roles_from_resume(persona_data)
        role_titles = inferred.suggested_roles

        assert len(role_titles) > 0, f"Persona {persona_key} must have at least one inferred role"

        for title in role_titles:
            assert "intern" not in title.lower(), (
                f"Senior persona '{persona_key}' was incorrectly assigned intern title: '{title}'"
            )


class TestMultiTenantProfileIsolation:
    """Ensures candidate profiles and search preferences never leak across accounts."""

    def test_build_profile_dict_isolation(self, temp_db):
        updater = ProfileUpdater(db_manager=temp_db)

        # Candidate A profile in database
        candidate_a_id = create_test_user(temp_db, "user_a@example.com", "User A")
        temp_db.save_user_candidate_profile(
            user_id=candidate_a_id,
            profile_data={
                "personal": {"full_name": "Candidate A", "email": "user_a@example.com"},
                "search_preferences": {"target_roles": ["Chief Financial Officer"], "target_locations": ["London"]},
                "candidate_inputs": {"preferred_work_arrangement": "Remote"},
            },
        )

        # Candidate B builds profile from parsed resume with NO existing profile
        parsed_resume_b = {
            "name": "Candidate B",
            "email": "resume_b@example.com",
            "phone": "+91 9999999999",
            "education": [{"degree": "B.Com", "institution": "Mumbai University", "graduation_year": 2024}],
            "work_experience": [],
            "technical_skills": ["Accounting", "Excel"],
        }

        profile_b = updater.build_profile_dict(parsed_resume_b, existing_profile=None)

        # Ensure Candidate A's search preferences are NOT leaked into Candidate B's profile
        b_prefs = profile_b.get("search_preferences", {})
        assert b_prefs.get("target_roles") != ["Chief Financial Officer"], (
            "Candidate A's target roles leaked into Candidate B's profile!"
        )
        assert b_prefs.get("target_locations") != ["London"], (
            "Candidate A's target locations leaked into Candidate B's profile!"
        )

    def test_sync_user_profile_preserves_registered_email(self, temp_db):
        from pathlib import Path
        updater = ProfileUpdater(db_manager=temp_db)
        user_id = create_test_user(temp_db, "official_account@example.com", "Candidate Account")

        with tempfile.TemporaryDirectory() as tmp_base:
            base_dir = Path(tmp_base)
            user_dir = base_dir / str(user_id)
            user_dir.mkdir(parents=True, exist_ok=True)
            pdf_path = user_dir / "resume.pdf"
            pdf_path.write_bytes(generate_persona_pdf("cs_mobile_ai_student"))

            profile_data = updater.sync_user_profile(
                user_id=user_id,
                resume_path=pdf_path,
                user_base_dir=base_dir,
            )
            assert profile_data is not None
            assert profile_data["personal"]["email"] == "official_account@example.com", (
                f"Expected official account email to be preserved, got {profile_data['personal']['email']}"
            )


class TestAtomicDiscoveryLockingAndRecovery:
    """Verifies atomic discovery locking and restart recovery."""

    def test_duplicate_discovery_run_blocked(self, temp_db):
        user_id = create_test_user(temp_db, "discovery_user@example.com", "Discovery User")

        # First run succeeds
        run_1 = temp_db.create_discovery_run(
            user_id=user_id,
            target_roles=["Tax Associate"],
            target_locations=["Remote"],
        )
        assert run_1["id"] > 0

        # Second simultaneous run for same user must raise DuplicateDiscoveryRunError
        with pytest.raises(DuplicateDiscoveryRunError):
            temp_db.create_discovery_run(
                user_id=user_id,
                target_roles=["Tax Associate"],
                target_locations=["Remote"],
            )

        # Distinct user can run concurrently
        user_2_id = create_test_user(temp_db, "other_user@example.com", "Other User")
        run_2 = temp_db.create_discovery_run(
            user_id=user_2_id,
            target_roles=["Software Engineer"],
            target_locations=["Remote"],
        )
        assert run_2["id"] > 0

        # Complete user 1's run
        temp_db.update_discovery_run(run_1["id"], status="COMPLETED")

        # Now user 1 can create a new run
        run_3 = temp_db.create_discovery_run(
            user_id=user_id,
            target_roles=["Tax Associate"],
            target_locations=["Remote"],
        )
        assert run_3["id"] > 0

    def test_recover_interrupted_discovery_runs(self, temp_db):
        user_id = create_test_user(temp_db, "interrupted_user@example.com", "Interrupted User")
        run = temp_db.create_discovery_run(
            user_id=user_id,
            target_roles=["Data Analyst"],
            target_locations=["Remote"],
        )

        # Simulate server crash/restart recovery
        recovered_count = temp_db.recover_interrupted_discovery_runs()
        assert recovered_count >= 1

        updated_run = temp_db.get_discovery_run(run["id"])
        assert updated_run["status"] == "FAILED"
        assert "server restart" in updated_run["error_message"].lower()


class TestJobDeduplicationLocationDifferentiation:
    """Verifies that duplicate checks respect location differentiation."""

    def test_same_company_title_different_location_not_duplicate(self, temp_db):
        # Insert job in New York
        job = Job(
            company_name="Apex Software",
            job_title="Backend Developer",
            location="New York, NY",
            job_url="https://example.com/jobs/apex-ny-1",
            platform="custom",
            work_arrangement="Remote",
        )
        saved_job = temp_db.add_job(job)
        assert saved_job.id > 0

        # Same company & title in London should NOT be duplicate
        is_dup_london, _, _ = temp_db.check_is_duplicate(
            job_url="https://example.com/jobs/apex-london-2",
            company_name="Apex Software",
            job_title="Backend Developer",
            location="London, UK",
        )
        assert is_dup_london is False, "Distinct location job was incorrectly flagged as duplicate"

        # Same company, title, AND location should be duplicate
        is_dup_ny, _, _ = temp_db.check_is_duplicate(
            job_url="https://example.com/jobs/apex-ny-different-url",
            company_name="Apex Software",
            job_title="Backend Developer",
            location="New York, NY",
        )
        assert is_dup_ny is True, "Identical title, company, and location must be flagged as duplicate"


class TestHonestMatchExplanation:
    """Verifies that unevaluated opportunities return honest unevaluated states."""

    def test_unevaluated_job_match_explanation(self, temp_db):
        from backend.api.routers.jobs import get_job_match_explanation
        from unittest.mock import MagicMock

        user_id = create_test_user(temp_db, "seeker@example.com", "Job Seeker")
        job = Job(
            company_name="Target Corp",
            job_title="Auditor",
            location="Remote",
            job_url="https://example.com/job/target-auditor",
            platform="custom",
        )
        saved = temp_db.add_job(job)

        # Mock DashboardService instance with temp_db
        mock_service = MagicMock()
        mock_service.db = temp_db
        mock_service.get_user_match_results_for_jobs.return_value = {}

        from unittest.mock import patch
        with patch("backend.api.routers.jobs.DashboardService.get_instance", return_value=mock_service):
            resp = get_job_match_explanation(
                job_id=saved.id,
                auth_ctx=(user_id, MagicMock()),
            )

        assert resp["is_evaluated"] is False
        assert resp["match_score"] is None
        assert resp["is_eligible"] is None
        assert resp["eligibility_status"] == "UNKNOWN"
        assert "not yet been evaluated" in resp["explanation"].lower()


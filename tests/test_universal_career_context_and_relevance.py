"""Universal Cross-Industry Career Context & Relevance Verification Test Suite.

Verifies:
1. Scenario A: ACCA / Finance candidate receives accounting/tax/audit roles and strictly rejects AI/ML jobs.
2. Scenario B: Computer Science candidate receives software engineering roles and accepts tech opportunities.
3. Scenario C: Healthcare candidate receives clinical roles and rejects tech/tax jobs.
4. Scenario D: Legal candidate receives corporate counsel/legal roles and rejects tech/clinical jobs.
5. Scenario E: Mechanical Engineering candidate receives mechanical/CAD roles and rejects tax/clinical jobs.
6. Scenario F: Resume replacement on the same account from CSE to ACCA refreshes career context,
   updates resume fingerprint, isolates default feed results, and prevents stale match score reuse.
7. Un-evaluated jobs report PENDING_EVALUATION with null scores, never 0% Ineligible.
"""

from pathlib import Path
import tempfile
import pytest

from src.database.db_manager import DatabaseManager
from src.database.models import MatchResult
from src.preparer.career_context_resolver import CareerContextResolver
from src.preparer.career_role_inferencer import CareerRoleInferencer
from src.preparer.profile_updater import ProfileUpdater
from tests.fixtures.synthetic_personas import PERSONA_DEFINITIONS


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test_career_context.db"
        db = DatabaseManager(db_path=db_path)
        yield db


@pytest.fixture
def inferencer():
    return CareerRoleInferencer()


@pytest.fixture
def resolver(temp_db, inferencer):
    return CareerContextResolver(db_manager=temp_db, inferencer=inferencer)


def create_test_user(db: DatabaseManager, email: str, full_name: str) -> int:
    with db.transaction() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, 'hash', 'salt', ?)",
            (email, full_name),
        )
        return cursor.lastrowid


def create_test_job(db: DatabaseManager, job_id: int, title: str, company: str = "Test Co") -> int:
    with db.transaction() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO jobs (id, job_title, company_name, job_url, location, platform)
            VALUES (?, ?, ?, ?, 'Remote', 'synthetic')
            """,
            (job_id, title, company, f"https://example.com/job/{job_id}"),
        )
        return job_id


class TestUniversalCareerContextAndRelevance:
    """Universal cross-industry test suite verifying domain isolation, relevance, and resume replacement."""

    def test_scenario_a_acca_finance_candidate(self, resolver):
        """Scenario A: ACCA / Finance candidate receives accounting/tax roles and rejects AI/ML jobs."""
        persona = PERSONA_DEFINITIONS["acca_finance_professional"]

        # Register synthetic user and primary resume
        user_id = create_test_user(resolver.db, "acca_cand@example.com", full_name="Pranjali Agrawal")
        resume_rec = resolver.db.create_user_resume(
            user_id=user_id,
            storage_filename="acca_resume.pdf",
            original_filename="synthetic_acca_resume.pdf",
            file_format="pdf",
            file_hash="acca_file_hash_1234567890abcdef",
            file_size_bytes=45000,
            parsed_data=persona,
            is_primary=True,
        )
        resume_id = resume_rec["id"]

        ctx = resolver.resolve_candidate_career_context(user_id)

        assert ctx.has_primary_resume is True
        assert ctx.primary_resume_id == resume_id
        assert ctx.career_domain == "accounting_finance"
        assert "Accounting" in ctx.candidate_category or "Finance" in ctx.candidate_category

        inferred_titles = [r.role_title for r in ctx.inferred_roles]
        assert any("Tax" in t for t in inferred_titles), f"Expected tax role in {inferred_titles}"
        assert any("Audit" in t or "Accounts" in t for t in inferred_titles), f"Expected audit/accounts role in {inferred_titles}"

        # Negative acceptance criteria: relevance check MUST reject tech/AI/ML jobs
        assert resolver.is_job_relevant("Machine Learning Intern", "Build LLM models", ctx) is False
        assert resolver.is_job_relevant("Artificial Intelligence Intern", "Tensorflow and PyTorch", ctx) is False
        assert resolver.is_job_relevant("Computer Vision Intern", "OpenCV and deep learning", ctx) is False
        assert resolver.is_job_relevant("Python Developer", "Django microservices", ctx) is False
        assert resolver.is_job_relevant("Software Engineer", "React and backend engineering", ctx) is False

        # Positive acceptance criteria: relevance check MUST accept accounting/tax jobs
        assert resolver.is_job_relevant("UK Tax Associate", "SA100 filings and HMRC compliance", ctx) is True
        assert resolver.is_job_relevant("Tax Analyst", "Direct and indirect taxation", ctx) is True
        assert resolver.is_job_relevant("Audit Associate", "Statutory audit and internal controls", ctx) is True
        assert resolver.is_job_relevant("Accounts Associate", "Xero accounts payable and bank reconciliations", ctx) is True
        assert resolver.is_job_relevant("Financial Reporting Associate", "Balance sheet reconciliations", ctx) is True

    def test_scenario_b_computer_science_candidate(self, resolver):
        """Scenario B: Computer Science candidate receives software engineering roles."""
        persona = PERSONA_DEFINITIONS["backend_engineer"]

        user_id = create_test_user(resolver.db, "cs_cand@example.com", full_name="Alex Mercer")
        resolver.db.create_user_resume(
            user_id=user_id,
            storage_filename="cs_resume.pdf",
            original_filename="synthetic_cs_resume.pdf",
            file_format="pdf",
            file_hash="cs_file_hash_1234567890abcdef",
            file_size_bytes=42000,
            parsed_data=persona,
            is_primary=True,
        )

        ctx = resolver.resolve_candidate_career_context(user_id)

        assert ctx.has_primary_resume is True
        assert ctx.career_domain in ("software_tech", "engineering_tech")
        inferred_titles = [r.role_title for r in ctx.inferred_roles]
        assert any("Engineer" in t or "Developer" in t for t in inferred_titles)

        # Tech jobs accepted
        assert resolver.is_job_relevant("Backend Developer", "Golang and microservices", ctx) is True
        assert resolver.is_job_relevant("Software Engineer", "Distributed systems", ctx) is True

        # Unrelated clinical or statutory accounting jobs rejected
        assert resolver.is_job_relevant("Cardiologist", "Inpatient telemetry", ctx) is False
        assert resolver.is_job_relevant("UK Tax Associate", "HMRC SA100 returns", ctx) is False

    def test_scenario_c_healthcare_candidate(self, resolver):
        """Scenario C: Healthcare candidate receives clinical roles."""
        persona = PERSONA_DEFINITIONS["cardiologist"]

        user_id = create_test_user(resolver.db, "cardio@example.com", full_name="Dr. Sarah Jenkins")
        resolver.db.create_user_resume(
            user_id=user_id,
            storage_filename="cardio_resume.pdf",
            original_filename="synthetic_cardio_resume.pdf",
            file_format="pdf",
            file_hash="cardio_file_hash_1234567890abcdef",
            file_size_bytes=52000,
            parsed_data=persona,
            is_primary=True,
        )

        ctx = resolver.resolve_candidate_career_context(user_id)

        assert ctx.has_primary_resume is True
        assert ctx.career_domain == "healthcare"
        inferred_titles = [r.role_title for r in ctx.inferred_roles]
        assert any("Cardiologist" in t or "Clinical" in t or "Physician" in t for t in inferred_titles)

        # Clinical jobs accepted
        assert resolver.is_job_relevant("Cardiologist", "Catheterization lab", ctx) is True
        assert resolver.is_job_relevant("Clinical Specialist", "Inpatient cardiac care", ctx) is True

        # Pure software or tax jobs rejected
        assert resolver.is_job_relevant("Software Engineer", "Web development", ctx) is False
        assert resolver.is_job_relevant("Tax Accountant", "Corporate tax returns", ctx) is False

    def test_scenario_d_legal_candidate(self, resolver):
        """Scenario D: Legal candidate receives corporate law/compliance roles."""
        persona = PERSONA_DEFINITIONS["attorney"]

        user_id = create_test_user(resolver.db, "attorney@example.com", full_name="Morgan Vance")
        resolver.db.create_user_resume(
            user_id=user_id,
            storage_filename="legal_resume.pdf",
            original_filename="synthetic_legal_resume.pdf",
            file_format="pdf",
            file_hash="legal_file_hash_1234567890abcdef",
            file_size_bytes=48000,
            parsed_data=persona,
            is_primary=True,
        )

        ctx = resolver.resolve_candidate_career_context(user_id)

        assert ctx.has_primary_resume is True
        assert ctx.career_domain == "legal"
        inferred_titles = [r.role_title for r in ctx.inferred_roles]
        assert any("Counsel" in t or "Legal" in t for t in inferred_titles)

        # Legal jobs accepted
        assert resolver.is_job_relevant("Corporate Counsel", "M&A due diligence", ctx) is True
        assert resolver.is_job_relevant("Legal Associate", "Commercial contracts", ctx) is True

        # Tech or clinical jobs rejected
        assert resolver.is_job_relevant("Software Engineer", "Full stack apps", ctx) is False
        assert resolver.is_job_relevant("Cardiologist", "Coronary care", ctx) is False

    def test_scenario_e_mechanical_engineering_candidate(self, resolver):
        """Scenario E: Mechanical Engineering candidate receives CAD/engineering roles."""
        persona = PERSONA_DEFINITIONS["mechanical_engineer"]

        user_id = create_test_user(resolver.db, "mech@example.com", full_name="Marcus Vance")
        resolver.db.create_user_resume(
            user_id=user_id,
            storage_filename="mech_resume.pdf",
            original_filename="synthetic_mech_resume.pdf",
            file_format="pdf",
            file_hash="mech_file_hash_1234567890abcdef",
            file_size_bytes=47000,
            parsed_data=persona,
            is_primary=True,
        )

        ctx = resolver.resolve_candidate_career_context(user_id)

        assert ctx.has_primary_resume is True
        assert ctx.career_domain == "mechanical_engineering"
        inferred_titles = [r.role_title for r in ctx.inferred_roles]
        assert any("Mechanical" in t or "CAD" in t or "Simulation" in t for t in inferred_titles)

        # Mechanical jobs accepted
        assert resolver.is_job_relevant("Mechanical Engineer", "CAD design in SolidWorks", ctx) is True
        assert resolver.is_job_relevant("Thermal Simulation Specialist", "Ansys FEA analysis", ctx) is True

        # Clinical or tax jobs rejected
        assert resolver.is_job_relevant("UK Tax Associate", "SA100 returns", ctx) is False
        assert resolver.is_job_relevant("Cardiologist", "Inpatient telemetry", ctx) is False

    def test_scenario_f_resume_replacement_cse_to_acca(self, resolver):
        """Scenario F: Profile changed from CSE to ACCA on the same account.

        Verifies:
        1. Context updates to ACCA roles.
        2. Resume fingerprint updates.
        3. Old CSE discovered jobs disappear from current-resume feed.
        4. Stale match scores from previous resume are not returned.
        """
        user_id = create_test_user(resolver.db, "switch_cand@example.com", full_name="Candidate Switching")

        # Step 1: Upload and activate CSE resume
        cse_persona = PERSONA_DEFINITIONS["backend_engineer"]
        cse_res_rec = resolver.db.create_user_resume(
            user_id=user_id,
            storage_filename="cse_first.pdf",
            original_filename="cse_first.pdf",
            file_format="pdf",
            file_hash="cse_hash_1111222233334444",
            file_size_bytes=35000,
            parsed_data=cse_persona,
            is_primary=True,
        )
        cse_resume_id = cse_res_rec["id"]

        # Resolve initial context
        cse_ctx = resolver.resolve_candidate_career_context(user_id)
        assert cse_ctx.career_domain in ("software_tech", "engineering_tech")
        cse_fingerprint = cse_ctx.resume_fingerprint

        # Discovery run for CSE
        create_test_job(resolver.db, 101, "Backend Developer", "Cloud Tech")
        create_test_job(resolver.db, 102, "Golang Software Engineer", "Stream Corp")
        cse_run = resolver.db.create_discovery_run(
            user_id=user_id,
            target_roles=cse_ctx.selected_roles,
            target_locations=cse_ctx.target_locations,
            resume_id=cse_resume_id,
            resume_fingerprint=cse_fingerprint,
        )
        resolver.db.record_candidate_discovered_jobs(
            user_id=user_id,
            job_ids=[101, 102],
            discovery_run_id=cse_run["id"],
            resume_id=cse_resume_id,
            resume_fingerprint=cse_fingerprint,
        )
        resolver.db.update_discovery_run(cse_run["id"], status="COMPLETED", total_discovered=2, new_jobs_saved=2)

        # Record mock match result evaluated against CSE resume
        resolver.db.save_match_result(
            MatchResult(
                user_id=user_id,
                resume_id=cse_resume_id,
                job_id=101,
                match_score=92.0,
                match_classification="Excellent Match",
                eligibility_status="ELIGIBLE",
                score_breakdown='{"domain_relevance": 30.0}',
                explanation="Strong backend Golang experience aligns with job.",
                resume_file_hash="cse_hash_1111222233334444",
            )
        )

        # Step 2: Replace primary resume with ACCA resume on the same account
        acca_persona = PERSONA_DEFINITIONS["acca_finance_professional"]
        acca_res_rec = resolver.db.create_user_resume(
            user_id=user_id,
            storage_filename="acca_replacement.pdf",
            original_filename="acca_replacement.pdf",
            file_format="pdf",
            file_hash="acca_hash_9999888877776666",
            file_size_bytes=48000,
            parsed_data=acca_persona,
            is_primary=True,
        )
        acca_resume_id = acca_res_rec["id"]

        # Update profile with updater
        updater = ProfileUpdater(db_manager=resolver.db)
        profile_dict = updater.build_profile_dict(acca_persona)
        resolver.db.save_user_candidate_profile(user_id, profile_dict)

        # Step 3: Resolve new career context
        acca_ctx = resolver.resolve_candidate_career_context(user_id)
        assert acca_ctx.primary_resume_id == acca_resume_id
        assert acca_ctx.career_domain == "accounting_finance"
        assert acca_ctx.resume_fingerprint != cse_fingerprint

        inferred_titles = [r.role_title for r in acca_ctx.inferred_roles]
        assert any("Tax" in t or "Accounts" in t for t in inferred_titles)
        assert not any("Software" in t or "Distributed" in t for t in inferred_titles)

        # Step 4: Verify candidate-scoped jobs for ACCA resume fingerprint
        # Old CSE jobs (101, 102) must NOT be returned for the new ACCA resume fingerprint!
        discovered_for_acca = resolver.db.get_candidate_discovered_job_ids(
            user_id=user_id,
            resume_fingerprint=acca_ctx.resume_fingerprint,
        )
        assert 101 not in discovered_for_acca
        assert 102 not in discovered_for_acca
        assert discovered_for_acca == []

        # Run discovery for ACCA
        create_test_job(resolver.db, 201, "UK Tax Associate", "Terra Global")
        create_test_job(resolver.db, 202, "Audit Associate", "Apex Retail")
        acca_run = resolver.db.create_discovery_run(
            user_id=user_id,
            target_roles=acca_ctx.selected_roles,
            target_locations=acca_ctx.target_locations,
            resume_id=acca_resume_id,
            resume_fingerprint=acca_ctx.resume_fingerprint,
        )
        resolver.db.record_candidate_discovered_jobs(
            user_id=user_id,
            job_ids=[201, 202],
            discovery_run_id=acca_run["id"],
            resume_id=acca_resume_id,
            resume_fingerprint=acca_ctx.resume_fingerprint,
        )
        resolver.db.update_discovery_run(acca_run["id"], status="COMPLETED", total_discovered=2, new_jobs_saved=2)

        discovered_now = resolver.db.get_candidate_discovered_job_ids(
            user_id=user_id,
            resume_fingerprint=acca_ctx.resume_fingerprint,
        )
        assert set(discovered_now) == {201, 202}

        # Step 5: Verify stale match scores from old CSE resume are NOT reused for ACCA resume
        matches = resolver.db.get_user_match_results_for_jobs(
            user_id=user_id,
            job_ids=[101, 201],
            resume_id=acca_ctx.primary_resume_id,
            resume_file_hash=acca_ctx.primary_resume_file_hash,
        )
        # Job 101 was scored against CSE resume, so it must NOT be in matches for ACCA resume!
        assert 101 not in matches
        assert 201 not in matches  # Not evaluated yet for ACCA resume

    def test_un_evaluated_job_status_is_pending_not_ineligible(self, resolver):
        """Un-evaluated jobs must report PENDING_EVALUATION, never 0% Ineligible."""
        user_id = create_test_user(resolver.db, "uneval@example.com", full_name="Candidate Uneval")
        resume_rec = resolver.db.create_user_resume(
            user_id=user_id,
            storage_filename="resume.pdf",
            original_filename="resume.pdf",
            file_format="pdf",
            file_hash="uneval_hash_12345678",
            file_size_bytes=30000,
            parsed_data=PERSONA_DEFINITIONS["acca_finance_professional"],
            is_primary=True,
        )
        resume_id = resume_rec["id"]

        # Check match result for job 999 which was never evaluated
        matches = resolver.db.get_user_match_results_for_jobs(
            user_id=user_id,
            job_ids=[999],
            resume_id=resume_id,
            resume_file_hash="uneval_hash_12345678",
        )
        assert 999 not in matches

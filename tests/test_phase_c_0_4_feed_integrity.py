"""Phase C.0.4 Regression Test Suite: Critical Job Feed Integrity Hotfix.

Validates:
1. Strict elimination of cross-industry job feed leakage.
2. Prevention of UniversalMatcher scoring fallback hallucinations (0.0 ratio, not 1.0, for empty skills/duties).
3. Positive domain alignment and discipline mismatch enforcement in eligibility engine.
4. Candidate-scoped resume fingerprint persistence and filtering in match_results and candidate_discovered_jobs.
5. Absolute integrity of default Explore Jobs feed for both ACCA/Finance and CS/AI personas.
"""

import pytest
import os
import tempfile

from src.database.db_manager import DatabaseManager
from src.database.models import MatchResult
from src.matcher.universal_matcher import (
    UniversalSkillMatcher,
    ResponsibilityAlignmentEvaluator,
    EducationCompatibilityEvaluator,
    UniversalEligibilityEvaluator,
    NormalizedCandidateFacts,
    NormalizedJobRequirements,
    NormalizedSkill,
    NormalizedEducation,
    NormalizedExperience,
)
from src.preparer.career_context_resolver import CareerContextResolver, CandidateCareerContext
from dashboard.services.dashboard_service import DashboardService
from src.security.session_manager import SessionManager


@pytest.fixture
def test_db():
    """Provides a fresh isolated in-memory or temporary SQLite database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    os.environ["APP_ENV"] = "test"
    os.environ["DATABASE_PATH"] = db_path
    db = DatabaseManager(db_path=db_path)
    yield db
    if os.path.exists(db_path):
        os.remove(db_path)


class TestRelevanceGatePrecision:
    """Verifies that CareerContextResolver.is_job_relevant rejects cross-domain leaks and requires positive alignment."""

    def test_acca_candidate_relevance_checks(self):
        resolver = CareerContextResolver()
        acca_ctx = CandidateCareerContext(
            user_id=105,
            has_primary_resume=True,
            career_domain="accounting_finance",
            candidate_category="Accounting & Finance",
            selected_roles=["Tax Associate", "Accounts Associate", "Audit Associate"],
            supporting_skills=["Tax", "Audit", "Financial Reporting", "Tally", "Xero", "GST"],
        )

        # Tech/AI jobs must be strictly rejected
        assert not resolver.is_job_relevant("Generative AI Engineering Intern — Venxr", "", acca_ctx)
        assert not resolver.is_job_relevant("Applied Research Intern (NLP/ML/GenAI)", "", acca_ctx)
        assert not resolver.is_job_relevant("AI/ML Intern, Document Intelligence", "", acca_ctx)
        assert not resolver.is_job_relevant("AI Engineer Intern", "", acca_ctx)
        assert not resolver.is_job_relevant("AI Intern – Small Language Models (SLMs)", "", acca_ctx)
        assert not resolver.is_job_relevant("Voice AI Internship in Delhi", "", acca_ctx)
        assert not resolver.is_job_relevant("Commercial Analytics Intern", "", acca_ctx)
        assert not resolver.is_job_relevant("ML AI Intern", "", acca_ctx)
        assert not resolver.is_job_relevant("Software Engineer Intern", "", acca_ctx)

        # Unrelated non-tech jobs must be strictly rejected
        assert not resolver.is_job_relevant("Fiction Writer (Romance, Dark Romance...) – Internship", "", acca_ctx)
        assert not resolver.is_job_relevant("Training And Internship Counselor", "", acca_ctx)
        assert not resolver.is_job_relevant("Founders Office Internship - Female", "", acca_ctx)
        assert not resolver.is_job_relevant("Clinical Research Nurse", "", acca_ctx)
        assert not resolver.is_job_relevant("Corporate Litigation Counsel", "", acca_ctx)

        # Relevant accounting/finance jobs must pass
        assert resolver.is_job_relevant("Tax Executive, Personal Tax Compliance Unit", "", acca_ctx)
        assert resolver.is_job_relevant("Record to Report Ops Associate", "", acca_ctx)
        assert resolver.is_job_relevant("Associate Tax Accountant", "", acca_ctx)
        assert resolver.is_job_relevant("Junior Accountant", "", acca_ctx)
        assert resolver.is_job_relevant("Private Client Tax Associate", "", acca_ctx)
        assert resolver.is_job_relevant("Tax Associate II", "", acca_ctx)
        assert resolver.is_job_relevant("Associate - Accounting & Finance", "", acca_ctx)

    def test_cs_candidate_relevance_checks(self):
        resolver = CareerContextResolver()
        cs_ctx = CandidateCareerContext(
            user_id=1,
            has_primary_resume=True,
            career_domain="software_tech",
            candidate_category="Software & Technology",
            selected_roles=["AI Intern", "Machine Learning Intern", "Data Science Intern", "Python Developer Intern"],
            supporting_skills=["Python", "Machine Learning", "Deep Learning", "TensorFlow", "React"],
        )

        # Tech/AI jobs must be accepted
        assert resolver.is_job_relevant("Generative AI Engineering Intern — Venxr", "", cs_ctx)
        assert resolver.is_job_relevant("Applied Research Intern (NLP/ML/GenAI)", "", cs_ctx)
        assert resolver.is_job_relevant("AI/ML Intern, Document Intelligence", "", cs_ctx)
        assert resolver.is_job_relevant("AI Engineer Intern", "", cs_ctx)
        assert resolver.is_job_relevant("Voice AI Internship in Delhi", "", cs_ctx)
        assert resolver.is_job_relevant("Python Developer Intern", "", cs_ctx)

        # Accounting, legal, clinical, and writing jobs must be rejected
        assert not resolver.is_job_relevant("Tax Executive, Personal Tax Compliance Unit", "", cs_ctx)
        assert not resolver.is_job_relevant("Associate Tax Accountant", "", cs_ctx)
        assert not resolver.is_job_relevant("Junior Accountant", "", cs_ctx)
        assert not resolver.is_job_relevant("Clinical Staff Nurse", "", cs_ctx)
        assert not resolver.is_job_relevant("Fiction Writer", "", cs_ctx)
        assert not resolver.is_job_relevant("Training And Internship Counselor", "", cs_ctx)


class TestUniversalMatcherHallucinationDefense:
    """Verifies that empty job skills or missing duties NEVER award 100% scores."""

    def test_empty_skills_with_no_candidate_overlap_awards_zero_ratio(self):
        facts = NormalizedCandidateFacts(
            skills=[NormalizedSkill(name="Tax", canonical_name="tax"), NormalizedSkill(name="Audit", canonical_name="audit")],
            education=[NormalizedEducation(degree="BBA", major="Finance", degree_rank=3, verification_status="USER_CONFIRMED")],
            location="India",
        )
        reqs = NormalizedJobRequirements(
            job_title="Generative AI Engineering Intern — Venxr",
            location="Pune",
            mandatory_skills=[],
            preferred_skills=[],
        )

        assessments, skill_ratio, conf = UniversalSkillMatcher.evaluate(facts, reqs)
        assert skill_ratio == 0.0, f"Expected 0.0 skill ratio for AI role with zero candidate match, got {skill_ratio}"

    def test_empty_responsibilities_with_no_title_overlap_awards_zero_ratio(self):
        facts = NormalizedCandidateFacts(
            skills=[NormalizedSkill(name="Tax", canonical_name="tax")],
            experience=[NormalizedExperience(employer="Audit Firm", job_title="Tax Associate", responsibilities=["Filing tax returns"])],
            education=[NormalizedEducation(degree="BBA", major="Finance", degree_rank=3, verification_status="USER_CONFIRMED")],
        )
        reqs = NormalizedJobRequirements(
            job_title="Generative AI Engineering Intern — Venxr",
            responsibilities=[],
        )

        resp_ratio, notes = ResponsibilityAlignmentEvaluator.evaluate(facts, reqs)
        assert resp_ratio == 0.0, f"Expected 0.0 responsibility ratio for AI role with zero duties match, got {resp_ratio}"

    def test_discipline_mismatch_triggers_ineligible_status(self):
        facts = NormalizedCandidateFacts(
            skills=[NormalizedSkill(name="Tax", canonical_name="tax")],
            education=[NormalizedEducation(degree="BBA", major="Finance", degree_rank=3, verification_status="USER_CONFIRMED")],
            location="India",
        )
        reqs = NormalizedJobRequirements(
            job_title="Generative AI Engineering Intern — Venxr",
            location="India",
            is_internship=True,
        )

        edu_analysis, edu_ratio, edu_conf = EducationCompatibilityEvaluator.evaluate(facts, reqs)
        assert edu_analysis.get("major_match") == "DISCIPLINE_MISMATCH"
        assert edu_ratio <= 0.20

        status, reasons = UniversalEligibilityEvaluator.evaluate(facts, reqs, edu_analysis, {}, {})
        assert status == "INELIGIBLE", f"Expected INELIGIBLE for cross-domain discipline mismatch, got {status}"
        assert any("incompatible" in r.lower() for r in reasons)


class TestResumeFingerprintPersistenceAndScoping:
    """Verifies that match_results stores resume_fingerprint and db queries scope to active fingerprint."""

    def test_save_and_fetch_match_result_with_fingerprint(self, test_db):
        with test_db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('test_fp@example.com', 'h', 's', 'FP User')")
            user_id = cursor.lastrowid
            cursor.execute("INSERT INTO resumes (user_id, storage_filename, original_filename, file_format, file_hash, file_size_bytes, is_primary) VALUES (?, 'res.pdf', 'resume.pdf', 'pdf', 'abcd1234efgh5678abcd1234efgh5678', 1000, 1)", (user_id,))
            res_id = cursor.lastrowid

        mr = MatchResult(
            user_id=user_id,
            resume_id=res_id,
            job_id=None,
            job_description_id=None,
            match_score=85.0,
            match_classification="Good Match",
            eligibility_status="ELIGIBLE",
            score_breakdown="{}",
            explanation="Test evaluation",
            resume_file_hash="abcd1234efgh5678abcd1234efgh5678",
            resume_fingerprint=f"rfp_{res_id}_abcd1234efgh5678",
        )
        mid = test_db.save_match_result(mr)
        assert mid > 0

        # Retrieve and verify fingerprint preserved
        retrieved = test_db.get_match_result(mid, user_id=user_id)
        assert retrieved is not None
        assert retrieved.resume_fingerprint == f"rfp_{res_id}_abcd1234efgh5678"

    def test_get_user_match_results_for_jobs_rejects_stale_fingerprint(self, test_db):
        with test_db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('test_stale@example.com', 'h', 's', 'Stale User')")
            user_id = cursor.lastrowid
            cursor.execute("INSERT INTO companies (name) VALUES ('TechCorp')")
            cid = cursor.lastrowid
            cursor.execute("INSERT INTO jobs (company_id, company_name, job_title, job_description, job_url, platform) VALUES (?, 'TechCorp', 'Software Engineer', 'Description', 'https://example.com/job', 'LinkedIn')", (cid,))
            jid = cursor.lastrowid

        # Match evaluated under Resume A
        mr_a = MatchResult(
            user_id=user_id,
            resume_id=None,
            job_id=jid,
            job_description_id=None,
            match_score=90.0,
            match_classification="Excellent",
            eligibility_status="ELIGIBLE",
            score_breakdown="{}",
            explanation="Evaluated on Resume A",
            resume_file_hash="hash_aaaa",
            resume_fingerprint="rfp_101_hash_aaaa",
        )
        test_db.save_match_result(mr_a)

        # Query with Resume B fingerprint -> should return empty dict (stale score shielded)
        results = test_db.get_user_match_results_for_jobs(
            user_id=user_id,
            job_ids=[jid],
            resume_fingerprint="rfp_202_hash_bbbb",
        )
        assert jid not in results, "Stale score from Resume A leaked into Resume B query!"

        # Query with Resume A fingerprint -> returns match
        results_a = test_db.get_user_match_results_for_jobs(
            user_id=user_id,
            job_ids=[jid],
            resume_fingerprint="rfp_101_hash_aaaa",
        )
        assert jid in results_a
        assert results_a[jid].match_score == 90.0


class TestLiveDatabaseFeedIntegrity:
    """Verifies that the live default Explore Jobs feed for User 105 is strictly accounting/tax/audit jobs."""

    def test_user_105_feed_contains_only_relevant_jobs(self):
        from backend.api.routers.jobs import list_jobs
        live_db_path = "data/storage/job_assistant.db"
        if not os.path.exists(live_db_path):
            pytest.skip("Live database not found.")

        os.environ["DATABASE_PATH"] = live_db_path
        db = DatabaseManager(db_path=live_db_path)
        DashboardService.get_instance(db_manager=db)
        session_mgr = SessionManager(db_manager=db)
        session = session_mgr.create_user_session(user_id=105, email="pranjali.a.agrawal@gmail.com")

        items = list_jobs(
            search=None,
            arrangement=None,
            platform=None,
            min_score=None,
            only_eligible=None,
            saved_only=False,
            recommended_only=False,
            auth_ctx=(105, session),
        )

        assert len(items) > 0, "Expected discovered jobs for User 105, found 0."
        prohibited_terms = ["ai", "machine learning", "nlp", "writer", "counselor", "defense", "small language"]

        for idx, item in enumerate(items, 1):
            title_lower = item.job_title.lower()
            # Must not contain prohibited cross-industry terms
            for bad_term in prohibited_terms:
                assert bad_term not in title_lower, f"Item #{idx} '{item.job_title}' contained prohibited term '{bad_term}'!"

            # Must contain relevant accounting/finance keywords
            has_relevant = any(t in title_lower for t in ["tax", "account", "audit", "finance", "compliance", "report"])
            assert has_relevant, f"Item #{idx} '{item.job_title}' has no relevant accounting/tax/audit keywords!"


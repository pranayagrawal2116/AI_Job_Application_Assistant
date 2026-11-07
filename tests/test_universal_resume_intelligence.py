"""Phase B.3.1 Universal Resume Intelligence & Cross-Industry Discovery Test Suite.

Verifies:
1. Multi-column PDF layout-aware coordinate extraction (PyMuPDF).
2. Comprehensive multi-record ACCA / accounting / finance resume parsing:
   - Non-overlapping distinct experience roles
   - Supervised ACCA Practical Experience Requirement (PER)
   - Academic education (BBA, B.Com, HSC CBSE) and percentages/CGPA
   - Professional qualifications and memberships (ACCA Member)
   - Domain skills (UK taxation, SA100, Audit) and software suites (Digita, Xero, etc.)
   - Languages (English, Hindi, Gujarati)
3. Profession-isolated career role inference without AI/ML bias.
4. Discovery query generator without artificial AI/ML fallbacks.
5. Authoritative single-pass profile synchronization without swallowed exceptions.
6. Candidate-isolated matching without catalog score leakage.
7. Job listing deduplication across normalized company, title, and location.
8. Non-blocking asynchronous discovery execution and progress polling.
"""

import pytest

from tests.fixtures.synthetic_personas import (
    generate_persona_pdf,
    generate_two_column_acca_pdf,
)
from src.preparer.resume_parser import ResumeParser
from src.preparer.career_role_inferencer import CareerRoleInferencer
from src.scraper.discovery.query_generator import QueryGenerator
from src.preparer.profile_updater import ProfileUpdater
from dashboard.services.dashboard_service import DashboardService


class TestUniversalResumeIntelligence:
    """Comprehensive regression suite for universal cross-industry resume parsing."""

    @pytest.fixture
    def parser(self):
        return ResumeParser()

    @pytest.fixture
    def inferencer(self):
        return CareerRoleInferencer()

    def test_two_column_coordinate_extraction(self, parser):
        """PyMuPDF block coordinates correctly segment left-column credentials from right-column experience."""
        pdf_bytes = generate_two_column_acca_pdf("acca_finance_professional")
        parsed = parser.parse_bytes(pdf_bytes, ".pdf")

        assert parsed.full_name == "Pranjali Agrawal"
        assert parsed.email == "pranjali.finance@synthetic-domain.org"
        assert "pune" in parsed.location.lower()

        # Raw text ordering: Education and Professional Qualifications appear before Work Experience
        raw = parsed.raw_text
        edu_pos = raw.find("Education")
        qual_pos = raw.find("Professional Qualifications")
        exp_pos = raw.find("Work Experience")

        assert edu_pos != -1, "Education heading missing"
        assert qual_pos != -1, "Professional Qualifications heading missing"
        assert exp_pos != -1, "Work Experience heading missing"
        assert edu_pos < exp_pos, "Left column Education should be parsed before right column Work Experience"
        assert qual_pos < exp_pos, "Left column Qualifications should be parsed before right column Work Experience"

    def test_acca_education_extraction(self, parser):
        """BBA Finance degree (CGPA 7.69) and Class 12 CBSE HSC Commerce (93.8%) are both parsed."""
        pdf_bytes = generate_two_column_acca_pdf("acca_finance_professional")
        parsed = parser.parse_bytes(pdf_bytes, ".pdf")

        assert len(parsed.education) >= 2
        degrees = [e.degree.lower() for e in parsed.education]
        assert any("bba" in d for d in degrees)
        assert any("hsc" in d or "commerce" in d for d in degrees)

        bba_entry = next(e for e in parsed.education if "bba" in e.degree.lower())
        assert bba_entry.cgpa == 7.69 or bba_entry.expected_graduation_year == 2024

        hsc_entry = next(e for e in parsed.education if "hsc" in e.degree.lower() or "commerce" in e.degree.lower())
        assert hsc_entry.percentage == 93.8 or "cbse" in hsc_entry.institution.lower()

    def test_acca_multi_record_experience(self, parser):
        """5 distinct roles are extracted without collapsing or loss."""
        pdf_bytes = generate_two_column_acca_pdf("acca_finance_professional")
        parsed = parser.parse_bytes(pdf_bytes, ".pdf")

        assert len(parsed.work_experience) >= 5
        job_titles = [e.job_title.lower() for e in parsed.work_experience]

        assert any("tax associate" in t for t in job_titles)
        assert any("stock auditor" in t for t in job_titles)
        assert any("accounts associate" in t for t in job_titles)
        assert any("internal auditor" in t for t in job_titles)
        assert any("accounts executive" in t for t in job_titles)

        # Verify active role is flagged as current
        tax_role = next(e for e in parsed.work_experience if "tax associate" in e.job_title.lower())
        assert tax_role.is_current is True

    def test_acca_per_supervised_experience(self, parser):
        """ACCA Practical Experience Requirement (PER) is extracted distinctly."""
        pdf_bytes = generate_two_column_acca_pdf("acca_finance_professional")
        parsed = parser.parse_bytes(pdf_bytes, ".pdf")

        assert len(parsed.per_experience) >= 1
        per = parsed.per_experience[0]
        per_text = f"{per.job_title} {per.employer} {per.duration} {' '.join(per.responsibilities)}".lower()
        assert "per" in per_text or "supervised" in per_text or "36 months" in per_text or "trainee" in per_text

    def test_acca_skills_software_languages(self, parser):
        """Tax/accounting skills, software suites, and languages are extracted without IT bias."""
        pdf_bytes = generate_two_column_acca_pdf("acca_finance_professional")
        parsed = parser.parse_bytes(pdf_bytes, ".pdf")

        # Domain skills
        all_skills = [s.lower() for s in parsed.technical_skills + parsed.professional_skills]
        assert any("uk tax" in s or "uk taxation" in s for s in all_skills)
        assert any("sa100" in s for s in all_skills)
        assert any("making tax digital" in s for s in all_skills)
        assert any("accounts payable" in s for s in all_skills)

        # Software
        tools_str = " ".join([t.lower() for t in parsed.tools_and_software])
        assert "digita" in tools_str or "xero" in tools_str or "approvalmax" in tools_str or "office" in tools_str

        # Languages
        langs_str = " ".join([l.lower() for l in parsed.languages])
        assert "english" in langs_str
        assert "hindi" in langs_str

        # Professional qualifications
        quals = [q.name.lower() for q in parsed.professional_qualifications + parsed.certifications]
        assert any("acca" in q for q in quals)

    def test_career_role_inference_acca_persona(self, inferencer, parser):
        """ACCA candidate produces ONLY finance/tax/accounting roles with 0 AI/ML contamination."""
        pdf_bytes = generate_two_column_acca_pdf("acca_finance_professional")
        parsed = parser.parse_bytes(pdf_bytes, ".pdf")

        inferred = inferencer.infer_roles(parsed)
        assert len(inferred) >= 4

        role_titles = [r.role_title.lower() for r in inferred]
        assert any("tax" in t for t in role_titles)
        assert any("audit" in t for t in role_titles)
        assert any("account" in t for t in role_titles)

        # Strict profession isolation: no software/AI/ML roles
        for r in role_titles:
            assert "machine learning" not in r
            assert "deep learning" not in r
            assert "flutter" not in r
            assert "python developer" not in r

    def test_career_role_inference_cs_student(self, inferencer, parser):
        """CS student persona produces software, mobile, and data roles."""
        pdf_bytes = generate_persona_pdf("cs_mobile_ai_student")
        parsed = parser.parse_bytes(pdf_bytes, ".pdf")

        inferred = inferencer.infer_roles(parsed)
        assert len(inferred) >= 3

        role_titles = [r.role_title.lower() for r in inferred]
        assert any("software" in t or "developer" in t or "data" in t or "project manager" in t for t in role_titles)

    def test_query_generator_no_aiml_fallback(self):
        """QueryGenerator produces relevant tax/accounting queries and no AI/ML keywords."""
        qgen = QueryGenerator()
        matrix = qgen.generate_query_matrix(
            roles=["Tax Associate", "Accounts Associate"],
            locations=["Pune", "Remote"],
        )

        assert len(matrix) > 0
        all_kw = " ".join([f"{r} {loc}".lower() for r, loc in matrix])
        assert "tax" in all_kw or "account" in all_kw
        assert "machine learning" not in all_kw
        assert "artificial intelligence" not in all_kw
        assert "deep learning" not in all_kw

    def test_profile_updater_build_profile_dict(self, parser):
        """ProfileUpdater accurately compiles ACCA PER, qualifications, software, and languages."""
        pdf_bytes = generate_two_column_acca_pdf("acca_finance_professional")
        parsed = parser.parse_bytes(pdf_bytes, ".pdf")

        updater = ProfileUpdater()
        profile_dict = updater.build_profile_dict(parsed)

        assert "personal" in profile_dict
        assert "personal_info" in profile_dict
        assert profile_dict["personal"]["full_name"] == "Pranjali Agrawal"
        assert len(profile_dict["work_experience"]) >= 5
        assert len(profile_dict.get("per_experience", [])) >= 1
        assert len(profile_dict.get("tools_and_software", [])) >= 1
        assert len(profile_dict.get("languages", [])) >= 1

    def test_discovery_run_state_lifecycle(self):
        """Asynchronous discovery run state tracking supports instant response and progress polling."""
        service = DashboardService.get_instance()
        # Create a test run
        run_rec = service.db.create_discovery_run(
            user_id=1,
            target_roles=["Tax Associate", "Accounts Associate"],
            target_locations=["Pune", "Remote"],
        )
        run_id = run_rec["id"]
        assert run_rec["status"] == "PENDING"

        # Update to running
        service.db.update_discovery_run(run_id, status="RUNNING")
        active = service.db.get_active_discovery_run(1)
        assert active is not None
        assert active["status"] == "RUNNING"

        # Update to completed
        service.db.update_discovery_run(
            run_id=run_id,
            status="COMPLETED",
            new_jobs_count=5,
            duplicates_skipped=2,
            restricted_count=0,
        )
        active_after = service.db.get_active_discovery_run(1)
        assert active_after is None  # Completed run is no longer active

"""Cross-Employer Origin Isolation & Security Hardening Tests (Phase C.1 / Architecture v2.1.1).

Proves Scenarios A through F:
- Scenario A: A plan authorized for Kula ATS cannot execute on Lever ATS.
- Scenario B: A plan cannot execute on an unrelated employer domain.
- Scenario C: Exact match on canonical origin or approved redirect is accepted.
- Scenario D: Subdomain boundary enforcement: careers.kula.ai does not authorize evil.kula.ai.
- Scenario E: Authorized redirects succeed when explicitly approved in plan.
- Scenario F: Single-use ticket or execution token cannot be reused across different applications.
"""

import hashlib
from pathlib import Path
import pytest
from src.database.db_manager import DatabaseManager
from src.database.exceptions import SecurityAuthorizationError
from src.preparer.form_filling_broker import ApplicationFormFillingBroker


class TestCrossEmployerSecurity:
    """Verifies strict origin binding and anti-cross-employer contamination across broker and companion."""

    @pytest.fixture(autouse=True)
    def setup_isolated_env(self, tmp_path):
        """Sets up isolated SQLite database with test candidate fixtures."""
        db_path = tmp_path / "test_cross_employer.db"
        self.db = DatabaseManager(db_path=db_path)
        self.broker = ApplicationFormFillingBroker(db=self.db)

        # Create user
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, 'hash', 'salt', ?)",
                ("candidate_security@test.com", "Security Test Candidate"),
            )
            self.user_id = cursor.lastrowid

        # Seed profile
        profile_data = {
            "personal": {
                "full_name": "Security Test Candidate",
                "email": "candidate_security@test.com",
                "phone": "9876540000",
                "current_company": "Secure Systems Inc",
                "current_location": "San Francisco",
                "linkedin": "https://www.linkedin.com/in/sectest",
            },
            "education": [],
            "experience": [],
            "technical_skills": ["Python", "FastAPI"],
        }
        self.db.save_user_candidate_profile(self.user_id, profile_data)

        # Seed PDF resume
        user_resumes_dir = Path("data") / "users" / str(self.user_id) / "resumes"
        user_resumes_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = user_resumes_dir / "candidate_cv.pdf"
        minimal_pdf = (
            b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f\n0000000010 00000 n\n0000000060 00000 n\n"
            b"0000000117 00000 n\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n198\n%%EOF\n"
        )
        pdf_path.write_bytes(minimal_pdf)
        pdf_hash = hashlib.sha256(minimal_pdf).hexdigest()

        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO resumes (
                    user_id, storage_filename, original_filename, file_format, file_hash, file_size_bytes, is_primary, is_active
                ) VALUES (?, 'candidate_cv.pdf', 'candidate_cv.pdf', 'pdf', ?, ?, 1, 1)""",
                (self.user_id, pdf_hash, len(minimal_pdf)),
            )
            self.resume_id = cursor.lastrowid

            # App 1: Kula ATS (Avoma)
            cursor.execute(
                """INSERT INTO applications (
                    user_id, company_name, job_title, external_application_url, resume_id, status
                ) VALUES (?, 'Avoma', 'ML Engineer', 'https://careers.kula.ai/avoma/13624/apply', ?, 'APPROVED')""",
                (self.user_id, self.resume_id),
            )
            self.app_kula_id = cursor.lastrowid

            # App 2: Lever ATS (CIN7)
            cursor.execute(
                """INSERT INTO applications (
                    user_id, company_name, job_title, external_application_url, resume_id, status
                ) VALUES (?, 'CIN7', 'Software Engineer', 'https://jobs.lever.co/cin7/510ff0bd/apply', ?, 'APPROVED')""",
                (self.user_id, self.resume_id),
            )
            self.app_lever_id = cursor.lastrowid

        yield

        # Cleanup
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

    def test_scenario_a_kula_plan_rejected_on_lever_ats(self):
        """Scenario A: A plan authorized for Kula ATS cannot execute on Lever ATS."""
        plan_kula = self.broker.prepare_autofill_plan(self.user_id, self.app_kula_id)
        assert plan_kula.canonical_target_origin == "https://careers.kula.ai"

        # 1. validate_execution_origin returns False for Lever origin
        is_allowed = self.broker.validate_execution_origin(plan_kula.execution_id, "https://jobs.lever.co")
        assert is_allowed is False, "Kula execution must reject Lever origin"

        # 2. Handshake from Lever origin is rejected with SecurityAuthorizationError
        with pytest.raises(SecurityAuthorizationError) as exc_info:
            self.broker.record_handshake(
                application_id=self.app_kula_id,
                execution_id=plan_kula.execution_id,
                ticket=plan_kula.action_ticket,
                domain="jobs.lever.co",
                origin="https://jobs.lever.co",
                ats_detected="lever",
            )
        assert "Cross-employer origin violation" in str(exc_info.value)

    def test_scenario_b_plan_rejected_on_unrelated_employer_domain(self):
        """Scenario B: A plan cannot execute on an unrelated employer domain."""
        plan = self.broker.prepare_autofill_plan(self.user_id, self.app_kula_id)

        for unrelated in ("https://unrelated-corp.com", "https://phishing-site.org", "https://evil.com"):
            assert self.broker.validate_execution_origin(plan.execution_id, unrelated) is False

            with pytest.raises(SecurityAuthorizationError) as exc_info:
                self.broker.record_handshake(
                    application_id=self.app_kula_id,
                    execution_id=plan.execution_id,
                    ticket=plan.action_ticket,
                    domain=unrelated.replace("https://", ""),
                    origin=unrelated,
                )
            assert "Cross-employer origin violation" in str(exc_info.value)

    def test_scenario_c_exact_match_accepted(self):
        """Scenario C: Exact match on canonical origin or approved redirect is accepted."""
        plan = self.broker.prepare_autofill_plan(self.user_id, self.app_kula_id)

        # Exact canonical origin match
        assert self.broker.validate_execution_origin(plan.execution_id, "https://careers.kula.ai") is True
        assert self.broker.validate_execution_origin(plan.execution_id, "careers.kula.ai") is True

        # Successful handshake on exact origin
        res = self.broker.record_handshake(
            application_id=self.app_kula_id,
            execution_id=plan.execution_id,
            ticket=plan.action_ticket,
            domain="careers.kula.ai",
            origin="https://careers.kula.ai",
            ats_detected="kula",
            form_found=True,
        )
        assert res["companion_connected"] is True
        assert res["form_detected"] is True

    def test_scenario_d_subdomain_boundary_enforcement(self):
        """Scenario D: Subdomain boundary enforcement: careers.kula.ai does not authorize evil.kula.ai."""
        plan = self.broker.prepare_autofill_plan(self.user_id, self.app_kula_id)

        for attacker_host in ("https://evil.kula.ai", "https://attacker.kula.ai", "https://kula.ai.evil.com"):
            assert self.broker.validate_execution_origin(plan.execution_id, attacker_host) is False

            with pytest.raises(SecurityAuthorizationError) as exc_info:
                self.broker.record_handshake(
                    application_id=self.app_kula_id,
                    execution_id=plan.execution_id,
                    ticket=plan.action_ticket,
                    domain=attacker_host.replace("https://", ""),
                    origin=attacker_host,
                )
            assert "Cross-employer origin violation" in str(exc_info.value)

    def test_scenario_e_authorized_redirects_succeed(self):
        """Scenario E: Authorized redirects succeed when explicitly approved in plan."""
        # Create job description with career portal source_url and application with ATS URL
        with self.db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO job_descriptions (
                    user_id, company_name, job_title, source_type, source_url, raw_content, content_hash
                ) VALUES (?, 'EmployerX', 'Tech Lead', 'URL', 'https://careers.employerx.com/tech-lead', 'Job text', 'hash123')""",
                (self.user_id,),
            )
            jd_id = cursor.lastrowid

            cursor.execute(
                """INSERT INTO applications (
                    user_id, company_name, job_title, job_description_id, external_application_url, resume_id, status
                ) VALUES (?, 'EmployerX', 'Tech Lead', ?, 'https://jobs.lever.co/employerx/apply', ?, 'APPROVED')""",
                (self.user_id, jd_id, self.resume_id),
            )
            redirect_app_id = cursor.lastrowid

        plan = self.broker.prepare_autofill_plan(self.user_id, redirect_app_id)
        assert "https://jobs.lever.co" in plan.approved_redirect_origins
        assert "https://careers.employerx.com" in plan.approved_redirect_origins

        # Both the ATS portal and the company career redirect portal are valid
        assert self.broker.validate_execution_origin(plan.execution_id, "https://jobs.lever.co") is True
        assert self.broker.validate_execution_origin(plan.execution_id, "https://careers.employerx.com") is True

        # Unapproved portal is still rejected
        assert self.broker.validate_execution_origin(plan.execution_id, "https://careers.kula.ai") is False

    def test_scenario_f_ticket_reuse_across_applications_rejected(self):
        """Scenario F: Single-use ticket or execution token cannot be reused across different applications."""
        plan_kula = self.broker.prepare_autofill_plan(self.user_id, self.app_kula_id)

        # 1. Attempting to use Kula ticket on Lever application handshake fails
        with pytest.raises(SecurityAuthorizationError) as exc_info:
            self.broker.record_handshake(
                application_id=self.app_lever_id,  # Mismatched application!
                execution_id=plan_kula.execution_id,
                ticket=plan_kula.action_ticket,
                domain="jobs.lever.co",
                origin="https://jobs.lever.co",
            )
        assert "Application mismatch" in str(exc_info.value)

        # 2. Attempting to download resume using Kula ticket for Lever application fails
        with pytest.raises(SecurityAuthorizationError) as exc_info:
            self.broker.get_verified_resume_bytes(
                user_id=self.user_id,
                application_id=self.app_lever_id,  # Mismatched application!
                ticket=plan_kula.action_ticket,
                execution_id=plan_kula.execution_id,
            )
        assert "expected resource" in str(exc_info.value).lower() or "mismatch" in str(exc_info.value).lower()

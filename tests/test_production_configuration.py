"""Comprehensive Production Configuration & Windows Deployment Preflight Tests (Phase C.0)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.api.routers.dashboard import get_dashboard_summary
from dashboard.services.dashboard_service import DashboardService
from src.config.env_loader import validate_production_configuration
from src.database.db_manager import DatabaseManager
from src.preparer.career_role_inferencer import CareerRoleInferencer


def _make_valid_production_secrets():
    """Generates distinct, valid 64-hex tokens and required paths for production testing."""
    import secrets
    keys = {
        "APP_ENV": "production",
        "ACTION_TICKET_ACTIVE_KEY_ID": "prod_v1",
        "SECURITY_SCAN_ACTIVE_KEY_ID": "scan_prod_v1",
        "DATABASE_PATH": r"D:\AIJobAssistantData\database\job_assistant.db",
        "USER_STORAGE_BASE": r"D:\AIJobAssistantData\users",
        "BACKUP_DIR": r"D:\AIJobAssistantData\backups",
        "EXPORTS_DIR": r"D:\AIJobAssistantData\exports",
        "ALLOW_AUTOMATED_SUBMISSION": "false",
        "RESPECT_ROBOTS_TXT": "true",
    }
    for name in [
        "ACTION_TICKET_SECRET_KEY",
        "SECURITY_SCAN_SIGNING_KEY",
        "SESSION_SECRET_KEY",
        "PASSWORD_RESET_PEPPER",
        "AUDIT_LOG_PEPPER",
    ]:
        keys[name] = secrets.token_hex(32)

    keys["ACTION_TICKET_ROTATION_KEYS"] = json.dumps({"prod_v1": keys["ACTION_TICKET_SECRET_KEY"]})
    keys["SECURITY_SCAN_ROTATION_KEYS"] = json.dumps({"scan_prod_v1": keys["SECURITY_SCAN_SIGNING_KEY"]})
    return keys


class TestProductionConfigurationValidation:
    """Tests production environment validation, placeholder rejection, and entropy checks."""

    def test_valid_production_configuration_passes(self):
        env_dict = _make_valid_production_secrets()
        report = validate_production_configuration(env_dict, enforce=True)
        assert report.is_valid is True
        assert report.database_path == env_dict["DATABASE_PATH"]

    def test_rejects_missing_mandatory_secret_in_production(self):
        env_dict = _make_valid_production_secrets()
        del env_dict["SESSION_SECRET_KEY"]
        with pytest.raises(ValueError, match="is missing or empty"):
            validate_production_configuration(env_dict, enforce=True)

    def test_rejects_placeholder_secret(self):
        env_dict = _make_valid_production_secrets()
        env_dict["SESSION_SECRET_KEY"] = "generate_and_insert_64_character_hex_session_secret_key_0000000000"
        with pytest.raises(ValueError, match="contains an insecure default placeholder"):
            validate_production_configuration(env_dict, enforce=True)

    def test_rejects_short_secret(self):
        env_dict = _make_valid_production_secrets()
        env_dict["SESSION_SECRET_KEY"] = "abcdef123456"
        with pytest.raises(ValueError, match="must be exactly 64 hexadecimal characters"):
            validate_production_configuration(env_dict, enforce=True)

    def test_rejects_low_entropy_secret(self):
        env_dict = _make_valid_production_secrets()
        # 64 characters of only 'a'
        env_dict["SESSION_SECRET_KEY"] = "a" * 64
        with pytest.raises(ValueError, match="dangerously low entropy"):
            validate_production_configuration(env_dict, enforce=True)

    def test_rejects_reused_secrets(self):
        env_dict = _make_valid_production_secrets()
        # Reuse same secret for two purposes
        env_dict["PASSWORD_RESET_PEPPER"] = env_dict["SESSION_SECRET_KEY"]
        with pytest.raises(ValueError, match="Cryptographic key reuse violation"):
            validate_production_configuration(env_dict, enforce=True)

    def test_rejects_automated_submission_in_production(self):
        env_dict = _make_valid_production_secrets()
        env_dict["ALLOW_AUTOMATED_SUBMISSION"] = "true"
        with pytest.raises(ValueError, match="ALLOW_AUTOMATED_SUBMISSION must be false in production"):
            validate_production_configuration(env_dict, enforce=True)

    def test_rejects_invalid_rotation_json(self):
        env_dict = _make_valid_production_secrets()
        env_dict["ACTION_TICKET_ROTATION_KEYS"] = "invalid_json_string{"
        with pytest.raises(ValueError, match="is not valid JSON"):
            validate_production_configuration(env_dict, enforce=True)


class TestDynamicStoragePaths:
    """Verifies that database and storage managers resolve environment paths dynamically."""

    def test_database_manager_dynamic_paths(self, monkeypatch):
        test_db_path = r"D:\AIJobAssistantData\database\test_assistant.db"
        test_backup_dir = r"D:\AIJobAssistantData\backups"
        test_exports_dir = r"D:\AIJobAssistantData\exports"

        monkeypatch.setenv("DATABASE_PATH", test_db_path)
        monkeypatch.setenv("BACKUP_DIR", test_backup_dir)
        monkeypatch.setenv("EXPORTS_DIR", test_exports_dir)

        # Do not initialize connection to real D:\ drive on macOS test runner
        with patch.object(DatabaseManager, "_init_db"):
            db = DatabaseManager(db_path=None)
            assert str(db.db_path) == test_db_path
            assert str(db.backup_dir) == test_backup_dir
            assert str(db.exports_dir) == test_exports_dir

    def test_dashboard_service_user_storage_base(self, monkeypatch):
        test_storage = r"D:\AIJobAssistantData\users"
        monkeypatch.setenv("USER_STORAGE_BASE", test_storage)

        with patch.object(DatabaseManager, "_init_db"):
            service = DashboardService(db_manager=DatabaseManager(db_path=":memory:"))
            assert str(service.storage_base_dir) == test_storage


class TestCareerDomainInferenceAndDashboardFallbacks:
    """Verifies Priority F: truthful career domain inference without AI/ML or finance defaults."""

    def setup_method(self):
        self.inferencer = CareerRoleInferencer()

    def test_infer_accounting_domain(self):
        data = {
            "certifications": [{"name": "ACCA Affiliate"}],
            "education": [{"degree": "B.Sc. Applied Accounting"}],
        }
        res = self.inferencer.infer_career_domain(data)
        assert res["domain"] == "accounting_finance"
        assert res["domain_label"] == "Accounting & Finance"
        assert res["suggested_roles_label"] == "accounting, audit, and tax"

    def test_infer_healthcare_domain(self):
        data = {
            "certifications": [{"name": "MBBS Registered Practitioner"}],
            "education": [{"degree": "Bachelor of Medicine and Bachelor of Surgery (MBBS)"}],
        }
        res = self.inferencer.infer_career_domain(data)
        assert res["domain"] == "healthcare"
        assert res["domain_label"] == "Healthcare & Medicine"
        assert res["suggested_roles_label"] == "clinical and healthcare"

    def test_infer_legal_domain(self):
        data = {
            "certifications": [{"name": "State Bar Council Advocate"}],
            "education": [{"degree": "Bachelor of Laws (LL.B.)"}],
        }
        res = self.inferencer.infer_career_domain(data)
        assert res["domain"] == "legal"
        assert res["domain_label"] == "Legal & Compliance"
        assert res["suggested_roles_label"] == "legal and compliance"

    def test_infer_investment_domain(self):
        data = {
            "certifications": [{"name": "CFA Charterholder"}],
            "work_experience": [{"job_title": "Portfolio Analyst"}],
        }
        res = self.inferencer.infer_career_domain(data)
        assert res["domain"] == "investment_risk"
        assert res["domain_label"] == "Investment & Risk"
        assert res["suggested_roles_label"] == "investment and risk management"

    def test_infer_project_management_domain(self):
        data = {
            "certifications": [{"name": "Project Management Professional (PMP)"}],
        }
        res = self.inferencer.infer_career_domain(data)
        assert res["domain"] == "project_management"
        assert res["domain_label"] == "Project Management"
        assert res["suggested_roles_label"] == "project and program management"

    def test_neutral_fallback_when_no_domain_matched(self):
        data = {
            "certifications": [],
            "education": [],
            "work_experience": [],
        }
        res = self.inferencer.infer_career_domain(data)
        assert res["domain"] is None
        assert res["domain_label"] is None

    def test_dashboard_action_does_not_default_to_finance_for_unknown_profession(self):
        """Dashboard must recommend verified profile opportunities, never finance or AI/ML defaults."""
        mock_service = MagicMock()
        mock_session = MagicMock()
        mock_session.session_id = "test_sess"
        user_id = 999

        # Candidate has 1 resume and high completeness, but professional qualification is generic
        mock_service.get_user_resumes.return_value = [{"id": 1, "is_primary": 1}]
        mock_service.db.get_user_candidate_profile.return_value = {
            "profile_data": {
                "full_name": "Test Candidate",
                "email": "test@candidate.org",
                "certifications": [{"name": "Board-Certified Specialist"}],  # Triggers professionally_qualified
                "education": [{"degree": "Doctorate"}],
                "skills": ["Management", "Leadership"],
            }
        }
        mock_service.get_candidate_dashboard_metrics.return_value = {
            "total_catalog_jobs": 10,
            "jobs_discovered_for_user": 5,
            "evaluated_matches_count": 5,
            "eligible_matches_count": 0,
        }
        mock_service.list_candidate_applications.return_value = []
        mock_service.list_application_follow_ups.return_value = []
        mock_service.db.get_active_discovery_run.return_value = None

        with patch("backend.api.routers.dashboard.DashboardService.get_instance", return_value=mock_service):
            with patch.object(CareerRoleInferencer, "infer_roles", return_value=[]):
                summary = get_dashboard_summary(auth_ctx=(user_id, mock_session))

                rec = summary["recommended_action"]
                # Must NOT contain 'accounting' or 'finance'
                assert "accounting" not in rec["title"].lower()
                assert "finance" not in rec["title"].lower()
                assert "Explore opportunities based on your verified profile" in rec["title"]


class TestCandidateDiscoveredJobsAndMetrics:
    """Verifies Priority G: candidate_discovered_jobs persistence and unique metrics counting."""

    def test_record_and_count_candidate_discovered_jobs(self, tmp_path):
        db_file = str(tmp_path / "test_discovered.db")
        db = DatabaseManager(db_path=db_file)

        # Create test users and jobs
        with db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('cand@example.com', 'h', 's', 'Candidate One')")
            user_id = cursor.lastrowid

        from src.database.models import Job
        job_1 = Job(
            platform="LinkedIn",
            company_name="Tech Corp",
            job_title="Software Engineer",
            job_url="https://example.com/job/1",
            job_description="Python developer role",
        )
        saved_1 = db.insert_job(job_1)

        job_2 = Job(
            platform="Indeed",
            company_name="Data Corp",
            job_title="Data Analyst",
            job_url="https://example.com/job/2",
            job_description="SQL and reporting role",
        )
        saved_2 = db.insert_job(job_2)

        # Record associations
        inserted = db.record_candidate_discovered_jobs(user_id, [saved_1.id, saved_2.id])
        assert inserted == 2

        # Idempotency: re-recording the same jobs returns 0 new associations
        inserted_dup = db.record_candidate_discovered_jobs(user_id, [saved_1.id, saved_2.id])
        assert inserted_dup == 0

        # Simulate discovery run with total_discovered = 10 (e.g. 10 hits across queries)
        run_rec = db.create_discovery_run(user_id, ["Developer"], ["Remote"])
        db.update_discovery_run(run_rec["id"], status="COMPLETED", total_discovered=10)

        # Check metrics
        metrics = db.get_candidate_matching_metrics(user_id)
        assert metrics["total_catalog_jobs"] == 2
        # Unique discovered jobs for candidate is 2, not 10!
        assert metrics["jobs_discovered_for_user"] == 2
        # Total discovery occurrences tracks the sum of query results (10)
        assert metrics["total_discovery_occurrences"] == 10


class TestPowerShellDeploymentScriptsIntegrity:
    """Verifies that deployment PowerShell scripts enforce single worker and proper preflight flags."""

    def test_service_install_script_contains_preflight_and_single_worker(self):
        script_path = Path(__file__).resolve().parent.parent / "deploy" / "windows" / "service_install.ps1"
        assert script_path.exists()
        content = script_path.read_text(encoding="utf-8")

        assert "--workers 1" in content
        assert "--env-file" in content
        assert "validate_production_configuration" in content
        assert "load_production_env" in content
        assert "http://127.0.0.1:8000/api/health" in content

    def test_run_app_script_contains_single_worker_and_env_loading(self):
        script_path = Path(__file__).resolve().parent.parent / "deploy" / "windows" / "run_app.ps1"
        assert script_path.exists()
        content = script_path.read_text(encoding="utf-8")

        assert "--workers 1" in content
        assert "--env-file" in content
        assert "validate_production_configuration" in content

    def test_backup_database_script_loads_env_and_verifies_integrity(self):
        script_path = Path(__file__).resolve().parent.parent / "deploy" / "windows" / "backup_database.ps1"
        assert script_path.exists()
        content = script_path.read_text(encoding="utf-8")

        assert "load_production_env" in content
        assert "PRAGMA integrity_check" in content
        assert "INTEGRITY_CHECK_FAILED" in content

    def test_iis_web_config_enforces_10mb_and_https_redirect(self):
        config_path = Path(__file__).resolve().parent.parent / "deploy" / "iis" / "web.config"
        assert config_path.exists()
        content = config_path.read_text(encoding="utf-8")

        assert 'maxAllowedContentLength="10485760"' in content
        assert "HTTP to HTTPS Redirect" in content
        assert "HTTP_X_FORWARDED_PROTO" in content

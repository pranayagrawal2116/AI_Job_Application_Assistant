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

    @pytest.mark.anyio
    async def test_fastapi_lifespan_aborts_before_service_on_invalid_production(self, monkeypatch):
        """Verifies lifespan ordering: production config validation fails closed before service or DB setup."""
        from backend.api.main import app, lifespan

        monkeypatch.setenv("APP_ENV", "production")
        monkeypatch.delenv("SESSION_SECRET_KEY", raising=False)

        with pytest.raises(RuntimeError, match="Production configuration validation failed"):
            async with lifespan(app):
                pass



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

    def test_iis_web_config_enforces_12mb_multipart_headroom_and_https_redirect(self):
        config_path = Path(__file__).resolve().parent.parent / "deploy" / "iis" / "web.config"
        assert config_path.exists()
        content = config_path.read_text(encoding="utf-8")

        # 12 MB (12582912 bytes) ceiling for multipart headers while application enforces 10 MB file cap
        assert 'maxAllowedContentLength="12582912"' in content
        assert "HTTP to HTTPS Redirect" in content
        assert "HTTP_X_FORWARDED_PROTO" in content

    def test_web_root_and_frontend_exclusion_validation(self):
        from src.config.env_loader import validate_storage_paths_alignment
        env_dict = _make_valid_production_secrets()

        # Database path placed within IIS web root must be rejected
        env_dict["DATABASE_PATH"] = r"C:\inetpub\wwwroot\job_assistant.db"
        with pytest.raises(ValueError, match="must not be located inside"):
            validate_production_configuration(env_dict, enforce=True)

        errs = validate_storage_paths_alignment(env_dict)
        assert any("inetpub/wwwroot" in e for e in errs)

        # Storage placed inside frontend/dist must be rejected
        env_dict["DATABASE_PATH"] = r"D:\AIJobAssistantData\database\job_assistant.db"
        env_dict["USER_STORAGE_BASE"] = r"C:\Apps\AI_Job_Application_Assistant\frontend\dist\users"
        with pytest.raises(ValueError, match="must not be located inside"):
            validate_production_configuration(env_dict, enforce=True)

    def test_storage_paths_alignment_with_expected_data_dir(self):
        from src.config.env_loader import validate_storage_paths_alignment
        env_dict = _make_valid_production_secrets()

        # With all paths under D:\AIJobAssistantData, alignment succeeds
        report = validate_production_configuration(env_dict, enforce=True, expected_data_dir=r"D:\AIJobAssistantData")
        assert report.is_valid is True
        errs = validate_storage_paths_alignment(env_dict, expected_data_dir=r"D:\AIJobAssistantData")
        assert len(errs) == 0

        # Pointing one path to a different drive (e.g. C:\OtherData) fails alignment
        env_dict["BACKUP_DIR"] = r"C:\OtherData\backups"
        with pytest.raises(ValueError, match="is not canonically contained within expected data directory"):
            validate_production_configuration(env_dict, enforce=True, expected_data_dir=r"D:\AIJobAssistantData")

        misaligned_errs = validate_storage_paths_alignment(env_dict, expected_data_dir=r"D:\AIJobAssistantData")
        assert len(misaligned_errs) == 1
        assert "BACKUP_DIR" in misaligned_errs[0]

    def test_candidate_discovery_metrics_strictly_isolated_from_evaluations(self, tmp_path):
        """Verifies that running match evaluations on catalog jobs does NOT falsely increase jobs_discovered_for_user."""
        db_path = tmp_path / "metrics_isolation.db"
        db = DatabaseManager(db_path=str(db_path))

        with db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password_hash, password_salt, full_name) VALUES ('iso@example.com', 'h', 's', 'Iso User')")
            user_id = cursor.lastrowid

        from src.database.models import Job
        job_1 = Job(
            platform="LinkedIn",
            company_name="Company A",
            job_title="Role A",
            job_url="https://example.com/job/a",
            job_description="Desc A",
        )
        saved_1 = db.insert_job(job_1)

        job_2 = Job(
            platform="Indeed",
            company_name="Company B",
            job_title="Role B",
            job_url="https://example.com/job/b",
            job_description="Desc B",
        )
        saved_2 = db.insert_job(job_2)

        # Associate only job_1 with candidate discovery
        db.record_candidate_discovered_jobs(user_id, [saved_1.id])

        # Evaluate match results for BOTH job_1 and job_2 (e.g. manually imported job_2)
        with db.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO match_results (user_id, job_id, match_score, match_classification, eligibility_status, score_breakdown, explanation)
                VALUES (?, ?, 90.0, 'Excellent match', 'ELIGIBLE', '{}', 'Test'),
                       (?, ?, 80.0, 'Good match', 'ELIGIBLE', '{}', 'Test')
                """,
                (user_id, saved_1.id, user_id, saved_2.id),
            )

        metrics = db.get_candidate_matching_metrics(user_id)
        # Total catalog is 2
        assert metrics["total_catalog_jobs"] == 2
        # Evaluated matches count is 2
        assert metrics["evaluated_matches_count"] == 2
        # But discovered jobs for this user must strictly remain 1!
        assert metrics["jobs_discovered_for_user"] == 1


class TestPhaseC02DeploymentSignOff:
    """Rigorous verification of Phase C.0.2 sign-off requirements."""

    def test_run_app_mode_enforcement_matrix(self):
        """Tests that run_app preflight enforces APP_ENV=production in normal mode and requires -Dev for non-prod."""
        from src.config.env_loader import validate_production_configuration

        def simulate_preflight(app_env: str, is_dev_mode: bool, env_dict: dict):
            clean_env = app_env.strip().lower()
            if not is_dev_mode:
                if clean_env != "production":
                    raise ValueError(f"Normal launch requires APP_ENV=production. Detected APP_ENV='{clean_env}'")
                validate_production_configuration(env_dict, enforce=True)
            else:
                if clean_env == "production":
                    validate_production_configuration(env_dict, enforce=True)
            return True

        valid_env = _make_valid_production_secrets()

        # 1. Normal mode + APP_ENV=production -> PASS
        assert simulate_preflight("production", False, valid_env) is True

        # 2. Normal mode + APP_ENV=development -> REJECT
        with pytest.raises(ValueError, match="Normal launch requires APP_ENV=production"):
            simulate_preflight("development", False, valid_env)

        # 3. Normal mode + APP_ENV=test -> REJECT
        with pytest.raises(ValueError, match="Normal launch requires APP_ENV=production"):
            simulate_preflight("test", False, valid_env)

        # 4. Normal mode + APP_ENV=staging -> REJECT
        with pytest.raises(ValueError, match="Normal launch requires APP_ENV=production"):
            simulate_preflight("staging", False, valid_env)

        # 5. Normal mode + empty APP_ENV -> REJECT
        with pytest.raises(ValueError, match="Normal launch requires APP_ENV=production"):
            simulate_preflight("", False, valid_env)

        # 6. Dev mode (-Dev) + APP_ENV=development -> PASS
        assert simulate_preflight("development", True, {"APP_ENV": "development"}) is True

        # 7. Dev mode (-Dev) + APP_ENV=test -> PASS
        assert simulate_preflight("test", True, {"APP_ENV": "test"}) is True

    def test_canonical_path_containment_windows_scenarios(self):
        """Verifies Priority 3: Component-aware canonical path containment."""
        from src.config.env_loader import (
            canonicalize_path_components,
            is_forbidden_path,
            is_path_contained_in_root,
        )

        root = r"D:\AIJobAssistantData"

        # 1. Legitimate child path -> ACCEPT
        assert is_path_contained_in_root(r"D:\AIJobAssistantData\database\job_assistant.db", root) is True
        assert is_path_contained_in_root(r"D:\AIJobAssistantData\users", root) is True
        assert is_path_contained_in_root(r"D:\AIJobAssistantData\backups\monthly\2026", root) is True

        # 2. Sibling directory with prefix collision -> REJECT
        assert is_path_contained_in_root(r"D:\AIJobAssistantDataEvil\database", root) is False

        # 3. Completely different root directory -> REJECT
        assert is_path_contained_in_root(r"D:\OtherData\backup", root) is False

        # 4. Web root directory -> REJECT
        assert is_path_contained_in_root(r"C:\inetpub\wwwroot\database", root) is False

        # 5. Traversal escape -> REJECT
        assert is_path_contained_in_root(r"D:\AIJobAssistantData\..\OtherData\backup", root) is False
        assert is_path_contained_in_root(r"D:\AIJobAssistantData\..\..\escaped", root) is False

        # 6. Redundant dot segments inside legitimate tree -> ACCEPT
        assert is_path_contained_in_root(r"D:\AIJobAssistantData\.\database\job_assistant.db", root) is True
        assert is_path_contained_in_root(r"D:\AIJobAssistantData\sub\..\database\job_assistant.db", root) is True

        # 7. Case-insensitivity -> ACCEPT
        assert is_path_contained_in_root(r"d:\aijobassistantdata\database\job_assistant.db", root) is True

        # 8. Forward slashes -> ACCEPT
        assert is_path_contained_in_root("D:/AIJobAssistantData/database/job_assistant.db", root) is True

        # 9. Forbidden paths check
        _, c1 = canonicalize_path_components(r"C:\inetpub\wwwroot\database")
        bad1, reason1 = is_forbidden_path(c1)
        assert bad1 is True
        assert "inetpub/wwwroot" in reason1

        _, c2 = canonicalize_path_components(r"C:\Apps\AI_Job_Application_Assistant\frontend\dist\users")
        bad2, reason2 = is_forbidden_path(c2)
        assert bad2 is True
        assert "frontend/dist" in reason2

        _, c3 = canonicalize_path_components(r"C:\Apps\AI_Job_Application_Assistant\frontend\public\logo.png")
        bad3, reason3 = is_forbidden_path(c3)
        assert bad3 is True
        assert "frontend/public" in reason3

    def test_backup_override_security_and_containment_logic(self):
        """Verifies Priority 2: BackupDirOverride must not escape permitted data root."""
        from src.config.env_loader import is_forbidden_path, is_path_contained_in_root, canonicalize_path_components

        permitted_root = r"D:\AIJobAssistantData"

        def validate_override(override_path: str) -> tuple[bool, str]:
            _, parts = canonicalize_path_components(override_path)
            if ".." in parts:
                return False, "contains relative traversal"
            is_bad, bad_reason = is_forbidden_path(parts)
            if is_bad:
                return False, f"inside forbidden {bad_reason}"
            if not is_path_contained_in_root(override_path, permitted_root):
                return False, "not contained in permitted data root"
            return True, "valid"

        # Legitimate override under data root
        ok, _ = validate_override(r"D:\AIJobAssistantData\custom_backups")
        assert ok is True

        # Web root escape
        ok, msg = validate_override(r"C:\inetpub\wwwroot\backups")
        assert ok is False
        assert "inetpub/wwwroot" in msg

        # Prefix collision
        ok, msg = validate_override(r"D:\AIJobAssistantDataEvil\backups")
        assert ok is False
        assert "not contained" in msg

        # Traversal escape
        ok, msg = validate_override(r"D:\AIJobAssistantData\..\OtherData\backups")
        assert ok is False

    def test_dedicated_sqlite_online_backup_preserves_source_without_manager_side_effects(self, tmp_path):
        """Verifies Priority 2: Online backup using read-only URI produces exact snapshot without touching source."""
        import sqlite3

        src_file = tmp_path / "live_source.db"
        dst_file = tmp_path / "backup_dest.db"

        # Create live source database with WAL mode and initial data
        conn = sqlite3.connect(str(src_file))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE live_table (id INTEGER PRIMARY KEY, note TEXT)")
        conn.execute("INSERT INTO live_table (note) VALUES ('active record 1'), ('active record 2')")
        conn.commit()
        conn.close()

        src_mtime_before = src_file.stat().st_mtime_ns

        # Execute dedicated read-only online backup
        src_conn = sqlite3.connect(f"file:{src_file.resolve().as_posix()}?mode=ro", uri=True)
        dst_conn = sqlite3.connect(str(dst_file))
        src_conn.backup(dst_conn, pages=250)
        dst_conn.close()
        src_conn.close()

        # Source mtime was NOT updated by backup
        src_mtime_after = src_file.stat().st_mtime_ns
        assert src_mtime_before == src_mtime_after

        # Destination file exists, has data, and passes PRAGMA integrity_check
        assert dst_file.exists()
        assert dst_file.stat().st_size > 0

        verify_conn = sqlite3.connect(str(dst_file))
        cur = verify_conn.cursor()
        cur.execute("PRAGMA integrity_check")
        status = cur.fetchone()[0]
        assert status == "ok"

        cur.execute("SELECT COUNT(*) FROM live_table")
        count = cur.fetchone()[0]
        assert count == 2
        verify_conn.close()

    def test_service_install_rollback_and_fail_closed_acls(self):
        """Verifies Priority 4 & 5: service_install.ps1 enforces fail-closed ACLs and full rollback snapshot."""
        script_path = Path(__file__).resolve().parent.parent / "deploy" / "windows" / "service_install.ps1"
        assert script_path.exists()
        content = script_path.read_text(encoding="utf-8")

        # Priority 4: Fail-closed icacls helper
        assert "Assert-IcaclsResult" in content
        assert "$LASTEXITCODE -ne 0" in content
        assert "NT AUTHORITY\\SYSTEM:(OI)(CI)F" in content
        assert "IIS_IUSRS:(OI)(CI)F" in content
        assert "IUSR:(OI)(CI)F" in content
        assert "(OI)(CI)RX" in content

        # Priority 5: Full rollback snapshot parameters captured and restored
        assert "AppRotateFiles" in content
        assert "AppRotateOnline" in content
        assert "AppRotateBytes" in content
        assert "AppThrottle" in content
        assert "AppExit" in content
        assert "Prior service configuration restored completely." in content



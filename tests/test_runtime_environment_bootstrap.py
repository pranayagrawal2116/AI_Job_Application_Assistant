"""Authoritative Runtime Environment Bootstrap & Fail-Fast Validation Test Suite (Phase C.0.6).

Verifies authoritative APP_ENV resolution, fail-closed validation, .env discovery & precedence,
lazy security preflight initialization, production secret enforcement, and FastAPI lifespan failure.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.config.env_loader import (
    ProductionConfigurationError,
    find_env_file,
    load_production_env,
)
from src.config.runtime_environment import (
    bootstrap_runtime_environment,
    resolve_app_env,
)
from src.database.db_manager import DatabaseManager
from src.database.exceptions import SecurityAuthorizationError
from src.security.security_preflight import SecurityPreflightManager

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestRuntimeEnvironmentBootstrap(unittest.TestCase):
    """Regression test suite for authoritative environment resolution and lifecycle validation."""

    def setUp(self):
        self.orig_env = os.environ.copy()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)

    # -------------------------------------------------------------------------
    # Test 1 — Valid development environment
    # -------------------------------------------------------------------------
    def test_01_valid_development_environment(self):
        """Test 1: APP_ENV=development resolves to 'development' and configuration passes."""
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
            resolved = resolve_app_env()
            self.assertEqual(resolved, "development")

            # Bootstrap passes and exposes typed runtime environment
            runtime = bootstrap_runtime_environment(enforce_production=True)
            self.assertEqual(runtime.app_env, "development")
            self.assertTrue(runtime.is_development)
            self.assertFalse(runtime.is_production)
            self.assertFalse(runtime.is_test)
            self.assertTrue(runtime.is_config_ready)

    # -------------------------------------------------------------------------
    # Test 2 — Development alias
    # -------------------------------------------------------------------------
    def test_02_development_alias(self):
        """Test 2: APP_ENV=dev normalizes to 'development'."""
        with patch.dict(os.environ, {"APP_ENV": "dev"}, clear=True):
            resolved = resolve_app_env()
            self.assertEqual(resolved, "development")

            runtime = bootstrap_runtime_environment()
            self.assertEqual(runtime.app_env, "development")
            self.assertTrue(runtime.is_development)
            # Process environment is synchronized
            self.assertEqual(os.environ.get("APP_ENV"), "development")

    # -------------------------------------------------------------------------
    # Test 3 — Test environment
    # -------------------------------------------------------------------------
    def test_03_test_environment(self):
        """Test 3: APP_ENV=test resolves to 'test' and passes configuration."""
        with patch.dict(os.environ, {"APP_ENV": "test"}, clear=True):
            resolved = resolve_app_env()
            self.assertEqual(resolved, "test")

            runtime = bootstrap_runtime_environment()
            self.assertEqual(runtime.app_env, "test")
            self.assertTrue(runtime.is_test)
            self.assertFalse(runtime.is_development)
            self.assertFalse(runtime.is_production)

    # -------------------------------------------------------------------------
    # Test 4 — Missing APP_ENV
    # -------------------------------------------------------------------------
    def test_04_missing_app_env(self):
        """Test 4: Isolated subprocess with APP_ENV removed and no .env fails closed with actionable error."""
        # Run clean python subprocess without inheriting pytest's APP_ENV
        clean_env = {k: v for k, v in os.environ.items() if k not in ("APP_ENV", "ENV_FILE")}
        script = """
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
from src.config.runtime_environment import resolve_app_env
try:
    resolve_app_env()
    print("UNEXPECTED_SUCCESS")
    sys.exit(0)
except Exception as e:
    print(f"EXPECTED_ERROR:{type(e).__name__}:{e}")
    sys.exit(42)
"""
        proc = subprocess.run(
            [sys.executable, "-c", script],
            env=clean_env,
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        self.assertEqual(proc.returncode, 42)
        self.assertIn("EXPECTED_ERROR:SecurityAuthorizationError", proc.stdout)
        self.assertIn("APP_ENV environment variable is missing", proc.stdout)

    # -------------------------------------------------------------------------
    # Test 5 — Empty APP_ENV
    # -------------------------------------------------------------------------
    def test_05_empty_app_env(self):
        """Test 5: APP_ENV='' fails closed with explicit empty-value error."""
        with patch.dict(os.environ, {"APP_ENV": ""}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                resolve_app_env()
            self.assertIn("empty or whitespace", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Test 6 — Whitespace APP_ENV
    # -------------------------------------------------------------------------
    def test_06_whitespace_app_env(self):
        """Test 6: APP_ENV with whitespace only is rejected."""
        with patch.dict(os.environ, {"APP_ENV": "   \t \n "}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                resolve_app_env()
            self.assertIn("empty or whitespace", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Test 7 — Unknown APP_ENV
    # -------------------------------------------------------------------------
    def test_07_unknown_app_env(self):
        """Test 7: APP_ENV=unknown is untrusted and rejected."""
        with patch.dict(os.environ, {"APP_ENV": "unknown_custom"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                resolve_app_env()
            self.assertIn("Unrecognized or untrusted APP_ENV", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Test 8 — Root .env discovery
    # -------------------------------------------------------------------------
    def test_08_root_env_discovery(self):
        """Test 8: Project root .env is discovered and loads APP_ENV."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir).resolve()
            env_file = tmp_root / ".env"
            env_file.write_text("APP_ENV=qa\nCUSTOM_VAR=discovered_test\n", encoding="utf-8")

            with patch("src.config.env_loader.get_project_root", return_value=tmp_root):
                with patch.dict(os.environ, {}, clear=True):
                    found = find_env_file()
                    self.assertEqual(found, env_file)
                    loaded = load_production_env()
                    self.assertEqual(loaded, env_file)
                    self.assertEqual(os.environ.get("CUSTOM_VAR"), "discovered_test")
                    self.assertEqual(resolve_app_env(), "qa")

    # -------------------------------------------------------------------------
    # Test 9 — ENV_FILE override
    # -------------------------------------------------------------------------
    def test_09_env_file_override(self):
        """Test 9: ENV_FILE environment variable resolves according to precedence rules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir).resolve()
            custom_env = tmp_root / "staging.env"
            custom_env.write_text("APP_ENV=staging\nSTAGING_KEY=active\n", encoding="utf-8")

            with patch.dict(os.environ, {"ENV_FILE": str(custom_env)}, clear=True):
                found = find_env_file()
                self.assertEqual(found, custom_env)

                loaded = load_production_env()
                self.assertEqual(loaded, custom_env)
                self.assertEqual(os.environ.get("STAGING_KEY"), "active")
                self.assertEqual(resolve_app_env(), "staging")

    # -------------------------------------------------------------------------
    # Test 10 — Existing process variable precedence
    # -------------------------------------------------------------------------
    def test_10_process_variable_precedence(self):
        """Test 10: Process environment variables take precedence over dotenv file variables."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            env_file = tmp_root / ".env"
            env_file.write_text("APP_ENV=qa\n", encoding="utf-8")

            # Ambient process has APP_ENV=development
            with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
                load_production_env(env_path=env_file, override=False)
                # Ambient process variable must NOT be overwritten
                self.assertEqual(os.environ.get("APP_ENV"), "development")
                self.assertEqual(resolve_app_env(), "development")

    # -------------------------------------------------------------------------
    # Test 11 — Uvicorn startup abort on invalid environment
    # -------------------------------------------------------------------------
    def test_11_uvicorn_startup_abort_on_invalid_env(self):
        """Test 11: Invalid environment causes FastAPI lifespan to abort before initializing DashboardService."""
        clean_env = {k: v for k, v in os.environ.items() if k not in ("APP_ENV", "ENV_FILE")}
        clean_env["APP_ENV"] = "invalid_environment_name"

        script = """
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
from backend.api.main import app

async def test_lifespan():
    try:
        async with app.router.lifespan_context(app):
            pass
        print("UNEXPECTED_STARTUP_SUCCESS")
        sys.exit(0)
    except RuntimeError as re:
        print(f"EXPECTED_LIFESPAN_ABORT:{re}")
        sys.exit(43)

asyncio.run(test_lifespan())
"""
        proc = subprocess.run(
            [sys.executable, "-c", script],
            env=clean_env,
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        self.assertEqual(proc.returncode, 43)
        self.assertIn("EXPECTED_LIFESPAN_ABORT", proc.stdout)
        self.assertIn("Application environment resolution failed", proc.stdout)

    # -------------------------------------------------------------------------
    # Test 12 — Security preflight initialization under development
    # -------------------------------------------------------------------------
    def test_12_security_preflight_initialization(self):
        """Test 12: SecurityPreflightManager initializes under development and accesses evidence verifier on demand."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db = Path(tmpdir) / "test.db"
            db = DatabaseManager(db_path=str(test_db))

            with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
                preflight = SecurityPreflightManager(db_manager=db)
                self.assertIsNotNone(preflight)
                # Lazy initialization succeeds under valid APP_ENV
                verifier = preflight.evidence_verifier
                self.assertIsNotNone(verifier)
                self.assertEqual(verifier.app_env, "development")

    # -------------------------------------------------------------------------
    # Test 13 — Existing strict production behavior
    # -------------------------------------------------------------------------
    def test_13_existing_strict_production_behavior(self):
        """Test 13: Production mode strictly fails closed when secrets are missing."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            # Missing production secrets must raise ProductionConfigurationError
            with self.assertRaises(ProductionConfigurationError):
                bootstrap_runtime_environment(enforce_production=True)

    # -------------------------------------------------------------------------
    # Test 14 — Security policy preservation across environments
    # -------------------------------------------------------------------------
    def test_14_security_policy_preservation(self):
        """Test 14: Staging, QA, and Production environments enforce Ed25519-only and reject permissive overrides."""
        from src.security.legacy_evidence_verifier import LegacyEvidenceTrustStore

        for env_name in ("production", "prod", "staging", "qa"):
            with patch.dict(os.environ, {"APP_ENV": env_name}, clear=True):
                normalized = resolve_app_env()
                self.assertIn(normalized, ("production", "staging", "qa"))
                # Permissive algorithm policy is strictly rejected in production/staging/qa
                with self.assertRaises(SecurityAuthorizationError):
                    LegacyEvidenceTrustStore(algorithm_policy="permissive")


if __name__ == "__main__":
    unittest.main()

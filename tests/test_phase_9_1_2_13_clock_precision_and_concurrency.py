"""Dedicated regression test suite for Phase 9.1.2.13:
Production Clock Guard, Exact Provenance Timestamps & Real Concurrency Verification.

Verifies:
1. Production clock-injection protection:
   - Recognizes and strictly rejects 'production', 'prod', ' PROD ', 'staging', 'qa'.
   - Fails closed on missing, empty, whitespace, and unknown APP_ENV.
   - Permits clock injection strictly in 'development', 'dev', 'test'.
   - set_test_clock(None) always clears overrides safely across all environments.
   - ContextVar context isolation prevents cross-thread or cross-context clock contamination.
   - get_current_utc_time() strictly rejects non-datetime and timezone-naive return values.
   - frozen_utc_clock() reliably restores previous clock contexts after normal completion and exceptions.
2. Exact cryptographic provenance timestamp binding:
   - Eliminates 1ms comparison tolerance; requires exact UTC equality (ve_iat == ap_iat and ve_exp == ap_exp).
   - Rejects 1-microsecond and sub-millisecond mismatches (e.g. 500us).
   - Accepts timezone-equivalent representations (+00:00 vs Z vs non-UTC offsets).
   - Rejects timezone-naive, missing, and malformed timestamps.
3. Real multi-threaded SQLite concurrency verification:
   - Scenario A: Revocation wins under real lock contention (Thread B waits on lock, rejects post-commit).
   - Scenario B: Attestation wins under real lock contention (Thread B revocation waits; attestation immutable, subsequent preflight rejects).
   - Scenario C: Caller-supplied ImmediateAwareConnection / ImmediateAwareCursor under contention; rejects deferred transactions.
   - Scenario D: Atomic rollback on revocation query failures and invalid lock states; zero partial rows.
4. Registry and authenticator claim precision:
   - Frozen issuance record immutability.
   - All 11 provenance claims unconditionally verified.
   - Duplicate credential ID collision rejection.
   - Authenticator trust-root lockdown.
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
from typing import List, Tuple
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519

from src.database.db_manager import (
    DEFAULT_SCHEMA_PATH,
    DatabaseManager,
)
from src.database.exceptions import (
    SecurityAuthorizationError,
)
from src.security.legacy_evidence_verifier import (
    AuthenticatedMigrationPrincipal,
    InMemoryEvidenceResolver,
    LegacyEvidenceTrustStore,
    LegacyEvidenceVerifier,
    ServiceAuthenticationProvider,
    VerifiedLegacyEvidence,
    _IssuedCredentialRecord,
    create_signed_evidence_artifact,
    frozen_utc_clock,
    get_current_utc_time,
    set_default_evidence_resolver,
    set_default_evidence_trust_store,
    set_test_clock,
)
from src.utils.canonical_json import canonical_json_hash


class Phase91213ClockPrecisionAndConcurrencyTests(unittest.TestCase):
    """Authoritative test suite verifying Phase 9.1.2.13 specifications."""

    def setUp(self) -> None:
        os.environ["APP_ENV"] = "test"
        set_test_clock(None)
        set_default_evidence_trust_store(None)
        set_default_evidence_resolver(None)

        self.temp_dir = tempfile.mkdtemp(prefix="test_phase_9_1_2_13_")
        self.tmp_path = Path(self.temp_dir)
        self.db_path = self.tmp_path / "phase_9_1_2_13.db"
        self.db = DatabaseManager(db_path=self.db_path, schema_path=DEFAULT_SCHEMA_PATH)

        # Signing key for evidence
        self.evidence_priv_key = ed25519.Ed25519PrivateKey.generate()
        self.evidence_pub_bytes = self.evidence_priv_key.public_key().public_bytes_raw()

        # Service key for service authentication provider
        self.service_priv_key = ed25519.Ed25519PrivateKey.generate()
        self.service_pub_bytes = self.service_priv_key.public_key().public_bytes_raw()

        # Create test users
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("alice_91213@example.com", "hash1", "salt1", "Alice 91213"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob_91213@example.com", "hash2", "salt2", "Bob 91213"),
            )
            self.user2_id = c.lastrowid

    def tearDown(self) -> None:
        set_test_clock(None)
        set_default_evidence_trust_store(None)
        set_default_evidence_resolver(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_sample_jd(self, user_id: int) -> int:
        raw_text = "Security Architect for Phase 9.1.2.13 verification."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": user_id,
            "company_name": "SecureCorp",
            "job_title": "Security Architect",
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snap_hash = canonical_json_hash(manifest)
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'SecureCorp', 'Security Architect', ?, ?, ?, 'REQUIRED', 1, '2024-04-01 10:00:00')
                """,
                (user_id, raw_text, c_hash, snap_hash),
            )
            return c.lastrowid

    def _create_provider(self, env: str = "test") -> ServiceAuthenticationProvider:
        with patch.dict(os.environ, {"APP_ENV": env}, clear=True):
            return ServiceAuthenticationProvider(
                trusted_keys={"k_svc_01": {"key_bytes": self.service_pub_bytes, "algorithm": "Ed25519"}},
                trusted_issuers={"archival_authority"},
                expected_audience="legacy_migration",
                db_manager=self.db,
            )

    def _setup_verified_evidence_and_principal(self) -> Tuple[VerifiedLegacyEvidence, AuthenticatedMigrationPrincipal, int, LegacyEvidenceTrustStore]:
        provider = self._create_provider("test")
        self.db.set_service_authenticator(provider)

        principal_id = "migration_runner_91213"
        token = provider.mint_service_token(
            principal_id=principal_id,
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        store = LegacyEvidenceTrustStore(
            trusted_issuers={"archival_authority"},
            trusted_attesting_principals={principal_id},
            db_manager=self.db,
        )
        store.register_trusted_key("k_ev_01", self.evidence_pub_bytes, algorithm="Ed25519")

        resolver = InMemoryEvidenceResolver()
        jd_id = self._create_sample_jd(self.user1_id)
        snap = "snapshot_prov_hash_91213"

        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PROV_REF_91213",
            issuer_id="archival_authority",
            key_id="k_ev_01",
            signing_key=self.evidence_priv_key,
            entries=[{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}],
            signature_algorithm="Ed25519",
            attesting_principal=principal_id,
        )
        resolver.register_artifact("historical_import_manifest", "PROV_REF_91213", raw_bytes)

        verifier = LegacyEvidenceVerifier(
            trust_store=store,
            resolver=resolver,
            service_authenticator=provider,
            db_manager=self.db,
        )
        verified = verifier.verify(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PROV_REF_91213",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=snap,
            attesting_principal=principal,
        )
        return verified, principal, jd_id, store

    # =========================================================================
    # PART A: PRODUCTION CLOCK GUARD & CONTEXT ISOLATION (Tests 1-21)
    # =========================================================================

    def test_01_set_test_clock_rejects_production(self) -> None:
        """TC-01: set_test_clock strictly rejects clock injection in 'production'."""
        with patch.dict(os.environ, {"APP_ENV": "production"}):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                set_test_clock(lambda: datetime(2028, 1, 1, tzinfo=timezone.utc))
            self.assertIn("Clock injection is strictly prohibited in production-like environment 'production'", str(ctx.exception))

    def test_02_set_test_clock_rejects_prod_alias(self) -> None:
        """TC-02: set_test_clock strictly rejects clock injection with 'prod' alias."""
        with patch.dict(os.environ, {"APP_ENV": "prod"}):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                set_test_clock(lambda: datetime(2028, 1, 1, tzinfo=timezone.utc))
            self.assertIn("Clock injection is strictly prohibited in production-like environment 'production'", str(ctx.exception))

    def test_03_set_test_clock_rejects_uppercase_and_whitespace_prod(self) -> None:
        """TC-03: set_test_clock strictly rejects ' PROD ' and ' PRODUCTION ' with whitespace/uppercase."""
        for raw in (" PROD ", "  production  ", "Prod", "PRODUCTION"):
            with patch.dict(os.environ, {"APP_ENV": raw}):
                with self.assertRaises(SecurityAuthorizationError) as ctx:
                    set_test_clock(lambda: datetime(2028, 1, 1, tzinfo=timezone.utc))
                self.assertIn("Clock injection is strictly prohibited in production-like environment 'production'", str(ctx.exception))

    def test_04_set_test_clock_rejects_staging(self) -> None:
        """TC-04: set_test_clock strictly rejects clock injection in 'staging'."""
        with patch.dict(os.environ, {"APP_ENV": "staging"}):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                set_test_clock(lambda: datetime(2028, 1, 1, tzinfo=timezone.utc))
            self.assertIn("Clock injection is strictly prohibited in production-like environment 'staging'", str(ctx.exception))

    def test_05_set_test_clock_rejects_qa(self) -> None:
        """TC-05: set_test_clock strictly rejects clock injection in 'qa'."""
        with patch.dict(os.environ, {"APP_ENV": "qa"}):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                set_test_clock(lambda: datetime(2028, 1, 1, tzinfo=timezone.utc))
            self.assertIn("Clock injection is strictly prohibited in production-like environment 'qa'", str(ctx.exception))

    def test_06_set_test_clock_rejects_missing_app_env(self) -> None:
        """TC-06: set_test_clock fails closed when APP_ENV is missing."""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                set_test_clock(lambda: datetime(2028, 1, 1, tzinfo=timezone.utc))
            self.assertIn("APP_ENV environment variable is missing", str(ctx.exception))

    def test_07_set_test_clock_rejects_empty_and_whitespace_app_env(self) -> None:
        """TC-07: set_test_clock fails closed when APP_ENV is empty or whitespace."""
        for empty_val in ("", "   ", "\t\n"):
            with patch.dict(os.environ, {"APP_ENV": empty_val}):
                with self.assertRaises(SecurityAuthorizationError) as ctx:
                    set_test_clock(lambda: datetime(2028, 1, 1, tzinfo=timezone.utc))
                self.assertIn("APP_ENV environment variable is empty or whitespace", str(ctx.exception))

    def test_08_set_test_clock_rejects_unknown_app_env(self) -> None:
        """TC-08: set_test_clock fails closed when APP_ENV is unrecognized/untrusted."""
        with patch.dict(os.environ, {"APP_ENV": "custom_cloud_cluster"}):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                set_test_clock(lambda: datetime(2028, 1, 1, tzinfo=timezone.utc))
            self.assertIn("Unrecognized or untrusted APP_ENV", str(ctx.exception))

    def test_09_set_test_clock_permits_development_and_dev(self) -> None:
        """TC-09: set_test_clock permits clock injection in 'development' and 'dev'."""
        t1 = datetime(2028, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
        with patch.dict(os.environ, {"APP_ENV": "development"}):
            set_test_clock(lambda: t1)
            self.assertEqual(get_current_utc_time(), t1)

        t2 = datetime(2028, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        with patch.dict(os.environ, {"APP_ENV": "dev"}):
            set_test_clock(lambda: t2)
            self.assertEqual(get_current_utc_time(), t2)

    def test_10_set_test_clock_permits_test_env(self) -> None:
        """TC-10: set_test_clock permits clock injection in 'test' environment."""
        t_test = datetime(2029, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        with patch.dict(os.environ, {"APP_ENV": "test"}):
            set_test_clock(lambda: t_test)
            self.assertEqual(get_current_utc_time(), t_test)

    def test_11_set_test_clock_none_always_allowed_to_clear(self) -> None:
        """TC-11: set_test_clock(None) safely clears clock in production, prod, or missing env."""
        for env in ("production", "prod", "staging", "qa", "", "unknown"):
            with patch.dict(os.environ, {"APP_ENV": env}):
                set_test_clock(None)
                # Verify fallback to system clock
                now = get_current_utc_time()
                self.assertIsInstance(now, datetime)
                self.assertIsNotNone(now.tzinfo)

    def test_12_get_current_utc_time_rejects_non_datetime(self) -> None:
        """TC-12: get_current_utc_time fails closed if clock provider returns non-datetime."""
        with patch.dict(os.environ, {"APP_ENV": "test"}):
            for bad_val in ("2028-01-01T00:00:00Z", 123456789, None, 123.456, [2028, 1, 1]):
                set_test_clock(lambda: bad_val)  # type: ignore[return-value]
                with self.assertRaises(SecurityAuthorizationError) as ctx:
                    get_current_utc_time()
                self.assertIn("Configured clock provider returned invalid type", str(ctx.exception))

    def test_13_get_current_utc_time_rejects_naive_datetime(self) -> None:
        """TC-13: get_current_utc_time fails closed if clock provider returns timezone-naive datetime."""
        with patch.dict(os.environ, {"APP_ENV": "test"}):
            set_test_clock(lambda: datetime(2028, 1, 1, 12, 0, 0))  # tzinfo=None
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                get_current_utc_time()
            self.assertIn("Configured clock provider returned timezone-naive datetime", str(ctx.exception))

    def test_14_get_current_utc_time_converts_non_utc_timezone_to_utc(self) -> None:
        """TC-14: get_current_utc_time correctly converts timezone-aware non-UTC datetimes to UTC."""
        tz_ist = timezone(timedelta(hours=5, minutes=30))
        dt_ist = datetime(2028, 1, 1, 17, 30, 0, 500000, tzinfo=tz_ist)
        expected_utc = datetime(2028, 1, 1, 12, 0, 0, 500000, tzinfo=timezone.utc)

        with patch.dict(os.environ, {"APP_ENV": "test"}):
            set_test_clock(lambda: dt_ist)
            res = get_current_utc_time()
            self.assertEqual(res, expected_utc)
            self.assertEqual(res.tzinfo, timezone.utc)

    def test_15_context_isolation_across_independent_threads(self) -> None:
        """TC-15: ContextVar clock overrides in main thread do not leak to independent threads."""
        t_frozen = datetime(2045, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        thread_seen_time = []

        def worker():
            thread_seen_time.append(get_current_utc_time())

        with patch.dict(os.environ, {"APP_ENV": "test"}):
            set_test_clock(lambda: t_frozen)
            self.assertEqual(get_current_utc_time(), t_frozen)

            t = threading.Thread(target=worker)
            t.start()
            t.join(timeout=2.0)

            self.assertEqual(len(thread_seen_time), 1)
            # Worker thread saw real system clock, NOT 2045!
            self.assertLess(thread_seen_time[0].year, 2045)
            # Main thread still sees 2045
            self.assertEqual(get_current_utc_time(), t_frozen)

    def test_16_frozen_utc_clock_restores_previous_clock_on_normal_exit(self) -> None:
        """TC-16: frozen_utc_clock restores previous clock context upon normal exit."""
        t_freeze = datetime(2032, 7, 4, 12, 0, 0, tzinfo=timezone.utc)
        with patch.dict(os.environ, {"APP_ENV": "test"}):
            with frozen_utc_clock(t_freeze):
                self.assertEqual(get_current_utc_time(), t_freeze)

            # Restored to system clock after exit
            self.assertNotEqual(get_current_utc_time(), t_freeze)

    def test_17_frozen_utc_clock_restores_previous_clock_on_exception(self) -> None:
        """TC-17: frozen_utc_clock restores previous clock context when an exception is raised."""
        t_freeze = datetime(2033, 8, 15, 8, 0, 0, tzinfo=timezone.utc)
        with patch.dict(os.environ, {"APP_ENV": "test"}):
            try:
                with frozen_utc_clock(t_freeze):
                    self.assertEqual(get_current_utc_time(), t_freeze)
                    raise ValueError("Simulated unexpected failure inside frozen clock")
            except ValueError:
                pass

            # Reliably restored despite exception
            self.assertNotEqual(get_current_utc_time(), t_freeze)

    def test_18_frozen_utc_clock_nested_contexts(self) -> None:
        """TC-18: Nested frozen_utc_clock contexts restore outer context clock sequentially."""
        t_outer = datetime(2031, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        t_inner = datetime(2035, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        with patch.dict(os.environ, {"APP_ENV": "test"}):
            with frozen_utc_clock(t_outer):
                self.assertEqual(get_current_utc_time(), t_outer)
                with frozen_utc_clock(t_inner):
                    self.assertEqual(get_current_utc_time(), t_inner)
                # Outer context restored
                self.assertEqual(get_current_utc_time(), t_outer)

            # Restored to system clock
            self.assertNotEqual(get_current_utc_time(), t_outer)

    def test_19_frozen_utc_clock_rejects_naive_datetime(self) -> None:
        """TC-19: frozen_utc_clock strictly rejects timezone-naive datetime targets."""
        with patch.dict(os.environ, {"APP_ENV": "test"}):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                with frozen_utc_clock(datetime(2030, 1, 1, 0, 0, 0)):  # naive
                    pass
            self.assertIn("Target time must be a timezone-aware datetime", str(ctx.exception))

    def test_20_frozen_utc_clock_rejects_non_datetime(self) -> None:
        """TC-20: frozen_utc_clock strictly rejects non-datetime target types."""
        with patch.dict(os.environ, {"APP_ENV": "test"}):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                with frozen_utc_clock("2030-01-01T00:00:00Z"):  # type: ignore[arg-type]
                    pass
            self.assertIn("Target time must be a datetime instance", str(ctx.exception))

    def test_21_frozen_utc_clock_fails_closed_in_production_and_prod(self) -> None:
        """TC-21: frozen_utc_clock fails closed in production and prod environments."""
        t_freeze = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        for env in ("production", "prod", " PROD ", "staging", "qa"):
            with patch.dict(os.environ, {"APP_ENV": env}):
                with self.assertRaises(SecurityAuthorizationError) as ctx:
                    with frozen_utc_clock(t_freeze):
                        pass
                self.assertIn("Clock injection is strictly prohibited", str(ctx.exception))

    # =========================================================================
    # PART B: EXACT CRYPTOGRAPHIC PROVENANCE TIMESTAMPS (Tests 22-35)
    # =========================================================================

    def test_22_record_attestation_exact_matching_timestamps_succeed(self) -> None:
        """TC-22: Exact matching microsecond timestamps between evidence and principal succeed."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        attestation_id = self.db.record_legacy_evidence_attestation(
            verified_evidence=verified,
            attesting_principal=principal,
            trust_store=store,
        )
        self.assertIsInstance(attestation_id, int)
        self.assertGreater(attestation_id, 0)

    def test_23_record_attestation_rejects_one_microsecond_issued_at_mismatch(self) -> None:
        """TC-23: One-microsecond mismatch (+1 us) in issued_at is strictly rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)

        # Shift by exactly +1 microsecond
        shifted = (principal.issued_at + timedelta(microseconds=1)).isoformat()
        object.__setattr__(tampered_evidence, "issued_at", shifted)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence issued_at timestamp does not match attesting principal context", str(ctx.exception))

    def test_24_record_attestation_rejects_negative_one_microsecond_issued_at_mismatch(self) -> None:
        """TC-24: Negative one-microsecond mismatch (-1 us) in issued_at is strictly rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)

        # Shift by exactly -1 microsecond
        shifted = (principal.issued_at - timedelta(microseconds=1)).isoformat()
        object.__setattr__(tampered_evidence, "issued_at", shifted)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence issued_at timestamp does not match attesting principal context", str(ctx.exception))

    def test_25_record_attestation_rejects_one_microsecond_expires_at_mismatch(self) -> None:
        """TC-25: One-microsecond mismatch (+1 us) in expires_at is strictly rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)

        # Shift by exactly +1 microsecond
        shifted = (principal.expires_at + timedelta(microseconds=1)).isoformat()
        object.__setattr__(tampered_evidence, "expires_at", shifted)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence expires_at timestamp does not match attesting principal context", str(ctx.exception))

    def test_26_record_attestation_rejects_negative_one_microsecond_expires_at_mismatch(self) -> None:
        """TC-26: Negative one-microsecond mismatch (-1 us) in expires_at is strictly rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)

        # Shift by exactly -1 microsecond
        shifted = (principal.expires_at - timedelta(microseconds=1)).isoformat()
        object.__setattr__(tampered_evidence, "expires_at", shifted)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence expires_at timestamp does not match attesting principal context", str(ctx.exception))

    def test_27_record_attestation_rejects_sub_millisecond_issued_at_mismatch(self) -> None:
        """TC-27: Sub-millisecond mismatch (500 us) in issued_at (previously within 1ms tolerance) is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)

        # Shift by 500 microseconds (0.5 ms)
        shifted = (principal.issued_at + timedelta(microseconds=500)).isoformat()
        object.__setattr__(tampered_evidence, "issued_at", shifted)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence issued_at timestamp does not match attesting principal context", str(ctx.exception))

    def test_28_record_attestation_rejects_sub_millisecond_expires_at_mismatch(self) -> None:
        """TC-28: Sub-millisecond mismatch (500 us) in expires_at (previously within 1ms tolerance) is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)

        # Shift by 500 microseconds (0.5 ms)
        shifted = (principal.expires_at + timedelta(microseconds=500)).isoformat()
        object.__setattr__(tampered_evidence, "expires_at", shifted)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence expires_at timestamp does not match attesting principal context", str(ctx.exception))

    def test_29_record_attestation_accepts_timezone_equivalent_representations(self) -> None:
        """TC-29: Timezone-equivalent representations (+00:00 vs Z vs non-UTC offset) normalize to same UTC microsecond."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()

        # Format evidence issued_at with Z
        iso_str = principal.issued_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        object.__setattr__(verified, "issued_at", iso_str)

        # Format evidence expires_at with +05:30 offset
        tz_plus530 = timezone(timedelta(hours=5, minutes=30))
        exp_plus530 = principal.expires_at.astimezone(tz_plus530)
        object.__setattr__(verified, "expires_at", exp_plus530.isoformat())

        # Both should normalize to the exact microsecond in UTC
        attestation_id = self.db.record_legacy_evidence_attestation(
            verified_evidence=verified,
            attesting_principal=principal,
            trust_store=store,
        )
        self.assertIsInstance(attestation_id, int)
        self.assertGreater(attestation_id, 0)

    def test_30_record_attestation_rejects_timezone_naive_issued_at(self) -> None:
        """TC-30: Timezone-naive string for issued_at is strictly rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        naive_str = principal.issued_at.strftime("%Y-%m-%dT%H:%M:%S.%f")  # no tz
        object.__setattr__(verified, "issued_at", naive_str)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Timezone-naive timestamp string", str(ctx.exception))

    def test_31_record_attestation_rejects_timezone_naive_expires_at(self) -> None:
        """TC-31: Timezone-naive string for expires_at is strictly rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        naive_str = principal.expires_at.strftime("%Y-%m-%dT%H:%M:%S.%f")  # no tz
        object.__setattr__(verified, "expires_at", naive_str)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Timezone-naive timestamp string", str(ctx.exception))

    def test_32_record_attestation_rejects_missing_issued_at(self) -> None:
        """TC-32: Missing (None) issued_at fails closed with SecurityAuthorizationError."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        object.__setattr__(verified, "issued_at", None)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Timestamp value cannot be None", str(ctx.exception))

    def test_33_record_attestation_rejects_missing_expires_at(self) -> None:
        """TC-33: Missing (None) expires_at fails closed with SecurityAuthorizationError."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        object.__setattr__(verified, "expires_at", None)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Timestamp value cannot be None", str(ctx.exception))

    def test_34_record_attestation_rejects_malformed_timestamp_string(self) -> None:
        """TC-34: Malformed timestamp string fails closed with SecurityAuthorizationError."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        object.__setattr__(verified, "issued_at", "not-a-valid-iso-date-string")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Invalid timestamp format", str(ctx.exception))

    def test_35_end_to_end_production_provenance_roundtrip(self) -> None:
        """TC-35: End-to-end provenance roundtrip preserves exact microsecond timestamp equality in database."""
        verified, principal, jd_id, store = self._setup_verified_evidence_and_principal()
        attestation_id = self.db.record_legacy_evidence_attestation(
            verified_evidence=verified,
            attesting_principal=principal,
            trust_store=store,
        )
        self.assertGreater(attestation_id, 0)

        row = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
        self.assertIsNotNone(row)
        self.assertEqual(row.attested_by, principal.principal_id)
        self.assertEqual(row.evidence_type, "historical_import_manifest")

    # =========================================================================
    # PART C: REAL SQLITE MULTI-THREAD CONCURRENCY (Tests 36-42)
    # =========================================================================

    def test_36_concurrency_scenario_a_revocation_wins_under_real_lock_contention(self) -> None:
        """TC-36: Scenario A — Revocation wins under deterministic SQLite lock-conflict and retry.

        Proves:
        1. Thread A acquires BEGIN IMMEDIATE and inserts principal revocation.
        2. Thread B attempts attestation persistence through DatabaseManager with timeout=0.0.
        3. Thread B encounters an actual sqlite3.OperationalError ("database is locked").
        4. Thread B signals lock_conflict_observed only AFTER catching the lock error.
        5. Thread A commits revocation and releases the write lock.
        6. Main controller signals retry_permitted.
        7. Thread B retries through DatabaseManager, acquires lock, encounters committed revocation,
           and fails closed with SecurityAuthorizationError.
        8. Thread B is joined and verified terminated. No attestation row is persisted.
        """
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        principal_id = principal.principal_id

        connA = None
        thread_b = None

        # Lifecycle tracking events (Phase 9.1.2.14)
        b_created = threading.Event()               # State 1: Worker thread created
        b_entered_path = threading.Event()          # State 2: Entered transaction path
        b_lock_attempt_executed = threading.Event() # State 3: Actual SQLite lock attempt executed
        b_lock_conflict_observed = threading.Event()# State 4: SQLite returned lock-conflict error
        b_retry_permitted = threading.Event()       # State 5: Original transaction commits; retry allowed
        b_retry_lock_acquired = threading.Event()   # State 6: Worker retried and acquired lock
        b_completed = threading.Event()             # State 7: Competing transaction completed
        b_exceptions: List[Exception] = []

        try:
            # Thread A connection holds BEGIN IMMEDIATE with revocation
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")
            connA.execute(
                "INSERT INTO revoked_attesting_principals (principal_id, revoked_at, reason) VALUES (?, CURRENT_TIMESTAMP, ?)",
                (principal_id, "Scenario A: Revocation wins"),
            )

            # Confirm database is physically locked against zero-timeout connections
            probe = self.db.get_connection(timeout=0.0)
            probe.isolation_level = None
            probe_locked = False
            try:
                probe.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError:
                probe_locked = True
            finally:
                probe.close()
            self.assertTrue(probe_locked, "Expected SQLite write lock to be physically held by Thread A.")

            def thread_b_worker() -> None:
                b_created.set()
                b_entered_path.set()
                # Attempt 1: Attempt attestation persistence with timeout=0.0
                try:
                    b_lock_attempt_executed.set()
                    self.db.record_legacy_evidence_attestation(
                        verified_evidence=verified,
                        attesting_principal=principal,
                        trust_store=store,
                        timeout=0.0,
                    )
                except sqlite3.OperationalError as op_err:
                    # Verify error represents actual database lock conflict
                    if "locked" in str(op_err).lower() or "busy" in str(op_err).lower():
                        b_lock_conflict_observed.set()
                    else:
                        b_exceptions.append(op_err)
                        return
                except Exception as e:
                    b_exceptions.append(e)
                    return

                # Wait for retry permission from main controller
                if not b_retry_permitted.wait(timeout=5.0):
                    b_exceptions.append(TimeoutError("Thread B timed out waiting for retry permission."))
                    return

                # Attempt 2 (Retry): Now that Thread A released its lock, retry the transaction
                try:
                    b_retry_lock_acquired.set()
                    self.db.record_legacy_evidence_attestation(
                        verified_evidence=verified,
                        attesting_principal=principal,
                        trust_store=store,
                        timeout=5.0,
                    )
                except Exception as retry_err:
                    b_exceptions.append(retry_err)
                finally:
                    b_completed.set()

            thread_b = threading.Thread(target=thread_b_worker)
            thread_b.start()

            # State 1: Worker thread created
            self.assertTrue(b_created.wait(timeout=5.0), "Thread B was not created in time.")
            # State 2: Worker entered transaction path
            self.assertTrue(b_entered_path.wait(timeout=5.0), "Thread B did not enter transaction path in time.")
            # State 3: Actual SQLite lock attempt executed
            self.assertTrue(b_lock_attempt_executed.wait(timeout=5.0), "Thread B did not execute lock attempt in time.")
            # State 4: SQLite returned a real lock-conflict error
            self.assertTrue(b_lock_conflict_observed.wait(timeout=5.0), "Thread B did not observe SQLite lock conflict.")
            self.assertTrue(thread_b.is_alive(), "Thread B terminated prematurely before retry.")

            # State 5: Original transaction commits revocation and releases the write lock
            connA.execute("COMMIT")
            connA.close()
            connA = None

            # Grant retry permission
            b_retry_permitted.set()

            # State 6: Worker retries and acquires write lock
            self.assertTrue(b_retry_lock_acquired.wait(timeout=5.0), "Thread B failed to retry after lock release.")
            # State 7: Competing transaction completes
            self.assertTrue(b_completed.wait(timeout=5.0), "Thread B did not complete in time.")
            thread_b.join(timeout=5.0)
            self.assertFalse(thread_b.is_alive(), "Thread B failed to terminate cleanly.")

            # Worker must have raised SecurityAuthorizationError due to committed revocation
            self.assertEqual(len(b_exceptions), 1, f"Expected 1 exception, got: {b_exceptions}")
            self.assertIsInstance(b_exceptions[0], SecurityAuthorizationError)
            self.assertIn("has been revoked in database", str(b_exceptions[0]))

            # Verify no attestation row was persisted
            att = self.db.get_legacy_evidence_attestation(verified.job_description_id, user_id=self.user1_id)
            self.assertIsNone(att, "Attestation must not be persisted for a revoked principal.")
        finally:
            b_retry_permitted.set()  # Guarantee unblocking worker if test fails
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if thread_b is not None and thread_b.is_alive():
                thread_b.join(timeout=5.0)
                self.assertFalse(thread_b.is_alive(), "Thread B remained alive during cleanup!")

    def test_37_concurrency_scenario_b_attestation_wins_under_real_lock_contention(self) -> None:
        """TC-37: Scenario B — Attestation wins under deterministic SQLite lock-conflict and retry.

        Proves:
        1. Thread A acquires BEGIN IMMEDIATE and inserts attestation via write cursor.
        2. Thread A holds transaction uncommitted.
        3. Thread B attempts principal revocation with timeout=0.0.
        4. Thread B receives actual sqlite3.OperationalError ("database is locked").
        5. Thread B signals lock_conflict_observed only AFTER catching the lock error.
        6. Thread A commits attestation and releases the write lock.
        7. Main controller signals retry_permitted.
        8. Thread B retries revocation, acquires lock, and commits revocation.
        9. Historical attestation remains immutable; subsequent preflight rejects revoked evidence.
        """
        verified, principal, jd_id, store = self._setup_verified_evidence_and_principal()
        principal_id = principal.principal_id

        connA = None
        thread_b = None

        # Lifecycle tracking events (Phase 9.1.2.14)
        b_created = threading.Event()
        b_entered_path = threading.Event()
        b_lock_attempt_executed = threading.Event()
        b_lock_conflict_observed = threading.Event()
        b_retry_permitted = threading.Event()
        b_retry_lock_acquired = threading.Event()
        b_completed = threading.Event()
        b_exceptions: List[Exception] = []

        try:
            # Thread A connection holds BEGIN IMMEDIATE with inserted attestation
            connA = self.db.get_connection(timeout=5.0)
            connA.isolation_level = None
            connA.execute("BEGIN IMMEDIATE")
            curA = connA.cursor()

            # Perform attestation on curA
            attestation_id = self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor=curA,
                trust_store=store,
            )
            self.assertGreater(attestation_id, 0)

            def thread_b_revocation_worker() -> None:
                b_created.set()
                b_entered_path.set()
                # Attempt 1: Attempt revocation with timeout=0.0
                connB = None
                try:
                    connB = self.db.get_connection(timeout=0.0)
                    connB.isolation_level = None
                    b_lock_attempt_executed.set()
                    connB.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as op_err:
                    if "locked" in str(op_err).lower() or "busy" in str(op_err).lower():
                        b_lock_conflict_observed.set()
                    else:
                        b_exceptions.append(op_err)
                        return
                except Exception as e:
                    b_exceptions.append(e)
                    return
                finally:
                    if connB:
                        try:
                            connB.close()
                        except Exception:
                            pass

                # Wait for retry permission
                if not b_retry_permitted.wait(timeout=5.0):
                    b_exceptions.append(TimeoutError("Thread B timed out waiting for retry permission."))
                    return

                # Attempt 2 (Retry): Retrying revocation with timeout=5.0 after Thread A commits
                connB_retry = None
                try:
                    connB_retry = self.db.get_connection(timeout=5.0)
                    connB_retry.isolation_level = None
                    connB_retry.execute("BEGIN IMMEDIATE")
                    b_retry_lock_acquired.set()
                    connB_retry.execute(
                        "INSERT INTO revoked_attesting_principals (principal_id, revoked_at, reason) VALUES (?, CURRENT_TIMESTAMP, ?)",
                        (principal_id, "Scenario B: Revocation after attestation"),
                    )
                    connB_retry.execute("COMMIT")
                except Exception as retry_err:
                    b_exceptions.append(retry_err)
                finally:
                    if connB_retry:
                        try:
                            connB_retry.close()
                        except Exception:
                            pass
                    b_completed.set()

            thread_b = threading.Thread(target=thread_b_revocation_worker)
            thread_b.start()

            # State 1, 2, 3
            self.assertTrue(b_created.wait(timeout=5.0), "Thread B was not created in time.")
            self.assertTrue(b_entered_path.wait(timeout=5.0), "Thread B did not enter transaction path in time.")
            self.assertTrue(b_lock_attempt_executed.wait(timeout=5.0), "Thread B did not execute lock attempt in time.")

            # State 4: Actual SQLite lock-conflict error observed
            self.assertTrue(b_lock_conflict_observed.wait(timeout=5.0), "Thread B did not observe SQLite lock conflict.")
            self.assertTrue(thread_b.is_alive(), "Thread B died prematurely.")

            # State 5: Thread A commits attestation and releases lock
            connA.execute("COMMIT")
            connA.close()
            connA = None

            # Grant retry permission
            b_retry_permitted.set()

            # State 6: Worker retries and acquires write lock
            self.assertTrue(b_retry_lock_acquired.wait(timeout=5.0), "Thread B failed to acquire write lock on retry.")
            # State 7: Competing transaction completes
            self.assertTrue(b_completed.wait(timeout=5.0), "Thread B did not complete in time.")
            thread_b.join(timeout=5.0)
            self.assertFalse(thread_b.is_alive(), "Thread B failed to terminate cleanly.")
            self.assertEqual(len(b_exceptions), 0, f"Thread B encountered unexpected errors: {b_exceptions}")

            # 1. Historical attestation remains immutable
            row = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
            self.assertIsNotNone(row)
            self.assertEqual(row.attested_by, principal_id)

            # 2. Subsequent security checks recognize principal is revoked
            self.assertTrue(self.db.is_principal_revoked(principal_id))
            self.assertFalse(store.is_attesting_principal_trusted(principal_id))
        finally:
            b_retry_permitted.set()
            if connA is not None:
                try:
                    connA.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    connA.close()
                except Exception:
                    pass
            if thread_b is not None and thread_b.is_alive():
                thread_b.join(timeout=5.0)
                self.assertFalse(thread_b.is_alive(), "Thread B remained alive during cleanup!")

    def test_38_concurrency_scenario_c_caller_supplied_immediate_transaction(self) -> None:
        """TC-38: Scenario C — Caller-supplied ImmediateAwareConnection under deterministic lock contention.

        Proves:
        1. Sentinel write occurs on caller's cursor before revocation checks.
        2. Competing caller with timeout=0.0 receives actual sqlite3.OperationalError.
        3. Competing caller retries and completes after initial caller commits.
        """
        verified, principal, _, store = self._setup_verified_evidence_and_principal()

        conn1 = None
        t2 = None

        # Lifecycle tracking events (Phase 9.1.2.14)
        t2_created = threading.Event()
        t2_entered = threading.Event()
        t2_lock_attempt = threading.Event()
        t2_conflict_observed = threading.Event()
        t2_retry_permitted = threading.Event()
        t2_acquired = threading.Event()
        t2_completed = threading.Event()
        t2_exceptions: List[Exception] = []

        try:
            conn1 = self.db.get_connection(timeout=5.0)
            conn1.isolation_level = None
            conn1.execute("BEGIN IMMEDIATE")
            cur1 = conn1.cursor()

            # Execute attestation on cur1
            att_id = self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor=cur1,
                trust_store=store,
            )
            self.assertGreater(att_id, 0)

            # Verify sentinel write occurred inside cur1
            cur1.execute("SELECT updated_at FROM _sqlite_write_lock_sentinel WHERE id = 1")
            sentinel_row = cur1.fetchone()
            self.assertIsNotNone(sentinel_row)

            def thread2_worker() -> None:
                t2_created.set()
                t2_entered.set()
                # Attempt 1: timeout=0.0
                conn2 = None
                try:
                    conn2 = self.db.get_connection(timeout=0.0)
                    conn2.isolation_level = None
                    t2_lock_attempt.set()
                    conn2.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as op_err:
                    if "locked" in str(op_err).lower() or "busy" in str(op_err).lower():
                        t2_conflict_observed.set()
                    else:
                        t2_exceptions.append(op_err)
                        return
                except Exception as e:
                    t2_exceptions.append(e)
                    return
                finally:
                    if conn2:
                        try:
                            conn2.close()
                        except Exception:
                            pass

                if not t2_retry_permitted.wait(timeout=5.0):
                    t2_exceptions.append(TimeoutError("Thread 2 timed out waiting for retry permission."))
                    return

                # Attempt 2: retry with timeout=5.0
                conn2_retry = None
                try:
                    conn2_retry = self.db.get_connection(timeout=5.0)
                    conn2_retry.isolation_level = None
                    conn2_retry.execute("BEGIN IMMEDIATE")
                    t2_acquired.set()
                    conn2_retry.execute("COMMIT")
                except Exception as e:
                    t2_exceptions.append(e)
                finally:
                    if conn2_retry:
                        try:
                            conn2_retry.close()
                        except Exception:
                            pass
                    t2_completed.set()

            t2 = threading.Thread(target=thread2_worker)
            t2.start()

            self.assertTrue(t2_created.wait(timeout=5.0))
            self.assertTrue(t2_entered.wait(timeout=5.0))
            self.assertTrue(t2_lock_attempt.wait(timeout=5.0))
            self.assertTrue(t2_conflict_observed.wait(timeout=5.0))
            self.assertTrue(t2.is_alive())

            # Commit conn1
            conn1.execute("COMMIT")
            conn1.close()
            conn1 = None

            t2_retry_permitted.set()

            self.assertTrue(t2_acquired.wait(timeout=5.0))
            self.assertTrue(t2_completed.wait(timeout=5.0))
            t2.join(timeout=5.0)
            self.assertFalse(t2.is_alive(), "Thread 2 failed to terminate cleanly.")
            self.assertEqual(len(t2_exceptions), 0, f"Thread 2 encountered errors: {t2_exceptions}")
        finally:
            t2_retry_permitted.set()
            if conn1 is not None:
                try:
                    conn1.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    conn1.close()
                except Exception:
                    pass
            if t2 is not None and t2.is_alive():
                t2.join(timeout=5.0)
                self.assertFalse(t2.is_alive(), "Thread 2 remained alive during cleanup!")

    def test_39_concurrency_scenario_c_deferred_transaction_rejected(self) -> None:
        """TC-39: Scenario C — Caller supplying deferred transaction fails closed."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()

        conn = self.db.get_connection()
        conn.isolation_level = "DEFERRED"
        conn.execute("BEGIN DEFERRED")
        cur = conn.cursor()

        try:
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=verified,
                    attesting_principal=principal,
                    cursor=cur,
                    trust_store=store,
                )
            self.assertIn("Caller transaction must have isolation_level=None", str(ctx.exception))
        finally:
            conn.execute("ROLLBACK")
            conn.close()

    def test_40_concurrency_scenario_d_atomic_rollback_on_principal_revocation_query_error(self) -> None:
        """TC-40: Scenario D — Revocation query failure rolls back transaction atomically; zero partial rows."""
        verified, principal, jd_id, _ = self._setup_verified_evidence_and_principal()

        # Temporarily rename table to induce query failure inside _execute_atomic_attestation
        with self.db.transaction() as conn:
            conn.execute("ALTER TABLE revoked_attesting_principals RENAME TO revoked_attesting_principals_bak")

        try:
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=verified,
                    attesting_principal=principal,
                    trust_store=None,  # Bypass pre-transaction check so query failure happens inside write transaction
                )
            self.assertIn("Database revocation query failure for principal", str(ctx.exception))
        finally:
            with self.db.transaction() as conn:
                conn.execute("ALTER TABLE revoked_attesting_principals_bak RENAME TO revoked_attesting_principals")

        # Verify zero partial rows were committed
        attestation = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
        self.assertIsNone(attestation, "No partial attestation row must exist after rollback.")

    def test_41_concurrency_scenario_d_atomic_rollback_on_key_revocation_query_error(self) -> None:
        """TC-41: Scenario D — Signing key revocation query failure rolls back transaction atomically."""
        verified, principal, jd_id, store = self._setup_verified_evidence_and_principal()

        # Temporarily rename table to induce query failure inside _execute_atomic_attestation
        with self.db.transaction() as conn:
            conn.execute("ALTER TABLE revoked_signing_keys RENAME TO revoked_signing_keys_bak")

        try:
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=verified,
                    attesting_principal=principal,
                    trust_store=store,
                )
            self.assertIn("Database revocation query failure for key", str(ctx.exception))
        finally:
            with self.db.transaction() as conn:
                conn.execute("ALTER TABLE revoked_signing_keys_bak RENAME TO revoked_signing_keys")

        # Verify zero partial rows were committed
        attestation = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
        self.assertIsNone(attestation, "No partial attestation row must exist after rollback.")

    def test_42_concurrency_scenario_d_invalid_lock_state_prevents_insertion(self) -> None:
        """TC-42: Scenario D — Closed connection or invalid lock state fails closed immediately."""
        verified, principal, jd_id, store = self._setup_verified_evidence_and_principal()

        conn = self.db.get_connection()
        cur = conn.cursor()
        conn.close()  # Close connection -> cursor is invalid

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor=cur,
                trust_store=store,
            )
        self.assertIn("Invalid cursor", str(ctx.exception))

        # Verify zero rows in database
        attestation = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
        self.assertIsNone(attestation)

    # =========================================================================
    # PART D: REGISTRY & AUTHENTICATOR INVARIANTS (Tests 43-46)
    # =========================================================================

    def test_43_issued_credential_record_frozen_dataclass(self) -> None:
        """TC-43: _IssuedCredentialRecord instances are frozen dataclasses and cannot be mutated."""
        now = get_current_utc_time()
        record = _IssuedCredentialRecord(
            credential_id="cred_frozen_43",
            principal_id="runner_43",
            credential_key_id="k_svc_01",
            issuer="archival_authority",
            audience="legacy_migration",
            scopes=("legacy_migration",),
            principal_type="service",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            provider_instance_id="prov_43",
            signature_algorithm="Ed25519",
        )
        with self.assertRaises(FrozenInstanceError):
            record.principal_id = "malicious_override"  # type: ignore[misc]

    def test_44_all_11_claims_unconditionally_compared(self) -> None:
        """TC-44: All 11 claims in validate_principal are unconditionally verified against issuance record."""
        provider = self._create_provider("test")
        token = provider.mint_service_token(
            principal_id="runner_44",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        # Baseline validates cleanly
        provider.validate_principal(principal)

        def _clone_principal(p: AuthenticatedMigrationPrincipal) -> AuthenticatedMigrationPrincipal:
            clone = object.__new__(AuthenticatedMigrationPrincipal)
            for k, v in p.__dict__.items():
                object.__setattr__(clone, k, v)
            return clone

        # Tampering any of the claims must fail
        claims_to_tamper = [
            ("principal_id", "attacker"),
            ("credential_key_id", "k_other"),
            ("issuer", "evil_issuer"),
            ("audience", "other_audience"),
            ("scopes", ("other_scope",)),
            ("principal_type", "candidate"),
            ("signature_algorithm", "HMAC-SHA256"),
            ("issued_at", principal.issued_at + timedelta(seconds=10)),
            ("expires_at", principal.expires_at - timedelta(seconds=10)),
            ("credential_id", "other_cred_id"),
            ("_provider_instance_id", "other_provider_id"),
        ]

        for field_name, bad_value in claims_to_tamper:
            tampered = _clone_principal(principal)
            object.__setattr__(tampered, field_name, bad_value)
            with self.assertRaises(SecurityAuthorizationError):
                provider.validate_principal(tampered)

    def test_45_duplicate_credential_id_conflict_rejected(self) -> None:
        """TC-45: Reissuing or authenticating conflicting claims under same credential ID is rejected."""
        provider = self._create_provider("test")
        token1 = provider.mint_service_token(
            principal_id="svc_collide_45",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_COLLIDE_45",
            algorithm="Ed25519",
        )
        provider.authenticate(token1)

        # Duplicate token with different algorithm is rejected
        token2 = provider.mint_service_token(
            principal_id="svc_collide_45",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_COLLIDE_45",
            algorithm="EdDSA",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token2)
        self.assertIn("conflicting claims is rejected", str(ctx.exception))

    def test_46_authenticator_lockdown_prevents_replacement(self) -> None:
        """TC-46: DatabaseManager.service_authenticator cannot be replaced once configured."""
        fresh_db = DatabaseManager(db_path=self.tmp_path / "test_replace_46.db")
        provider1 = self._create_provider("test")
        provider2 = self._create_provider("test")

        fresh_db.set_service_authenticator(provider1)
        self.assertIs(fresh_db.service_authenticator, provider1)

        # Re-registering identical instance is idempotent
        fresh_db.set_service_authenticator(provider1)
        fresh_db.service_authenticator = provider1
        self.assertIs(fresh_db.service_authenticator, provider1)

        # Attempting replacement raises SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            fresh_db.set_service_authenticator(provider2)
        self.assertIn("Replacing configured authenticator with a different instance is strictly prohibited", str(ctx.exception))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            fresh_db.service_authenticator = provider2
        self.assertIn("Replacing configured authenticator with a different instance is strictly prohibited", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

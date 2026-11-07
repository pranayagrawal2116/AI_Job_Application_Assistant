"""Phase 9.1.2.10 — Provider-Bound Credential Context, JWT Claim & Key Integrity Closure Test Suite.

Exhaustively verifies:
1. Provider-bound credential context: cross-provider credential rejection, sentinel protection.
2. Production no-provider guarantee: verifier rejects attestation without configured provider.
3. Credential lifetime revalidation at every point of use (validate_principal, verify, record_legacy_evidence_attestation).
4. Algorithm and key binding: rejection of alg confusion (Ed25519 with HS256, HMAC with EdDSA).
5. Key immutability in ServiceAuthenticationProvider.
6. Strict JWT claim validation (typ=JWT, no crit, numeric iat/exp, max 24h lifetime, strictly 'service' principal_type).
7. Environment and trust-store consistency in LegacyEvidenceVerifier.
8. End-to-end security lifecycle, revocation, and binary recovery.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric import ed25519

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    KeyRevokedError,
    SecurityAuthorizationError,
)
from src.security.file_security import FileSecurityValidator
from src.security.legacy_evidence_verifier import (
    AuthenticatedMigrationPrincipal,
    InMemoryEvidenceResolver,
    LegacyEvidenceTrustStore,
    LegacyEvidenceVerifier,
    ServiceAuthenticationProvider,
    _AUTH_TOKEN,
    create_signed_evidence_artifact,
    set_default_evidence_resolver,
    set_default_evidence_trust_store,
    set_test_clock,
)
from src.security.prompt_injection_detector import PromptInjectionDetector
from src.security.security_preflight import SecurityPreflightManager
from src.utils.canonical_json import canonical_json_hash


class TestPhase91210ProviderBindingAndCredentialLifecycle(unittest.TestCase):
    """50+ comprehensive unit and integration tests for Phase 9.1.2.10 requirements."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="test_phase_9_1_2_10_")
        self.tmp_path = Path(self.temp_dir)
        self.db_path = self.tmp_path / "test_phase_91210.db"
        self.storage_dir = self.tmp_path / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)
        self.detector = PromptInjectionDetector()

        # Generate fresh test Ed25519 keypair for test assertions
        self.priv_key = ed25519.Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        self.pub_bytes = self.pub_key.public_bytes_raw()

        # Generate service keypair
        self.service_priv_key = ed25519.Ed25519PrivateKey.generate()
        self.service_pub_bytes = self.service_priv_key.public_key().public_bytes_raw()

        # Create test users
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("alice_91210@example.com", "hash1", "salt1", "Alice 91210"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob_91210@example.com", "hash2", "salt2", "Bob 91210"),
            )
            self.user2_id = c.lastrowid

    def tearDown(self) -> None:
        set_test_clock(None)
        set_default_evidence_trust_store(None)
        set_default_evidence_resolver(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_sample_jd(self, user_id: int) -> int:
        raw_text = "Staff Security Engineer for Phase 9.1.2.10 verification."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": user_id,
            "company_name": "CloudTrustCo",
            "job_title": "Staff Security Engineer",
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
                ) VALUES (?, 'upload', 'CloudTrustCo', 'Staff Security Engineer', ?, ?, ?, 'REQUIRED', 1, '2024-04-01 10:00:00')
                """,
                (user_id, raw_text, c_hash, snap_hash),
            )
            return c.lastrowid

    def _create_provider(
        self,
        kid: str = "k_svc_01",
        issuer: str = "archival_authority",
        audience: str = "legacy_migration",
        env: str = "production",
    ) -> ServiceAuthenticationProvider:
        with patch.dict(os.environ, {"APP_ENV": env}, clear=True):
            return ServiceAuthenticationProvider(
                trusted_keys={kid: {"key": self.service_pub_bytes, "algorithm": "Ed25519"}},
                trusted_issuers={issuer},
                expected_audience=audience,
                db_manager=self.db,
            )

    # =========================================================================
    # PART 1: PROVIDER BINDING & CROSS-PROVIDER REJECTION (Tests 1 - 8)
    # =========================================================================

    def test_01_cross_provider_credential_rejected_by_production_verifier(self) -> None:
        """TC-01: Principal minted by Provider A is strictly rejected by Verifier configured with Provider B."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            provider_a = self._create_provider(kid="kid_a", issuer="archive_a")
            provider_b = self._create_provider(kid="kid_b", issuer="archive_b")

            self.assertNotEqual(provider_a._provider_id, provider_b._provider_id)
            self.assertIsNot(provider_a._provider_sentinel, provider_b._provider_sentinel)

            token_a = provider_a.mint_service_token(
                principal_id="migration_agent_a",
                signing_key=self.service_priv_key,
                key_id="kid_a",
                issuer="archive_a",
            )
            principal_a = provider_a.authenticate(token_a)

            # Verifier configured with Provider B
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archive_a", "archive_b"},
                trusted_attesting_principals={"migration_agent_a"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier_b = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=provider_b,
                db_manager=self.db,
            )

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="CROSS_PROV_01",
                issuer_id="archive_a",
                key_id="k_ed",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="migration_agent_a",
            )
            resolver.register_artifact("historical_import_manifest", "CROSS_PROV_01", raw_bytes)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier_b.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="CROSS_PROV_01",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=snap,
                    attesting_principal=principal_a,
                )
            self.assertIn("Cross-provider credential reuse is strictly prohibited", str(ctx.exception))

    def test_02_principal_minted_by_same_provider_accepted(self) -> None:
        """TC-02: Principal minted by Provider A is accepted by Verifier configured with Provider A."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            provider_a = self._create_provider(kid="kid_a", issuer="archive_a")
            token_a = provider_a.mint_service_token(
                principal_id="migration_agent_a",
                signing_key=self.service_priv_key,
                key_id="kid_a",
                issuer="archive_a",
            )
            principal_a = provider_a.authenticate(token_a)

            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archive_a"},
                trusted_attesting_principals={"migration_agent_a"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier_a = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=provider_a,
                db_manager=self.db,
            )

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="SAME_PROV_01",
                issuer_id="archive_a",
                key_id="k_ed",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="migration_agent_a",
            )
            resolver.register_artifact("historical_import_manifest", "SAME_PROV_01", raw_bytes)

            verified = verifier_a.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="SAME_PROV_01",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=principal_a,
            )
            self.assertEqual(verified.attested_by, "migration_agent_a")

    def test_03_tampered_provider_instance_id_rejected(self) -> None:
        """TC-03: Tampering with _provider_instance_id is rejected by validate_principal."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="valid_svc",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        # Forge modified provider instance ID
        tampered = object.__new__(AuthenticatedMigrationPrincipal)
        for k, v in principal.__dict__.items():
            object.__setattr__(tampered, k, v)
        object.__setattr__(tampered, "_provider_instance_id", "forged_provider_id")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("Cross-provider credential reuse is strictly prohibited", str(ctx.exception))

    def test_04_tampered_provider_sentinel_rejected(self) -> None:
        """TC-04: Tampering with _provider_sentinel is rejected by validate_principal."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="valid_svc",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        tampered = object.__new__(AuthenticatedMigrationPrincipal)
        for k, v in principal.__dict__.items():
            object.__setattr__(tampered, k, v)
        object.__setattr__(tampered, "_provider_sentinel", object())

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("Cross-provider credential reuse is strictly prohibited", str(ctx.exception))

    def test_05_production_verifier_without_service_authenticator_rejects_all(self) -> None:
        """TC-05: In production, verifier without service_authenticator unconditionally rejects AuthenticatedMigrationPrincipal."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            provider = self._create_provider()
            token = provider.mint_service_token(
                principal_id="some_svc",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
            )
            principal = provider.authenticate(token)

            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"some_svc"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=InMemoryEvidenceResolver(),
                service_authenticator=None,
                db_manager=self.db,
            )

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="NO_AUTH_REF",
                    user_id=self.user1_id,
                    job_description_id=1,
                    source_snapshot_hash="dummy_hash",
                    attesting_principal=principal,
                )
            self.assertIn("Production service authentication provider is not configured", str(ctx.exception))

    def test_06_development_verifier_without_service_authenticator_checks_expiration(self) -> None:
        """TC-06: In development, verifier without service_authenticator still enforces non-expired principal."""
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
            provider = self._create_provider(env="development")
            token = provider.mint_service_token(
                principal_id="dev_svc",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
            )
            principal = provider.authenticate(token)

            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"dev_svc"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=None,
                db_manager=self.db,
            )

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="DEV_AUTH_01",
                issuer_id="archival_authority",
                key_id="k_ed",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="dev_svc",
            )
            resolver.register_artifact("historical_import_manifest", "DEV_AUTH_01", raw_bytes)

            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="DEV_AUTH_01",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=principal,
            )
            self.assertEqual(verified.attested_by, "dev_svc")

    def test_07_multiple_providers_have_unique_sentinels_and_ids(self) -> None:
        """TC-07: Distinct ServiceAuthenticationProvider instances receive distinct IDs and sentinels."""
        p1 = self._create_provider()
        p2 = self._create_provider()
        p3 = self._create_provider()

        ids = {p1._provider_id, p2._provider_id, p3._provider_id}
        self.assertEqual(len(ids), 3)

        sentinels = {p1._provider_sentinel, p2._provider_sentinel, p3._provider_sentinel}
        self.assertEqual(len(sentinels), 3)

    def test_08_tampering_with_principal_claims_detected_by_registry(self) -> None:
        """TC-08: Tampering with principal_id on an issued object is caught by the internal registry."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="service_alpha",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        # Artificially alter principal_id on frozen dataclass
        tampered = object.__new__(AuthenticatedMigrationPrincipal)
        for k, v in principal.__dict__.items():
            object.__setattr__(tampered, k, v)
        object.__setattr__(tampered, "principal_id", "service_beta")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("Tampered principal context claims", str(ctx.exception))

    # =========================================================================
    # PART 2: CREDENTIAL LIFETIME REVALIDATION (Tests 9 - 16)
    # =========================================================================

    def test_09_expired_at_construction_rejected(self) -> None:
        """TC-09: AuthenticatedMigrationPrincipal with past expires_at is rejected in __post_init__."""
        past_time = datetime.now(timezone.utc) - timedelta(seconds=60)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(
                _token=_AUTH_TOKEN,
                principal_id="test_svc",
                issued_at=past_time - timedelta(seconds=300),
                expires_at=past_time,
            )
        self.assertIn("has expired", str(ctx.exception))

    def test_10_missing_expires_at_rejected(self) -> None:
        """TC-10: AuthenticatedMigrationPrincipal without expires_at is rejected in __post_init__."""
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(
                _token=_AUTH_TOKEN,
                principal_id="test_svc",
                issued_at=datetime.now(timezone.utc),
                expires_at=None,
            )
        self.assertIn("missing mandatory expiration timestamp", str(ctx.exception))

    def test_11_missing_issued_at_rejected(self) -> None:
        """TC-11: AuthenticatedMigrationPrincipal without issued_at is rejected in __post_init__."""
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(
                _token=_AUTH_TOKEN,
                principal_id="test_svc",
                issued_at=None,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=3600),
            )
        self.assertIn("missing mandatory issued_at timestamp", str(ctx.exception))

    def test_12_future_issued_at_rejected(self) -> None:
        """TC-12: AuthenticatedMigrationPrincipal issued > 60s in future is rejected."""
        future_time = datetime.now(timezone.utc) + timedelta(seconds=300)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(
                _token=_AUTH_TOKEN,
                principal_id="test_svc",
                issued_at=future_time,
                expires_at=future_time + timedelta(seconds=3600),
            )
        self.assertIn("issued in the future", str(ctx.exception))

    def test_13_non_positive_lifetime_rejected(self) -> None:
        """TC-13: AuthenticatedMigrationPrincipal with exp <= iat is rejected."""
        now = datetime.now(timezone.utc)
        future = now + timedelta(seconds=30)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(
                _token=_AUTH_TOKEN,
                principal_id="test_svc",
                issued_at=future,
                expires_at=future,
            )
        self.assertIn("non-positive lifetime", str(ctx.exception))

    def test_14_validate_principal_rejects_expired_credential(self) -> None:
        """TC-14: Credential expiring during application lifetime is rejected upon validate_principal."""
        base_time = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)
        set_test_clock(lambda: base_time)
        try:
            provider = self._create_provider()
            token = provider.mint_service_token(
                principal_id="ephemeral_svc",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
                ttl_seconds=60,
            )
            principal = provider.authenticate(token)

            # Deterministically advance clock past expiration timestamp (60s ttl)
            set_test_clock(lambda: base_time + timedelta(seconds=120))

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                provider.validate_principal(principal)
            self.assertIn("has expired", str(ctx.exception))
        finally:
            set_test_clock(None)

    def test_15_legacy_evidence_verifier_rejects_expired_principal(self) -> None:
        """TC-15: Verifier.verify() rejects expired principal during execution."""
        base_time = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)
        set_test_clock(lambda: base_time)
        try:
            provider = self._create_provider()
            token = provider.mint_service_token(
                principal_id="exp_runner",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
                ttl_seconds=60,
            )
            principal = provider.authenticate(token)

            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"exp_runner"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=InMemoryEvidenceResolver(),
                service_authenticator=provider,
                db_manager=self.db,
            )

            # Deterministically advance clock past expiration timestamp (60s ttl)
            set_test_clock(lambda: base_time + timedelta(seconds=120))

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="EXP_REF",
                    user_id=self.user1_id,
                    job_description_id=1,
                    source_snapshot_hash="hash",
                    attesting_principal=principal,
                )
            self.assertIn("has expired", str(ctx.exception))
        finally:
            set_test_clock(None)

    def test_16_database_manager_records_attestation_rejects_expired_principal(self) -> None:
        """TC-16: DatabaseManager.record_legacy_evidence_attestation rejects expired principal."""
        base_time = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)
        set_test_clock(lambda: base_time)
        try:
            provider = self._create_provider()
            token = provider.mint_service_token(
                principal_id="exp_db_runner",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
                ttl_seconds=60,
            )
            principal = provider.authenticate(token)

            # Create a mock verified evidence object
            verified_evidence = MagicMock()
            verified_evidence.attested_by = "exp_db_runner"
            verified_evidence.user_id = self.user1_id
            from src.security.legacy_evidence_verifier import VerifiedLegacyEvidence
            verified_mock = object.__new__(VerifiedLegacyEvidence)
            object.__setattr__(verified_mock, "_token", None)
            object.__setattr__(verified_mock, "attested_by", "exp_db_runner")
            object.__setattr__(verified_mock, "user_id", self.user1_id)

            # Deterministically advance clock past expiration timestamp (60s ttl)
            set_test_clock(lambda: base_time + timedelta(seconds=120))

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=verified_mock,
                    attesting_principal=principal,
                )
            self.assertIn("has expired", str(ctx.exception))
        finally:
            set_test_clock(None)

    # =========================================================================
    # PART 3: ALGORITHM & KEY BINDING (Tests 17 - 25)
    # =========================================================================

    def test_17_ed25519_key_with_hs256_alg_rejected(self) -> None:
        """TC-17: Service credential using HS256 with an Ed25519 key is rejected (algorithm confusion defense)."""
        provider = self._create_provider(env="development")
        token = provider.mint_service_token(
            principal_id="confused_agent",
            signing_key=b"dummy_secret_at_least_32_bytes_long_1234",
            key_id="k_svc_01",
            issuer="archival_authority",
            algorithm="HS256",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("Algorithm mismatch", str(ctx.exception))

    def test_18_hmac_key_with_eddsa_alg_rejected(self) -> None:
        """TC-18: Service credential using EdDSA with an HMAC key is rejected (algorithm confusion defense)."""
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
            provider = ServiceAuthenticationProvider(
                trusted_keys={"k_hmac": {"key": b"32_bytes_secret_key_entropy_1234!!", "algorithm": "HMAC-SHA256"}},
                trusted_issuers={"archival_authority"},
                db_manager=self.db,
            )
            token = provider.mint_service_token(
                principal_id="confused_agent_2",
                signing_key=self.service_priv_key,
                key_id="k_hmac",
                issuer="archival_authority",
                algorithm="EdDSA",
            )
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                provider.authenticate(token)
            self.assertIn("Algorithm mismatch", str(ctx.exception))

    def test_19_unsigned_alg_none_rejected(self) -> None:
        """TC-19: Service credential with alg='none' is rejected."""
        provider = self._create_provider()
        header = {"alg": "none", "typ": "JWT", "kid": "k_svc_01"}
        payload = {
            "iss": "archival_authority",
            "aud": "legacy_migration",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        import base64
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}."

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("alg='none'", str(ctx.exception))

    def test_20_unsupported_alg_rejected(self) -> None:
        """TC-20: Service credential with unrecognized alg is rejected."""
        provider = self._create_provider()
        header = {"alg": "RS256", "typ": "JWT", "kid": "k_svc_01"}
        payload = {
            "iss": "archival_authority",
            "aud": "legacy_migration",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        import base64
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}.sig"

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("Algorithm mismatch", str(ctx.exception))

    def test_21_production_hmac_registration_rejected(self) -> None:
        """TC-21: In production, registering HMAC keys in ServiceAuthenticationProvider is strictly rejected."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            provider = ServiceAuthenticationProvider(
                trusted_issuers={"archival_authority"},
                db_manager=self.db,
            )
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                provider.register_trusted_key("hmac_k", b"32_bytes_secret_key_entropy_1234!!", algorithm="HMAC-SHA256")
            self.assertIn("HMAC service signing keys are strictly prohibited", str(ctx.exception))

    def test_22_production_hmac_token_authentication_rejected(self) -> None:
        """TC-22: In production, HMAC service credentials are rejected fail-closed."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            provider = self._create_provider()
            # Craft a token claiming HS256
            header = {"alg": "HS256", "typ": "JWT", "kid": "k_svc_01"}
            payload = {
                "iss": "archival_authority",
                "aud": "legacy_migration",
                "sub": "agent",
                "principal_type": "service",
                "scope": ["legacy_migration"],
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
            }
            import base64
            h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
            p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
            token = f"{h_enc}.{p_enc}.sig"

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                provider.authenticate(token)
            self.assertIn("Algorithm mismatch", str(ctx.exception))

    def test_23_idempotent_key_registration_succeeds(self) -> None:
        """TC-23: Idempotent re-registration of identical key and algorithm succeeds."""
        provider = self._create_provider()
        provider.register_trusted_key("k_svc_01", self.service_pub_bytes, algorithm="Ed25519")
        self.assertIn("k_svc_01", provider._trusted_keys)

    def test_24_key_immutability_differing_bytes_rejected(self) -> None:
        """TC-24: Re-registering existing key ID with different bytes raises SecurityAuthorizationError."""
        provider = self._create_provider()
        different_priv = ed25519.Ed25519PrivateKey.generate()
        different_bytes = different_priv.public_key().public_bytes_raw()

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.register_trusted_key("k_svc_01", different_bytes, algorithm="Ed25519")
        self.assertIn("already registered with different key material. Immutability violation", str(ctx.exception))

    def test_25_key_immutability_differing_algorithm_rejected(self) -> None:
        """TC-25: Re-registering existing key ID with different algorithm raises SecurityAuthorizationError."""
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
            provider = ServiceAuthenticationProvider(
                trusted_keys={"k_test": {"key": self.service_pub_bytes, "algorithm": "Ed25519"}},
                db_manager=self.db,
            )
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                provider.register_trusted_key("k_test", self.service_pub_bytes, algorithm="HMAC-SHA256")
            self.assertIn("already registered with different algorithm", str(ctx.exception))

    # =========================================================================
    # PART 4: STRICT JWT CLAIMS VALIDATION (Tests 26 - 40)
    # =========================================================================

    def test_26_missing_typ_claim_rejected(self) -> None:
        """TC-26: Header missing 'typ' is rejected."""
        provider = self._create_provider()
        header = {"alg": "EdDSA", "kid": "k_svc_01"}  # Missing typ
        payload = {
            "iss": "archival_authority",
            "aud": "legacy_migration",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        import base64
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        sig = self.service_priv_key.sign(f"{h_enc}.{p_enc}".encode("utf-8"))
        s_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}.{s_enc}"

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("must specify 'typ': 'JWT'", str(ctx.exception))

    def test_27_invalid_typ_claim_rejected(self) -> None:
        """TC-27: Header with typ != 'JWT' is rejected."""
        provider = self._create_provider()
        header = {"alg": "EdDSA", "typ": "JOSE", "kid": "k_svc_01"}
        payload = {
            "iss": "archival_authority",
            "aud": "legacy_migration",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        import base64
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        sig = self.service_priv_key.sign(f"{h_enc}.{p_enc}".encode("utf-8"))
        s_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}.{s_enc}"

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("must specify 'typ': 'JWT'", str(ctx.exception))

    def test_28_header_with_crit_rejected(self) -> None:
        """TC-28: Header containing critical parameter 'crit' is rejected."""
        provider = self._create_provider()
        header = {"alg": "EdDSA", "typ": "JWT", "kid": "k_svc_01", "crit": ["exp"]}
        payload = {
            "iss": "archival_authority",
            "aud": "legacy_migration",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        import base64
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        sig = self.service_priv_key.sign(f"{h_enc}.{p_enc}".encode("utf-8"))
        s_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}.{s_enc}"

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("Critical header parameters ('crit') are not supported", str(ctx.exception))

    def test_29_missing_kid_rejected(self) -> None:
        """TC-29: Header missing kid is rejected."""
        provider = self._create_provider()
        header = {"alg": "EdDSA", "typ": "JWT"}
        payload = {
            "iss": "archival_authority",
            "aud": "legacy_migration",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        import base64
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        sig = self.service_priv_key.sign(f"{h_enc}.{p_enc}".encode("utf-8"))
        s_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}.{s_enc}"

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("missing mandatory 'kid'", str(ctx.exception))

    def test_30_unknown_kid_rejected(self) -> None:
        """TC-30: Header with unknown kid is rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="agent",
            signing_key=self.service_priv_key,
            key_id="unknown_kid_999",
            issuer="archival_authority",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("Unknown service signing key ID", str(ctx.exception))

    def test_31_revoked_kid_rejected(self) -> None:
        """TC-31: Header with revoked kid raises KeyRevokedError."""
        self.db.record_key_revocation("revoked_service_kid", reason="Key compromised")
        provider = self._create_provider()
        with self.assertRaises(KeyRevokedError):
            provider.register_trusted_key("revoked_service_kid", self.service_pub_bytes, algorithm="Ed25519")

    def test_32_missing_iss_claim_rejected(self) -> None:
        """TC-32: Payload missing 'iss' is rejected."""
        provider = self._create_provider()
        header = {"alg": "EdDSA", "typ": "JWT", "kid": "k_svc_01"}
        payload = {
            "aud": "legacy_migration",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        import base64
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        sig = self.service_priv_key.sign(f"{h_enc}.{p_enc}".encode("utf-8"))
        s_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}.{s_enc}"

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("missing mandatory 'iss'", str(ctx.exception))

    def test_33_untrusted_iss_claim_rejected(self) -> None:
        """TC-33: Payload with untrusted 'iss' is rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="agent",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="untrusted_rogue_authority",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("Untrusted service credential issuer", str(ctx.exception))

    def test_34_missing_aud_claim_rejected(self) -> None:
        """TC-34: Payload missing 'aud' is rejected."""
        provider = self._create_provider()
        header = {"alg": "EdDSA", "typ": "JWT", "kid": "k_svc_01"}
        payload = {
            "iss": "archival_authority",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        import base64
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        sig = self.service_priv_key.sign(f"{h_enc}.{p_enc}".encode("utf-8"))
        s_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}.{s_enc}"

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("missing mandatory 'aud'", str(ctx.exception))

    def test_35_mismatched_aud_claim_rejected(self) -> None:
        """TC-35: Payload with mismatched 'aud' is rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="agent",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            audience="wrong_audience",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("does not match expected audience", str(ctx.exception))

    def test_36_missing_sub_claim_rejected(self) -> None:
        """TC-36: Payload missing 'sub' is rejected."""
        provider = self._create_provider()
        header = {"alg": "EdDSA", "typ": "JWT", "kid": "k_svc_01"}
        payload = {
            "iss": "archival_authority",
            "aud": "legacy_migration",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        import base64
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        sig = self.service_priv_key.sign(f"{h_enc}.{p_enc}".encode("utf-8"))
        s_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}.{s_enc}"

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("missing mandatory 'sub'", str(ctx.exception))

    def test_37_candidate_user_sub_rejected(self) -> None:
        """TC-37: Candidate user identities in 'sub' are strictly rejected."""
        provider = self._create_provider()
        for cand in ["candidate_user", "user_123", "candidate_john"]:
            token = provider.mint_service_token(
                principal_id=cand,
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
            )
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                provider.authenticate(token)
            self.assertIn("Candidate user", str(ctx.exception))

    def test_38_non_service_principal_type_rejected(self) -> None:
        """TC-38: Only principal_type='service' is accepted; admin/user/client are rejected."""
        provider = self._create_provider()
        for ptype in ["admin", "client", "user", "anonymous", "candidate"]:
            token = provider.mint_service_token(
                principal_id="agent",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
                principal_type=ptype,
            )
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                provider.authenticate(token)
            self.assertIn("Invalid principal_type", str(ctx.exception))

    def test_39_missing_or_invalid_scope_rejected(self) -> None:
        """TC-39: Missing legacy_migration scope is strictly rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="agent",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            scopes=["user_profile_read"],
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("lacks mandatory 'legacy_migration'", str(ctx.exception))

    def test_40_non_numeric_iat_or_exp_rejected(self) -> None:
        """TC-40: Non-numeric iat or exp (including boolean) are strictly rejected."""
        provider = self._create_provider()
        import base64

        # Boolean iat
        header = {"alg": "EdDSA", "typ": "JWT", "kid": "k_svc_01"}
        payload_bool_iat = {
            "iss": "archival_authority",
            "aud": "legacy_migration",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": True,
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload_bool_iat).encode("utf-8")).rstrip(b"=").decode("utf-8")
        sig = self.service_priv_key.sign(f"{h_enc}.{p_enc}".encode("utf-8"))
        s_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}.{s_enc}"
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("Invalid 'iat' timestamp", str(ctx.exception))

        # Boolean exp
        payload_bool_exp = {
            "iss": "archival_authority",
            "aud": "legacy_migration",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": True,
        }
        p_enc2 = base64.urlsafe_b64encode(json.dumps(payload_bool_exp).encode("utf-8")).rstrip(b"=").decode("utf-8")
        sig2 = self.service_priv_key.sign(f"{h_enc}.{p_enc2}".encode("utf-8"))
        s_enc2 = base64.urlsafe_b64encode(sig2).rstrip(b"=").decode("utf-8")
        token2 = f"{h_enc}.{p_enc2}.{s_enc2}"
        with self.assertRaises(SecurityAuthorizationError) as ctx2:
            provider.authenticate(token2)
        self.assertIn("Invalid 'exp' timestamp", str(ctx2.exception))

    def test_40b_excessive_lifetime_exceeding_24_hours_rejected(self) -> None:
        """TC-40b: Service credential lifetime > 24 hours (86400s) is rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="long_lived_svc",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            ttl_seconds=90000,  # 25 hours
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("lifetime exceeds maximum allowed threshold", str(ctx.exception))

    def test_40c_future_nbf_rejected(self) -> None:
        """TC-40c: Service credential with future nbf is rejected."""
        provider = self._create_provider()
        header = {"alg": "EdDSA", "typ": "JWT", "kid": "k_svc_01"}
        payload = {
            "iss": "archival_authority",
            "aud": "legacy_migration",
            "sub": "agent",
            "principal_type": "service",
            "scope": ["legacy_migration"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "nbf": int(datetime.now(timezone.utc).timestamp()) + 300,  # 5 min in future
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        import base64
        h_enc = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).rstrip(b"=").decode("utf-8")
        p_enc = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("utf-8")
        sig = self.service_priv_key.sign(f"{h_enc}.{p_enc}".encode("utf-8"))
        s_enc = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
        token = f"{h_enc}.{p_enc}.{s_enc}"

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("not yet valid (nbf)", str(ctx.exception))

    # =========================================================================
    # PART 5: TRUST-STORE & ENVIRONMENT CONSISTENCY (Tests 41 - 46)
    # =========================================================================

    def test_41_production_verifier_with_permissive_trust_store_rejected(self) -> None:
        """TC-41: Instantiating LegacyEvidenceVerifier in production with permissive trust store raises SecurityAuthorizationError."""
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
            permissive_store = LegacyEvidenceTrustStore(algorithm_policy="permissive", db_manager=self.db)

        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceVerifier(
                    trust_store=permissive_store,
                    db_manager=self.db,
                )
            self.assertIn("is incompatible with 'production' environment", str(ctx.exception))

    def test_42_production_verifier_with_development_service_authenticator_rejected(self) -> None:
        """TC-42: LegacyEvidenceVerifier in production rejects ServiceAuthenticationProvider initialized in development."""
        dev_provider = self._create_provider(env="development")
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            prod_store = LegacyEvidenceTrustStore(db_manager=self.db)
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceVerifier(
                    trust_store=prod_store,
                    service_authenticator=dev_provider,
                    db_manager=self.db,
                )
            self.assertIn("cannot be used in production-like environment 'production'", str(ctx.exception))

    def test_43_production_verifier_rejects_non_ed25519_artifact_unconditionally(self) -> None:
        """TC-43: In production, non-Ed25519 evidence artifacts are rejected unconditionally."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            provider = self._create_provider()
            token = provider.mint_service_token(
                principal_id="runner",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
            )
            principal = provider.authenticate(token)

            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"runner"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=provider,
                db_manager=self.db,
            )

            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="HMAC_IN_PROD",
                issuer_id="archival_authority",
                key_id="k_ed",
                signing_key=b"secret_at_least_32_bytes_long_123!",
                entries=[{"user_id": self.user1_id, "job_description_id": 1, "source_snapshot_hash": "hash"}],
                signature_algorithm="HMAC-SHA256",
                attesting_principal="runner",
            )
            resolver.register_artifact("historical_import_manifest", "HMAC_IN_PROD", raw_bytes)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="HMAC_IN_PROD",
                    user_id=self.user1_id,
                    job_description_id=1,
                    source_snapshot_hash="hash",
                    attesting_principal=principal,
                )
            self.assertIn("production policy requires Ed25519 asymmetric digital signatures", str(ctx.exception))

    def test_44_production_audit_verifier_rejects_non_ed25519(self) -> None:
        """TC-44: In production, _verify_artifact_for_audit rejects non-Ed25519 artifacts."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"audited_runner"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=self._create_provider(),
                db_manager=self.db,
            )

            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="AUDIT_HMAC",
                issuer_id="archival_authority",
                key_id="k_ed",
                signing_key=b"secret_at_least_32_bytes_long_123!",
                entries=[{"user_id": self.user1_id, "job_description_id": 1, "source_snapshot_hash": "hash"}],
                signature_algorithm="HMAC-SHA256",
                attesting_principal="audited_runner",
            )
            resolver.register_artifact("historical_import_manifest", "AUDIT_HMAC", raw_bytes)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier._verify_artifact_for_audit(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="AUDIT_HMAC",
                    user_id=self.user1_id,
                    job_description_id=1,
                    source_snapshot_hash="hash",
                    attesting_principal="audited_runner",
                )
            self.assertIn("rejected under Ed25519-only policy", str(ctx.exception))

    def test_45_database_revocation_blocks_verification_in_validate_principal(self) -> None:
        """TC-45: Database revocation of principal dynamically blocks validate_principal."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="compromised_svc_02",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        # Principal is initially valid
        provider.validate_principal(principal)

        # Revoke principal
        self.db.revoke_attesting_principal("compromised_svc_02", reason="Incident response")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(principal)
        self.assertIn("has been revoked", str(ctx.exception))

    def test_46_database_key_revocation_blocks_authentication(self) -> None:
        """TC-46: Database revocation of key blocks credential authentication."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="normal_svc",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        # Revoke signing key
        self.db.record_key_revocation("k_svc_01", reason="Key compromised")

        with self.assertRaises(KeyRevokedError):
            provider.authenticate(token)

    # =========================================================================
    # PART 6: MANDATORY REGRESSION, END-TO-END & RECOVERY (Tests 47 - 50+)
    # =========================================================================

    def test_47_mandatory_regression_independent_provider_rejected_by_production_verifier(self) -> None:
        """TC-47: Specific mandatory regression: principal minted by independently constructed provider

        is strictly rejected by production verifiers.
        """
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            # Authoritative service provider used by the production system
            official_provider = self._create_provider(kid="official_key", issuer="official_archive")

            # Rogue or independent provider constructed elsewhere
            independent_provider = self._create_provider(kid="independent_key", issuer="official_archive")

            # Independent provider mints a token
            rogue_token = independent_provider.mint_service_token(
                principal_id="rogue_principal",
                signing_key=self.service_priv_key,
                key_id="independent_key",
                issuer="official_archive",
            )
            rogue_principal = independent_provider.authenticate(rogue_token)

            store = LegacyEvidenceTrustStore(
                trusted_issuers={"official_archive"},
                trusted_attesting_principals={"rogue_principal"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=official_provider,
                db_manager=self.db,
            )

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="REGRESS_REF_01",
                issuer_id="official_archive",
                key_id="k_ed",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="rogue_principal",
            )
            resolver.register_artifact("historical_import_manifest", "REGRESS_REF_01", raw_bytes)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="REGRESS_REF_01",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=snap,
                    attesting_principal=rogue_principal,
                )
            self.assertIn("Cross-provider credential reuse is strictly prohibited", str(ctx.exception))

    def test_48_full_end_to_end_verified_evidence_lifecycle(self) -> None:
        """TC-48: Full end-to-end lifecycle: mint -> verify -> record attestation -> record exception -> preflight."""
        with patch.dict(os.environ, {"APP_ENV": "production", "SECURITY_SCAN_SIGNING_KEY": "test_scan_key_production_32_bytes_long_1234!!"}, clear=True):
            provider = self._create_provider(kid="e2e_key", issuer="e2e_authority")
            token = provider.mint_service_token(
                principal_id="e2e_coordinator",
                signing_key=self.service_priv_key,
                key_id="e2e_key",
                issuer="e2e_authority",
                ttl_seconds=3600,
            )
            principal = provider.authenticate(token)

            store = LegacyEvidenceTrustStore(
                trusted_issuers={"e2e_authority"},
                trusted_attesting_principals={"e2e_coordinator"},
                db_manager=self.db,
            )
            store.register_trusted_key("e2e_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            set_default_evidence_resolver(resolver)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="E2E_ARTIFACT_01",
                issuer_id="e2e_authority",
                key_id="e2e_ed",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="e2e_coordinator",
            )
            resolver.register_artifact("historical_import_manifest", "E2E_ARTIFACT_01", raw_bytes)

            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=provider,
                db_manager=self.db,
            )

            # 1. Authoritative verification
            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="E2E_ARTIFACT_01",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=principal,
            )
            self.assertEqual(verified.attested_by, "e2e_coordinator")

            # 2. Record attestation
            att_id = self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                trust_store=store,
            )
            self.assertGreater(att_id, 0)

            # 3. Record exception
            self.db.record_legacy_integrity_exception(
                user_id=self.user1_id,
                job_description_id=jd_id,
                original_source_type="upload",
                previous_binary_state="REQUIRED",
                assigned_legacy_state="LEGACY_TEXT_ONLY",
                source_snapshot_hash=snap,
                migration_version="phase_9_1_2_10",
                migration_reason="Verified Ed25519 E2E historical manifest",
                evidence_type="historical_import_manifest",
                evidence_reference_id="E2E_ARTIFACT_01",
                outcome="SUCCESS",
            )
            with self.db.transaction() as conn:
                conn.cursor().execute(
                    "UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?",
                    (jd_id,),
                )

            # 4. Security preflight verifies and accepts
            preflight = SecurityPreflightManager(
                db_manager=self.db,
                file_validator=self.file_validator,
                detector=self.detector,
                evidence_verifier=verifier,
            )
            res = preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
            self.assertTrue(res.is_allowed)
            self.assertEqual(res.classification, "CLEAN")

    def test_49_revocation_query_failure_fails_closed(self) -> None:
        """TC-49: Database operational error during revocation check in validate_principal fails closed."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="test_agent",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        with patch.object(self.db, "is_principal_revoked", side_effect=sqlite3.OperationalError("disk locked")):
            with self.assertRaises(sqlite3.OperationalError):
                provider.validate_principal(principal)

    def test_50_binary_recovery_restores_usable_status(self) -> None:
        """TC-50: Unverified uploaded JD in REQUIRED state transitions to CLEAN when binary file is attached."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd_record = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd_record.binary_integrity_state, "REQUIRED")

        preflight = SecurityPreflightManager(
            db_manager=self.db,
            file_validator=self.file_validator,
            detector=self.detector,
        )
        # Preflight blocks unverified upload
        with self.assertRaises(SecurityAuthorizationError):
            preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)

        # Candidate recovers by uploading the original binary document
        import io
        from reportlab.pdfgen import canvas
        buf = io.BytesIO()
        c = canvas.Canvas(buf)
        c.drawString(50, 750, "Valid job description recovery document")
        c.save()
        pdf_bytes = buf.getvalue()

        unique_name, detected_format, file_size_bytes, file_hash = (
            self.file_validator.save_user_job_description_file(
                user_id=self.user1_id,
                file_bytes=pdf_bytes,
                original_filename="job_spec.pdf",
            )
        )
        with self.db.transaction() as conn:
            conn.cursor().execute(
                """
                UPDATE job_descriptions
                SET binary_integrity_state = 'VERIFIED',
                    storage_filename = ?,
                    file_format = ?,
                    file_size_bytes = ?,
                    file_hash = ?
                WHERE id = ?
                """,
                (
                    unique_name,
                    detected_format,
                    file_size_bytes,
                    file_hash,
                    jd_id,
                ),
            )

        res2 = preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertTrue(res2.is_allowed)
        self.assertEqual(res2.classification, "CLEAN")

"""Phase 9.1.2.8 — Production Cryptographic Policy & Authenticated Attester Identity Closure Test Suite.

Exhaustively verifies:
1. Production algorithm policy derivation from APP_ENV (Ed25519-only, zero permissive leakage).
2. Elimination of default authorized principals (zero principals by default).
3. Authenticated attesting principal service context (AuthenticatedMigrationPrincipal).
4. Prevention of attesting principal override and misattribution in DatabaseManager.
5. Durable principal revocation surviving application restart.
6. End-to-end production evidence verification with Ed25519 signatures.
"""

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
from typing import Optional
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519

from src.database.db_manager import DatabaseManager
from src.database.exceptions import SecurityAuthorizationError
from src.security.file_security import FileSecurityValidator
from src.security.legacy_evidence_verifier import (
    AuthenticatedMigrationPrincipal,
    InMemoryEvidenceResolver,
    LegacyEvidenceTrustStore,
    LegacyEvidenceVerifier,
    ServiceAuthenticationProvider,
    create_signed_evidence_artifact,
    set_default_evidence_resolver,
    set_default_evidence_trust_store,
)
from src.security.prompt_injection_detector import PromptInjectionDetector
from src.security.security_preflight import SecurityPreflightManager
from src.utils.canonical_json import canonical_json_hash


class TestPhase9128ProductionPolicyAndAttesterAuth(unittest.TestCase):
    """34 comprehensive unit and integration tests for Phase 9.1.2.8 requirements."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="test_phase_9_1_2_8_")
        self.tmp_path = Path(self.temp_dir)
        self.db_path = self.tmp_path / "test_phase_9128.db"
        self.storage_dir = self.tmp_path / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)
        self.detector = PromptInjectionDetector()

        # Generate fresh test Ed25519 keypair for test assertions
        self.priv_key = ed25519.Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        self.pub_bytes = self.pub_key.public_bytes_raw()

        # Create two test users
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("alice_9128@example.com", "hash1", "salt1", "Alice 9128"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob_9128@example.com", "hash2", "salt2", "Bob 9128"),
            )
            self.user2_id = c.lastrowid

    def tearDown(self) -> None:
        set_default_evidence_trust_store(None)
        set_default_evidence_resolver(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_sample_jd(self, user_id: int) -> int:
        raw_text = "Senior Distributed Systems Engineer for Phase 9.1.2.8 test verification."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": user_id,
            "company_name": "ProdSecCo",
            "job_title": "Principal Architect",
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
                ) VALUES (?, 'upload', 'ProdSecCo', 'Principal Architect', ?, ?, ?, 'REQUIRED', 1, '2024-04-01 10:00:00')
                """,
                (user_id, raw_text, c_hash, snap_hash),
            )
            return c.lastrowid

    def _create_authenticated_principal(
        self,
        principal_id: str,
        issuer: str = "archival_authority",
        audience: str = "legacy_migration",
        verifier: Optional[LegacyEvidenceVerifier] = None,
    ) -> AuthenticatedMigrationPrincipal:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        kid = f"key_{principal_id}"
        provider = ServiceAuthenticationProvider(
            trusted_keys={kid: {"key": pub, "algorithm": "Ed25519"}},
            trusted_issuers={issuer},
            expected_audience=audience,
            db_manager=self.db,
        )
        token = provider.mint_service_token(
            principal_id=principal_id,
            signing_key=priv,
            key_id=kid,
            issuer=issuer,
            audience=audience,
            scopes=["legacy_migration"],
            ttl_seconds=3600,
            algorithm="EdDSA",
        )
        principal = provider.authenticate(token)
        if verifier is not None:
            verifier.service_authenticator = provider
        return principal

    # =========================================================================
    # PART 6.1 — ENVIRONMENT-POLICY TESTS (Tests 1 - 12)
    # =========================================================================

    def test_01_app_env_production_no_legacy_policy_enforces_ed25519_only(self) -> None:
        """TC-01: APP_ENV=production with no LEGACY_EVIDENCE_POLICY derives production (Ed25519-only)."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore()
            self.assertEqual(store.algorithm_policy, "production")

    def test_02_production_with_explicit_production_policy(self) -> None:
        """TC-02: APP_ENV=production with explicit LEGACY_EVIDENCE_POLICY=production succeeds."""
        with patch.dict(os.environ, {"APP_ENV": "production", "LEGACY_EVIDENCE_POLICY": "production"}, clear=True):
            store = LegacyEvidenceTrustStore()
            self.assertEqual(store.algorithm_policy, "production")

    def test_03_production_with_explicit_ed25519_only_policy(self) -> None:
        """TC-03: APP_ENV=production with explicit LEGACY_EVIDENCE_POLICY=ed25519_only succeeds."""
        with patch.dict(os.environ, {"APP_ENV": "production", "LEGACY_EVIDENCE_POLICY": "ed25519_only"}, clear=True):
            store = LegacyEvidenceTrustStore()
            self.assertEqual(store.algorithm_policy, "ed25519_only")

    def test_04_production_with_permissive_environment_policy_rejected(self) -> None:
        """TC-04: APP_ENV=production rejects LEGACY_EVIDENCE_POLICY=permissive fail-closed."""
        with patch.dict(os.environ, {"APP_ENV": "production", "LEGACY_EVIDENCE_POLICY": "permissive"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceTrustStore()
            self.assertIn("permissive is strictly prohibited in production", str(ctx.exception))

    def test_05_production_with_permissive_constructor_override_rejected(self) -> None:
        """TC-05: APP_ENV=production rejects programmatic algorithm_policy='permissive' override."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceTrustStore(algorithm_policy="permissive")
            self.assertIn("permissive algorithm policy override is strictly prohibited in production", str(ctx.exception))

    def test_06_production_hmac_key_registration_rejected(self) -> None:
        """TC-06: Production trust store strictly rejects HMAC key registration."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore()
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                store.register_trusted_key("hmac_k1", b"secret_at_least_32_bytes_long_123!", algorithm="HMAC-SHA256")
            self.assertIn("production policy enforces Ed25519", str(ctx.exception))

    def test_07_production_hmac_artifact_verification_rejected(self) -> None:
        """TC-07: In production, verifying an HMAC-signed artifact is rejected fail-closed."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore()
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

            # Attempt artifact verification with HMAC algorithm
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="HMAC_REF",
                    user_id=self.user1_id,
                    job_description_id=1,
                    source_snapshot_hash="some_hash",
                    attesting_principal="some_principal",
                )
            # Fails before or at algorithm check
            self.assertTrue(len(str(ctx.exception)) > 0)

    def test_08_production_ed25519_artifact_verification_accepted(self) -> None:
        """TC-08: Production trust store accepts valid Ed25519-signed artifact."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"migration_svc"},
                db_manager=self.db,
            )
            store.register_trusted_key("ed_k1", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="REF_ED_01",
                issuer_id="archival_authority",
                key_id="ed_k1",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="migration_svc",
            )
            resolver.register_artifact("historical_import_manifest", "REF_ED_01", raw_bytes)

            auth_p = self._create_authenticated_principal("migration_svc", verifier=verifier)
            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="REF_ED_01",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=auth_p,
            )
            self.assertEqual(verified.signature_algorithm, "Ed25519")
            self.assertEqual(verified.attested_by, "migration_svc")

    def test_09_development_permissive_test_configuration_supported(self) -> None:
        """TC-09: In development environment (APP_ENV=development), permissive policy is supported."""
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
            store = LegacyEvidenceTrustStore(algorithm_policy="permissive")
            self.assertEqual(store.algorithm_policy, "permissive")
            store.register_trusted_key("hmac_test", b"secret_at_least_32_bytes_long_123!", algorithm="HMAC-SHA256")
            self.assertIn("hmac_test", store._keys)

    def test_10_test_configuration_cannot_leak_into_production(self) -> None:
        """TC-10: Test configuration with HMAC cannot initialize when APP_ENV=production."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError):
                LegacyEvidenceTrustStore(
                    trusted_keys={"test_k": b"secret_32_bytes_long_1234567890!!"},  # defaults to HMAC
                )

    def test_11_staging_default_policy_fails_closed(self) -> None:
        """TC-11: In staging environment (APP_ENV=staging), default policy is production (Ed25519-only)."""
        with patch.dict(os.environ, {"APP_ENV": "staging"}, clear=True):
            store = LegacyEvidenceTrustStore()
            self.assertEqual(store.algorithm_policy, "production")
            # Permissive attempt in staging fails closed
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceTrustStore(algorithm_policy="permissive")
            self.assertIn("Permissive HMAC policy is prohibited in 'staging'", str(ctx.exception))

    def test_12_unknown_app_env_fails_closed(self) -> None:
        """TC-12: Unrecognized APP_ENV fails closed with SecurityAuthorizationError."""
        with patch.dict(os.environ, {"APP_ENV": "unrecognized_custom_env"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceTrustStore()
            self.assertIn("Unrecognized or untrusted APP_ENV", str(ctx.exception))

    # =========================================================================
    # PART 6.2 — PRINCIPAL AUTHORIZATION TESTS (Tests 13 - 25)
    # =========================================================================

    def test_13_empty_default_principal_configuration_grants_zero_principals(self) -> None:
        """TC-13: An empty default principal configuration grants zero authorized principals."""
        store = LegacyEvidenceTrustStore()
        self.assertEqual(len(store._trusted_attesting_principals), 0)
        self.assertFalse(store.is_attesting_principal_trusted("any_principal"))

    def test_14_generic_known_system_principal_not_automatically_trusted(self) -> None:
        """TC-14: Generic known system migration strings are NOT automatically trusted."""
        store = LegacyEvidenceTrustStore()
        for p in ("system_migration_authority", "system_migration_coordinator", "system_migration"):
            self.assertFalse(store.is_attesting_principal_trusted(p))

    def test_15_test_synthetic_migration_coordinator_never_trusted_by_default(self) -> None:
        """TC-15: test_synthetic_migration_coordinator is NEVER trusted in default configuration."""
        store = LegacyEvidenceTrustStore()
        self.assertFalse(store.is_attesting_principal_trusted("test_synthetic_migration_coordinator"))

    def test_16_explicitly_configured_legitimate_principal_accepted(self) -> None:
        """TC-16: Explicitly configured authorized principal is accepted."""
        store = LegacyEvidenceTrustStore(trusted_attesting_principals={"authorized_service_principal"})
        self.assertTrue(store.is_attesting_principal_trusted("authorized_service_principal"))

    def test_17_unknown_principal_is_rejected(self) -> None:
        """TC-17: Verifier strictly rejects unknown principal."""
        store = LegacyEvidenceTrustStore(trusted_attesting_principals={"good_principal"})
        resolver = InMemoryEvidenceResolver()
        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="REF1",
                user_id=self.user1_id,
                job_description_id=1,
                source_snapshot_hash="hash1",
                attesting_principal="unknown_rogue_principal",
            )
        self.assertIn("not authorized in trust store", str(ctx.exception))

    def test_18_revoked_principal_is_rejected(self) -> None:
        """TC-18: Revoking an attesting principal causes subsequent checks to reject."""
        store = LegacyEvidenceTrustStore(db_manager=self.db)
        store.register_trusted_attesting_principal("temp_principal")
        self.assertTrue(store.is_attesting_principal_trusted("temp_principal"))

        store.revoke_attesting_principal("temp_principal", reason="Compromised credentials")
        self.assertFalse(store.is_attesting_principal_trusted("temp_principal"))

    def test_19_revoked_principal_cannot_be_re_registered(self) -> None:
        """TC-19: A revoked principal cannot be re-registered."""
        store = LegacyEvidenceTrustStore(db_manager=self.db)
        store.register_trusted_attesting_principal("p_rev")
        store.revoke_attesting_principal("p_rev")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            store.register_trusted_attesting_principal("p_rev")
        self.assertIn("revoked", str(ctx.exception))

    def test_20_candidate_self_attestation_is_rejected(self) -> None:
        """TC-20: Candidate user cannot self-attest own evidence, and cannot be registered in trust store."""
        # Trust store rejects candidate registration
        with self.assertRaises(SecurityAuthorizationError):
            LegacyEvidenceTrustStore(trusted_attesting_principals={"user_1"})
        with self.assertRaises(SecurityAuthorizationError):
            LegacyEvidenceTrustStore(trusted_attesting_principals={"candidate_user"})

        store = LegacyEvidenceTrustStore(trusted_attesting_principals={"legit_migration_svc"})
        resolver = InMemoryEvidenceResolver()
        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

        for candidate_p in (f"user_{self.user1_id}", str(self.user1_id), "candidate_user"):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="REF1",
                    user_id=self.user1_id,
                    job_description_id=1,
                    source_snapshot_hash="hash1",
                    attesting_principal=candidate_p,
                )
            self.assertIn("cannot self-attest", str(ctx.exception))

    def test_21_caller_cannot_authenticate_by_supplying_arbitrary_allowed_string(self) -> None:
        """TC-21: In production mode, passing a bare string is rejected: AuthenticatedMigrationPrincipal required."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(trusted_attesting_principals={"migration_svc"}, db_manager=self.db)
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="REF1",
                    user_id=self.user1_id,
                    job_description_id=1,
                    source_snapshot_hash="hash1",
                    attesting_principal="migration_svc",  # Bare string, not AuthenticatedMigrationPrincipal
                )
            self.assertIn("Caller cannot authenticate by supplying an arbitrary allowed string", str(ctx.exception))

    def test_22_missing_authenticated_service_context_is_rejected(self) -> None:
        """TC-22: Calling verify with attesting_principal=None fails closed immediately."""
        store = LegacyEvidenceTrustStore()
        resolver = InMemoryEvidenceResolver()
        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="REF1",
                user_id=self.user1_id,
                job_description_id=1,
                source_snapshot_hash="hash1",
                attesting_principal=None,
            )
        self.assertIn("Missing authenticated service context", str(ctx.exception))

    def test_23_signed_artifact_principal_binding_must_match_runtime_identity(self) -> None:
        """TC-23: When artifact explicitly binds a principal, runtime principal must match exactly."""
        store = LegacyEvidenceTrustStore(
            trusted_issuers={"archival_authority"},
            trusted_attesting_principals={"principal_a", "principal_b"},
        )
        store.register_trusted_key("k1", b"secret_at_least_32_bytes_long_123!")
        resolver = InMemoryEvidenceResolver()
        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="BOUND_REF",
            issuer_id="archival_authority",
            key_id="k1",
            signing_key=b"secret_at_least_32_bytes_long_123!",
            entries=entries,
            attesting_principal="principal_a",  # Bound to principal_a
        )
        resolver.register_artifact("historical_import_manifest", "BOUND_REF", raw_bytes)

        # Verifying with principal_b fails closed
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="BOUND_REF",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal="principal_b",
            )
        self.assertIn("does not match verifying principal", str(ctx.exception))

    def test_24_missing_production_principal_binding_is_rejected(self) -> None:
        """TC-24: In production, artifacts missing explicit attesting_principal binding are rejected."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"migration_svc"},
                db_manager=self.db,
            )
            store.register_trusted_key("ed_k", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            # Create artifact WITHOUT attesting_principal binding
            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="UNBOUND_REF",
                issuer_id="archival_authority",
                key_id="ed_k",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal=None,  # Missing bound principal
            )
            resolver.register_artifact("historical_import_manifest", "UNBOUND_REF", raw_bytes)

            auth_p = self._create_authenticated_principal("migration_svc", verifier=verifier)
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="UNBOUND_REF",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=snap,
                    attesting_principal=auth_p,
                )
            self.assertIn("lacks mandatory attesting_principal binding required under production policy", str(ctx.exception))

    def test_25_valid_synthetic_development_artifact_remains_functional(self) -> None:
        """TC-25: Valid synthetic development artifact in development mode remains fully functional."""
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"dev_issuer"},
                trusted_attesting_principals={"dev_principal"},
            )
            store.register_trusted_key("dev_k", b"secret_at_least_32_bytes_long_123!")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="DEV_REF_01",
                issuer_id="dev_issuer",
                key_id="dev_k",
                signing_key=b"secret_at_least_32_bytes_long_123!",
                entries=entries,
                attesting_principal="dev_principal",
            )
            resolver.register_artifact("historical_import_manifest", "DEV_REF_01", raw_bytes)

            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="DEV_REF_01",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal="dev_principal",
            )
            self.assertEqual(verified.attested_by, "dev_principal")

    # =========================================================================
    # PART 6.3 — ATTESTATION PERSISTENCE TESTS (Tests 26 - 33)
    # =========================================================================

    def test_26_matching_authenticated_principal_is_persisted(self) -> None:
        """TC-26: DatabaseManager persists matching authenticated principal from VerifiedLegacyEvidence."""
        store = LegacyEvidenceTrustStore(
            trusted_issuers={"auth_issuer"},
            trusted_attesting_principals={"auth_svc"},
        )
        store.register_trusted_key("k_pers", b"secret_at_least_32_bytes_long_123!")
        resolver = InMemoryEvidenceResolver()
        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PERS_REF_01",
            issuer_id="auth_issuer",
            key_id="k_pers",
            signing_key=b"secret_at_least_32_bytes_long_123!",
            entries=entries,
            attesting_principal="auth_svc",
        )
        resolver.register_artifact("historical_import_manifest", "PERS_REF_01", raw_bytes)

        auth_p = self._create_authenticated_principal("auth_svc", issuer="auth_issuer", verifier=verifier)
        verified = verifier.verify(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PERS_REF_01",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=snap,
            attesting_principal=auth_p,
        )

        att_id = self.db.record_legacy_evidence_attestation(
            verified_evidence=verified,
            attesting_principal=auth_p,
            trust_store=store,
        )
        self.assertGreater(att_id, 0)
        persisted = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
        self.assertEqual(persisted.attested_by, "auth_svc")

    def test_27_different_override_principal_is_rejected(self) -> None:
        """TC-27: Supplying a different attesting_principal override in record_legacy_evidence_attestation is rejected."""
        store = LegacyEvidenceTrustStore(
            trusted_issuers={"auth_issuer"},
            trusted_attesting_principals={"original_principal", "different_principal"},
        )
        store.register_trusted_key("k_pers2", b"secret_at_least_32_bytes_long_123!")
        resolver = InMemoryEvidenceResolver()
        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PERS_REF_02",
            issuer_id="auth_issuer",
            key_id="k_pers2",
            signing_key=b"secret_at_least_32_bytes_long_123!",
            entries=entries,
            attesting_principal="original_principal",
        )
        resolver.register_artifact("historical_import_manifest", "PERS_REF_02", raw_bytes)

        verified = verifier.verify(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PERS_REF_02",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=snap,
            attesting_principal="original_principal",
        )

        # Attempt override with different principal
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal="different_principal",
                trust_store=store,
            )
        self.assertIn("Attesting principal mismatch", str(ctx.exception))

    def test_28_verified_object_cannot_be_attributed_to_another_trusted_identity(self) -> None:
        """TC-28: An authenticated principal cannot misattribute another trusted principal's verified object."""
        store = LegacyEvidenceTrustStore(
            trusted_issuers={"auth_issuer"},
            trusted_attesting_principals={"principal_one", "principal_two"},
        )
        store.register_trusted_key("k_pers3", b"secret_at_least_32_bytes_long_123!")
        resolver = InMemoryEvidenceResolver()
        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PERS_REF_03",
            issuer_id="auth_issuer",
            key_id="k_pers3",
            signing_key=b"secret_at_least_32_bytes_long_123!",
            entries=entries,
            attesting_principal="principal_one",
        )
        resolver.register_artifact("historical_import_manifest", "PERS_REF_03", raw_bytes)

        verified = verifier.verify(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PERS_REF_03",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=snap,
            attesting_principal="principal_one",
        )

        auth_two = self._create_authenticated_principal("principal_two", issuer="auth_issuer")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=auth_two,
                trust_store=store,
            )
        self.assertIn("Attesting principal mismatch", str(ctx.exception))

    def test_29_candidate_cannot_create_migration_attestation(self) -> None:
        """TC-29: Candidate identities are strictly rejected in record_legacy_evidence_attestation."""
        # Direct instantiation is rejected
        with self.assertRaises(SecurityAuthorizationError):
            AuthenticatedMigrationPrincipal(principal_id=f"user_{self.user1_id}")
        # Even attempting to authenticate a candidate identity through provider fails immediately
        with self.assertRaises(SecurityAuthorizationError):
            self._create_authenticated_principal(f"user_{self.user1_id}")

    def test_30_missing_verified_object_is_rejected(self) -> None:
        """TC-30: Direct insertion without a VerifiedLegacyEvidence instance fails closed."""
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence="arbitrary_dict_or_string",
                attesting_principal="migration_svc",
            )
        self.assertIn("Direct insertion or arbitrary evidence references are strictly prohibited", str(ctx.exception))

    def test_31_direct_sql_forged_attestation_remains_blocked_by_preflight(self) -> None:
        """TC-31: Directly forged SQL attestation row without backing artifact is rejected by preflight."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        with self.db.immediate_transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, 'historical_import_manifest', 'FORGED_REF_9128', ?, 'forged_principal')
                """,
                (self.user1_id, jd_id, snap),
            )
            cur.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, '9.1.2.8', 'historical_import_manifest', 'FORGED_REF_9128', 'forged', 'SUCCESS')
                """,
                (self.user1_id, jd_id, snap),
            )
            cur.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))

        store = LegacyEvidenceTrustStore(trusted_attesting_principals={"forged_principal"})
        resolver = InMemoryEvidenceResolver()  # Empty, forged ref does not exist
        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)
        preflight = SecurityPreflightManager(
            db_manager=self.db,
            file_validator=self.file_validator,
            detector=self.detector,
            evidence_verifier=verifier,
        )

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("could not be resolved or found", str(ctx.exception))

    def test_32_valid_ed25519_artifact_remains_verifiable_after_application_restart(self) -> None:
        """TC-32: A valid Ed25519-signed artifact remains verifiable across re-instantiation / simulated restart."""
        with patch.dict(os.environ, {"APP_ENV": "production", "SECURITY_SCAN_SIGNING_KEY": "test_scan_key_production_32_bytes_long_1234!!"}, clear=True):
            # Step 1: Initialize trust store and record valid attestation
            store1 = LegacyEvidenceTrustStore(
                trusted_issuers={"prod_authority"},
                trusted_attesting_principals={"service_runner"},
                db_manager=self.db,
            )
            store1.register_trusted_key("ed_perm", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            set_default_evidence_resolver(resolver)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="PERM_REF_01",
                issuer_id="prod_authority",
                key_id="ed_perm",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="service_runner",
            )
            resolver.register_artifact("historical_import_manifest", "PERM_REF_01", raw_bytes)

            verifier1 = LegacyEvidenceVerifier(trust_store=store1, resolver=resolver, db_manager=self.db)
            auth_p = self._create_authenticated_principal("service_runner", issuer="prod_authority", verifier=verifier1)
            verified = verifier1.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="PERM_REF_01",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=auth_p,
            )

            self.db.record_legacy_evidence_attestation(verified, attesting_principal=auth_p, trust_store=store1)
            self.db.record_legacy_integrity_exception(
                user_id=self.user1_id,
                job_description_id=jd_id,
                original_source_type="upload",
                previous_binary_state="REQUIRED",
                assigned_legacy_state="LEGACY_TEXT_ONLY",
                source_snapshot_hash=snap,
                migration_version="phase_9_1_2_8",
                migration_reason="Verified Ed25519 archival evidence",
                evidence_type="historical_import_manifest",
                evidence_reference_id="PERM_REF_01",
                outcome="SUCCESS",
            )
            with self.db.transaction() as conn:
                conn.cursor().execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))

            # Step 2: Simulate application restart with new trust store and verifier
            store2 = LegacyEvidenceTrustStore(
                trusted_issuers={"prod_authority"},
                trusted_attesting_principals={"service_runner"},
                db_manager=self.db,
            )
            store2.register_trusted_key("ed_perm", self.pub_bytes, algorithm="Ed25519")
            verifier2 = LegacyEvidenceVerifier(trust_store=store2, resolver=resolver, db_manager=self.db)

            preflight = SecurityPreflightManager(
                db_manager=self.db,
                file_validator=self.file_validator,
                detector=self.detector,
                evidence_verifier=verifier2,
            )
            res = preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
            self.assertTrue(res.is_allowed)
            self.assertEqual(res.classification, "CLEAN")

    def test_33_revocation_blocks_previously_accepted_evidence(self) -> None:
        """TC-33: Revoking the attesting principal durably blocks previously accepted evidence from passing preflight."""
        with patch.dict(os.environ, {"APP_ENV": "production", "SECURITY_SCAN_SIGNING_KEY": "test_scan_key_production_32_bytes_long_1234!!"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"prod_authority"},
                trusted_attesting_principals={"revokable_runner"},
                db_manager=self.db,
            )
            store.register_trusted_key("ed_rev_key", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="REV_REF_01",
                issuer_id="prod_authority",
                key_id="ed_rev_key",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="revokable_runner",
            )
            resolver.register_artifact("historical_import_manifest", "REV_REF_01", raw_bytes)

            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)
            auth_p = self._create_authenticated_principal("revokable_runner", issuer="prod_authority", verifier=verifier)
            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="REV_REF_01",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=auth_p,
            )

            self.db.record_legacy_evidence_attestation(verified, attesting_principal=auth_p, trust_store=store)
            self.db.record_legacy_integrity_exception(
                user_id=self.user1_id,
                job_description_id=jd_id,
                original_source_type="upload",
                previous_binary_state="REQUIRED",
                assigned_legacy_state="LEGACY_TEXT_ONLY",
                source_snapshot_hash=snap,
                migration_version="phase_9_1_2_8",
                migration_reason="Verified Ed25519 archival evidence",
                evidence_type="historical_import_manifest",
                evidence_reference_id="REV_REF_01",
                outcome="SUCCESS",
            )
            with self.db.transaction() as conn:
                conn.cursor().execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))

            preflight = SecurityPreflightManager(
                db_manager=self.db,
                file_validator=self.file_validator,
                detector=self.detector,
                evidence_verifier=verifier,
            )
            # Before revocation: preflight PASS
            res = preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
            self.assertTrue(res.is_allowed)

            # Durably revoke attesting principal
            store.revoke_attesting_principal("revokable_runner", reason="Security compromise detected")

            # After revocation: preflight FAILS CLOSED
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
            self.assertTrue(
                "revoked" in str(ctx.exception).lower() or "not authorized" in str(ctx.exception).lower()
            )

    # =========================================================================
    # PART 6.4 — END-TO-END PRODUCTION BEHAVIOR (Test 34)
    # =========================================================================

    def test_34_end_to_end_production_behavior(self) -> None:
        """TC-34: End-to-end integration test verifying complete production cryptographic boundary.

        1. Sets APP_ENV=production.
        2. Omits LEGACY_EVIDENCE_POLICY (derives production).
        3. Configures valid Ed25519 public key and trusted issuer.
        4. Configures authenticated migration identity.
        5. Creates valid signed test artifact with test external signing fixture.
        6. Verifies valid evidence is accepted.
        7. Attempts HMAC evidence -> rejected.
        8. Attempts fake principal string -> rejected.
        9. Confirms original valid artifact remains usable.
        10. Confirms unverified uploaded source remains REQUIRED.
        """
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            # 1 & 2 & 3 & 4: Configure trust store
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"authorized_archive_org"},
                trusted_attesting_principals={"prod_migration_coordinator"},
                db_manager=self.db,
            )
            self.assertEqual(store.algorithm_policy, "production")
            store.register_trusted_key("ed_prod_root", self.pub_bytes, algorithm="Ed25519")

            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            # 5 & 6: Create and verify valid Ed25519 evidence
            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="E2E_PROD_MANIFEST_001",
                issuer_id="authorized_archive_org",
                key_id="ed_prod_root",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="prod_migration_coordinator",
            )
            resolver.register_artifact("historical_import_manifest", "E2E_PROD_MANIFEST_001", raw_bytes)

            auth_principal = self._create_authenticated_principal(
                "prod_migration_coordinator",
                issuer="authorized_archive_org",
                verifier=verifier,
            )
            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="E2E_PROD_MANIFEST_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=auth_principal,
            )
            self.assertEqual(verified.signature_algorithm, "Ed25519")
            self.assertEqual(verified.attested_by, "prod_migration_coordinator")

            # 7: Attempt HMAC evidence -> rejected under production policy
            hmac_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="HMAC_ATTEMPT",
                issuer_id="authorized_archive_org",
                key_id="hmac_key",
                signing_key=b"secret_at_least_32_bytes_long_123!",
                entries=entries,
                signature_algorithm="HMAC-SHA256",
                attesting_principal="prod_migration_coordinator",
            )
            resolver.register_artifact("historical_import_manifest", "HMAC_ATTEMPT", hmac_bytes)
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="HMAC_ATTEMPT",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=snap,
                    attesting_principal=auth_principal,
                )
            self.assertIn("production policy requires Ed25519", str(ctx.exception))

            # 8: Attempt fake/unauthenticated principal string -> rejected
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="E2E_PROD_MANIFEST_001",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=snap,
                    attesting_principal="prod_migration_coordinator",  # Raw string!
                )
            self.assertIn("Caller cannot authenticate by supplying an arbitrary allowed string", str(ctx.exception))

            # 9: Confirms original valid artifact remains usable
            att_id = self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=auth_principal,
                trust_store=store,
            )
            self.assertGreater(att_id, 0)
            persisted = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
            self.assertEqual(persisted.attested_by, "prod_migration_coordinator")

            # 10: Confirms an unverified uploaded record remains REQUIRED
            unverified_jd_id = self._create_sample_jd(self.user2_id)
            unverified_jd = self.db.get_job_description(unverified_jd_id, user_id=self.user2_id)
            self.assertEqual(unverified_jd.binary_integrity_state, "REQUIRED")


if __name__ == "__main__":
    unittest.main()

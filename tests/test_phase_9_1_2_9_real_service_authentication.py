"""Phase 9.1.2.9 — Genuine Service Identity Authentication & Environment Fail-Closed Closure Test Suite.

Exhaustively verifies:
1. Environment policy derivation (Ed25519-only production/staging/qa, fail-closed on missing/empty/unknown APP_ENV).
2. Elimination of manufactured/bypassable principal objects (direct instantiation blocked, sentinel-guarded).
3. Elimination of bypass flags (require_authenticated_context=False strictly rejected in production/staging/qa).
4. Service credential verification (JWT format, Ed25519 signatures, revocation checks, audience/issuer/scope).
5. Database revocation durability and fail-closed behavior on database errors.
6. Zero-synthetic identity guarantee in production.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from typing import List, Optional
import unittest
from unittest.mock import MagicMock, patch

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
    create_test_authenticated_principal,
    resolve_app_env,
    set_default_evidence_resolver,
    set_default_evidence_trust_store,
)
from src.security.prompt_injection_detector import PromptInjectionDetector
from src.security.security_preflight import SecurityPreflightManager
from src.utils.canonical_json import canonical_json_hash


class TestPhase9129RealServiceAuthentication(unittest.TestCase):
    """45 comprehensive unit and integration tests verifying Phase 9.1.2.9 requirements."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="test_phase_9_1_2_9_")
        self.tmp_path = Path(self.temp_dir)
        self.db_path = self.tmp_path / "test_phase_9129.db"
        self.storage_dir = self.tmp_path / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)
        self.detector = PromptInjectionDetector()

        # Generate fresh test Ed25519 keypairs
        self.priv_key = ed25519.Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        self.pub_bytes = self.pub_key.public_bytes_raw()

        self.service_priv_key = ed25519.Ed25519PrivateKey.generate()
        self.service_pub_key = self.service_priv_key.public_key()
        self.service_pub_bytes = self.service_pub_key.public_bytes_raw()

        # Create two test users
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("alice_9129@example.com", "hash1", "salt1", "Alice 9129"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob_9129@example.com", "hash2", "salt2", "Bob 9129"),
            )
            self.user2_id = c.lastrowid

    def tearDown(self) -> None:
        set_default_evidence_trust_store(None)
        set_default_evidence_resolver(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_sample_jd(self, user_id: int) -> int:
        raw_text = "Staff Security Engineer for Phase 9.1.2.9 test verification."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": user_id,
            "company_name": "SecureCorp",
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
                ) VALUES (?, 'upload', 'SecureCorp', 'Staff Security Engineer', ?, ?, ?, 'REQUIRED', 1, '2024-04-01 10:00:00')
                """,
                (user_id, raw_text, c_hash, snap_hash),
            )
            return c.lastrowid

    def _create_authenticated_principal(
        self,
        principal_id: str,
        issuer: str = "archival_authority",
        audience: str = "legacy_migration",
        scopes: Optional[List[str]] = None,
    ) -> AuthenticatedMigrationPrincipal:
        kid = f"key_{principal_id}"
        provider = ServiceAuthenticationProvider(
            trusted_keys={kid: {"key": self.service_pub_bytes, "algorithm": "Ed25519"}},
            trusted_issuers={issuer},
            expected_audience=audience,
            db_manager=self.db,
        )
        token = provider.mint_service_token(
            principal_id=principal_id,
            signing_key=self.service_priv_key,
            key_id=kid,
            issuer=issuer,
            audience=audience,
            scopes=scopes or ["legacy_migration"],
            ttl_seconds=3600,
            algorithm="EdDSA",
        )
        return provider.authenticate(token)

    # =========================================================================
    # PART 1: ENVIRONMENT POLICY TESTS (Tests 1 - 12)
    # =========================================================================

    def test_01_app_env_production_enforces_ed25519_only(self) -> None:
        """TC-01: APP_ENV=production derives production algorithm policy and enforces Ed25519-only."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            self.assertEqual(resolve_app_env(), "production")
            store = LegacyEvidenceTrustStore(db_manager=self.db)
            self.assertEqual(store.algorithm_policy, "production")

    def test_02_production_rejects_permissive_env_override(self) -> None:
        """TC-02: Setting LEGACY_EVIDENCE_POLICY=permissive in production is rejected."""
        with patch.dict(os.environ, {"APP_ENV": "production", "LEGACY_EVIDENCE_POLICY": "permissive"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceTrustStore(db_manager=self.db)
            self.assertIn("strictly prohibited", str(ctx.exception))

    def test_03_production_rejects_permissive_constructor_override(self) -> None:
        """TC-03: Passing algorithm_policy='permissive' to constructor in production is rejected."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceTrustStore(algorithm_policy="permissive", db_manager=self.db)
            self.assertIn("strictly prohibited", str(ctx.exception))

    def test_04_production_rejects_require_authenticated_context_false_in_constructor(self) -> None:
        """TC-04: LegacyEvidenceVerifier constructor rejects require_authenticated_context=False in production."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(db_manager=self.db)
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceVerifier(trust_store=store, require_authenticated_context=False, db_manager=self.db)
            self.assertIn("strictly prohibited", str(ctx.exception))

    def test_05_production_rejects_require_authenticated_context_false_in_verify(self) -> None:
        """TC-05: LegacyEvidenceVerifier.verify() rejects require_authenticated_context=False in production."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(db_manager=self.db)
            verifier = LegacyEvidenceVerifier(trust_store=store, db_manager=self.db)
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="REF_01",
                    user_id=self.user1_id,
                    job_description_id=1,
                    source_snapshot_hash="snap",
                    attesting_principal="some_principal",
                    require_authenticated_context=False,
                )
            self.assertIn("strictly prohibited", str(ctx.exception))

    def test_06_staging_rejects_permissive_policy(self) -> None:
        """TC-06: APP_ENV=staging enforces Ed25519-only and rejects permissive policy."""
        with patch.dict(os.environ, {"APP_ENV": "staging"}, clear=True):
            self.assertEqual(resolve_app_env(), "staging")
            store = LegacyEvidenceTrustStore(db_manager=self.db)
            self.assertEqual(store.algorithm_policy, "production")
            with self.assertRaises(SecurityAuthorizationError):
                LegacyEvidenceTrustStore(algorithm_policy="permissive", db_manager=self.db)

    def test_07_staging_rejects_require_authenticated_context_false(self) -> None:
        """TC-07: APP_ENV=staging rejects require_authenticated_context=False in constructor and verify."""
        with patch.dict(os.environ, {"APP_ENV": "staging"}, clear=True):
            store = LegacyEvidenceTrustStore(db_manager=self.db)
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceVerifier(trust_store=store, require_authenticated_context=False, db_manager=self.db)
            self.assertIn("strictly prohibited", str(ctx.exception))

    def test_08_qa_rejects_permissive_policy(self) -> None:
        """TC-08: APP_ENV=qa enforces Ed25519-only and rejects permissive policy."""
        with patch.dict(os.environ, {"APP_ENV": "qa"}, clear=True):
            self.assertEqual(resolve_app_env(), "qa")
            store = LegacyEvidenceTrustStore(db_manager=self.db)
            self.assertEqual(store.algorithm_policy, "production")
            with self.assertRaises(SecurityAuthorizationError):
                LegacyEvidenceTrustStore(algorithm_policy="permissive", db_manager=self.db)

    def test_09_qa_rejects_require_authenticated_context_false(self) -> None:
        """TC-09: APP_ENV=qa rejects require_authenticated_context=False in constructor."""
        with patch.dict(os.environ, {"APP_ENV": "qa"}, clear=True):
            store = LegacyEvidenceTrustStore(db_manager=self.db)
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceVerifier(trust_store=store, require_authenticated_context=False, db_manager=self.db)
            self.assertIn("strictly prohibited", str(ctx.exception))

    def test_10_missing_app_env_fails_closed(self) -> None:
        """TC-10: Missing APP_ENV environment variable fails closed with SecurityAuthorizationError."""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                resolve_app_env()
            self.assertIn("Application security policy fails closed", str(ctx.exception))

    def test_11_empty_or_whitespace_app_env_fails_closed(self) -> None:
        """TC-11: Empty or whitespace-only APP_ENV fails closed with SecurityAuthorizationError."""
        with patch.dict(os.environ, {"APP_ENV": ""}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                resolve_app_env()
            self.assertIn("Application security policy fails closed", str(ctx.exception))

        with patch.dict(os.environ, {"APP_ENV": "   \t\n  "}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                resolve_app_env()
            self.assertIn("Application security policy fails closed", str(ctx.exception))

    def test_12_development_and_test_allow_permissive_policy(self) -> None:
        """TC-12: APP_ENV=development and APP_ENV=test explicitly permit permissive HMAC policy."""
        with patch.dict(os.environ, {"APP_ENV": "development"}, clear=True):
            self.assertEqual(resolve_app_env(), "development")
            store = LegacyEvidenceTrustStore(algorithm_policy="permissive")
            self.assertEqual(store.algorithm_policy, "permissive")

        with patch.dict(os.environ, {"APP_ENV": "test"}, clear=True):
            self.assertEqual(resolve_app_env(), "test")
            store_test = LegacyEvidenceTrustStore(algorithm_policy="permissive")
            self.assertEqual(store_test.algorithm_policy, "permissive")

    # =========================================================================
    # PART 2: AUTHENTICATED PRINCIPAL INTEGRITY TESTS (Tests 13 - 25)
    # =========================================================================

    def test_13_direct_authenticated_principal_construction_rejected(self) -> None:
        """TC-13: Direct construction of AuthenticatedMigrationPrincipal fails with SecurityAuthorizationError."""
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(principal_id="service_runner")
        self.assertIn("cannot be directly instantiated", str(ctx.exception))

    def test_14_authenticated_principal_token_tampering_rejected(self) -> None:
        """TC-14: Supplying a forged or fake _token to AuthenticatedMigrationPrincipal is rejected."""
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(_token="forged_token", principal_id="service_runner")
        self.assertIn("cannot be directly instantiated", str(ctx.exception))

    def test_15_legacy_evidence_verifier_has_no_create_authenticated_principal(self) -> None:
        """TC-15: Neither LegacyEvidenceVerifier nor AuthenticatedMigrationPrincipal exposes unverified creator."""
        self.assertFalse(hasattr(AuthenticatedMigrationPrincipal, "create_authenticated_principal"))
        self.assertFalse(hasattr(LegacyEvidenceVerifier, "create_authenticated_principal"))

    def test_16_production_rejects_raw_string_principal(self) -> None:
        """TC-16: In production, passing a raw string for attesting_principal is rejected."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"migration_svc"},
                db_manager=self.db,
            )
            store.register_trusted_key("k1", self.pub_bytes, algorithm="Ed25519")
            verifier = LegacyEvidenceVerifier(trust_store=store, db_manager=self.db)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="REF_01",
                    user_id=self.user1_id,
                    job_description_id=1,
                    source_snapshot_hash="snap",
                    attesting_principal="migration_svc",  # Raw string!
                )
            self.assertIn("Caller cannot authenticate by supplying an arbitrary allowed string", str(ctx.exception))

    def test_17_production_rejects_fake_auth_source_metadata(self) -> None:
        """TC-17: Callers cannot bypass verification by supplying duck-typed objects with fake auth metadata."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"migration_svc"},
                db_manager=self.db,
            )
            store.register_trusted_key("k1", self.pub_bytes, algorithm="Ed25519")
            verifier = LegacyEvidenceVerifier(trust_store=store, db_manager=self.db)

            class FakePrincipal:
                principal_id = "migration_svc"
                is_authenticated = True
                authentication_source = "production_vault"
                scopes = ("legacy_migration",)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="REF_01",
                    user_id=self.user1_id,
                    job_description_id=1,
                    source_snapshot_hash="snap",
                    attesting_principal=FakePrincipal(),  # Duck-typed fake object!
                )
            self.assertIn("AuthenticatedMigrationPrincipal", str(ctx.exception))

    def test_18_service_auth_rejects_missing_credential(self) -> None:
        """TC-18: ServiceAuthenticationProvider rejects missing or empty credential."""
        provider = ServiceAuthenticationProvider(db_manager=self.db)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(None)
        self.assertIn("Missing service credential", str(ctx.exception))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate("")
        self.assertIn("Missing service credential", str(ctx.exception))

    def test_19_service_auth_rejects_invalid_token_format(self) -> None:
        """TC-19: ServiceAuthenticationProvider rejects tokens not matching 3 dot-separated segments."""
        provider = ServiceAuthenticationProvider(db_manager=self.db)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate("invalid_non_jwt_token")
        self.assertIn("expected 3 dot-separated segments", str(ctx.exception))

    def test_20_service_auth_rejects_unsigned_or_none_alg(self) -> None:
        """TC-20: ServiceAuthenticationProvider strictly rejects alg='none' tokens."""
        provider = ServiceAuthenticationProvider(db_manager=self.db)
        header = json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")
        payload = json.dumps({"sub": "admin_svc", "exp": 9999999999}).encode("utf-8")
        import base64
        h_b64 = base64.urlsafe_b64encode(header).decode("utf-8").rstrip("=")
        p_b64 = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
        token = f"{h_b64}.{p_b64}."

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("alg='none'", str(ctx.exception))

    def test_21_service_auth_rejects_hmac_in_production(self) -> None:
        """TC-21: ServiceAuthenticationProvider rejects HMAC tokens under production policy."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            provider = ServiceAuthenticationProvider(
                trusted_issuers={"archival_authority"},
                db_manager=self.db,
            )
            # Registering HMAC key in production is rejected
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                provider.register_trusted_key("hmac_k", b"secret_at_least_32_bytes_long_123!", algorithm="HMAC-SHA256")
            self.assertIn("strictly prohibited in 'production'", str(ctx.exception))

    def test_22_service_auth_rejects_expired_credential(self) -> None:
        """TC-22: ServiceAuthenticationProvider rejects expired service credentials."""
        kid = "exp_key"
        provider = ServiceAuthenticationProvider(
            trusted_keys={kid: {"key": self.service_pub_bytes, "algorithm": "Ed25519"}},
            trusted_issuers={"archival_authority"},
            db_manager=self.db,
        )
        expired_token = provider.mint_service_token(
            principal_id="expired_svc",
            signing_key=self.service_priv_key,
            key_id=kid,
            issuer="archival_authority",
            scopes=["legacy_migration"],
            ttl_seconds=-300,  # Expired 5 minutes ago
            algorithm="EdDSA",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(expired_token)
        self.assertIn("has expired", str(ctx.exception))

    def test_23_service_auth_rejects_untrusted_issuer_or_audience(self) -> None:
        """TC-23: ServiceAuthenticationProvider rejects tokens with untrusted issuer or wrong audience."""
        kid = "iss_key"
        provider = ServiceAuthenticationProvider(
            trusted_keys={kid: {"key": self.service_pub_bytes, "algorithm": "Ed25519"}},
            trusted_issuers={"authorized_authority"},
            expected_audience="legacy_migration",
            db_manager=self.db,
        )
        # Untrusted issuer
        bad_issuer_token = provider.mint_service_token(
            principal_id="svc_1",
            signing_key=self.service_priv_key,
            key_id=kid,
            issuer="rogue_untrusted_issuer",
            audience="legacy_migration",
            algorithm="EdDSA",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(bad_issuer_token)
        self.assertIn("Untrusted service credential issuer", str(ctx.exception))

        # Wrong audience
        bad_aud_token = provider.mint_service_token(
            principal_id="svc_1",
            signing_key=self.service_priv_key,
            key_id=kid,
            issuer="authorized_authority",
            audience="wrong_audience",
            algorithm="EdDSA",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(bad_aud_token)
        self.assertIn("does not match expected audience", str(ctx.exception))

    def test_24_service_auth_rejects_missing_legacy_migration_scope(self) -> None:
        """TC-24: ServiceAuthenticationProvider rejects credentials lacking 'legacy_migration' scope."""
        kid = "scope_key"
        provider = ServiceAuthenticationProvider(
            trusted_keys={kid: {"key": self.service_pub_bytes, "algorithm": "Ed25519"}},
            trusted_issuers={"archival_authority"},
            db_manager=self.db,
        )
        bad_scope_token = provider.mint_service_token(
            principal_id="svc_without_migration",
            signing_key=self.service_priv_key,
            key_id=kid,
            issuer="archival_authority",
            scopes=["user_profile_read", "analytics"],
            algorithm="EdDSA",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(bad_scope_token)
        self.assertIn("lacks mandatory 'legacy_migration' authorization scope", str(ctx.exception))

    def test_25_service_auth_rejects_candidate_user_identity(self) -> None:
        """TC-25: Candidate users are strictly rejected from authenticating as service migration principals."""
        kid = "cand_key"
        provider = ServiceAuthenticationProvider(
            trusted_keys={kid: {"key": self.service_pub_bytes, "algorithm": "Ed25519"}},
            trusted_issuers={"archival_authority"},
            db_manager=self.db,
        )
        candidate_token = provider.mint_service_token(
            principal_id=f"user_{self.user1_id}",
            signing_key=self.service_priv_key,
            key_id=kid,
            issuer="archival_authority",
            scopes=["legacy_migration"],
            algorithm="EdDSA",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(candidate_token)
        self.assertIn("Candidate user", str(ctx.exception))

    # =========================================================================
    # PART 3: VERIFIED ARTIFACT BINDING TESTS (Tests 26 - 31)
    # =========================================================================

    def test_26_valid_service_identity_accepted_by_authenticator(self) -> None:
        """TC-26: Valid token produces genuine AuthenticatedMigrationPrincipal instance."""
        auth_p = self._create_authenticated_principal("migration_operator")
        self.assertEqual(auth_p.principal_id, "migration_operator")
        self.assertTrue(auth_p.is_authenticated)
        self.assertFalse(auth_p.is_revoked)
        self.assertEqual(auth_p.authorization_scope, "legacy_migration")

    def test_27_service_auth_rejects_revoked_principal(self) -> None:
        """TC-27: Revoked service principal is rejected during authentication."""
        # Revoke principal in DB
        self.db.revoke_attesting_principal("revoked_operator", reason="Credential compromise")

        kid = "rev_key"
        provider = ServiceAuthenticationProvider(
            trusted_keys={kid: {"key": self.service_pub_bytes, "algorithm": "Ed25519"}},
            trusted_issuers={"archival_authority"},
            db_manager=self.db,
        )
        token = provider.mint_service_token(
            principal_id="revoked_operator",
            signing_key=self.service_priv_key,
            key_id=kid,
            issuer="archival_authority",
            scopes=["legacy_migration"],
            algorithm="EdDSA",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("has been revoked", str(ctx.exception))

    def test_28_production_requires_bound_principal_in_artifact(self) -> None:
        """TC-28: In production, artifacts missing explicit attesting_principal binding fail closed."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"migration_svc"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            # Artifact WITHOUT bound principal
            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="UNBOUND_01",
                issuer_id="archival_authority",
                key_id="k_ed",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal=None,
            )
            resolver.register_artifact("historical_import_manifest", "UNBOUND_01", raw_bytes)

            auth_p = self._create_authenticated_principal("migration_svc")
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="UNBOUND_01",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=snap,
                    attesting_principal=auth_p,
                )
            self.assertIn("lacks mandatory attesting_principal binding", str(ctx.exception))

    def test_29_mismatched_bound_principal_is_rejected(self) -> None:
        """TC-29: Artifact bound to principal_a cannot be verified by principal_b."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"principal_a", "principal_b"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            # Artifact bound to principal_a
            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="BOUND_A",
                issuer_id="archival_authority",
                key_id="k_ed",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="principal_a",
            )
            resolver.register_artifact("historical_import_manifest", "BOUND_A", raw_bytes)

            auth_b = self._create_authenticated_principal("principal_b")
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="BOUND_A",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=snap,
                    attesting_principal=auth_b,
                )
            self.assertIn("does not match verifying principal", str(ctx.exception))

    def test_30_valid_ed25519_artifact_with_authenticated_identity_accepted(self) -> None:
        """TC-30: Valid Ed25519 signed artifact verified with authentic service principal succeeds."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"authorized_runner"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed_valid", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="VALID_ED_01",
                issuer_id="archival_authority",
                key_id="k_ed_valid",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="authorized_runner",
            )
            resolver.register_artifact("historical_import_manifest", "VALID_ED_01", raw_bytes)

            auth_p = self._create_authenticated_principal("authorized_runner")
            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="VALID_ED_01",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=auth_p,
            )
            self.assertEqual(verified.signature_algorithm, "Ed25519")
            self.assertEqual(verified.attested_by, "authorized_runner")

    def test_31_tampered_signature_or_payload_rejected(self) -> None:
        """TC-31: Corrupted or tampered signature on evidence artifact is strictly rejected."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"authorized_runner"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed_tamper", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            raw_bytes, art_dict = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="TAMPER_01",
                issuer_id="archival_authority",
                key_id="k_ed_tamper",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="authorized_runner",
            )
            # Tamper signature
            tampered_dict = dict(art_dict)
            tampered_dict["signature"] = "00" * 64
            tampered_bytes = json.dumps(tampered_dict).encode("utf-8")
            resolver.register_artifact("historical_import_manifest", "TAMPER_01", tampered_bytes)

            auth_p = self._create_authenticated_principal("authorized_runner")
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="TAMPER_01",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=snap,
                    attesting_principal=auth_p,
                )
            self.assertTrue(
                "signature verification failed" in str(ctx.exception).lower()
                or "cryptographic" in str(ctx.exception).lower()
            )

    # =========================================================================
    # PART 4: ATTESTATION PERSISTENCE & REVOCATION TESTS (Tests 32 - 40)
    # =========================================================================

    def test_32_database_persists_authenticated_principal_identity(self) -> None:
        """TC-32: DatabaseManager records verified evidence with the matching authenticated principal."""
        store = LegacyEvidenceTrustStore(
            trusted_issuers={"archival_authority"},
            trusted_attesting_principals={"persisted_runner"},
            db_manager=self.db,
        )
        store.register_trusted_key("k_pers", b"secret_at_least_32_bytes_long_123!")
        resolver = InMemoryEvidenceResolver()
        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PERS_01",
            issuer_id="archival_authority",
            key_id="k_pers",
            signing_key=b"secret_at_least_32_bytes_long_123!",
            entries=entries,
            attesting_principal="persisted_runner",
        )
        resolver.register_artifact("historical_import_manifest", "PERS_01", raw_bytes)

        auth_p = self._create_authenticated_principal("persisted_runner")
        verified = verifier.verify(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PERS_01",
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
        self.assertEqual(persisted.attested_by, "persisted_runner")

    def test_33_database_rejects_caller_override_in_production(self) -> None:
        """TC-33: Supplying a caller string override to record_legacy_evidence_attestation is rejected in production."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"authorized_runner"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="OVERRIDE_01",
                issuer_id="archival_authority",
                key_id="k_ed",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="authorized_runner",
            )
            resolver.register_artifact("historical_import_manifest", "OVERRIDE_01", raw_bytes)

            auth_p = self._create_authenticated_principal("authorized_runner")
            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="OVERRIDE_01",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=auth_p,
            )

            # Passing raw string override is rejected
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=verified,
                    attesting_principal="authorized_runner",  # Raw string in production!
                    trust_store=store,
                )
            self.assertIn("AuthenticatedMigrationPrincipal context is required", str(ctx.exception))

    def test_34_database_rejects_raw_string_principal_in_production(self) -> None:
        """TC-34: In production, DatabaseManager strictly rejects unauthenticated string principals."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            mock_verified = MagicMock()
            mock_verified.attested_by = "some_string_principal"
            mock_verified.user_id = self.user1_id
            mock_verified.job_description_id = 1
            mock_verified.evidence_type = "historical_import_manifest"
            mock_verified.evidence_reference_id = "REF_X"
            mock_verified.source_snapshot_hash = "snap_x"

            with self.assertRaises(SecurityAuthorizationError):
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=mock_verified,
                    attesting_principal="some_string_principal",
                )

    def test_35_database_rejects_revoked_principal_at_recording_time(self) -> None:
        """TC-35: DatabaseManager verifies principal is not revoked prior to inserting attestation."""
        store = LegacyEvidenceTrustStore(
            trusted_issuers={"archival_authority"},
            trusted_attesting_principals={"late_revoked_runner"},
            db_manager=self.db,
        )
        store.register_trusted_key("k_pers2", b"secret_at_least_32_bytes_long_123!")
        resolver = InMemoryEvidenceResolver()
        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver)

        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="LATE_REV_01",
            issuer_id="archival_authority",
            key_id="k_pers2",
            signing_key=b"secret_at_least_32_bytes_long_123!",
            entries=entries,
            attesting_principal="late_revoked_runner",
        )
        resolver.register_artifact("historical_import_manifest", "LATE_REV_01", raw_bytes)

        auth_p = self._create_authenticated_principal("late_revoked_runner")
        verified = verifier.verify(
            evidence_type="historical_import_manifest",
            evidence_reference_id="LATE_REV_01",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=snap,
            attesting_principal=auth_p,
        )

        # Revoke before recording
        self.db.revoke_attesting_principal("late_revoked_runner", reason="Security incident")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=auth_p,
                trust_store=store,
            )
        self.assertIn("has been revoked", str(ctx.exception))

    def test_36_database_error_during_revocation_check_fails_closed(self) -> None:
        """TC-36: Database error during revocation check fails closed with SecurityAuthorizationError."""
        mock_db = MagicMock()
        mock_db.is_principal_revoked.side_effect = sqlite3.OperationalError("database is locked")

        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"test_runner"},
                db_manager=mock_db,
            )
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                store.is_attesting_principal_trusted("test_runner")
            self.assertIn("Database revocation query failure", str(ctx.exception))

    def test_37_direct_sql_attestation_blocked_by_preflight(self) -> None:
        """TC-37: Direct SQL insertion of legacy exception without valid evidence is blocked by preflight."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        with self.db.immediate_transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, 'historical_import_manifest', 'FAKE_SQL_REF', ?, 'fake_sql_principal')
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
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, '9.1.2.9', 'historical_import_manifest', 'FAKE_SQL_REF', 'forged', 'SUCCESS')
                """,
                (self.user1_id, jd_id, snap),
            )
            cur.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))

        store = LegacyEvidenceTrustStore(trusted_attesting_principals={"fake_sql_principal"}, db_manager=self.db)
        resolver = InMemoryEvidenceResolver()  # Empty: FAKE_SQL_REF does not exist
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

    def test_38_preflight_fails_closed_when_revocation_query_fails(self) -> None:
        """TC-38: Preflight fails closed when database query for revocation throws an exception."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        store = LegacyEvidenceTrustStore(
            trusted_issuers={"archival_authority"},
            trusted_attesting_principals={"reliable_runner"},
            db_manager=self.db,
        )
        store.register_trusted_key("k_pre", b"secret_at_least_32_bytes_long_123!")
        resolver = InMemoryEvidenceResolver()
        set_default_evidence_resolver(resolver)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PRE_REF_01",
            issuer_id="archival_authority",
            key_id="k_pre",
            signing_key=b"secret_at_least_32_bytes_long_123!",
            entries=entries,
            attesting_principal="reliable_runner",
        )
        resolver.register_artifact("historical_import_manifest", "PRE_REF_01", raw_bytes)

        verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)
        auth_p = self._create_authenticated_principal("reliable_runner")
        verified = verifier.verify(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PRE_REF_01",
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
            migration_version="phase_9_1_2_9",
            migration_reason="Verified test evidence",
            evidence_type="historical_import_manifest",
            evidence_reference_id="PRE_REF_01",
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

        # Mock database error during revocation check
        with patch.object(self.db, "is_principal_revoked", side_effect=sqlite3.OperationalError("disk I/O error")):
            with self.assertRaises(SecurityAuthorizationError):
                preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)

    def test_39_revoking_principal_invalidates_existing_records_in_preflight(self) -> None:
        """TC-39: Revoking an attesting principal immediately invalidates previously accepted records in preflight."""
        with patch.dict(os.environ, {"APP_ENV": "production", "SECURITY_SCAN_SIGNING_KEY": "test_scan_key_production_32_bytes_long_1234!!"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"prod_authority"},
                trusted_attesting_principals={"compromised_svc"},
                db_manager=self.db,
            )
            store.register_trusted_key("ed_comp", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="COMP_REF_01",
                issuer_id="prod_authority",
                key_id="ed_comp",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="compromised_svc",
            )
            resolver.register_artifact("historical_import_manifest", "COMP_REF_01", raw_bytes)

            verifier = LegacyEvidenceVerifier(trust_store=store, resolver=resolver, db_manager=self.db)
            auth_p = self._create_authenticated_principal("compromised_svc", issuer="prod_authority")
            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="COMP_REF_01",
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
                migration_version="phase_9_1_2_9",
                migration_reason="Verified Ed25519 evidence",
                evidence_type="historical_import_manifest",
                evidence_reference_id="COMP_REF_01",
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
            # Before revocation: passes
            res = preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
            self.assertTrue(res.is_allowed)

            # Revoke attesting principal
            store.revoke_attesting_principal("compromised_svc", reason="Attester key compromise")

            # After revocation: preflight fails closed
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
            self.assertTrue(
                "revoked" in str(ctx.exception).lower() or "not authorized" in str(ctx.exception).lower()
            )

    def test_40_binary_recovery_restores_usable_status(self) -> None:
        """TC-40: An uploaded JD in REQUIRED state becomes usable when original binary is provided."""
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

        # After binary recovery: preflight succeeds
        res = preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertTrue(res.is_allowed)
        self.assertEqual(res.classification, "CLEAN")

    # =========================================================================
    # PART 5: PRODUCTION NO-PROVIDER GUARANTEE & END-TO-END (Tests 41 - 45)
    # =========================================================================

    def test_41_production_without_service_authenticator_disables_attestation(self) -> None:
        """TC-41: In production, lack of ServiceAuthenticationProvider disables legacy attestation creation."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"prod_authority"},
                trusted_attesting_principals={"some_svc"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            # verifier without service_authenticator
            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=None,
                db_manager=self.db,
            )
            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="REF_NO_AUTH",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=snap,
                    attesting_principal="some_svc",
                )
            self.assertIn("Caller cannot authenticate by supplying an arbitrary allowed string", str(ctx.exception))

    def test_42_production_without_archival_provider_grants_zero_exceptions(self) -> None:
        """TC-42: Production without configured archival authority grants exactly zero legacy exceptions."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            # No keys registered, no issuers registered
            store = LegacyEvidenceTrustStore(db_manager=self.db)
            self.assertEqual(store.algorithm_policy, "production")
            self.assertFalse(store.has_keys())

            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            verifier = LegacyEvidenceVerifier(trust_store=store, db_manager=self.db)

            with self.assertRaises(SecurityAuthorizationError):
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="REF_NONE",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=snap,
                    attesting_principal="any_principal",
                )

    def test_43_unverified_uploaded_job_descriptions_remain_required(self) -> None:
        """TC-43: Unverified uploaded job descriptions remain in REQUIRED binary integrity state."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd_record = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd_record.binary_integrity_state, "REQUIRED")
        self.assertIsNone(jd_record.storage_filename)

        preflight = SecurityPreflightManager(db_manager=self.db)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("missing required binary metadata", str(ctx.exception))

    def test_44_production_environment_contains_zero_synthetic_credentials(self) -> None:
        """TC-44: create_test_authenticated_principal raises SecurityAuthorizationError under production policy."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                create_test_authenticated_principal("test_principal")
            self.assertIn("strictly prohibited", str(ctx.exception))

        with patch.dict(os.environ, {"APP_ENV": "staging"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                create_test_authenticated_principal("test_principal")
            self.assertIn("strictly prohibited", str(ctx.exception))

    def test_45_end_to_end_production_security_lifecycle(self) -> None:
        """TC-45: Complete end-to-end integration test verifying full production security lifecycle.

        1. Configures production environment (Ed25519-only).
        2. Configures ServiceAuthenticationProvider with Ed25519 signing key.
        3. Configures LegacyEvidenceTrustStore with Ed25519 public key.
        4. Issues authentic service credential token.
        5. Authenticates service principal through ServiceAuthenticationProvider.
        6. Verifies valid Ed25519 signed archival evidence.
        7. Records attestation and legacy exception in SQLite.
        8. Confirms SecurityPreflightManager verifies record and allows processing.
        9. Revokes attesting principal and confirms Preflight immediately blocks record.
        10. Confirms uploaded JD without evidence remains REQUIRED.
        """
        with patch.dict(os.environ, {"APP_ENV": "production", "SECURITY_SCAN_SIGNING_KEY": "test_scan_key_production_32_bytes_long_1234!!"}, clear=True):
            # Step 1: Trust store & verifier
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"national_archives"},
                trusted_attesting_principals={"migration_agent_45"},
                db_manager=self.db,
            )
            store.register_trusted_key("ed_root_45", self.pub_bytes, algorithm="Ed25519")
            resolver = InMemoryEvidenceResolver()
            set_default_evidence_resolver(resolver)

            # Step 2: Service authentication provider
            auth_provider = ServiceAuthenticationProvider(
                trusted_keys={"auth_key_45": {"key": self.service_pub_bytes, "algorithm": "Ed25519"}},
                trusted_issuers={"auth_authority_45"},
                expected_audience="legacy_migration",
                db_manager=self.db,
            )
            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=auth_provider,
                db_manager=self.db,
            )

            # Step 3: Create target JD
            jd_id = self._create_sample_jd(self.user1_id)
            snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
            entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

            # Step 4: Issue authentic service token
            service_token = auth_provider.mint_service_token(
                principal_id="migration_agent_45",
                signing_key=self.service_priv_key,
                key_id="auth_key_45",
                issuer="auth_authority_45",
                scopes=["legacy_migration"],
                ttl_seconds=3600,
                algorithm="EdDSA",
            )

            # Step 5: Authenticate service principal
            authenticated_principal = auth_provider.authenticate(service_token)
            self.assertEqual(authenticated_principal.principal_id, "migration_agent_45")

            # Step 6: Create signed Ed25519 evidence artifact and verify
            raw_artifact, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="ARCHIVE_E2E_45",
                issuer_id="national_archives",
                key_id="ed_root_45",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal=authenticated_principal,
            )
            resolver.register_artifact("historical_import_manifest", "ARCHIVE_E2E_45", raw_artifact)

            verified_evidence = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="ARCHIVE_E2E_45",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=authenticated_principal,
            )
            self.assertEqual(verified_evidence.signature_algorithm, "Ed25519")
            self.assertEqual(verified_evidence.attested_by, "migration_agent_45")

            # Step 7: Record attestation and migration exception in SQLite
            att_id = self.db.record_legacy_evidence_attestation(
                verified_evidence=verified_evidence,
                attesting_principal=authenticated_principal,
                trust_store=store,
            )
            self.assertGreater(att_id, 0)

            self.db.record_legacy_integrity_exception(
                user_id=self.user1_id,
                job_description_id=jd_id,
                original_source_type="upload",
                previous_binary_state="REQUIRED",
                assigned_legacy_state="LEGACY_TEXT_ONLY",
                source_snapshot_hash=snap,
                migration_version="phase_9_1_2_9",
                migration_reason="Verified Ed25519 national archive evidence",
                evidence_type="historical_import_manifest",
                evidence_reference_id="ARCHIVE_E2E_45",
                outcome="SUCCESS",
            )
            with self.db.transaction() as conn:
                conn.cursor().execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))

            # Step 8: Preflight checks pass
            preflight = SecurityPreflightManager(
                db_manager=self.db,
                file_validator=self.file_validator,
                detector=self.detector,
                evidence_verifier=verifier,
            )
            preflight_res = preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
            self.assertTrue(preflight_res.is_allowed)
            self.assertEqual(preflight_res.classification, "CLEAN")

            # Step 9: Revoke attesting principal -> immediate preflight failure
            store.revoke_attesting_principal("migration_agent_45", reason="Lifecycle decommissioning")
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
            self.assertTrue(
                "revoked" in str(ctx.exception).lower() or "not authorized" in str(ctx.exception).lower()
            )

            # Step 10: Unverified uploaded JD remains REQUIRED
            unverified_jd_id = self._create_sample_jd(self.user2_id)
            unverified_record = self.db.get_job_description(unverified_jd_id, user_id=self.user2_id)
            self.assertEqual(unverified_record.binary_integrity_state, "REQUIRED")


if __name__ == "__main__":
    unittest.main()

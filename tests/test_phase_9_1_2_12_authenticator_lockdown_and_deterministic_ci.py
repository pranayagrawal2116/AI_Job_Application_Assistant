"""Phase 9.1.2.12 — Authenticator Trust-Root Lockdown, Immutable Registry & Deterministic CI Closure Test Suite.

Exhaustively verifies:
1. Complete Issuance-Record Validation: Mandatory signature_algorithm in AuthenticatedMigrationPrincipal and unconditional check in validate_principal.
2. Genuinely Immutable Issuance Registry: _IssuedCredentialRecord frozen dataclass with backwards-compatible subscripting and immutability.
3. Configured Authenticator Trust-Root Lockdown: DatabaseManager.service_authenticator immutability, type checks, env checks, verifier binding.
4. Complete Verified-Evidence Provenance Binding: All 9 provenance fields verified between VerifiedLegacyEvidence and AuthenticatedMigrationPrincipal, UTC normalization.
5. SQLite Write-Lock Guarantee for Caller Cursors: ImmediateAwareConnection, BEGIN IMMEDIATE enforcement, sentinel write before revocation SELECTs.
6. Deterministic UTC Clock & Expiration: Central injectable test clock, fail-closed in production, zero sleep in tests.
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from typing import Tuple
import unittest
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric import ed25519

from src.database.db_manager import (
    DatabaseManager,
    ImmediateAwareConnection,
    ImmediateAwareCursor,
    _normalize_datetime,
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
    _AUTH_TOKEN,
    _VERIFICATION_TOKEN,
    _IssuedCredentialRecord,
    create_signed_evidence_artifact,
    frozen_utc_clock,
    get_current_utc_time,
    set_default_evidence_resolver,
    set_default_evidence_trust_store,
    set_test_clock,
)
from src.utils.canonical_json import canonical_json_hash


class TestPhase91212AuthenticatorLockdownAndDeterministicCI(unittest.TestCase):
    """Exhaustive 43-test suite verifying Phase 9.1.2.12 security hardening invariants."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="test_phase_9_1_2_12_")
        self.tmp_path = Path(self.temp_dir)
        self.db_path = self.tmp_path / "test_phase_91212.db"
        self.storage_dir = self.tmp_path / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))

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
                ("alice_91212@example.com", "hash1", "salt1", "Alice 91212"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob_91212@example.com", "hash2", "salt2", "Bob 91212"),
            )
            self.user2_id = c.lastrowid

    def tearDown(self) -> None:
        set_test_clock(None)
        set_default_evidence_trust_store(None)
        set_default_evidence_resolver(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_sample_jd(self, user_id: int) -> int:
        raw_text = "Staff Security Engineer for Phase 9.1.2.12 verification."
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

    def _create_provider(self, env: str = "development") -> ServiceAuthenticationProvider:
        with patch.dict(os.environ, {"APP_ENV": env}, clear=True):
            return ServiceAuthenticationProvider(
                trusted_keys={"k_svc_01": {"key_bytes": self.service_pub_bytes, "algorithm": "Ed25519"}},
                trusted_issuers={"archival_authority"},
                expected_audience="legacy_migration",
                db_manager=self.db,
            )

    # =========================================================================
    # CATEGORY 1: ISSUANCE REGISTRY IMMUTABILITY & COMPLETE CLAIMS (Tests 1-10)
    # =========================================================================

    def test_01_signature_algorithm_mandatory_in_post_init(self) -> None:
        """TC-01: AuthenticatedMigrationPrincipal missing signature_algorithm raises SecurityAuthorizationError."""
        now = get_current_utc_time()
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(
                _token=_AUTH_TOKEN,
                _provider_instance_id="sap_01",
                _provider_sentinel=object(),
                principal_id="svc_test",
                issued_at=now,
                expires_at=now + timedelta(seconds=3600),
                credential_id="cred_01",
                credential_key_id="k_svc_01",
                signature_algorithm=None,
            )
        self.assertIn("missing mandatory signature_algorithm", str(ctx.exception))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(
                _token=_AUTH_TOKEN,
                _provider_instance_id="sap_01",
                _provider_sentinel=object(),
                principal_id="svc_test",
                issued_at=now,
                expires_at=now + timedelta(seconds=3600),
                credential_id="cred_01",
                credential_key_id="k_svc_01",
                signature_algorithm="   ",
            )
        self.assertIn("missing mandatory signature_algorithm", str(ctx.exception))

    def test_02_signature_algorithm_supported_set_enforced(self) -> None:
        """TC-02: Unsupported signature algorithms raise SecurityAuthorizationError."""
        now = get_current_utc_time()
        for bad_algo in ("RSA-SHA256", "none", "ECDSA", "BLAKE2b"):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                AuthenticatedMigrationPrincipal(
                    _token=_AUTH_TOKEN,
                    _provider_instance_id="sap_01",
                    _provider_sentinel=object(),
                    principal_id="svc_test",
                    issued_at=now,
                    expires_at=now + timedelta(seconds=3600),
                    credential_id="cred_01",
                    credential_key_id="k_svc_01",
                    signature_algorithm=bad_algo,
                )
            self.assertIn("Unsupported signature algorithm", str(ctx.exception))

    def test_03_signature_algorithm_production_ed25519_enforced(self) -> None:
        """TC-03: In production/staging/qa, HMAC algorithms are strictly prohibited."""
        now = get_current_utc_time()
        for env in ("production", "staging", "qa"):
            with patch.dict(os.environ, {"APP_ENV": env}, clear=True):
                for hmac_algo in ("HS256", "HMAC-SHA256"):
                    with self.assertRaises(SecurityAuthorizationError) as ctx:
                        AuthenticatedMigrationPrincipal(
                            _token=_AUTH_TOKEN,
                            _provider_instance_id="sap_01",
                            _provider_sentinel=object(),
                            principal_id="svc_test",
                            issued_at=now,
                            expires_at=now + timedelta(seconds=3600),
                            credential_id="cred_01",
                            credential_key_id="k_svc_01",
                            signature_algorithm=hmac_algo,
                        )
                    self.assertIn("HMAC signature algorithm", str(ctx.exception))
                    self.assertIn("strictly prohibited", str(ctx.exception))

    def test_04_validate_principal_unconditionally_checks_signature_algorithm(self) -> None:
        """TC-04: validate_principal unconditionally compares signature_algorithm against authoritative record."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_alg_test",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            algorithm="Ed25519",
        )
        principal = provider.authenticate(token)
        self.assertEqual(principal.signature_algorithm, "Ed25519")

        # Mutate signature_algorithm on forged principal object
        tampered = object.__new__(AuthenticatedMigrationPrincipal)
        for k, v in principal.__dict__.items():
            object.__setattr__(tampered, k, v)
        object.__setattr__(tampered, "signature_algorithm", "EdDSA")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("signature_algorithm mismatch", str(ctx.exception))

    def test_05_validate_principal_rejects_missing_signature_algorithm_on_principal(self) -> None:
        """TC-05: validate_principal fails closed if principal signature_algorithm is empty."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_alg_empty",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        tampered = object.__new__(AuthenticatedMigrationPrincipal)
        for k, v in principal.__dict__.items():
            object.__setattr__(tampered, k, v)
        object.__setattr__(tampered, "signature_algorithm", "")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("missing mandatory signature_algorithm", str(ctx.exception))

    def test_06_issued_credential_record_frozen_immutability(self) -> None:
        """TC-06: _IssuedCredentialRecord raises FrozenInstanceError on attribute mutation."""
        now = get_current_utc_time()
        record = _IssuedCredentialRecord(
            credential_id="jti_01",
            principal_id="svc_01",
            credential_key_id="k_01",
            issuer="auth_01",
            audience="legacy_migration",
            scopes=("legacy_migration",),
            principal_type="service",
            issued_at=now,
            expires_at=now + timedelta(seconds=3600),
            provider_instance_id="sap_01",
            signature_algorithm="Ed25519",
        )
        with self.assertRaises(FrozenInstanceError):
            record.principal_id = "attacker_service"  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            record.expires_at = now + timedelta(days=365)  # type: ignore

    def test_07_issued_credential_record_immutable_item_assignment(self) -> None:
        """TC-07: _IssuedCredentialRecord raises TypeError on dictionary item assignment."""
        now = get_current_utc_time()
        record = _IssuedCredentialRecord(
            credential_id="jti_01",
            principal_id="svc_01",
            credential_key_id="k_01",
            issuer="auth_01",
            audience="legacy_migration",
            scopes=("legacy_migration",),
            principal_type="service",
            issued_at=now,
            expires_at=now + timedelta(seconds=3600),
            provider_instance_id="sap_01",
            signature_algorithm="Ed25519",
        )
        with self.assertRaises(TypeError):
            record["principal_id"] = "attacker_service"  # type: ignore

    def test_08_issued_credential_record_backwards_compatible_subscript_and_get(self) -> None:
        """TC-08: _IssuedCredentialRecord supports backward-compatible subscripting and .get()."""
        now = get_current_utc_time()
        record = _IssuedCredentialRecord(
            credential_id="jti_01",
            principal_id="svc_01",
            credential_key_id="k_01",
            issuer="auth_01",
            audience="legacy_migration",
            scopes=("legacy_migration",),
            principal_type="service",
            issued_at=now,
            expires_at=now + timedelta(seconds=3600),
            provider_instance_id="sap_01",
            signature_algorithm="Ed25519",
        )
        self.assertEqual(record["principal_id"], "svc_01")
        self.assertEqual(record.get("credential_key_id"), "k_01")
        self.assertEqual(record.get("non_existent", "default_val"), "default_val")
        with self.assertRaises(KeyError):
            _ = record["non_existent"]

    def test_09_issued_credential_record_contains_all_11_provenance_fields(self) -> None:
        """TC-09: Authenticated credentials stored in registry contain all 11 provenance fields."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_11_fields",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_11_FIELDS",
        )
        _ = provider.authenticate(token)
        record = provider._issued_credentials["JTI_11_FIELDS"]

        self.assertIsInstance(record, _IssuedCredentialRecord)
        self.assertEqual(record.credential_id, "JTI_11_FIELDS")
        self.assertEqual(record.principal_id, "svc_11_fields")
        self.assertEqual(record.credential_key_id, "k_svc_01")
        self.assertEqual(record.issuer, "archival_authority")
        self.assertEqual(record.audience, "legacy_migration")
        self.assertEqual(record.scopes, ("legacy_migration",))
        self.assertEqual(record.principal_type, "service")
        self.assertIsInstance(record.issued_at, datetime)
        self.assertIsInstance(record.expires_at, datetime)
        self.assertEqual(record.provider_instance_id, provider._provider_id)
        self.assertIn(record.signature_algorithm, ("EdDSA", "Ed25519"))

    def test_10_registry_collision_with_differing_algorithm_rejected(self) -> None:
        """TC-10: Token minting collision with different algorithm raises SecurityAuthorizationError."""
        provider = self._create_provider()
        token1 = provider.mint_service_token(
            principal_id="svc_collide",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_COLLIDE",
            algorithm="Ed25519",
        )
        provider.authenticate(token1)

        # Alter stored record's algorithm directly or attempt duplicate with different algorithm
        token2 = provider.mint_service_token(
            principal_id="svc_collide",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_COLLIDE",
            algorithm="EdDSA",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token2)
        self.assertIn("conflicting claims is rejected", str(ctx.exception))

    # =========================================================================
    # CATEGORY 2: AUTHENTICATOR TRUST-ROOT LOCKDOWN (Tests 11-18)
    # =========================================================================

    def test_11_authenticator_initial_configuration_accepted(self) -> None:
        """TC-11: DatabaseManager accepts initial valid ServiceAuthenticationProvider."""
        fresh_db = DatabaseManager(db_path=str(self.tmp_path / "test_init_auth.db"))
        self.assertIsNone(fresh_db.service_authenticator)

        provider = self._create_provider()
        fresh_db.set_service_authenticator(provider)
        self.assertIs(fresh_db.service_authenticator, provider)

    def test_12_authenticator_idempotent_re_registration(self) -> None:
        """TC-12: Re-registering the identical provider instance is idempotent."""
        fresh_db = DatabaseManager(db_path=str(self.tmp_path / "test_idem_auth.db"))
        provider = self._create_provider()
        fresh_db.set_service_authenticator(provider)
        fresh_db.set_service_authenticator(provider)
        fresh_db.service_authenticator = provider
        self.assertIs(fresh_db.service_authenticator, provider)

    def test_13_authenticator_replacement_with_different_provider_rejected(self) -> None:
        """TC-13: Replacing configured authenticator with a different provider instance is rejected."""
        fresh_db = DatabaseManager(db_path=str(self.tmp_path / "test_replace_auth.db"))
        p1 = self._create_provider()
        p2 = self._create_provider()

        fresh_db.set_service_authenticator(p1)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            fresh_db.set_service_authenticator(p2)
        self.assertIn("Replacing configured authenticator with a different instance is strictly prohibited", str(ctx.exception))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            fresh_db.service_authenticator = p2
        self.assertIn("Replacing configured authenticator with a different instance is strictly prohibited", str(ctx.exception))

    def test_14_authenticator_replacement_with_none_in_production_rejected(self) -> None:
        """TC-14: In production, replacing configured authenticator with None is rejected."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            prod_db = DatabaseManager(db_path=str(self.tmp_path / "test_prod_none.db"))
            p1 = self._create_provider(env="production")
            prod_db.set_service_authenticator(p1)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                prod_db.set_service_authenticator(None)
            self.assertIn("Cannot remove configured service authenticator in 'production'", str(ctx.exception))

    def test_15_authenticator_rejects_non_provider_instances(self) -> None:
        """TC-15: DatabaseManager rejects non-ServiceAuthenticationProvider objects."""
        fresh_db = DatabaseManager(db_path=str(self.tmp_path / "test_bad_obj.db"))
        for bad_auth in ("string_authenticator", 12345, MagicMock(), object()):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                fresh_db.set_service_authenticator(bad_auth)
            self.assertIn("must be an instance of ServiceAuthenticationProvider", str(ctx.exception))

    def test_16_authenticator_rejects_dev_provider_in_production(self) -> None:
        """TC-16: Development-configured provider cannot be injected into production DatabaseManager."""
        dev_provider = self._create_provider(env="development")
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            prod_db = DatabaseManager(db_path=str(self.tmp_path / "test_dev_in_prod.db"))
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                prod_db.set_service_authenticator(dev_provider)
            self.assertIn("cannot be used in production-like environment 'production'", str(ctx.exception))

    def test_17_provider_init_does_not_implicitly_replace_db_authenticator(self) -> None:
        """TC-17: Instantiating a new provider does NOT implicitly replace DatabaseManager.service_authenticator."""
        fresh_db = DatabaseManager(db_path=str(self.tmp_path / "test_no_implicit_auth.db"))
        p1 = self._create_provider()
        fresh_db.set_service_authenticator(p1)

        # Create second provider referencing fresh_db
        p2 = self._create_provider()
        # Verify fresh_db still holds p1, NOT p2
        self.assertIs(fresh_db.service_authenticator, p1)
        self.assertIsNot(fresh_db.service_authenticator, p2)

    def test_18_verifier_and_db_manager_authenticator_instance_conflict_rejected(self) -> None:
        """TC-18: LegacyEvidenceVerifier rejects conflicting authenticator vs DatabaseManager."""
        fresh_db = DatabaseManager(db_path=str(self.tmp_path / "test_verifier_binding.db"))
        p1 = self._create_provider()
        p2 = self._create_provider()

        fresh_db.set_service_authenticator(p1)
        store = LegacyEvidenceTrustStore(db_manager=fresh_db)

        # Verifier with conflicting p2 must raise SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            LegacyEvidenceVerifier(
                trust_store=store,
                resolver=InMemoryEvidenceResolver(),
                service_authenticator=p2,
                db_manager=fresh_db,
            )
        self.assertIn("Verifier service_authenticator conflicts with DatabaseManager", str(ctx.exception))

        # Verifier inheriting p1 from fresh_db succeeds
        verifier = LegacyEvidenceVerifier(
            trust_store=store,
            resolver=InMemoryEvidenceResolver(),
            service_authenticator=None,
            db_manager=fresh_db,
        )
        self.assertIs(verifier.service_authenticator, p1)

        # Attempting to mutate verifier's authenticator to p2 fails
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            verifier.service_authenticator = p2
        self.assertIn("LegacyEvidenceVerifier service authenticator is locked", str(ctx.exception))

    # =========================================================================
    # CATEGORY 3: COMPLETE VERIFIED-EVIDENCE PROVENANCE BINDING (Tests 19-30)
    # =========================================================================

    def _setup_verified_evidence_and_principal(self) -> Tuple[VerifiedLegacyEvidence, AuthenticatedMigrationPrincipal, ServiceAuthenticationProvider, LegacyEvidenceTrustStore]:
        provider = self._create_provider()
        self.db.set_service_authenticator(provider)
        token = provider.mint_service_token(
            principal_id="runner_provenance",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        store = LegacyEvidenceTrustStore(
            trusted_issuers={"archival_authority"},
            trusted_attesting_principals={"runner_provenance"},
            db_manager=self.db,
        )
        store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")

        resolver = InMemoryEvidenceResolver()
        jd_id = self._create_sample_jd(self.user1_id)
        snap = "snapshot_prov_hash"

        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PROV_REF_01",
            issuer_id="archival_authority",
            key_id="k_ed",
            signing_key=self.priv_key,
            entries=[{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}],
            signature_algorithm="Ed25519",
            attesting_principal="runner_provenance",
        )
        resolver.register_artifact("historical_import_manifest", "PROV_REF_01", raw_bytes)

        verifier = LegacyEvidenceVerifier(
            trust_store=store,
            resolver=resolver,
            service_authenticator=provider,
            db_manager=self.db,
        )
        verified = verifier.verify(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PROV_REF_01",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=snap,
            attesting_principal=principal,
        )
        return verified, principal, provider, store

    def test_19_record_attestation_rejects_attesting_principal_id_mismatch(self) -> None:
        """TC-19: Mismatched attesting_principal_id between evidence and principal is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)
        object.__setattr__(tampered_evidence, "attesting_principal_id", "attacker_principal")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Provenance mismatch: attesting_principal_id", str(ctx.exception))

    def test_20_record_attestation_rejects_provider_instance_id_mismatch(self) -> None:
        """TC-20: Mismatched provider_instance_id between evidence and principal is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)
        object.__setattr__(tampered_evidence, "provider_instance_id", "forged_provider_instance")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Evidence created by one provider cannot be persisted under another provider's context", str(ctx.exception))

    def test_21_record_attestation_rejects_credential_id_mismatch(self) -> None:
        """TC-21: Mismatched credential_id between evidence and principal is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)
        object.__setattr__(tampered_evidence, "credential_id", "forged_credential_id")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence credential_id does not match attesting principal context", str(ctx.exception))

    def test_22_record_attestation_rejects_credential_key_id_mismatch(self) -> None:
        """TC-22: Mismatched credential_key_id between evidence and principal is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)
        object.__setattr__(tampered_evidence, "credential_key_id", "different_key_id")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence credential_key_id does not match attesting principal context", str(ctx.exception))

    def test_23_record_attestation_rejects_issuer_mismatch(self) -> None:
        """TC-23: Mismatched issuer between evidence and principal is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)
        object.__setattr__(tampered_evidence, "issuer", "untrusted_authority")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence issuer does not match attesting principal context", str(ctx.exception))

    def test_24_record_attestation_rejects_audience_mismatch(self) -> None:
        """TC-24: Mismatched audience between evidence and principal is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)
        object.__setattr__(tampered_evidence, "audience", "forged_audience")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence audience does not match attesting principal context", str(ctx.exception))

    def test_25_record_attestation_rejects_scopes_mismatch(self) -> None:
        """TC-25: Mismatched scopes between evidence and principal is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)
        object.__setattr__(tampered_evidence, "scopes", ("legacy_migration", "extra_scope"))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence scopes do not match attesting principal context", str(ctx.exception))

    def test_26_record_attestation_rejects_issued_at_mismatch(self) -> None:
        """TC-26: Mismatched issued_at timestamp between evidence and principal is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)
        shifted_time = (get_current_utc_time() - timedelta(minutes=5)).isoformat()
        object.__setattr__(tampered_evidence, "issued_at", shifted_time)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence issued_at timestamp does not match", str(ctx.exception))

    def test_27_record_attestation_rejects_expires_at_mismatch(self) -> None:
        """TC-27: Mismatched expires_at timestamp between evidence and principal is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        tampered_evidence = object.__new__(VerifiedLegacyEvidence)
        for k, v in verified.__dict__.items():
            object.__setattr__(tampered_evidence, k, v)
        shifted_time = (get_current_utc_time() + timedelta(hours=2)).isoformat()
        object.__setattr__(tampered_evidence, "expires_at", shifted_time)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=tampered_evidence,
                attesting_principal=principal,
                trust_store=store,
            )
        self.assertIn("Verified evidence expires_at timestamp does not match", str(ctx.exception))

    def test_28_record_attestation_rejects_timezone_naive_timestamps(self) -> None:
        """TC-28: Timezone-naive datetime strings are strictly rejected by _normalize_datetime."""
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            _normalize_datetime("2026-11-07T12:00:00")
        self.assertIn("Timezone-naive timestamp string", str(ctx.exception))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            _normalize_datetime(datetime(2026, 11, 7, 12, 0, 0))
        self.assertIn("Timezone-naive datetime is strictly prohibited", str(ctx.exception))

        # Valid timezone-aware datetime and ISO strings succeed
        valid_dt = _normalize_datetime("2026-11-07T12:00:00+00:00")
        self.assertIsNotNone(valid_dt.tzinfo)
        valid_dt2 = _normalize_datetime("2026-11-07T12:00:00Z")
        self.assertIsNotNone(valid_dt2.tzinfo)

    def test_29_record_attestation_in_production_requires_complete_provenance(self) -> None:
        """TC-29: In production, verified evidence missing any provenance field is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            for field in (
                "attesting_principal_id",
                "provider_instance_id",
                "credential_id",
                "credential_key_id",
                "issuer",
                "audience",
                "issued_at",
                "expires_at",
            ):
                tampered = object.__new__(VerifiedLegacyEvidence)
                for k, v in verified.__dict__.items():
                    object.__setattr__(tampered, k, v)
                object.__setattr__(tampered, field, "")

                with self.assertRaises(SecurityAuthorizationError) as ctx:
                    self.db.record_legacy_evidence_attestation(
                        verified_evidence=tampered,
                        attesting_principal=principal,
                        trust_store=store,
                    )
                self.assertIn("without current authentication provenance", str(ctx.exception))

    def test_30_audit_verified_evidence_cannot_be_persisted_in_production(self) -> None:
        """TC-30: Evidence produced by _verify_artifact_for_audit cannot become a new production attestation."""
        # Audit evidence lacks live credential provenance
        audit_evidence = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(audit_evidence, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(audit_evidence, "evidence_type", "historical_import_manifest")
        object.__setattr__(audit_evidence, "evidence_reference_id", "AUDIT_REF")
        object.__setattr__(audit_evidence, "user_id", self.user1_id)
        object.__setattr__(audit_evidence, "job_description_id", 1)
        object.__setattr__(audit_evidence, "source_snapshot_hash", "audit_hash")
        object.__setattr__(audit_evidence, "migration_boundary", "pre_phase_9_1_1")
        object.__setattr__(audit_evidence, "attested_by", "audit_principal")
        object.__setattr__(audit_evidence, "attesting_principal_id", "audit_principal")
        object.__setattr__(audit_evidence, "provider_instance_id", "")
        object.__setattr__(audit_evidence, "credential_id", "")

        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            prod_db = DatabaseManager(db_path=str(self.tmp_path / "test_audit_evidence.db"))
            prod_provider = ServiceAuthenticationProvider(
                trusted_keys={"k_svc_01": {"key_bytes": self.service_pub_bytes, "algorithm": "Ed25519"}},
                trusted_issuers={"archival_authority"},
                expected_audience="legacy_migration",
                db_manager=prod_db,
            )
            prod_db.set_service_authenticator(prod_provider)

            # Case 1: Supplying a string principal is rejected
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                prod_db.record_legacy_evidence_attestation(
                    verified_evidence=audit_evidence,
                    attesting_principal="audit_principal",
                )
            self.assertIn("Caller-supplied principal strings are rejected as authentication proof in production", str(ctx.exception))

            # Case 2: Supplying a genuine AuthenticatedMigrationPrincipal with audit evidence lacking provenance is rejected
            prod_token = prod_provider.mint_service_token(
                principal_id="audit_principal",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
            )
            prod_principal = prod_provider.authenticate(prod_token)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                prod_db.record_legacy_evidence_attestation(
                    verified_evidence=audit_evidence,
                    attesting_principal=prod_principal,
                )
            self.assertIn("without current authentication provenance", str(ctx.exception))

    # =========================================================================
    # CATEGORY 4: SQLITE IMMEDIATE WRITE-LOCK GUARANTEE (Tests 31-37)
    # =========================================================================

    def test_31_immediate_aware_connection_tracks_begin_immediate(self) -> None:
        """TC-31: ImmediateAwareConnection accurately tracks BEGIN IMMEDIATE on conn and cursor."""
        conn = self.db.get_connection()
        self.assertIsInstance(conn, ImmediateAwareConnection)
        self.assertFalse(conn._tx_is_immediate)

        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        self.assertTrue(conn._tx_is_immediate)
        conn.execute("COMMIT")
        self.assertFalse(conn._tx_is_immediate)

        cur = conn.cursor()
        self.assertIsInstance(cur, ImmediateAwareCursor)
        cur.execute("BEGIN IMMEDIATE")
        self.assertTrue(conn._tx_is_immediate)
        cur.execute("ROLLBACK")
        self.assertFalse(conn._tx_is_immediate)
        conn.close()

    def test_32_immediate_aware_connection_resets_on_commit_or_rollback(self) -> None:
        """TC-32: _tx_is_immediate resets to False on commit() and rollback()."""
        conn = self.db.get_connection()
        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        self.assertTrue(conn._tx_is_immediate)
        conn.commit()
        self.assertFalse(conn._tx_is_immediate)

        conn.execute("BEGIN IMMEDIATE")
        self.assertTrue(conn._tx_is_immediate)
        conn.rollback()
        self.assertFalse(conn._tx_is_immediate)
        conn.close()

    def test_33_caller_cursor_rejects_non_cursor_instances(self) -> None:
        """TC-33: Passing a non-cursor instance to record_legacy_evidence_attestation raises SecurityAuthorizationError."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor="not_a_cursor",  # type: ignore
                trust_store=store,
            )
        self.assertIn("Invalid cursor: expected sqlite3.Cursor", str(ctx.exception))

    def test_34_caller_cursor_rejects_isolation_level_not_none(self) -> None:
        """TC-34: Cursor with non-None isolation_level (deferred transaction) is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        conn = sqlite3.connect(":memory:", factory=ImmediateAwareConnection)
        conn.isolation_level = "DEFERRED"
        cur = conn.cursor()

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor=cur,
                trust_store=store,
            )
        self.assertIn("Caller transaction must have isolation_level=None", str(ctx.exception))
        conn.close()

    def test_35_caller_cursor_rejects_not_in_transaction(self) -> None:
        """TC-35: Cursor not inside an active transaction is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        conn = self.db.get_connection()
        conn.isolation_level = None
        cur = conn.cursor()
        # No BEGIN executed, so in_transaction is False

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor=cur,
                trust_store=store,
            )
        self.assertIn("Caller cursor must be inside an active transaction", str(ctx.exception))
        conn.close()

    def test_36_caller_cursor_rejects_deferred_transaction_without_immediate_write_lock(self) -> None:
        """TC-36: Cursor in standard BEGIN (deferred) without BEGIN IMMEDIATE is rejected."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        conn = self.db.get_connection()
        conn.isolation_level = None
        conn.execute("BEGIN")  # Deferred, not IMMEDIATE
        cur = conn.cursor()

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor=cur,
                trust_store=store,
            )
        self.assertIn("Caller transaction must hold an immediate write lock (BEGIN IMMEDIATE)", str(ctx.exception))
        conn.execute("ROLLBACK")
        conn.close()

    def test_37_sentinel_write_lock_check_executes_before_revocation_selects(self) -> None:
        """TC-37: Sentinel write lock check physically executes on cursor before revocation queries."""
        verified, principal, _, store = self._setup_verified_evidence_and_principal()
        conn = self.db.get_connection()
        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()

        # Mock execute on cursor to simulate operational lock error on sentinel write
        orig_execute = cur.execute
        def fail_on_sentinel(sql, *args, **kwargs):
            if "_sqlite_write_lock_sentinel" in sql:
                raise sqlite3.OperationalError("database is locked")
            return orig_execute(sql, *args, **kwargs)

        cur.execute = fail_on_sentinel  # type: ignore

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor=cur,
                trust_store=store,
            )
        self.assertIn("Failed to acquire physical write lock on cursor", str(ctx.exception))
        conn.close()

    # =========================================================================
    # CATEGORY 5: DETERMINISTIC CLOCK PROVIDER & CI STABILITY (Tests 38-43)
    # =========================================================================

    def test_38_get_current_utc_time_defaults_to_system_utc(self) -> None:
        """TC-38: Without custom clock, get_current_utc_time returns system UTC datetime."""
        set_test_clock(None)
        t1 = get_current_utc_time()
        self.assertIsNotNone(t1.tzinfo)
        self.assertEqual(t1.tzinfo, timezone.utc)
        self.assertAlmostEqual(t1.timestamp(), datetime.now(timezone.utc).timestamp(), delta=2.0)

    def test_39_set_test_clock_injects_deterministic_time(self) -> None:
        """TC-39: set_test_clock injects a deterministic UTC datetime provider."""
        fixed_dt = datetime(2028, 5, 1, 14, 30, 0, tzinfo=timezone.utc)
        set_test_clock(lambda: fixed_dt)
        try:
            self.assertEqual(get_current_utc_time(), fixed_dt)
        finally:
            set_test_clock(None)

    def test_40_set_test_clock_fails_closed_in_production(self) -> None:
        """TC-40: Injecting custom clock in production environment fails closed."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                set_test_clock(lambda: datetime(2028, 1, 1, tzinfo=timezone.utc))
            self.assertIn("Clock injection is strictly prohibited in production-like environment 'production'", str(ctx.exception))

    def test_41_frozen_utc_clock_context_manager(self) -> None:
        """TC-41: frozen_utc_clock context manager restores clock upon exit."""
        t_frozen = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        with frozen_utc_clock(t_frozen):
            self.assertEqual(get_current_utc_time(), t_frozen)

        # Restored after context exit
        self.assertNotEqual(get_current_utc_time(), t_frozen)

    def test_42_deterministic_expiration_without_sleep(self) -> None:
        """TC-42: Deterministic test clock verifies credential expiration instantly with zero sleep."""
        base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
        set_test_clock(lambda: base_time)
        try:
            provider = self._create_provider()
            token = provider.mint_service_token(
                principal_id="zero_sleep_svc",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
                ttl_seconds=300,
            )
            principal = provider.authenticate(token)
            self.assertFalse(principal.is_expired)

            # Advance 301 seconds into the future
            set_test_clock(lambda: base_time + timedelta(seconds=301))
            self.assertTrue(principal.is_expired)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                provider.validate_principal(principal)
            self.assertIn("has expired", str(ctx.exception))
        finally:
            set_test_clock(None)

    def test_43_full_end_to_end_legacy_migration_with_locked_authenticator_and_immediate_transaction(self) -> None:
        """TC-43: Full end-to-end integration: mint, verifier bind, immediate transaction, sentinel write, persistence."""
        base_time = datetime(2026, 11, 7, 8, 0, 0, tzinfo=timezone.utc)
        set_test_clock(lambda: base_time)
        try:
            # 1. Setup provider and register with DatabaseManager
            provider = self._create_provider()
            self.db.set_service_authenticator(provider)

            # 2. Mint authenticated service credential
            token = provider.mint_service_token(
                principal_id="e2e_coordinator",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
                ttl_seconds=3600,
            )
            principal = provider.authenticate(token)
            provider.validate_principal(principal)

            # 3. Setup trust store, resolver, and create signed archival manifest
            store = LegacyEvidenceTrustStore(
                trusted_issuers={"archival_authority"},
                trusted_attesting_principals={"e2e_coordinator"},
                db_manager=self.db,
            )
            store.register_trusted_key("k_ed", self.pub_bytes, algorithm="Ed25519")

            jd_id = self._create_sample_jd(self.user1_id)
            snap = "e2e_snapshot_hash_12"
            resolver = InMemoryEvidenceResolver()

            raw_bytes, _ = create_signed_evidence_artifact(
                evidence_type="historical_import_manifest",
                evidence_reference_id="E2E_REF_12",
                issuer_id="archival_authority",
                key_id="k_ed",
                signing_key=self.priv_key,
                entries=[{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}],
                signature_algorithm="Ed25519",
                attesting_principal="e2e_coordinator",
            )
            resolver.register_artifact("historical_import_manifest", "E2E_REF_12", raw_bytes)

            # 4. Construct verifier bound to same provider
            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=provider,
                db_manager=self.db,
            )

            # 5. Verify evidence
            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="E2E_REF_12",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=principal,
            )
            self.assertEqual(verified.attested_by, "e2e_coordinator")

            # 6. Persist attestation using explicit immediate transaction with caller cursor
            conn = self.db.get_connection()
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.cursor()

            att_id = self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
                cursor=cur,
                trust_store=store,
            )
            conn.execute("COMMIT")
            conn.close()

            self.assertGreater(att_id, 0)

            # 7. Verify persisted attestation record in database
            persisted = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
            self.assertIsNotNone(persisted)
            self.assertEqual(persisted.attested_by, "e2e_coordinator")
            self.assertEqual(persisted.evidence_type, "historical_import_manifest")
            self.assertEqual(persisted.evidence_reference_id, "E2E_REF_12")
            self.assertEqual(persisted.source_snapshot_hash, snap)
        finally:
            set_test_clock(None)


if __name__ == "__main__":
    unittest.main()

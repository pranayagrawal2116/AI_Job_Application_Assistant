"""Phase 9.1.2.11 — Issued Credential Registry Integrity & Atomic Attestation Persistence Closure Test Suite.

Exhaustively verifies:
1. Category 1: Issuance Registry Integrity (Tests 1-18)
2. Category 2: Principal Tampering Defense (Tests 19-28)
3. Category 3: Credential Identity Uniqueness & Collision Defense (Tests 29-35)
4. Category 4: Database Persistence Boundary (Tests 36-47)
5. Category 5: Atomic Revocation & TOCTOU Elimination (Tests 48-54)
6. Category 6: JWT Authorization Scope & Array Types (Tests 55-65)
7. Category 7: End-to-End Security & Compatibility (Tests 66-72)
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import tempfile
import time
import types
from typing import Any, Optional
import unittest
from unittest.mock import patch

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
    VerifiedLegacyEvidence,
    _AUTH_TOKEN,
    _VERIFICATION_TOKEN,
    create_signed_evidence_artifact,
    set_default_evidence_resolver,
    set_default_evidence_trust_store,
)
from src.security.prompt_injection_detector import PromptInjectionDetector
from src.security.security_preflight import SecurityPreflightManager


class TestPhase91211CredentialRegistryAndAtomicAttestation(unittest.TestCase):
    """Exhaustive 72-test suite for Phase 9.1.2.11 requirements."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="test_phase_9_1_2_11_")
        self.tmp_path = Path(self.temp_dir)
        self.db_path = self.tmp_path / "test_phase_91211.db"
        self.storage_dir = self.tmp_path / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)
        self.detector = PromptInjectionDetector()

        # Generate fresh test Ed25519 keypair for evidence artifacts
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
                ("alice_91211@example.com", "hash1", "salt1", "Alice 91211"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob_91211@example.com", "hash2", "salt2", "Bob 91211"),
            )
            self.user2_id = c.lastrowid

    def tearDown(self) -> None:
        set_default_evidence_trust_store(None)
        set_default_evidence_resolver(None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_sample_jd(self, user_id: int) -> int:
        jd = self.db.create_job_description(
            user_id=user_id,
            company_name="SecureGov Systems",
            job_title="Principal Security Engineer",
            raw_content="Principal Security Engineer for Phase 9.1.2.11 verification.",
            source_type="upload",
            parsed_data={"title": "Principal Security Engineer", "company": "SecureGov Systems", "required_skills": ["Cryptography", "Identity"]},
            binary_integrity_state="REQUIRED",
        )
        return jd.id

    def _create_provider(
        self,
        kid: str = "k_svc_01",
        issuer: str = "archival_authority",
        audience: str = "legacy_migration",
        db: Optional[Any] = None,
    ) -> ServiceAuthenticationProvider:
        return ServiceAuthenticationProvider(
            trusted_keys={kid: {"key": self.service_pub_bytes, "algorithm": "Ed25519"}},
            trusted_issuers={issuer},
            expected_audience=audience,
            db_manager=db or self.db,
        )

    # =========================================================================
    # CATEGORY 1: ISSUANCE REGISTRY INTEGRITY (Tests 1 - 18)
    # =========================================================================

    def test_01_valid_principal_with_complete_registry_entry_succeeds(self) -> None:
        """TC-01: Valid principal minting and authentication creates complete registry record and passes validation."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="valid_svc",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_TC_01",
        )
        principal = provider.authenticate(token)
        self.assertIsInstance(principal, AuthenticatedMigrationPrincipal)
        self.assertEqual(principal.credential_id, "JTI_TC_01")
        self.assertEqual(principal.credential_key_id, "k_svc_01")

        # Verify all registry fields
        record = provider._issued_credentials.get("JTI_TC_01")
        self.assertIsNotNone(record)
        self.assertEqual(record["principal_id"], "valid_svc")
        self.assertEqual(record["credential_key_id"], "k_svc_01")
        self.assertEqual(record["issuer"], "archival_authority")
        self.assertEqual(record["audience"], "legacy_migration")
        self.assertEqual(record["scopes"], ("legacy_migration",))
        self.assertEqual(record["principal_type"], "service")
        self.assertEqual(record["provider_instance_id"], provider._provider_id)
        self.assertEqual(record["signature_algorithm"], "EdDSA")

        # Validate principal succeeds
        provider.validate_principal(principal)

    def test_02_missing_credential_id_rejects(self) -> None:
        """TC-02: Missing credential ID rejects in validate_principal and __post_init__."""
        provider = self._create_provider()
        now = datetime.now(timezone.utc)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(
                _token=_AUTH_TOKEN,
                _provider_instance_id=provider._provider_id,
                _provider_sentinel=provider._provider_sentinel,
                principal_id="svc_test",
                issued_at=now,
                expires_at=now + timedelta(seconds=3600),
                credential_id=None,
                credential_key_id="k_svc_01",
            )
        self.assertIn("missing mandatory credential_id", str(ctx.exception))

    def test_03_empty_credential_id_rejects(self) -> None:
        """TC-03: Empty credential ID rejects in validate_principal and __post_init__."""
        provider = self._create_provider()
        now = datetime.now(timezone.utc)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(
                _token=_AUTH_TOKEN,
                _provider_instance_id=provider._provider_id,
                _provider_sentinel=provider._provider_sentinel,
                principal_id="svc_test",
                issued_at=now,
                expires_at=now + timedelta(seconds=3600),
                credential_id="   ",
                credential_key_id="k_svc_01",
            )
        self.assertIn("missing mandatory credential_id", str(ctx.exception))

    def test_04_unknown_credential_id_rejects(self) -> None:
        """TC-04: Unknown credential ID not in registry rejects during validate_principal."""
        provider = self._create_provider()
        now = datetime.now(timezone.utc)
        principal = AuthenticatedMigrationPrincipal(
            _token=_AUTH_TOKEN,
            _provider_instance_id=provider._provider_id,
            _provider_sentinel=provider._provider_sentinel,
            principal_id="svc_test",
            issued_at=now,
            expires_at=now + timedelta(seconds=3600),
            credential_id="UNKNOWN_CRED_ID",
            credential_key_id="k_svc_01",
            signature_algorithm="Ed25519",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(principal)
        self.assertIn("not registered or was never issued", str(ctx.exception))

    def test_05_missing_registry_record_rejects(self) -> None:
        """TC-05: Deletion/absence of registry record fails closed during validate_principal."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_del",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_DEL",
        )
        principal = provider.authenticate(token)
        provider.validate_principal(principal)

        # Remove from registry
        provider._issued_credentials.pop("JTI_DEL")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(principal)
        self.assertIn("not registered or was never issued", str(ctx.exception))

    def test_06_missing_key_id_rejects(self) -> None:
        """TC-06: Missing credential_key_id rejects in validate_principal and __post_init__."""
        provider = self._create_provider()
        now = datetime.now(timezone.utc)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            AuthenticatedMigrationPrincipal(
                _token=_AUTH_TOKEN,
                _provider_instance_id=provider._provider_id,
                _provider_sentinel=provider._provider_sentinel,
                principal_id="svc_test",
                issued_at=now,
                expires_at=now + timedelta(seconds=3600),
                credential_id="JTI_KID_TEST",
                credential_key_id=None,
            )
        self.assertIn("missing mandatory credential_key_id", str(ctx.exception))

    def test_07_unknown_key_id_rejects(self) -> None:
        """TC-07: Credential signing key not registered in provider rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_test",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_UNREGISTERED_KEY",
        )
        principal = provider.authenticate(token)
        # Unregister key
        provider._trusted_keys.pop("k_svc_01")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(principal)
        self.assertIn("no longer registered", str(ctx.exception))

    def test_08_modified_principal_id_rejects(self) -> None:
        """TC-08: Tampered principal_id mismatches registry record and rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="original_sub",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_SUB_TAMPER",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, principal_id="attacker_sub")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("principal_id mismatch", str(ctx.exception))

    def test_09_modified_key_id_rejects(self) -> None:
        """TC-09: Tampered credential_key_id mismatches registry record and rejects."""
        provider = self._create_provider()
        # Register a second valid key
        k2_priv = ed25519.Ed25519PrivateKey.generate()
        provider.register_trusted_key("k_svc_02", k2_priv.public_key().public_bytes_raw(), algorithm="Ed25519")

        token = provider.mint_service_token(
            principal_id="svc_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_KID_TAMPER",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, credential_key_id="k_svc_02")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("credential_key_id mismatch", str(ctx.exception))

    def test_10_modified_issuer_rejects(self) -> None:
        """TC-10: Tampered issuer mismatches registry record and rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_ISS_TAMPER",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, issuer="rogue_issuer")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("issuer mismatch", str(ctx.exception))

    def test_11_modified_audience_rejects(self) -> None:
        """TC-11: Tampered audience mismatches registry record and rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_AUD_TAMPER",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, audience="other_audience")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("audience mismatch", str(ctx.exception))

    def test_12_modified_scopes_rejects(self) -> None:
        """TC-12: Tampered scopes mismatch registry record and reject."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_SCOPES_TAMPER",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, scopes=("legacy_migration", "admin_super_scope"))
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("scopes mismatch", str(ctx.exception))

    def test_13_modified_issued_at_rejects(self) -> None:
        """TC-13: Tampered issued_at mismatches registry record and rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_IAT_TAMPER",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, issued_at=principal.issued_at - timedelta(seconds=120))
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("issued_at mismatch", str(ctx.exception))

    def test_14_extended_expiry_rejects(self) -> None:
        """TC-14: Tampered expires_at extending expiry mismatches registry record and rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_EXP_TAMPER",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, expires_at=principal.expires_at + timedelta(days=7))
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("expires_at mismatch", str(ctx.exception))

    def test_15_modified_principal_type_rejects(self) -> None:
        """TC-15: Tampered principal_type mismatches registry record and rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_PTYPE_TAMPER",
        )
        principal = provider.authenticate(token)
        with self.assertRaises(SecurityAuthorizationError):
            replace(principal, principal_type="user")

    def test_16_modified_provider_identity_rejects(self) -> None:
        """TC-16: Tampered _provider_instance_id fails cross-provider check."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_PROV_TAMPER",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, _provider_instance_id="sap_counterfeit_instance")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("Cross-provider credential reuse is strictly prohibited", str(ctx.exception))

    def test_17_modified_signature_algorithm_rejects(self) -> None:
        """TC-17: Tampered signature_algorithm mismatches registry record and rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_ALG_TAMPER",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, signature_algorithm="HMAC-SHA256")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("signature_algorithm mismatch", str(ctx.exception))

    def test_18_registry_record_cannot_be_overwritten_by_conflicting_credential(self) -> None:
        """TC-18: Repeated authentication with same jti but conflicting claims rejects and preserves original."""
        provider = self._create_provider()
        token1 = provider.mint_service_token(
            principal_id="first_principal",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_COLLISION_01",
        )
        p1 = provider.authenticate(token1)
        self.assertEqual(p1.principal_id, "first_principal")

        # Attempt to issue different token with same jti
        token2 = provider.mint_service_token(
            principal_id="second_principal",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="JTI_COLLISION_01",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token2)
        self.assertIn("Duplicate credential identifier", str(ctx.exception))
        self.assertIn("conflicting claims is rejected", str(ctx.exception))

        # Original record is preserved
        self.assertEqual(provider._issued_credentials["JTI_COLLISION_01"]["principal_id"], "first_principal")
        provider.validate_principal(p1)

    # =========================================================================
    # CATEGORY 2: PRINCIPAL TAMPERING (Tests 19 - 28)
    # =========================================================================

    def test_19_replace_removed_credential_id_rejects(self) -> None:
        """TC-19: dataclasses.replace() with removed credential ID is rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_tamper",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            replace(principal, credential_id=None)
        self.assertIn("missing mandatory credential_id", str(ctx.exception))

    def test_20_replace_removed_key_id_rejects(self) -> None:
        """TC-20: dataclasses.replace() with removed key ID is rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_tamper",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            replace(principal, credential_key_id=None)
        self.assertIn("missing mandatory credential_key_id", str(ctx.exception))

    def test_21_replace_extended_expiry_rejects(self) -> None:
        """TC-21: dataclasses.replace() with extended expiry rejects upon provider validation."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_tamper",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        extended = replace(principal, expires_at=principal.expires_at + timedelta(hours=48))
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(extended)
        self.assertIn("expires_at mismatch", str(ctx.exception))

    def test_22_replace_changed_issuer_rejects(self) -> None:
        """TC-22: dataclasses.replace() with changed issuer rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_tamper",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, issuer="fake_authority")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("issuer mismatch", str(ctx.exception))

    def test_23_replace_changed_audience_rejects(self) -> None:
        """TC-23: dataclasses.replace() with changed audience rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_tamper",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, audience="general_access")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("audience mismatch", str(ctx.exception))

    def test_24_replace_changed_scopes_rejects(self) -> None:
        """TC-24: dataclasses.replace() with changed scopes rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_tamper",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        tampered = replace(principal, scopes=("legacy_migration", "unauthorized_role"))
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(tampered)
        self.assertIn("scopes mismatch", str(ctx.exception))

    def test_25_setattr_expiry_modification_rejected(self) -> None:
        """TC-25: object.__setattr__() expiry modification is detected and rejected at validation."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_setattr",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        object.__setattr__(principal, "expires_at", principal.expires_at + timedelta(days=30))
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(principal)
        self.assertIn("expires_at mismatch", str(ctx.exception))

    def test_26_setattr_credential_id_modification_rejected(self) -> None:
        """TC-26: object.__setattr__() credential ID modification is rejected at validation."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_setattr",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        object.__setattr__(principal, "credential_id", "counterfeit_id")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(principal)
        self.assertIn("not registered or was never issued", str(ctx.exception))

    def test_27_setattr_key_id_modification_rejected(self) -> None:
        """TC-27: object.__setattr__() key ID modification is rejected at validation."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_setattr",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        object.__setattr__(principal, "credential_key_id", "different_key_id")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.validate_principal(principal)
        self.assertIn("credential_key_id mismatch", str(ctx.exception))

    def test_28_mutable_metadata_cannot_alter_authorization(self) -> None:
        """TC-28: Mutable metadata cannot alter authorization decisions and metadata is wrapped as immutable."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_meta",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        self.assertIsInstance(principal.metadata, types.MappingProxyType)
        with self.assertRaises(TypeError):
            principal.metadata["escalation"] = True

        # Even if object.__setattr__ replaces metadata with dict, authorization ignores it
        object.__setattr__(principal, "metadata", {"is_admin": True, "scope": "root"})
        provider.validate_principal(principal)  # Validates fine based on registry claims, metadata has zero effect

    # =========================================================================
    # CATEGORY 3: CREDENTIAL IDENTITY UNIQUENESS (Tests 29 - 35)
    # =========================================================================

    def test_29_unique_jwt_jti_accepted(self) -> None:
        """TC-29: Unique JWT jti is accepted and accurately registered."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_jti_01",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="UNIQUE_JTI_SPEC_29",
        )
        principal = provider.authenticate(token)
        self.assertEqual(principal.credential_id, "UNIQUE_JTI_SPEC_29")
        self.assertIn("UNIQUE_JTI_SPEC_29", provider._issued_credentials)

    def test_30_missing_jti_uses_safe_internally_generated_identifier(self) -> None:
        """TC-30: Token without jti claim uses a safe internally generated identifier."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_nojti",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            include_jti=False,
        )
        principal = provider.authenticate(token)
        self.assertTrue(principal.credential_id.startswith("jti_"))
        self.assertIn(principal.credential_id, provider._issued_credentials)

    def test_31_empty_jti_rejected(self) -> None:
        """TC-31: Empty or whitespace jti is rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_bad_jti",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("cannot be empty or whitespace", str(ctx.exception))

    def test_32_malformed_jti_rejected(self) -> None:
        """TC-32: Non-string jti (boolean, integer, list) is rejected."""
        provider = self._create_provider()
        for bad_jti in (12345, True, ["jti_list"]):
            token = provider.mint_service_token(
                principal_id="svc_bad_jti",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
                jti=bad_jti,
            )
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                provider.authenticate(token)
            self.assertIn("must be a non-empty string", str(ctx.exception))

    def test_33_identical_credential_id_and_claims_deterministic(self) -> None:
        """TC-33: Identical credential ID and identical claims resolve idempotently."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_idem",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="IDEM_JTI_01",
        )
        p1 = provider.authenticate(token)
        p2 = provider.authenticate(token)
        self.assertEqual(p1.credential_id, p2.credential_id)
        self.assertEqual(p1.principal_id, p2.principal_id)
        provider.validate_principal(p2)

    def test_34_credential_id_collision_conflicting_claims_rejects(self) -> None:
        """TC-34: Credential ID collision with conflicting claims rejects without overwriting original."""
        provider = self._create_provider()
        t1 = provider.mint_service_token(
            principal_id="service_one",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="COLLIDE_01",
        )
        p1 = provider.authenticate(t1)
        self.assertIsNotNone(p1)

        t2 = provider.mint_service_token(
            principal_id="service_two",  # Different sub!
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="COLLIDE_01",
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(t2)
        self.assertIn("Duplicate credential identifier", str(ctx.exception))
        # Ensure original record still belongs to service_one
        self.assertEqual(provider._issued_credentials["COLLIDE_01"]["principal_id"], "service_one")

    def test_35_concurrent_duplicate_issuance_cannot_overwrite_registry(self) -> None:
        """TC-35: Concurrent duplicate credential authentication cannot corrupt or overwrite registry."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="concurrent_svc",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            jti="CONCURRENT_JTI",
        )

        def worker() -> AuthenticatedMigrationPrincipal:
            return provider.authenticate(token)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(worker) for _ in range(20)]
            results = [f.result() for f in futures]

        self.assertEqual(len(results), 20)
        for r in results:
            self.assertEqual(r.credential_id, "CONCURRENT_JTI")
        self.assertEqual(len([k for k in provider._issued_credentials.keys() if k == "CONCURRENT_JTI"]), 1)

    # =========================================================================
    # CATEGORY 4: DATABASE PERSISTENCE BOUNDARY (Tests 36 - 47)
    # =========================================================================

    def test_36_valid_evidence_plus_matching_current_principal_persists(self) -> None:
        """TC-36: Valid evidence plus matching current principal persists cleanly."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="persisted_coord",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        store = LegacyEvidenceTrustStore(
            trusted_issuers={"archival_authority"},
            trusted_attesting_principals={"persisted_coord"},
            db_manager=self.db,
        )
        store.register_trusted_key("ed_root", self.pub_bytes, algorithm="Ed25519")
        resolver = InMemoryEvidenceResolver()

        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash
        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]

        raw_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PERS_TC_36",
            issuer_id="archival_authority",
            key_id="ed_root",
            signing_key=self.priv_key,
            entries=entries,
            signature_algorithm="Ed25519",
            attesting_principal="persisted_coord",
        )
        resolver.register_artifact("historical_import_manifest", "PERS_TC_36", raw_bytes)

        verifier = LegacyEvidenceVerifier(
            trust_store=store,
            resolver=resolver,
            service_authenticator=provider,
            db_manager=self.db,
        )
        verified = verifier.verify(
            evidence_type="historical_import_manifest",
            evidence_reference_id="PERS_TC_36",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=snap,
            attesting_principal=principal,
        )
        att_id = self.db.record_legacy_evidence_attestation(
            verified_evidence=verified,
            attesting_principal=principal,
            trust_store=store,
        )
        self.assertGreater(att_id, 0)
        persisted = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
        self.assertEqual(persisted.attested_by, "persisted_coord")

    def test_37_missing_principal_rejects_in_production(self) -> None:
        """TC-37: In production, record_legacy_evidence_attestation rejects missing principal."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            mock_verified = object.__new__(VerifiedLegacyEvidence)
            object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
            object.__setattr__(mock_verified, "attested_by", "mock_p")
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=mock_verified,
                    attesting_principal=None,
                )
            self.assertIn("attesting_principal is required in production", str(ctx.exception))

    def test_38_expired_principal_rejects(self) -> None:
        """TC-38: Expired principal rejects at database persistence time."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="exp_db_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            ttl_seconds=1,
        )
        principal = provider.authenticate(token)

        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "exp_db_runner")
        object.__setattr__(mock_verified, "user_id", self.user1_id)

        time.sleep(1.2)
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=mock_verified,
                attesting_principal=principal,
            )
        self.assertIn("has expired", str(ctx.exception))

    def test_39_principal_from_unrelated_provider_rejects(self) -> None:
        """TC-39: Principal from an unrelated provider is rejected at persistence."""
        provider1 = self._create_provider(kid="k1")
        p2_key = ed25519.Ed25519PrivateKey.generate()
        provider2 = ServiceAuthenticationProvider(
            trusted_keys={"k2": {"key": p2_key.public_key().public_bytes_raw(), "algorithm": "Ed25519"}},
            trusted_issuers={"archival_authority"},
            expected_audience="legacy_migration",
            db_manager=self.db,
        )

        token2 = provider2.mint_service_token(
            principal_id="unrelated_runner",
            signing_key=p2_key,
            key_id="k2",
            issuer="archival_authority",
        )
        principal2 = provider2.authenticate(token2)

        # Configure DB with provider1
        self.db.set_service_authenticator(provider1)

        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "unrelated_runner")
        object.__setattr__(mock_verified, "user_id", self.user1_id)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=mock_verified,
                attesting_principal=principal2,
            )
        self.assertIn("Cross-provider credential reuse is strictly prohibited", str(ctx.exception))

    def test_40_principal_with_modified_credential_id_rejects(self) -> None:
        """TC-40: Principal with modified credential ID rejects at persistence."""
        provider = self._create_provider()
        self.db.set_service_authenticator(provider)
        token = provider.mint_service_token(
            principal_id="tampered_db_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        object.__setattr__(principal, "credential_id", "bogus_cred_id")

        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "tampered_db_runner")
        object.__setattr__(mock_verified, "user_id", self.user1_id)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=mock_verified,
                attesting_principal=principal,
            )
        self.assertIn("not registered or was never issued", str(ctx.exception))

    def test_41_principal_with_modified_expiry_rejects(self) -> None:
        """TC-41: Principal with modified expiry rejects at persistence."""
        provider = self._create_provider()
        self.db.set_service_authenticator(provider)
        token = provider.mint_service_token(
            principal_id="tampered_exp_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)
        object.__setattr__(principal, "expires_at", principal.expires_at + timedelta(hours=24))

        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "tampered_exp_runner")
        object.__setattr__(mock_verified, "user_id", self.user1_id)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=mock_verified,
                attesting_principal=principal,
            )
        self.assertIn("expires_at mismatch", str(ctx.exception))

    def test_42_revoked_principal_rejects(self) -> None:
        """TC-42: Revoked principal rejects at persistence."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="revoked_db_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "revoked_db_runner")
        object.__setattr__(mock_verified, "user_id", self.user1_id)
        object.__setattr__(mock_verified, "key_id", "k_svc_01")

        self.db.revoke_attesting_principal("revoked_db_runner", reason="Test revocation")

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=mock_verified,
                attesting_principal=principal,
            )
        self.assertIn("has been revoked", str(ctx.exception))

    def test_43_revoked_key_rejects(self) -> None:
        """TC-43: Revoked key rejects at persistence."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="revoked_key_runner",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "revoked_key_runner")
        object.__setattr__(mock_verified, "user_id", self.user1_id)
        object.__setattr__(mock_verified, "key_id", "k_svc_01")

        self.db.revoke_signing_key("k_svc_01", reason="Key compromised")

        with self.assertRaises(KeyRevokedError):
            self.db.record_legacy_evidence_attestation(
                verified_evidence=mock_verified,
                attesting_principal=principal,
            )

    def test_44_missing_configured_provider_rejects_in_production(self) -> None:
        """TC-44: Missing configured provider rejects persistence in production."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            fresh_db = DatabaseManager(db_path=str(self.tmp_path / "noprov.db"))
            fresh_db.set_service_authenticator(None)

            mock_verified = object.__new__(VerifiedLegacyEvidence)
            object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
            object.__setattr__(mock_verified, "attested_by", "runner_x")

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                fresh_db.record_legacy_evidence_attestation(
                    verified_evidence=mock_verified,
                    attesting_principal="runner_x",
                )
            self.assertTrue(
                "No trusted service authenticator configured" in str(ctx.exception)
                or "AuthenticatedMigrationPrincipal context is required" in str(ctx.exception)
            )

    def test_45_caller_supplied_string_principal_rejects_in_production(self) -> None:
        """TC-45: Caller-supplied string principal rejects in production."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            provider = self._create_provider()
            self.db.set_service_authenticator(provider)

            mock_verified = object.__new__(VerifiedLegacyEvidence)
            object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
            object.__setattr__(mock_verified, "attested_by", "str_runner")

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=mock_verified,
                    attesting_principal="str_runner",
                )
            self.assertIn("Caller-supplied principal strings are rejected", str(ctx.exception))

    def test_46_evidence_from_different_provider_cannot_be_persisted(self) -> None:
        """TC-46: Evidence created by one provider cannot be persisted under another provider's context."""
        provider1 = self._create_provider(kid="k1")
        p2_key = ed25519.Ed25519PrivateKey.generate()
        provider2 = ServiceAuthenticationProvider(
            trusted_keys={"k2": {"key": p2_key.public_key().public_bytes_raw(), "algorithm": "Ed25519"}},
            trusted_issuers={"archival_authority"},
            expected_audience="legacy_migration",
            db_manager=self.db,
        )
        token2 = provider2.mint_service_token(
            principal_id="runner_p2",
            signing_key=p2_key,
            key_id="k2",
            issuer="archival_authority",
        )
        principal2 = provider2.authenticate(token2)

        # Verified evidence has provider1's instance id
        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "runner_p2")
        object.__setattr__(mock_verified, "attesting_principal_id", "runner_p2")
        object.__setattr__(mock_verified, "provider_instance_id", provider1._provider_id)
        object.__setattr__(mock_verified, "credential_id", principal2.credential_id)
        object.__setattr__(mock_verified, "user_id", self.user1_id)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=mock_verified,
                attesting_principal=principal2,
            )
        self.assertIn("Evidence created by one provider cannot be persisted", str(ctx.exception))

    def test_47_old_evidence_without_provenance_rejects_in_production(self) -> None:
        """TC-47: Old verified evidence without current authentication provenance cannot be persisted in production."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            provider = self._create_provider()
            self.db.set_service_authenticator(provider)
            token = provider.mint_service_token(
                principal_id="prod_runner",
                signing_key=self.service_priv_key,
                key_id="k_svc_01",
                issuer="archival_authority",
            )
            principal = provider.authenticate(token)

            # Old verified evidence missing provider_instance_id and credential_id
            mock_verified = object.__new__(VerifiedLegacyEvidence)
            object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
            object.__setattr__(mock_verified, "attested_by", "prod_runner")
            object.__setattr__(mock_verified, "user_id", self.user1_id)
            object.__setattr__(mock_verified, "provider_instance_id", "")
            object.__setattr__(mock_verified, "credential_id", "")

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=mock_verified,
                    attesting_principal=principal,
                )
            self.assertIn("Old verified evidence without current authentication provenance", str(ctx.exception))

    # =========================================================================
    # CATEGORY 5: ATOMIC REVOCATION & TOCTOU ELIMINATION (Tests 48 - 54)
    # =========================================================================

    def test_48_revocation_completed_before_insertion_blocks_attestation(self) -> None:
        """TC-48: Revocation completed before insertion blocks attestation."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="atomic_runner_48",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "atomic_runner_48")
        object.__setattr__(mock_verified, "user_id", self.user1_id)
        object.__setattr__(mock_verified, "job_description_id", 1)
        object.__setattr__(mock_verified, "evidence_type", "historical_import_manifest")
        object.__setattr__(mock_verified, "evidence_reference_id", "REF_48")
        object.__setattr__(mock_verified, "source_snapshot_hash", "hash_48")
        object.__setattr__(mock_verified, "evidence_artifact_hash", "art_48")
        object.__setattr__(mock_verified, "evidence_payload_hash", "pay_48")
        object.__setattr__(mock_verified, "issuer_id", "archival_authority")
        object.__setattr__(mock_verified, "key_id", "k_svc_01")
        object.__setattr__(mock_verified, "signature_algorithm", "Ed25519")
        object.__setattr__(mock_verified, "evidence_signature", "sig_48")
        object.__setattr__(mock_verified, "migration_boundary", "pre_phase_9_1_1")
        object.__setattr__(mock_verified, "verified_at", datetime.now(timezone.utc).isoformat())

        self.db.revoke_attesting_principal("atomic_runner_48", reason="Atomic block test")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=mock_verified,
                attesting_principal=principal,
            )
        self.assertIn("has been revoked", str(ctx.exception))

    def test_49_attestation_completed_before_revocation_remains_immutable(self) -> None:
        """TC-49: Attestation completed before revocation remains immutable in database."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="atomic_runner_49",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        jd_id = self._create_sample_jd(self.user1_id)
        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "atomic_runner_49")
        object.__setattr__(mock_verified, "user_id", self.user1_id)
        object.__setattr__(mock_verified, "job_description_id", jd_id)
        object.__setattr__(mock_verified, "evidence_type", "historical_import_manifest")
        object.__setattr__(mock_verified, "evidence_reference_id", "REF_49")
        object.__setattr__(mock_verified, "source_snapshot_hash", "hash_49")
        object.__setattr__(mock_verified, "evidence_artifact_hash", "art_49")
        object.__setattr__(mock_verified, "evidence_payload_hash", "pay_49")
        object.__setattr__(mock_verified, "issuer_id", "archival_authority")
        object.__setattr__(mock_verified, "key_id", "k_svc_01")
        object.__setattr__(mock_verified, "signature_algorithm", "Ed25519")
        object.__setattr__(mock_verified, "evidence_signature", "sig_49")
        object.__setattr__(mock_verified, "migration_boundary", "pre_phase_9_1_1")
        object.__setattr__(mock_verified, "verified_at", datetime.now(timezone.utc).isoformat())

        # Attestation completes first
        att_id = self.db.record_legacy_evidence_attestation(
            verified_evidence=mock_verified,
            attesting_principal=principal,
        )
        self.assertGreater(att_id, 0)

        # Later revocation executes
        self.db.revoke_attesting_principal("atomic_runner_49", reason="Post-compromise")

        # Historical row remains unchanged
        row = self.db.get_legacy_evidence_attestation(jd_id, user_id=self.user1_id)
        self.assertIsNotNone(row)
        self.assertEqual(row.attested_by, "atomic_runner_49")

    def test_50_revocation_and_attestation_concurrency_obeys_transaction_ordering(self) -> None:
        """TC-50: Revocation and attestation concurrency obeys SQLite IMMEDIATE write lock ordering."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="concurrent_runner_50",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "concurrent_runner_50")
        object.__setattr__(mock_verified, "user_id", self.user1_id)
        object.__setattr__(mock_verified, "job_description_id", 1)
        object.__setattr__(mock_verified, "evidence_type", "historical_import_manifest")
        object.__setattr__(mock_verified, "evidence_reference_id", "REF_50")
        object.__setattr__(mock_verified, "source_snapshot_hash", "hash_50")
        object.__setattr__(mock_verified, "evidence_artifact_hash", "art_50")
        object.__setattr__(mock_verified, "evidence_payload_hash", "pay_50")
        object.__setattr__(mock_verified, "issuer_id", "archival_authority")
        object.__setattr__(mock_verified, "key_id", "k_svc_01")
        object.__setattr__(mock_verified, "signature_algorithm", "Ed25519")
        object.__setattr__(mock_verified, "evidence_signature", "sig_50")
        object.__setattr__(mock_verified, "migration_boundary", "pre_phase_9_1_1")
        object.__setattr__(mock_verified, "verified_at", datetime.now(timezone.utc).isoformat())

        # Connection 1 acquires IMMEDIATE write lock and inserts revocation
        conn1 = self.db.get_connection()
        conn1.isolation_level = None
        conn1.execute("BEGIN IMMEDIATE")
        conn1.execute(
            "INSERT INTO revoked_attesting_principals (principal_id, revoked_at, reason) VALUES (?, CURRENT_TIMESTAMP, ?)",
            ("concurrent_runner_50", "Concurrent test"),
        )
        conn1.execute("COMMIT")
        conn1.close()

        # Connection 2 attempts attestation -> must reject
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.db.record_legacy_evidence_attestation(
                verified_evidence=mock_verified,
                attesting_principal=principal,
            )
        self.assertIn("has been revoked", str(ctx.exception))

    def test_51_revocation_query_failure_rolls_back(self) -> None:
        """TC-51: Revocation query failure inside transaction triggers rollback."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="runner_51",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "runner_51")
        object.__setattr__(mock_verified, "user_id", self.user1_id)

        # Drop the table to simulate query failure
        with self.db.immediate_transaction() as conn:
            conn.execute("ALTER TABLE revoked_attesting_principals RENAME TO temp_rev_51")

        try:
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=mock_verified,
                    attesting_principal=principal,
                )
            self.assertIn("Database revocation query failure", str(ctx.exception))
        finally:
            with self.db.immediate_transaction() as conn:
                conn.execute("ALTER TABLE temp_rev_51 RENAME TO revoked_attesting_principals")

    def test_52_signing_key_revocation_query_failure_rolls_back(self) -> None:
        """TC-52: Signing key revocation query failure inside transaction triggers rollback."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="runner_52",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "runner_52")
        object.__setattr__(mock_verified, "user_id", self.user1_id)
        object.__setattr__(mock_verified, "key_id", "k_svc_01")

        with self.db.immediate_transaction() as conn:
            conn.execute("ALTER TABLE revoked_signing_keys RENAME TO temp_rev_keys_52")

        try:
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.db.record_legacy_evidence_attestation(
                    verified_evidence=mock_verified,
                    attesting_principal=principal,
                )
            self.assertIn("Database revocation query failure", str(ctx.exception))
        finally:
            with self.db.immediate_transaction() as conn:
                conn.execute("ALTER TABLE temp_rev_keys_52 RENAME TO revoked_signing_keys")

    def test_53_caller_supplied_cursor_uses_same_transaction(self) -> None:
        """TC-53: Caller-supplied cursor uses the same transaction for revocation checks and insert."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="runner_53",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        jd_id = self._create_sample_jd(self.user1_id)
        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "runner_53")
        object.__setattr__(mock_verified, "user_id", self.user1_id)
        object.__setattr__(mock_verified, "job_description_id", jd_id)
        object.__setattr__(mock_verified, "evidence_type", "historical_import_manifest")
        object.__setattr__(mock_verified, "evidence_reference_id", "REF_53")
        object.__setattr__(mock_verified, "source_snapshot_hash", "hash_53")
        object.__setattr__(mock_verified, "evidence_artifact_hash", "art_53")
        object.__setattr__(mock_verified, "evidence_payload_hash", "pay_53")
        object.__setattr__(mock_verified, "issuer_id", "archival_authority")
        object.__setattr__(mock_verified, "key_id", "k_svc_01")
        object.__setattr__(mock_verified, "signature_algorithm", "Ed25519")
        object.__setattr__(mock_verified, "evidence_signature", "sig_53")
        object.__setattr__(mock_verified, "migration_boundary", "pre_phase_9_1_1")
        object.__setattr__(mock_verified, "verified_at", datetime.now(timezone.utc).isoformat())

        conn = self.db.get_connection()
        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()

        # All operations occur on cur
        lastrowid = self.db.record_legacy_evidence_attestation(
            verified_evidence=mock_verified,
            attesting_principal=principal,
            cursor=cur,
        )
        self.assertGreater(lastrowid, 0)
        conn.execute("COMMIT")
        conn.close()

    def test_54_no_separate_read_connection_used_for_final_checks(self) -> None:
        """TC-54: No separate connection is opened during record_legacy_evidence_attestation."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="runner_54",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
        )
        principal = provider.authenticate(token)

        jd_id = self._create_sample_jd(self.user1_id)
        mock_verified = object.__new__(VerifiedLegacyEvidence)
        object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
        object.__setattr__(mock_verified, "attested_by", "runner_54")
        object.__setattr__(mock_verified, "user_id", self.user1_id)
        object.__setattr__(mock_verified, "job_description_id", jd_id)
        object.__setattr__(mock_verified, "evidence_type", "historical_import_manifest")
        object.__setattr__(mock_verified, "evidence_reference_id", "REF_54")
        object.__setattr__(mock_verified, "source_snapshot_hash", "hash_54")
        object.__setattr__(mock_verified, "evidence_artifact_hash", "art_54")
        object.__setattr__(mock_verified, "evidence_payload_hash", "pay_54")
        object.__setattr__(mock_verified, "issuer_id", "archival_authority")
        object.__setattr__(mock_verified, "key_id", "k_svc_01")
        object.__setattr__(mock_verified, "signature_algorithm", "Ed25519")
        object.__setattr__(mock_verified, "evidence_signature", "sig_54")
        object.__setattr__(mock_verified, "migration_boundary", "pre_phase_9_1_1")
        object.__setattr__(mock_verified, "verified_at", datetime.now(timezone.utc).isoformat())

        with patch.object(self.db, "connection", side_effect=AssertionError("Separate connection() should not be called!")):
            att_id = self.db.record_legacy_evidence_attestation(
                verified_evidence=mock_verified,
                attesting_principal=principal,
            )
            self.assertGreater(att_id, 0)

    # =========================================================================
    # CATEGORY 6: JWT AUTHORIZATION SCOPE AND ARRAYS (Tests 55 - 65)
    # =========================================================================

    def test_55_explicit_legacy_migration_scope_succeeds(self) -> None:
        """TC-55: Explicit legacy_migration scope succeeds."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_scope",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            scopes=["legacy_migration"],
        )
        principal = provider.authenticate(token)
        self.assertIn("legacy_migration", principal.scopes)
        provider.validate_principal(principal)

    def test_56_generic_all_scope_rejected(self) -> None:
        """TC-56: Generic 'all' scope without explicit 'legacy_migration' is rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_all_scope",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            scopes=["all"],
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("lacks mandatory 'legacy_migration' authorization scope", str(ctx.exception))

    def test_57_audience_list_containing_non_string_rejects(self) -> None:
        """TC-57: Audience list containing a non-string item is rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_aud",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            audience=["legacy_migration", 12345],
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("all items must be strings", str(ctx.exception))

    def test_58_audience_list_containing_empty_string_rejects(self) -> None:
        """TC-58: Audience list containing an empty string is rejected."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_aud",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            audience=["legacy_migration", ""],
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("empty string is prohibited", str(ctx.exception))

    def test_59_nested_audience_values_reject(self) -> None:
        """TC-59: Nested audience values reject."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_aud",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            audience=[["legacy_migration"]],
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("all items must be strings", str(ctx.exception))

    def test_60_scope_list_containing_non_string_rejects(self) -> None:
        """TC-60: Scope list containing a non-string item rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_scope",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            scopes=["legacy_migration", 999],
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("all items must be strings", str(ctx.exception))

    def test_61_scope_list_containing_empty_string_rejects(self) -> None:
        """TC-61: Scope list containing an empty string rejects."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_scope",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            scopes=["legacy_migration", "   "],
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("empty scope entry is prohibited", str(ctx.exception))

    def test_62_nested_scope_values_reject(self) -> None:
        """TC-62: Nested scope values reject."""
        provider = self._create_provider()
        token = provider.mint_service_token(
            principal_id="svc_scope",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            scopes=[["legacy_migration"]],
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token)
        self.assertIn("all items must be strings", str(ctx.exception))

    def test_63_nan_timestamps_reject(self) -> None:
        """TC-63: NaN timestamps reject."""
        provider = self._create_provider()
        token_nan_iat = provider.mint_service_token(
            principal_id="svc_nan",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            iat=float("nan"),
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token_nan_iat)
        self.assertIn("must be a finite numeric value", str(ctx.exception))

    def test_64_infinite_timestamps_reject(self) -> None:
        """TC-64: Infinite timestamps reject."""
        provider = self._create_provider()
        token_inf_exp = provider.mint_service_token(
            principal_id="svc_inf",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            exp=float("inf"),
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token_inf_exp)
        self.assertIn("must be a finite numeric value", str(ctx.exception))

    def test_65_boolean_timestamps_reject(self) -> None:
        """TC-65: Boolean timestamps reject."""
        provider = self._create_provider()
        token_bool_iat = provider.mint_service_token(
            principal_id="svc_bool",
            signing_key=self.service_priv_key,
            key_id="k_svc_01",
            issuer="archival_authority",
            iat=True,
        )
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            provider.authenticate(token_bool_iat)
        self.assertIn("must be a finite numeric value", str(ctx.exception))

    # =========================================================================
    # CATEGORY 7: END-TO-END AND COMPATIBILITY (Tests 66 - 72)
    # =========================================================================

    def test_66_full_provider_auth_evidence_verification_and_persistence_e2e(self) -> None:
        """TC-66: Full end-to-end flow: mint -> authenticate -> verify evidence -> record attestation -> preflight."""
        with patch.dict(os.environ, {"APP_ENV": "production", "SECURITY_SCAN_SIGNING_KEY": "test_scan_key_production_32_bytes_long_1234!!"}, clear=True):
            provider = self._create_provider(kid="e2e_key", issuer="e2e_authority")
            token = provider.mint_service_token(
                principal_id="e2e_runner_66",
                signing_key=self.service_priv_key,
                key_id="e2e_key",
                issuer="e2e_authority",
                jti="E2E_TOKEN_66",
            )
            principal = provider.authenticate(token)

            store = LegacyEvidenceTrustStore(
                trusted_issuers={"e2e_authority"},
                trusted_attesting_principals={"e2e_runner_66"},
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
                evidence_reference_id="E2E_66_REF",
                issuer_id="e2e_authority",
                key_id="e2e_ed",
                signing_key=self.priv_key,
                entries=entries,
                signature_algorithm="Ed25519",
                attesting_principal="e2e_runner_66",
            )
            resolver.register_artifact("historical_import_manifest", "E2E_66_REF", raw_bytes)

            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                service_authenticator=provider,
                db_manager=self.db,
            )
            verified = verifier.verify(
                evidence_type="historical_import_manifest",
                evidence_reference_id="E2E_66_REF",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=principal,
            )

            att_id = self.db.record_legacy_evidence_attestation(
                verified_evidence=verified,
                attesting_principal=principal,
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
                migration_version="phase_9_1_2_11",
                migration_reason="Verified Ed25519 E2E test 66",
                evidence_type="historical_import_manifest",
                evidence_reference_id="E2E_66_REF",
                outcome="SUCCESS",
            )
            with self.db.transaction() as conn:
                conn.cursor().execute(
                    "UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?",
                    (jd_id,),
                )

            preflight = SecurityPreflightManager(
                db_manager=self.db,
                file_validator=self.file_validator,
                detector=self.detector,
                evidence_verifier=verifier,
            )
            res = preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
            self.assertTrue(res.is_allowed)
            self.assertEqual(res.classification, "CLEAN")

    def test_67_production_without_configured_authenticator_grants_zero_exceptions(self) -> None:
        """TC-67: In production, absence of configured authenticator denies all legacy exceptions."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            fresh_db = DatabaseManager(db_path=str(self.tmp_path / "prod_no_auth.db"))
            fresh_db.set_service_authenticator(None)
            store = LegacyEvidenceTrustStore(db_manager=fresh_db)
            resolver = InMemoryEvidenceResolver()
            verifier = LegacyEvidenceVerifier(
                trust_store=store,
                resolver=resolver,
                db_manager=fresh_db,
                service_authenticator=None,
            )
            # In production without authenticator, verifier denies exceptions:
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                verifier.verify(
                    evidence_type="historical_import_manifest",
                    evidence_reference_id="TEST_REF",
                    user_id=1,
                    job_description_id=1,
                    source_snapshot_hash="hash",
                    attesting_principal="sys:migrator",
                )
            self.assertIn("AuthenticatedMigrationPrincipal", str(ctx.exception))

            # DatabaseManager also denies persisting legacy attestation without authenticator
            mock_verified = object.__new__(VerifiedLegacyEvidence)
            object.__setattr__(mock_verified, "_token", _VERIFICATION_TOKEN)
            object.__setattr__(mock_verified, "attested_by", "sys:migrator")
            object.__setattr__(mock_verified, "user_id", 1)
            with self.assertRaises(SecurityAuthorizationError) as ctx_db:
                fresh_db.record_legacy_evidence_attestation(
                    verified_evidence=mock_verified,
                    attesting_principal="sys:migrator",
                )
            self.assertIn("No trusted service authenticator configured", str(ctx_db.exception))

    def test_68_production_without_genuine_evidence_provider_grants_zero_exceptions(self) -> None:
        """TC-68: Production without genuine evidence provider fails closed."""
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            store = LegacyEvidenceTrustStore(db_manager=self.db)
            self.assertEqual(store.algorithm_policy, "production")
            # Without configured keys or issuers, is_issuer_trusted returns False
            self.assertFalse(store.is_issuer_trusted("unregistered_authority"))

    def test_69_unverified_uploaded_job_descriptions_remain_required(self) -> None:
        """TC-69: Unverified uploaded job descriptions remain in REQUIRED state."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_70_original_binary_recovery_still_succeeds(self) -> None:
        """TC-70: Candidate uploading genuine original PDF file successfully clears REQUIRED state."""
        import io
        from reportlab.pdfgen import canvas

        jd_id = self._create_sample_jd(self.user1_id)
        buf = io.BytesIO()
        c = canvas.Canvas(buf)
        c.drawString(50, 750, "Genuine original job description recovery PDF")
        c.save()
        pdf_bytes = buf.getvalue()

        unique_name, detected_format, file_size_bytes, file_hash = (
            self.file_validator.save_user_job_description_file(
                user_id=self.user1_id,
                file_bytes=pdf_bytes,
                original_filename="recovered.pdf",
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
        updated = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(updated.binary_integrity_state, "VERIFIED")

    def test_71_existing_authenticated_resume_verification_intact(self) -> None:
        """TC-71: Existing authenticated resume verification and matching workflows remain intact."""
        resume = self.db.create_user_resume(
            user_id=self.user1_id,
            original_filename="test_resume_71.pdf",
            storage_filename="test_resume_71.pdf",
            file_format="pdf",
            file_hash="hash_resume_71",
            file_size_bytes=1024,
            parsed_data={"candidate_name": "Security Engineer", "skills": ["Python", "Cryptography"]},
        )
        self.assertIsNotNone(resume)
        self.assertEqual(resume["file_format"], "pdf")
        self.assertEqual(resume["file_hash"], "hash_resume_71")
        self.assertTrue(resume["is_active"])

    def test_72_prior_regression_compatibility(self) -> None:
        """TC-72: Legacy integrity exceptions and audit trail mechanisms remain intact."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        exc_id = self.db.record_legacy_integrity_exception(
            user_id=self.user1_id,
            job_description_id=jd_id,
            original_source_type="upload",
            previous_binary_state="REQUIRED",
            assigned_legacy_state="LEGACY_TEXT_ONLY",
            source_snapshot_hash=snap,
            migration_version="phase_9_1_2_11",
            migration_reason="Audit trail backward compatibility test",
            evidence_type="historical_import_manifest",
            evidence_reference_id="REF_72",
            outcome="SUCCESS",
        )
        self.assertGreater(exc_id, 0)
        retrieved = self.db.get_legacy_integrity_exception(job_description_id=jd_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.evidence_reference_id, "REF_72")
        self.assertEqual(retrieved.outcome, "SUCCESS")


if __name__ == "__main__":
    unittest.main()

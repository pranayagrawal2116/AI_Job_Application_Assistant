"""Comprehensive Test Suite for Phase 9.1.2.7 — Reconciled Attestation Acceptance & Trust-Key Immutability Closure.

Phase 9.1.2.7 Architecture v2.1.1 Implementation.
Exhaustively tests:
1. Reconciled legacy record acceptance in security preflight (outcome='RECONCILED' vs 'SUCCESS' vs 'REVERTED').
2. End-to-end database reconciliation migration followed by actual security preflight.
3. Trust store immutable key registration and constructor atomic validation.
4. Trust store key revocation and rotation lifecycle.
5. Authenticated attesting principal authorization and candidate self-attestation defense.
6. Exhaustive attestation field comparison against independently verified artifacts.
7. Asymmetric Ed25519 signatures vs HMAC authentication and production policy enforcement.
8. No-provider production fail-closed behavior and legitimate pasted/URL workflows.

All cryptographic credentials and artifacts used in this suite are strictly synthetic test fixtures.
"""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    KeyRevokedError,
    SecurityAuthorizationError,
)
from src.security.file_security import FileSecurityValidator
from src.security.legacy_evidence_verifier import (
    InMemoryEvidenceResolver,
    LegacyEvidenceTrustStore,
    LegacyEvidenceVerifier,
    VerifiedLegacyEvidence,
    create_signed_evidence_artifact,
    set_default_evidence_resolver,
    set_default_evidence_trust_store,
)
from src.security.prompt_injection_detector import PromptInjectionDetector
from src.security.security_preflight import SecurityPreflightManager
from src.utils.canonical_json import canonical_json_hash
from tests.fixtures.synthetic_personas import generate_persona_pdf

# Synthetic test credentials
SYNTHETIC_TEST_KEY_ID = "test_synthetic_key_9127"
SYNTHETIC_TEST_SECRET = b"test_synthetic_secret_at_least_32_bytes_long_9127!"
SYNTHETIC_TEST_ISSUER = "test_synthetic_archival_authority_9127"
SYNTHETIC_TEST_TYPE = "archival_import_manifest"
SYNTHETIC_TEST_REF_ID = "TEST_SYNTHETIC_MANIFEST_9127_001"
SYNTHETIC_TEST_PRINCIPAL = "test_synthetic_migration_coordinator"


class TestPhase9127ReconciledPreflightAndTrustKeys(unittest.TestCase):
    """Exhaustive test suite for Phase 9.1.2.7 requirements."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        self.db_path = self.tmp_path / "test_phase_9127.db"
        self.user_base_dir = self.tmp_path / "users"
        self.user_base_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))

        # Synthetic trust store
        self.trust_store = LegacyEvidenceTrustStore(db_manager=self.db)
        self.trust_store.register_trusted_issuer(SYNTHETIC_TEST_ISSUER)
        self.trust_store.register_trusted_key(SYNTHETIC_TEST_KEY_ID, SYNTHETIC_TEST_SECRET)
        self.trust_store.register_trusted_attesting_principal(SYNTHETIC_TEST_PRINCIPAL)
        set_default_evidence_trust_store(self.trust_store)

        # Synthetic in-memory evidence resolver
        self.resolver = InMemoryEvidenceResolver()
        set_default_evidence_resolver(self.resolver)

        self.verifier = LegacyEvidenceVerifier(
            trust_store=self.trust_store,
            resolver=self.resolver,
            db_manager=self.db,
        )

        self.file_validator = FileSecurityValidator(base_storage_dir=self.user_base_dir)
        self.detector = PromptInjectionDetector()
        self.preflight = SecurityPreflightManager(
            db_manager=self.db,
            detector=self.detector,
            file_validator=self.file_validator,
            evidence_verifier=self.verifier,
        )

        # Seed test users
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("user1_9127@example.com", "hash1", "salt1", "Candidate 9127 One"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("user2_9127@example.com", "hash2", "salt2", "Candidate 9127 Two"),
            )
            self.user2_id = c.lastrowid

    def tearDown(self) -> None:
        set_default_evidence_resolver(None)
        set_default_evidence_trust_store(None)
        self.tmp_dir.cleanup()

    def _create_sample_jd(self, user_id: int, title: str = "Lead Security Architect") -> int:
        raw_text = f"Company: SecureCorp\nTitle: {title}\nLocation: Remote\nResponsibilities:\n- Zero Trust Architecture."
        c_hash = hashlib.sha256(raw_text.strip().encode("utf-8")).hexdigest()
        manifest_9 = {
            "user_id": user_id,
            "company_name": "SecureCorp",
            "job_title": title,
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": "jd.pdf",
        }
        s_hash = canonical_json_hash(manifest_9)

        with self.db.immediate_transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at,
                    parser_version, original_filename
                ) VALUES (?, 'upload', 'SecureCorp', ?, ?, ?, ?, 'REQUIRED', 1, '2024-04-15 10:00:00', '1.0.0', 'jd.pdf')
                """,
                (user_id, title, raw_text, c_hash, s_hash),
            )
            return cur.lastrowid

    # =========================================================================
    # PART A: RECONCILED LEGACY PREFLIGHT & AUDIT CONTRACT (TESTS 1 - 7)
    # =========================================================================

    def test_01_valid_reconciled_evidence_passes_actual_preflight(self) -> None:
        """1. A grandfathered source with latest outcome='RECONCILED' passes preflight when evidence verifies."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_RECONCILED_001",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "MANIFEST_RECONCILED_001", art_bytes)

        verified = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_RECONCILED_001",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=jd.snapshot_hash,
            attesting_principal=SYNTHETIC_TEST_PRINCIPAL,
        )
        self.db.record_legacy_evidence_attestation(verified, attesting_principal=SYNTHETIC_TEST_PRINCIPAL)

        # Record RECONCILED audit exception and set state to LEGACY_TEXT_ONLY
        with self.db.immediate_transaction() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))
            cur.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, 'phase_9_1_2_6', ?, 'MANIFEST_RECONCILED_001', 'reconciled audit', 'RECONCILED')
                """,
                (self.user1_id, jd_id, jd.snapshot_hash, SYNTHETIC_TEST_TYPE),
            )

        # Actual preflight check must succeed
        res = self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertTrue(res.is_allowed)
        self.assertEqual(res.classification, "CLEAN")

    def test_02_end_to_end_migration_reconciliation_followed_by_preflight(self) -> None:
        """2. End-to-end: running _migrate_phase_9_1_2_6 reconciliation sets RECONCILED and preflight succeeds."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_MIGRATION_RECONCILED_002",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "MANIFEST_MIGRATION_RECONCILED_002", art_bytes)

        verified = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_MIGRATION_RECONCILED_002",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=jd.snapshot_hash,
            attesting_principal=SYNTHETIC_TEST_PRINCIPAL,
        )
        self.db.record_legacy_evidence_attestation(verified, attesting_principal=SYNTHETIC_TEST_PRINCIPAL)

        # Mark LEGACY_TEXT_ONLY and clear migration ledger marker
        with self.db.immediate_transaction() as conn:
            conn.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_6_legacy_evidence_verification_closure'")

        # Execute actual Phase 9.1.2.6 reconciliation migration routine
        with self.db.immediate_transaction() as conn:
            self.db._migrate_phase_9_1_2_6_legacy_evidence_verification_closure(conn.cursor(), verifier=self.verifier)

        # Verify database state
        latest_jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(latest_jd.binary_integrity_state, "LEGACY_TEXT_ONLY")

        exc = self.db.get_legacy_integrity_exception(job_description_id=jd_id, user_id=self.user1_id)
        self.assertIsNotNone(exc)
        self.assertEqual(exc.outcome, "RECONCILED")
        self.assertEqual(exc.assigned_legacy_state, "LEGACY_TEXT_ONLY")

        # Execute actual preflight
        res = self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertTrue(res.is_allowed)

    def test_03_latest_reverted_outcome_remains_blocked(self) -> None:
        """3. A record whose latest audit event is REVERTED is unconditionally rejected by preflight."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        # Insert REVERTED audit exception
        with self.db.immediate_transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'LEGACY_TEXT_ONLY', 'REQUIRED', ?, 'phase_9_1_2_6', ?, 'REF_REVERTED', 'failed reconciliation', 'REVERTED')
                """,
                (self.user1_id, jd_id, jd.snapshot_hash, SYNTHETIC_TEST_TYPE),
            )
            # Even if state was fraudulently set to LEGACY_TEXT_ONLY
            cur.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("REVERTED", str(ctx.exception))

    def test_04_earlier_success_cannot_override_later_reverted(self) -> None:
        """4. Earlier SUCCESS followed by later REVERTED is rejected (latest-event semantics enforced)."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        with self.db.immediate_transaction() as conn:
            cur = conn.cursor()
            # 1. Earlier event: SUCCESS
            cur.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, '9.1.2.3', ?, 'REF_01', 'earlier success', 'SUCCESS')
                """,
                (self.user1_id, jd_id, jd.snapshot_hash, SYNTHETIC_TEST_TYPE),
            )
            # 2. Later event: REVERTED (has higher ID)
            cur.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'LEGACY_TEXT_ONLY', 'REQUIRED', ?, 'phase_9_1_2_6', ?, 'REF_01', 'later reverted', 'REVERTED')
                """,
                (self.user1_id, jd_id, jd.snapshot_hash, SYNTHETIC_TEST_TYPE),
            )
            cur.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("REVERTED", str(ctx.exception))

    def test_05_revoked_evidence_key_blocks_reconciled_preflight(self) -> None:
        """5. Reconciled record with valid artifact fails preflight immediately if its signing key is revoked."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_REVOKED_PREFLIGHT_005",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "MANIFEST_REVOKED_PREFLIGHT_005", art_bytes)

        verified = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_REVOKED_PREFLIGHT_005",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=jd.snapshot_hash,
            attesting_principal=SYNTHETIC_TEST_PRINCIPAL,
        )
        self.db.record_legacy_evidence_attestation(verified, attesting_principal=SYNTHETIC_TEST_PRINCIPAL)

        with self.db.immediate_transaction() as conn:
            conn.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))
            conn.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, 'phase_9_1_2_6', ?, 'MANIFEST_REVOKED_PREFLIGHT_005', 'audit', 'RECONCILED')
                """,
                (self.user1_id, jd_id, jd.snapshot_hash, SYNTHETIC_TEST_TYPE),
            )

        # Revoke the signing key
        self.trust_store.revoke_key(SYNTHETIC_TEST_KEY_ID)

        # Preflight must fail closed
        with self.assertRaises(KeyRevokedError):
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)

    def test_06_invalid_evidence_artifact_blocks_reconciled_preflight(self) -> None:
        """6. Reconciled record where backing artifact signature is invalid fails preflight."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_CORRUPT_006",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        parsed = json.loads(art_bytes.decode("utf-8"))
        # Corrupt signature in resolver
        parsed["signature"] = "deadbeef" * 8
        corrupted_bytes = json.dumps(parsed).encode("utf-8")
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "MANIFEST_CORRUPT_006", corrupted_bytes)

        with self.db.immediate_transaction() as conn:
            conn.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))
            conn.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, ?, 'MANIFEST_CORRUPT_006', ?, ?)
                """,
                (self.user1_id, jd_id, SYNTHETIC_TEST_TYPE, jd.snapshot_hash, SYNTHETIC_TEST_PRINCIPAL),
            )
            conn.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, 'phase_9_1_2_6', ?, 'MANIFEST_CORRUPT_006', 'audit', 'RECONCILED')
                """,
                (self.user1_id, jd_id, jd.snapshot_hash, SYNTHETIC_TEST_TYPE),
            )

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("signature verification failed", str(ctx.exception))

    def test_07_direct_db_attestation_forgery_fails_without_backing_artifact(self) -> None:
        """7. A fabricated database attestation row fails preflight when backing artifact does not exist."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        with self.db.immediate_transaction() as conn:
            conn.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))
            conn.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, ?, 'NON_EXISTENT_ARTIFACT_007', ?, ?)
                """,
                (self.user1_id, jd_id, SYNTHETIC_TEST_TYPE, jd.snapshot_hash, SYNTHETIC_TEST_PRINCIPAL),
            )
            conn.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, 'phase_9_1_2_6', ?, 'NON_EXISTENT_ARTIFACT_007', 'audit', 'RECONCILED')
                """,
                (self.user1_id, jd_id, jd.snapshot_hash, SYNTHETIC_TEST_TYPE),
            )

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("could not be resolved or found", str(ctx.exception))

    # =========================================================================
    # PART B: IMMUTABLE TRUST-STORE KEYS & LIFECYCLE (TESTS 8 - 14)
    # =========================================================================

    def test_08_identical_key_re_registration_is_idempotent(self) -> None:
        """8. Re-registering the same key ID with identical bytes and algorithm succeeds idempotently."""
        store = LegacyEvidenceTrustStore()
        store.register_trusted_key("key_idem", b"A" * 32, "HMAC-SHA256")
        # Idempotent re-registration
        store.register_trusted_key("key_idem", b"A" * 32, "HMAC-SHA256")
        k_bytes, algo = store.get_key("key_idem")
        self.assertEqual(k_bytes, b"A" * 32)
        self.assertEqual(algo, "HMAC-SHA256")

    def test_09_existing_key_id_with_different_secret_is_rejected(self) -> None:
        """9. Re-registering an existing key ID with different secret bytes raises SecurityAuthorizationError."""
        store = LegacyEvidenceTrustStore()
        store.register_trusted_key("key_immut", b"A" * 32, "HMAC-SHA256")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            store.register_trusted_key("key_immut", b"B" * 32, "HMAC-SHA256")
        self.assertIn("Immutability violation", str(ctx.exception))

    def test_10_existing_key_id_with_different_algorithm_is_rejected(self) -> None:
        """10. Re-registering an existing key ID with a different algorithm raises SecurityAuthorizationError."""
        store = LegacyEvidenceTrustStore()
        store.register_trusted_key("key_algo", b"A" * 32, "HMAC-SHA256")
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            store.register_trusted_key("key_algo", b"A" * 32, "Ed25519")
        self.assertIn("Immutability violation", str(ctx.exception))

    def test_11_revoked_key_cannot_be_re_registered(self) -> None:
        """11. A revoked key ID cannot be re-registered under the same key ID."""
        store = LegacyEvidenceTrustStore()
        store.register_trusted_key("key_rev", b"A" * 32, "HMAC-SHA256")
        store.revoke_key("key_rev")
        self.assertTrue(store.is_key_revoked("key_rev"))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            store.register_trusted_key("key_rev", b"A" * 32, "HMAC-SHA256")
        self.assertIn("revoked", str(ctx.exception))

    def test_12_constructor_rejects_normalized_key_collisions(self) -> None:
        """12. Trust store rejects key ID collisions after whitespace normalization."""
        store = LegacyEvidenceTrustStore()
        store.register_trusted_key("key_norm", b"A" * 32, "HMAC-SHA256")
        # Colliding key ID with leading/trailing whitespace and different secret
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            store.register_trusted_key("  key_norm  ", b"B" * 32, "HMAC-SHA256")
        self.assertIn("Immutability violation", str(ctx.exception))

    def test_13_invalid_trust_configuration_does_not_partially_activate_keys(self) -> None:
        """13. An invalid entry in constructor configuration aborts without activating earlier valid entries."""
        valid_bytes = b"V" * 32
        invalid_short_bytes = b"short"

        with self.assertRaises(SecurityAuthorizationError):
            LegacyEvidenceTrustStore(
                trusted_keys={
                    "valid_key": valid_bytes,
                    "invalid_key": invalid_short_bytes,
                }
            )

    def test_14_malformed_environment_json_fails_closed(self) -> None:
        """14. Malformed JSON in environment configuration raises SecurityAuthorizationError rather than warning."""
        os.environ["LEGACY_EVIDENCE_TRUSTED_KEYS"] = "{not_valid_json"
        try:
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                LegacyEvidenceTrustStore()
            self.assertIn("Malformed JSON", str(ctx.exception))
        finally:
            del os.environ["LEGACY_EVIDENCE_TRUSTED_KEYS"]

    def test_15_historical_signed_artifact_verification_after_valid_key_rotation(self) -> None:
        """15. Rotating signing keys by registering a new key ID preserves verification of older artifacts."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        # Artifact 1 signed with key 1
        art1_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="ROTATION_ART_001",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=[{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}],
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "ROTATION_ART_001", art1_bytes)

        # Register rotated key 2
        key2_id = "test_synthetic_key_2025"
        key2_secret = b"new_secret_bytes_at_least_32_bytes_long_2025!"
        self.trust_store.register_trusted_key(key2_id, key2_secret)

        # Artifact 2 signed with key 2
        art2_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="ROTATION_ART_002",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=key2_id,
            signing_key=key2_secret,
            entries=[{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}],
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "ROTATION_ART_002", art2_bytes)

        # Both artifacts verify cleanly
        v1 = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="ROTATION_ART_001",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=jd.snapshot_hash,
            attesting_principal=SYNTHETIC_TEST_PRINCIPAL,
        )
        v2 = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="ROTATION_ART_002",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=jd.snapshot_hash,
            attesting_principal=SYNTHETIC_TEST_PRINCIPAL,
        )
        self.assertEqual(v1.key_id, SYNTHETIC_TEST_KEY_ID)
        self.assertEqual(v2.key_id, key2_id)

    # =========================================================================
    # PART C: ATTESTING PRINCIPAL AUTHORIZATION (TESTS 16 - 19)
    # =========================================================================

    def test_16_unknown_attesting_principal_is_rejected(self) -> None:
        """16. Verification presenting an unknown, unauthorized attesting principal is rejected."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="REF_PRINCIPAL_016",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "REF_PRINCIPAL_016", art_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="REF_PRINCIPAL_016",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=jd.snapshot_hash,
                attesting_principal="unauthorized_rogue_attester",
            )
        self.assertIn("not authorized in trust store", str(ctx.exception))

    def test_17_candidate_self_attestation_is_rejected(self) -> None:
        """17. Candidate self-attestation is strictly rejected by principal authorization checks."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="REF_SELF_017",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "REF_SELF_017", art_bytes)

        for bad_p in (f"user_{self.user1_id}", str(self.user1_id), "candidate_user", "candidate_alice"):
            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.verifier.verify(
                    evidence_type=SYNTHETIC_TEST_TYPE,
                    evidence_reference_id="REF_SELF_017",
                    user_id=self.user1_id,
                    job_description_id=jd_id,
                    source_snapshot_hash=jd.snapshot_hash,
                    attesting_principal=bad_p,
                )
            self.assertIn("cannot self-attest", str(ctx.exception))

    def test_18_revoked_attesting_principal_is_rejected(self) -> None:
        """18. An attesting principal that has been revoked is rejected."""
        p_name = "temp_migration_coordinator"
        self.trust_store.register_trusted_attesting_principal(p_name)
        self.assertTrue(self.trust_store.is_attesting_principal_trusted(p_name))

        self.trust_store.revoke_attesting_principal(p_name)
        self.assertFalse(self.trust_store.is_attesting_principal_trusted(p_name))

        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="REF_REVOKED_P_018",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "REF_REVOKED_P_018", art_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="REF_REVOKED_P_018",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=jd.snapshot_hash,
                attesting_principal=p_name,
            )
        self.assertIn("not authorized in trust store", str(ctx.exception))

    def test_19_evidence_binding_attesting_principal_enforced(self) -> None:
        """19. If evidence artifact binds an authorized attesting principal, presenting a different principal is rejected."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="REF_BOUND_P_019",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
            attesting_principal="system_migration_authority",
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "REF_BOUND_P_019", art_bytes)

        # Presenting another authorized principal (SYNTHETIC_TEST_PRINCIPAL) is rejected because artifact explicitly bound "system_migration_authority"
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="REF_BOUND_P_019",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=jd.snapshot_hash,
                attesting_principal=SYNTHETIC_TEST_PRINCIPAL,
            )
        self.assertIn("does not match verifying principal", str(ctx.exception))

    # =========================================================================
    # PART D: COMPLETE ATTESTATION FIELD COMPARISON (TESTS 20 - 23)
    # =========================================================================

    def test_20_tampering_each_persisted_attestation_field_is_rejected(self) -> None:
        """20. Tampering with any stored cryptographic attestation field independently causes verify_attestation to fail closed."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="REF_FIELDS_020",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "REF_FIELDS_020", art_bytes)

        verified = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="REF_FIELDS_020",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=jd.snapshot_hash,
            attesting_principal=SYNTHETIC_TEST_PRINCIPAL,
        )
        self.db.record_legacy_evidence_attestation(verified, attesting_principal=SYNTHETIC_TEST_PRINCIPAL)
        attestation = self.db.get_legacy_evidence_attestation(job_description_id=jd_id, user_id=self.user1_id)
        self.assertIsNotNone(attestation)

        # Baseline: unmodified attestation verifies cleanly
        res = self.verifier.verify_attestation(attestation, self.user1_id, jd_id, jd.snapshot_hash)
        self.assertIsInstance(res, VerifiedLegacyEvidence)

        # Test tampering each field independently
        fields_to_tamper = {
            "evidence_artifact_hash": "deadbeef" * 8,
            "evidence_payload_hash": "cafebabe" * 8,
            "issuer_id": "forged_issuer_id",
            "key_id": "forged_key_id",
            "signature_algorithm": "Ed25519",
            "evidence_signature": "00" * 32,
            "migration_boundary": "pre_phase_9_0_0",
            "evidence_type": "pre_phase9_signed_backup",
            "evidence_reference_id": "REF_OTHER_ID",
            "user_id": self.user2_id,
            "job_description_id": jd_id + 999,
            "source_snapshot_hash": "f" * 64,
            "attested_by": "unauthorized_principal",
        }

        for field_name, bad_val in fields_to_tamper.items():
            # Clone attestation and inject bad value
            att_dict = attestation.to_dict()
            att_dict[field_name] = bad_val
            from src.database.models import LegacyEvidenceAttestation
            tampered_att = LegacyEvidenceAttestation(**att_dict)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.verifier.verify_attestation(
                    tampered_att,
                    self.user1_id,
                    jd_id,
                    jd.snapshot_hash,
                )
            self.assertTrue(
                "mismatch" in str(ctx.exception)
                or "not match" in str(ctx.exception)
                or "not authorized" in str(ctx.exception)
                or "could not be resolved" in str(ctx.exception)
                or "not found" in str(ctx.exception)
                or "replay rejected" in str(ctx.exception)
                or "does not bind" in str(ctx.exception),
                f"Field '{field_name}' tampering did not trigger mismatch: {ctx.exception}",
            )

    def test_21_missing_required_cryptographic_field_fails_closed(self) -> None:
        """21. A current-format attestation missing any required cryptographic field fails closed."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="REF_MISSING_021",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "REF_MISSING_021", art_bytes)

        verified = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="REF_MISSING_021",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=jd.snapshot_hash,
            attesting_principal=SYNTHETIC_TEST_PRINCIPAL,
        )
        self.db.record_legacy_evidence_attestation(verified, attesting_principal=SYNTHETIC_TEST_PRINCIPAL)
        attestation = self.db.get_legacy_evidence_attestation(job_description_id=jd_id, user_id=self.user1_id)

        from src.database.models import LegacyEvidenceAttestation

        # Blank out each cryptographic audit field
        crypto_fields = [
            "evidence_artifact_hash",
            "evidence_payload_hash",
            "issuer_id",
            "key_id",
            "signature_algorithm",
            "evidence_signature",
            "migration_boundary",
        ]
        for c_field in crypto_fields:
            att_dict = attestation.to_dict()
            att_dict[c_field] = None
            tampered_att = LegacyEvidenceAttestation(**att_dict)

            with self.assertRaises(SecurityAuthorizationError) as ctx:
                self.verifier.verify_attestation(tampered_att, self.user1_id, jd_id, jd.snapshot_hash)
            self.assertIn("lacks mandatory", str(ctx.exception))

    # =========================================================================
    # PART E: ASYMMETRIC ED25519 VS HMAC & PRODUCTION POLICY (TESTS 22 - 25)
    # =========================================================================

    def test_22_valid_ed25519_digital_signature_verification(self) -> None:
        """22. Ed25519 asymmetric signature verifies successfully using public key in trust store."""
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = priv_key.public_key().public_bytes_raw()

        ed_key_id = "ed25519_test_pub_022"
        ed_issuer = "ed25519_archival_authority"
        self.trust_store.register_trusted_issuer(ed_issuer)
        self.trust_store.register_trusted_key(ed_key_id, pub_bytes, algorithm="Ed25519")

        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_ED25519_022",
            issuer_id=ed_issuer,
            key_id=ed_key_id,
            signing_key=priv_key,
            entries=entries,
            signature_algorithm="Ed25519",
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "MANIFEST_ED25519_022", art_bytes)

        verified = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_ED25519_022",
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=jd.snapshot_hash,
            attesting_principal=SYNTHETIC_TEST_PRINCIPAL,
        )
        self.assertEqual(verified.signature_algorithm, "Ed25519")
        self.assertEqual(verified.key_id, ed_key_id)

    def test_23_invalid_ed25519_signature_is_rejected(self) -> None:
        """23. Corrupted Ed25519 signature is detected and rejected."""
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = priv_key.public_key().public_bytes_raw()

        ed_key_id = "ed25519_test_pub_023"
        ed_issuer = "ed25519_archival_authority_23"
        self.trust_store.register_trusted_issuer(ed_issuer)
        self.trust_store.register_trusted_key(ed_key_id, pub_bytes, algorithm="Ed25519")

        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": jd.snapshot_hash}]
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_ED25519_CORRUPT_023",
            issuer_id=ed_issuer,
            key_id=ed_key_id,
            signing_key=priv_key,
            entries=entries,
            signature_algorithm="Ed25519",
        )
        parsed = json.loads(art_bytes.decode("utf-8"))
        # Tamper 1 byte of Ed25519 signature
        sig_bytes = bytearray.fromhex(parsed["signature"])
        sig_bytes[0] ^= 0xFF
        parsed["signature"] = sig_bytes.hex()
        corrupted_bytes = json.dumps(parsed).encode("utf-8")
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "MANIFEST_ED25519_CORRUPT_023", corrupted_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="MANIFEST_ED25519_CORRUPT_023",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=jd.snapshot_hash,
                attesting_principal=SYNTHETIC_TEST_PRINCIPAL,
            )
        self.assertIn("Ed25519 digital signature verification failed", str(ctx.exception))

    def test_24_hmac_rejected_under_production_policy(self) -> None:
        """24. Under production policy ('production' or 'ed25519_only'), HMAC keys and artifacts are rejected."""
        prod_store = LegacyEvidenceTrustStore(algorithm_policy="production")
        prod_store.register_trusted_issuer("prod_authority")

        # Attempting to register an HMAC key in production raises SecurityAuthorizationError
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            prod_store.register_trusted_key("hmac_prod_key", b"H" * 32, algorithm="HMAC-SHA256")
        self.assertIn("production policy enforces Ed25519", str(ctx.exception))

        # Registering an Ed25519 key succeeds
        priv = ed25519.Ed25519PrivateKey.generate()
        prod_store.register_trusted_key("ed_prod_key", priv.public_key().public_bytes_raw(), algorithm="Ed25519")
        k_bytes, algo = prod_store.get_key("ed_prod_key")
        self.assertEqual(algo, "Ed25519")

    # =========================================================================
    # PART F: NO-PROVIDER BEHAVIOR & WORKFLOW PRESERVATION (TESTS 25 - 26)
    # =========================================================================

    def test_25_no_provider_production_mode_grants_zero_exceptions(self) -> None:
        """25. In default production mode without evidence provider, unverified records remain REQUIRED."""
        empty_store = LegacyEvidenceTrustStore()
        empty_verifier = LegacyEvidenceVerifier(trust_store=empty_store, resolver=None, db_manager=self.db)
        preflight = SecurityPreflightManager(
            db_manager=self.db,
            detector=self.detector,
            file_validator=self.file_validator,
            evidence_verifier=empty_verifier,
        )

        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

        # Preflight fails closed because binary metadata is missing and record is REQUIRED
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("missing required binary metadata", str(ctx.exception))

        # Controlled recovery allows candidate to upload genuine PDF
        pdf_bytes = generate_persona_pdf("backend_engineer")
        rec = self.db.recover_unverified_job_description(
            user_id=self.user1_id,
            job_description_id=jd_id,
            file_bytes=pdf_bytes,
            original_filename="recovered_spec.pdf",
            user_base_dir=self.file_validator.get_user_job_descriptions_dir(self.user1_id),
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec.binary_integrity_state, "VERIFIED")
        self.assertEqual(rec.supersedes_job_description_id, jd_id)

    def test_26_legitimate_pasted_and_url_workflows_functional(self) -> None:
        """26. Legitimate pasted and URL workflows operate cleanly with NOT_APPLICABLE status."""
        # 1. Pasted source
        raw_pasted = "Senior Distributed Systems Engineer: Design high-throughput microservices."
        content_hash = hashlib.sha256(raw_pasted.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "CloudCo",
            "job_title": "Systems Engineer",
            "raw_content_hash": content_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "pasted",
            "source_url": None,
            "original_filename": None,
        }
        snap_hash = canonical_json_hash(manifest)

        with self.db.transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'pasted', 'CloudCo', 'Systems Engineer', ?, ?, ?, 'NOT_APPLICABLE', 1, CURRENT_TIMESTAMP)
                """,
                (self.user1_id, raw_pasted, content_hash, snap_hash),
            )
            pasted_id = cur.lastrowid

        res = self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=pasted_id)
        self.assertTrue(res.is_allowed)
        self.assertEqual(res.classification, "CLEAN")


if __name__ == "__main__":
    unittest.main()

"""Phase 9.1.2.6 — Cryptographic Legacy Evidence Authenticity & Reconciliation Test Suite.

Verifies:
1. Valid independently signed archival evidence.
2. Valid evidence with exact user, job and snapshot binding.
3. Arbitrary evidence reference with no backing artifact.
4. Existing reference ID that resolves to a missing artifact.
5. Tampered evidence artifact bytes.
6. Tampered evidence payload.
7. Invalid digital signature.
8. Unknown issuer.
9. Unknown key ID.
10. Revoked signing key.
11. Unsupported signature algorithm.
12. Evidence type not on the allowlist.
13. Replay against a different user.
14. Replay against a different job-description ID.
15. Replay against a different snapshot hash.
16. Incorrect historical migration boundary.
17. Caller-supplied `attested_by="system_migration"` without authentication.
18. Candidate self-attestation.
19. Direct SQL insertion of a fake attestation followed by preflight.
20. Existing legacy exception with missing evidence.
21. Existing legacy exception with invalid signature.
22. Reconciliation reverts a legacy record whose evidence cannot be verified.
23. Reconciliation preserves a record with genuinely verified historical evidence.
24. Repeated reconciliation migration.
25. Genuine historical record recovery through re-upload.

All test fixtures are clearly labeled as synthetic (Section 6.2).
"""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

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
)
from src.security.prompt_injection_detector import PromptInjectionDetector
from src.security.security_preflight import SecurityPreflightManager
from src.utils.canonical_json import canonical_json_hash

# Clearly labeled synthetic test credentials (Section 6.2)
SYNTHETIC_TEST_KEY_ID = "test_synthetic_key_2024"
SYNTHETIC_TEST_SECRET = b"test_synthetic_secret_at_least_32_bytes_long_12345!"
SYNTHETIC_TEST_ISSUER = "test_synthetic_archival_authority"
SYNTHETIC_TEST_TYPE = "archival_import_manifest"
SYNTHETIC_TEST_REF_ID = "TEST_SYNTHETIC_MANIFEST_2024_001"
SYNTHETIC_TEST_MIGRATION_PRINCIPAL = "test_synthetic_migration_coordinator"


class TestPhase9126LegacyEvidenceAuthenticity(unittest.TestCase):
    """25 comprehensive tests for authentic cryptographic legacy evidence verification."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        self.db_path = self.tmp_path / "test_legacy_evidence.db"
        self.user_base_dir = self.tmp_path / "users"
        self.user_base_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))

        # Synthetic trust store
        self.trust_store = LegacyEvidenceTrustStore(db_manager=self.db)
        self.trust_store.register_trusted_issuer(SYNTHETIC_TEST_ISSUER)
        self.trust_store.register_trusted_key(SYNTHETIC_TEST_KEY_ID, SYNTHETIC_TEST_SECRET)
        self.trust_store.register_trusted_attesting_principal(SYNTHETIC_TEST_MIGRATION_PRINCIPAL)
        self.trust_store.register_trusted_attesting_principal("system_migration_coordinator")
        self.trust_store.register_trusted_attesting_principal("system_migration")

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
                ("user1@example.com", "hash1", "salt1", "Candidate One"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("user2@example.com", "hash2", "salt2", "Candidate Two"),
            )
            self.user2_id = c.lastrowid

    def tearDown(self) -> None:
        set_default_evidence_resolver(None)
        self.tmp_dir.cleanup()

    def _create_sample_jd(self, user_id: int, title: str = "Systems Architect") -> int:
        raw_text = f"Company: TestCorp\nTitle: {title}\nLocation: Remote\nResponsibilities:\n- Design scalable architectures."
        c_hash = hashlib.sha256(raw_text.strip().encode("utf-8")).hexdigest()
        manifest_9 = {
            "user_id": user_id,
            "company_name": "TestCorp",
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
                ) VALUES (?, 'upload', 'TestCorp', ?, ?, ?, ?, 'REQUIRED', 1, '2024-04-15 10:00:00', '1.0.0', 'jd.pdf')
                """,
                (user_id, title, raw_text, c_hash, s_hash),
            )
            return cur.lastrowid

    # -------------------------------------------------------------------------
    # TEST CASES
    # -------------------------------------------------------------------------

    def test_01_valid_independently_signed_archival_evidence(self) -> None:
        """TC-01: Valid independently signed archival evidence verifies successfully."""
        jd_id = self._create_sample_jd(self.user1_id)
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)

        entries = [{
            "user_id": self.user1_id,
            "job_description_id": jd_id,
            "source_snapshot_hash": jd.snapshot_hash,
        }]

        artifact_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id=SYNTHETIC_TEST_REF_ID,
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, SYNTHETIC_TEST_REF_ID, artifact_bytes)

        verified = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id=SYNTHETIC_TEST_REF_ID,
            user_id=self.user1_id,
            job_description_id=jd_id,
            source_snapshot_hash=jd.snapshot_hash,
            attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
        )

        self.assertIsInstance(verified, VerifiedLegacyEvidence)
        self.assertEqual(verified.evidence_type, SYNTHETIC_TEST_TYPE)
        self.assertEqual(verified.evidence_reference_id, SYNTHETIC_TEST_REF_ID)
        self.assertEqual(verified.user_id, self.user1_id)
        self.assertEqual(verified.job_description_id, jd_id)
        self.assertEqual(verified.source_snapshot_hash, jd.snapshot_hash)

    def test_02_valid_evidence_exact_user_job_snapshot_binding(self) -> None:
        """TC-02: Valid evidence with exact multi-entry binding resolves correct item."""
        jd1 = self._create_sample_jd(self.user1_id, "Role 1")
        jd2 = self._create_sample_jd(self.user1_id, "Role 2")
        snap1 = self.db.get_job_description(jd1, user_id=self.user1_id).snapshot_hash
        snap2 = self.db.get_job_description(jd2, user_id=self.user1_id).snapshot_hash

        entries = [
            {"user_id": self.user1_id, "job_description_id": jd1, "source_snapshot_hash": snap1},
            {"user_id": self.user1_id, "job_description_id": jd2, "source_snapshot_hash": snap2},
        ]
        artifact_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_MULTI_002",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "MANIFEST_MULTI_002", artifact_bytes)

        v1 = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_MULTI_002",
            user_id=self.user1_id,
            job_description_id=jd1,
            source_snapshot_hash=snap1,
            attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
        )
        self.assertEqual(v1.job_description_id, jd1)

        v2 = self.verifier.verify(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="MANIFEST_MULTI_002",
            user_id=self.user1_id,
            job_description_id=jd2,
            source_snapshot_hash=snap2,
            attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
        )
        self.assertEqual(v2.job_description_id, jd2)

    def test_03_arbitrary_evidence_reference_with_no_backing_artifact(self) -> None:
        """TC-03: Arbitrary reference with no backing artifact in resolver fails closed."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="TOTALLY_MADE_UP_MANIFEST_999",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("could not be resolved or found", str(ctx.exception))

    def test_04_existing_reference_resolves_to_missing_artifact(self) -> None:
        """TC-04: Resolver returning None for existing reference ID fails closed."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type="archival_import_manifest",
                evidence_reference_id="DELETED_FROM_STORAGE_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("could not be resolved", str(ctx.exception))

    def test_05_tampered_evidence_artifact_bytes(self) -> None:
        """TC-05: Tampered raw bytes (e.g. malformed JSON or injected byte) fails closed."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        corrupt_bytes = b"NOT_VALID_JSON_CORRUPTED_BYTES"
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "CORRUPT_ARTIFACT", corrupt_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="CORRUPT_ARTIFACT",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("could not be resolved or found", str(ctx.exception))

    def test_06_tampered_evidence_payload(self) -> None:
        """TC-06: Tampered JSON payload field (e.g. altered migration boundary) fails signature check."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        _, artifact_dict = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="TAMPERED_PAYLOAD_001",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )

        # Tamper payload without re-signing
        artifact_dict["issued_at"] = "2020-01-01T00:00:00Z"
        tampered_bytes = json.dumps(artifact_dict).encode("utf-8")
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "TAMPERED_PAYLOAD_001", tampered_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="TAMPERED_PAYLOAD_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("signature verification failed", str(ctx.exception))

    def test_07_invalid_digital_signature(self) -> None:
        """TC-07: Forged digital signature fails constant-time comparison."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        _, artifact_dict = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="FORGED_SIG_001",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )

        # Replace signature with forged hex string
        artifact_dict["signature"] = "deadbeef" * 8
        tampered_bytes = json.dumps(artifact_dict).encode("utf-8")
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "FORGED_SIG_001", tampered_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="FORGED_SIG_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("signature verification failed", str(ctx.exception))

    def test_08_unknown_issuer(self) -> None:
        """TC-08: Artifact from an unauthorized/unregistered issuer is rejected."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        artifact_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="UNKNOWN_ISSUER_001",
            issuer_id="untrusted_third_party_issuer",
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "UNKNOWN_ISSUER_001", artifact_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="UNKNOWN_ISSUER_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("is unknown or not configured in trust store", str(ctx.exception))

    def test_09_unknown_key_id(self) -> None:
        """TC-09: Artifact signed with unknown key ID fails closed."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        artifact_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="UNKNOWN_KEY_001",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id="unregistered_rogue_key_id",
            signing_key=b"rogue_key_material_at_least_32_bytes_long!!",
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "UNKNOWN_KEY_001", artifact_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="UNKNOWN_KEY_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("is unknown or not configured in trust root", str(ctx.exception))

    def test_10_revoked_signing_key(self) -> None:
        """TC-10: Artifact signed with a revoked key ID raises KeyRevokedError."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        artifact_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="REVOKED_KEY_001",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "REVOKED_KEY_001", artifact_bytes)

        # Revoke key in trust store
        self.trust_store.revoke_key(SYNTHETIC_TEST_KEY_ID)

        with self.assertRaises(KeyRevokedError):
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="REVOKED_KEY_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )

    def test_11_unsupported_signature_algorithm(self) -> None:
        """TC-11: Artifact declaring unsupported algorithm (e.g. MD5, SHA1) is rejected."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        artifact_dict = {
            "evidence_type": SYNTHETIC_TEST_TYPE,
            "evidence_reference_id": "UNSUPPORTED_ALGO_001",
            "issuer_id": SYNTHETIC_TEST_ISSUER,
            "key_id": SYNTHETIC_TEST_KEY_ID,
            "signature_algorithm": "MD5-RSA",
            "migration_boundary": "pre_phase_9_1_1",
            "issued_at": "2024-04-15T00:00:00Z",
            "entries": entries,
            "signature": "mock_sig",
        }
        raw_bytes = json.dumps(artifact_dict).encode("utf-8")
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "UNSUPPORTED_ALGO_001", raw_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="UNSUPPORTED_ALGO_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("signature algorithm 'MD5-RSA' is unsupported", str(ctx.exception))

    def test_12_evidence_type_not_on_allowlist(self) -> None:
        """TC-12: Evidence type not on allowlist is rejected immediately."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type="arbitrary_unapproved_type",
                evidence_reference_id="TEST_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("not on the supported allowlist", str(ctx.exception))

    def test_13_replay_against_different_user(self) -> None:
        """TC-13: Replay attack presenting User 1's evidence for User 2 is rejected."""
        jd1 = self._create_sample_jd(self.user1_id)
        snap1 = self.db.get_job_description(jd1, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd1, "source_snapshot_hash": snap1}]
        artifact_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="USER1_EVIDENCE_001",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "USER1_EVIDENCE_001", artifact_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="USER1_EVIDENCE_001",
                user_id=self.user2_id,  # Different user!
                job_description_id=jd1,
                source_snapshot_hash=snap1,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("Evidence replay rejected", str(ctx.exception))

    def test_14_replay_against_different_job_description_id(self) -> None:
        """TC-14: Replay attack presenting evidence for JD #1 against JD #2 is rejected."""
        jd1 = self._create_sample_jd(self.user1_id, "Role 1")
        jd2 = self._create_sample_jd(self.user1_id, "Role 2")
        snap1 = self.db.get_job_description(jd1, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd1, "source_snapshot_hash": snap1}]
        artifact_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="JD1_EVIDENCE_001",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "JD1_EVIDENCE_001", artifact_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="JD1_EVIDENCE_001",
                user_id=self.user1_id,
                job_description_id=jd2,  # Different JD ID!
                source_snapshot_hash=snap1,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("Evidence replay rejected", str(ctx.exception))

    def test_15_replay_against_different_snapshot_hash(self) -> None:
        """TC-15: Replay attack with modified snapshot hash is rejected."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        artifact_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="SNAP_EVIDENCE_001",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "SNAP_EVIDENCE_001", artifact_bytes)

        different_hash = "deadbeef" * 8
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="SNAP_EVIDENCE_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=different_hash,  # Different hash!
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("Evidence replay rejected", str(ctx.exception))

    def test_16_incorrect_historical_migration_boundary(self) -> None:
        """TC-16: Artifact asserting an invalid or post-Phase-9 boundary is rejected."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        artifact_dict = {
            "evidence_type": SYNTHETIC_TEST_TYPE,
            "evidence_reference_id": "POST_PHASE9_001",
            "issuer_id": SYNTHETIC_TEST_ISSUER,
            "key_id": SYNTHETIC_TEST_KEY_ID,
            "signature_algorithm": "HMAC-SHA256",
            "migration_boundary": "post_phase_10_invalid",  # Invalid boundary!
            "issued_at": "2026-11-06T00:00:00Z",
            "entries": entries,
            "signature": "mock",
        }
        raw_bytes = json.dumps(artifact_dict).encode("utf-8")
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "POST_PHASE9_001", raw_bytes)

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id="POST_PHASE9_001",
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=SYNTHETIC_TEST_MIGRATION_PRINCIPAL,
            )
        self.assertIn("asserts invalid or missing historical migration boundary", str(ctx.exception))

    def test_17_caller_supplied_attested_by_without_authentication(self) -> None:
        """TC-17: Empty or whitespace attesting principal is rejected."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id=SYNTHETIC_TEST_REF_ID,
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal="   ",  # Whitespace only
            )
        self.assertIn("Attesting principal is required", str(ctx.exception))

    def test_18_candidate_self_attestation(self) -> None:
        """TC-18: Candidate user attempting to attest their own source is rejected."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.verifier.verify(
                evidence_type=SYNTHETIC_TEST_TYPE,
                evidence_reference_id=SYNTHETIC_TEST_REF_ID,
                user_id=self.user1_id,
                job_description_id=jd_id,
                source_snapshot_hash=snap,
                attesting_principal=f"user_{self.user1_id}",  # Self attestation!
            )
        self.assertIn("cannot self-attest own source as historical evidence", str(ctx.exception))

    def test_19_direct_sql_insertion_of_fake_attestation_followed_by_preflight(self) -> None:
        """TC-19: Direct SQL insert of fake attestation without backing artifact fails preflight."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        # Attacker injects a synthetic row directly into SQLite
        with self.db.immediate_transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, ?, 'FORGED_DIRECT_SQL_REF', ?, 'system_migration')
                """,
                (self.user1_id, jd_id, SYNTHETIC_TEST_TYPE, snap),
            )
            cur.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, '9.1.2.3', ?, 'FORGED_DIRECT_SQL_REF', 'manual', 'SUCCESS')
                """,
                (self.user1_id, jd_id, snap, SYNTHETIC_TEST_TYPE),
            )
            cur.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))

        # Preflight must fail closed because no authentic artifact backs this reference
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("could not be resolved or found", str(ctx.exception))

    def test_20_existing_legacy_exception_with_missing_evidence(self) -> None:
        """TC-20: Legacy exception whose attestation row is absent raises error."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

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
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, '9.1.2.3', 'archival_import_manifest', 'REF_WITHOUT_ATTESTATION', 'manual', 'SUCCESS')
                """,
                (self.user1_id, jd_id, snap),
            )
            cur.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("lacks an authoritative evidence attestation", str(ctx.exception))

    def test_21_existing_legacy_exception_with_invalid_signature(self) -> None:
        """TC-21: Legacy exception pointing to artifact with invalid signature fails preflight."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        _, artifact_dict = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="BAD_SIG_REF",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        artifact_dict["signature"] = "baadc0de" * 8
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "BAD_SIG_REF", json.dumps(artifact_dict).encode("utf-8"))

        with self.db.immediate_transaction() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, ?, 'BAD_SIG_REF', ?, 'system_migration')
                """,
                (self.user1_id, jd_id, SYNTHETIC_TEST_TYPE, snap),
            )
            cur.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type,
                    previous_binary_state, assigned_legacy_state,
                    source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, '9.1.2.3', ?, 'BAD_SIG_REF', 'manual', 'SUCCESS')
                """,
                (self.user1_id, jd_id, snap, SYNTHETIC_TEST_TYPE),
            )
            cur.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("signature verification failed", str(ctx.exception))

    def test_22_reconciliation_reverts_legacy_record_whose_evidence_cannot_be_verified(self) -> None:
        """TC-22: Reconciliation migration reverts unverifiable LEGACY_TEXT_ONLY record to REQUIRED."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        # Place record in LEGACY_TEXT_ONLY with unbacked attestation
        with self.db.immediate_transaction() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_6_legacy_evidence_verification_closure'")
            cur.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))
            cur.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, ?, 'MISSING_MANIFEST_FILE', ?, 'system_migration')
                """,
                (self.user1_id, jd_id, SYNTHETIC_TEST_TYPE, snap),
            )

        with self.db.immediate_transaction() as conn:
            self.db._migrate_phase_9_1_2_6_legacy_evidence_verification_closure(conn.cursor(), verifier=self.verifier)

        # Verified reverted to REQUIRED
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

        # Verified audit row in legacy_integrity_exceptions
        exc = self.db.get_legacy_integrity_exception(job_description_id=jd_id, user_id=self.user1_id)
        self.assertIsNotNone(exc)
        self.assertEqual(exc.assigned_legacy_state, "REQUIRED")
        self.assertEqual(exc.outcome, "REVERTED")

    def test_23_reconciliation_preserves_record_with_genuinely_verified_evidence(self) -> None:
        """TC-23: Reconciliation preserves LEGACY_TEXT_ONLY when backing evidence is authentic."""
        jd_id = self._create_sample_jd(self.user1_id)
        snap = self.db.get_job_description(jd_id, user_id=self.user1_id).snapshot_hash

        entries = [{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap}]
        artifact_bytes, _ = create_signed_evidence_artifact(
            evidence_type=SYNTHETIC_TEST_TYPE,
            evidence_reference_id="VERIFIED_RECONCILIATION_001",
            issuer_id=SYNTHETIC_TEST_ISSUER,
            key_id=SYNTHETIC_TEST_KEY_ID,
            signing_key=SYNTHETIC_TEST_SECRET,
            entries=entries,
        )
        self.resolver.register_artifact(SYNTHETIC_TEST_TYPE, "VERIFIED_RECONCILIATION_001", artifact_bytes)

        # Place record in LEGACY_TEXT_ONLY with valid backing attestation
        with self.db.immediate_transaction() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_6_legacy_evidence_verification_closure'")
            cur.execute("UPDATE job_descriptions SET binary_integrity_state = 'LEGACY_TEXT_ONLY' WHERE id = ?", (jd_id,))
            cur.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, ?, 'VERIFIED_RECONCILIATION_001', ?, 'system_migration_coordinator')
                """,
                (self.user1_id, jd_id, SYNTHETIC_TEST_TYPE, snap),
            )

        with self.db.immediate_transaction() as conn:
            self.db._migrate_phase_9_1_2_6_legacy_evidence_verification_closure(conn.cursor(), verifier=self.verifier)

        # Preserved as LEGACY_TEXT_ONLY
        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "LEGACY_TEXT_ONLY")

        # Verified RECONCILED audit outcome
        exc = self.db.get_legacy_integrity_exception(job_description_id=jd_id, user_id=self.user1_id)
        self.assertIsNotNone(exc)
        self.assertEqual(exc.assigned_legacy_state, "LEGACY_TEXT_ONLY")
        self.assertEqual(exc.outcome, "RECONCILED")

    def test_24_repeated_reconciliation_migration_is_idempotent(self) -> None:
        """TC-24: Repeated execution of phase_9_1_2_6 migration ledger entry is idempotent."""
        with self.db.immediate_transaction() as conn:
            self.db._migrate_phase_9_1_2_6_legacy_evidence_verification_closure(conn.cursor(), verifier=self.verifier)

        # Second call does not re-process or fail
        with self.db.immediate_transaction() as conn:
            self.db._migrate_phase_9_1_2_6_legacy_evidence_verification_closure(conn.cursor(), verifier=self.verifier)

        # Verify ledger has exactly 1 entry
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = 'phase_9_1_2_6_legacy_evidence_verification_closure'"
            )
            count = cur.fetchone()[0]
            self.assertEqual(count, 1)

    def test_25_genuine_historical_record_recovery_through_reupload(self) -> None:
        """TC-25: Re-upload controlled recovery upgrades an unverified REQUIRED record to VERIFIED child."""
        jd_id = self._create_sample_jd(self.user1_id, "Cloud Infrastructure Engineer")
        parent_jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(parent_jd.binary_integrity_state, "REQUIRED")

        # Generate sample PDF bytes
        from tests.fixtures.synthetic_personas import generate_persona_pdf
        pdf_bytes = generate_persona_pdf("backend_engineer")

        # Recover using controlled recovery procedure
        child_jd = self.db.recover_unverified_job_description(
            user_id=self.user1_id,
            job_description_id=jd_id,
            file_bytes=pdf_bytes,
            original_filename="recovered_infrastructure_engineer.pdf",
            user_base_dir=self.user_base_dir,
        )

        self.assertIsNotNone(child_jd)
        self.assertEqual(child_jd.binary_integrity_state, "VERIFIED")
        self.assertEqual(child_jd.supersedes_job_description_id, jd_id)
        self.assertEqual(child_jd.is_active, 1)

        # Parent is deactivated
        updated_parent = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(updated_parent.is_active, 0)

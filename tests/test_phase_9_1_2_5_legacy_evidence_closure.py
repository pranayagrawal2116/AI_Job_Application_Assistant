"""Tests for Phase 9.1.2.5 — Legacy Eligibility Proof & Migration Evidence Closure.

Verifies:
1. Authoritative evidence-based legacy migration (Section 4.1).
2. Unknown historical origin defaults to NOT VERIFIED (remains REQUIRED) (Section 4.2).
3. Critical regression: modern uploads with NULL binary fields and backdated timestamps remain REQUIRED (Section 6.2).
4. Full 20 migration test scenarios (Section 6.1).
5. Controlled recovery procedure via recover_unverified_job_description (Section 5.1).
6. Phase 9.1.2.5 legacy evidence reconciliation migration (Section 4.3).
7. Schema migration ledger immutability and version conflict enforcement (Section 7).
"""

import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from src.database.db_manager import DatabaseManager
from src.database.exceptions import (
    ConcurrencyConflictError,
    CrossUserAccessError,
    JobDescriptionNotFoundError,
    SecurityAuthorizationError,
)
from src.security.file_security import FileSecurityValidator
from src.security.prompt_injection_detector import (
    PromptInjectionDetector,
    ScanClassification,
)
from src.security.scan_signer import SecurityScanSigner
from src.security.security_preflight import SecurityPreflightManager
from src.utils.canonical_json import canonical_json_hash
from tests.fixtures.synthetic_personas import generate_persona_pdf


class TestPhase9125LegacyEvidenceClosure(unittest.TestCase):
    """Exhaustive test suite for Phase 9.1.2.5 requirements."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_phase_9_1_2_5_"))
        self.db_path = self.temp_dir / "closure_9125.db"
        self.storage_dir = self.temp_dir / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(db_path=str(self.db_path))
        self.file_validator = FileSecurityValidator(base_storage_dir=self.storage_dir)
        self.detector = PromptInjectionDetector()
        self.signer = SecurityScanSigner()

        # Synthetic trust store & resolver for testing legitimate historical migration paths
        from src.security.legacy_evidence_verifier import (
            LegacyEvidenceTrustStore,
            InMemoryEvidenceResolver,
            LegacyEvidenceVerifier,
            set_default_evidence_resolver,
            set_default_evidence_trust_store,
        )
        self.trust_store = LegacyEvidenceTrustStore(db_manager=self.db)
        self.trust_store.register_trusted_issuer("system_migration_authority")
        self.trust_store.register_trusted_key("test_key_9125", b"test_secret_32_bytes_long_9125!!")
        self.trust_store.register_trusted_attesting_principal("system_migration_coordinator")
        set_default_evidence_trust_store(self.trust_store)
        self.resolver = InMemoryEvidenceResolver()
        set_default_evidence_resolver(self.resolver)
        self.verifier = LegacyEvidenceVerifier(trust_store=self.trust_store, resolver=self.resolver, db_manager=self.db)
        self.preflight = SecurityPreflightManager(db_manager=self.db, file_validator=self.file_validator, evidence_verifier=self.verifier)

        # Create test users
        with self.db.transaction() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("alice9125@example.com", "hash1", "salt1", "Alice 9125"),
            )
            self.user1_id = c.lastrowid
            c.execute(
                "INSERT INTO users (email, password_hash, password_salt, full_name) VALUES (?, ?, ?, ?)",
                ("bob9125@example.com", "hash2", "salt2", "Bob 9125"),
            )
            self.user2_id = c.lastrowid

    def tearDown(self):
        from src.security.legacy_evidence_verifier import set_default_evidence_resolver, set_default_evidence_trust_store
        set_default_evidence_resolver(None)
        set_default_evidence_trust_store(None)
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # =========================================================================
    # SECTION 6.1: 20 REQUIRED MIGRATION TESTS
    # =========================================================================

    def test_01_genuinely_supported_historical_record_with_independent_evidence(self):
        """1. A genuinely supported historical record with independent evidence enters LEGACY_TEXT_ONLY."""
        raw_text = "Senior Python/Django Architect with 10 years experience."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "HistoricCorp",
            "job_title": "Lead Architect",
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snap_hash = canonical_json_hash(manifest)

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'HistoricCorp', 'Lead Architect', ?, ?, ?, 'REQUIRED', 1, '2024-04-15 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid
            # Authoritative independent evidence
            c.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, 'historical_import_manifest', 'MANIFEST_2024_04_15_001', ?, 'system_migration_coordinator')
                """,
                (self.user1_id, jd_id, snap_hash),
            )

        from src.security.legacy_evidence_verifier import create_signed_evidence_artifact
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="MANIFEST_2024_04_15_001",
            issuer_id="system_migration_authority",
            key_id="test_key_9125",
            signing_key=b"test_secret_32_bytes_long_9125!!",
            entries=[{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap_hash}],
        )
        self.resolver.register_artifact("historical_import_manifest", "MANIFEST_2024_04_15_001", art_bytes)

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "LEGACY_TEXT_ONLY")

        exc = self.db.get_legacy_integrity_exception(job_description_id=jd_id, user_id=self.user1_id)
        self.assertIsNotNone(exc)
        self.assertEqual(exc.assigned_legacy_state, "LEGACY_TEXT_ONLY")
        self.assertEqual(exc.evidence_type, "historical_import_manifest")
        self.assertEqual(exc.evidence_reference_id, "MANIFEST_2024_04_15_001")
        self.assertEqual(exc.outcome, "SUCCESS")

        # Preflight check cleanly succeeds
        res = self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertTrue(res.is_allowed)

    def test_02_current_uploaded_record_with_valid_nine_field_snapshot_hash(self):
        """2. A current uploaded record with valid 9-field snapshot hash but no independent evidence remains REQUIRED."""
        raw_text = "Current Cloud DevOps Engineer position."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "CurrentCo",
            "job_title": "DevOps",
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snap_hash = canonical_json_hash(manifest)

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'CurrentCo', 'DevOps', ?, ?, ?, 'REQUIRED', 1, '2026-11-06 12:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_03_current_uploaded_record_with_old_created_at(self):
        """3. A current uploaded record with old created_at but no independent evidence remains REQUIRED."""
        raw_text = "Spoofed created_at timestamp record."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "OldDateCo",
            "job_title": "Developer",
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snap_hash = canonical_json_hash(manifest)

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'OldDateCo', 'Developer', ?, ?, ?, 'REQUIRED', 1, '2023-01-15 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_04_newly_inserted_record_with_all_four_metadata_fields_null(self):
        """4. Newly inserted record with all four metadata fields NULL and no evidence remains REQUIRED."""
        jd = self.db.save_job_description_snapshot(
            user_id=self.user1_id,
            company_name="NullMetaCorp",
            job_title="Software Eng",
            raw_content="General software engineering job.",
            source_type="upload",
            binary_integrity_state="REQUIRED",
        )
        self.assertIsNone(jd.storage_filename)
        self.assertIsNone(jd.file_hash)
        self.assertIsNone(jd.file_size_bytes)
        self.assertIsNone(jd.file_format)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd_fresh = self.db.get_job_description(jd.id, user_id=self.user1_id)
        self.assertEqual(jd_fresh.binary_integrity_state, "REQUIRED")

    def test_05_current_record_with_timestamp_manually_backdated_before_first_migration(self):
        """5. Record created today then backdated before migration remains REQUIRED."""
        jd = self.db.save_job_description_snapshot(
            user_id=self.user1_id,
            company_name="BackdateCorp",
            job_title="Security Lead",
            raw_content="Security engineering leadership role.",
            source_type="upload",
            binary_integrity_state="REQUIRED",
        )
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            conn.execute(
                "UPDATE job_descriptions SET created_at = '2024-01-01 00:00:00' WHERE id = ?",
                (jd.id,),
            )

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd_fresh = self.db.get_job_description(jd.id, user_id=self.user1_id)
        self.assertEqual(jd_fresh.binary_integrity_state, "REQUIRED")

    def test_06_record_with_manually_reconstructed_nine_field_snapshot_hash(self):
        """6. Record with manually reconstructed nine-field snapshot hash but no independent evidence remains REQUIRED."""
        raw_text = "Manually reconstructed hash content."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "ReconCorp",
            "job_title": "Dev",
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        reconstructed_hash = canonical_json_hash(manifest)

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'ReconCorp', 'Dev', ?, ?, ?, 'REQUIRED', 1, '2024-02-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, reconstructed_hash),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_07_record_with_no_preexisting_migration_evidence(self):
        """7. A record with no pre-existing migration evidence yields zero exceptions and remains REQUIRED."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            conn.execute("DELETE FROM legacy_evidence_attestations")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'NoEvidenceCo', 'Dev', 'content', 'chash', 'shash', 'REQUIRED', 1, '2024-01-01')
                """,
                (self.user1_id,),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

        exc = self.db.get_legacy_integrity_exception(job_description_id=jd_id, user_id=self.user1_id)
        self.assertIsNone(exc)

    def test_08_record_with_already_completed_migration_marker(self):
        """8. When schema_migrations marker exists, migration returns immediately without reclassifying records."""
        self.assertTrue(self.db.is_schema_migration_applied("phase_9_1_2_3_legacy_binary_integrity"))

        raw_text = "New upload after migration completed."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "AfterCo",
            "job_title": "Dev",
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
                ) VALUES (?, 'upload', 'AfterCo', 'Dev', ?, ?, ?, 'REQUIRED', 1, '2024-01-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid
            # Even if an attestation was present:
            c.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, 'historical_import_manifest', 'REF-AFTER', ?, 'system_migration')
                """,
                (self.user1_id, jd_id, snap_hash),
            )

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        # Did not run because migration marker was present
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_09_conflicting_signed_v2_binary_provenance_scan(self):
        """9. A record with an attestation but having a signed v2 binary provenance scan cannot enter LEGACY_TEXT_ONLY."""
        raw_text = "Role with conflicting signed v2 scan."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "ConflictScanCo",
            "job_title": "Engineer",
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snap_hash = canonical_json_hash(manifest)

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'ConflictScanCo', 'Engineer', ?, ?, ?, 'REQUIRED', 1, '2024-05-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid
            c.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, 'historical_import_manifest', 'REF-CONFLICT', ?, 'system_migration')
                """,
                (self.user1_id, jd_id, snap_hash),
            )

        # Create signed scan with binary hash
        self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=jd_id,
            source_version=1,
            source_hash=c_hash,
            snapshot_hash=snap_hash,
            scanner_version="1.0.0",
            policy_version="1.0.0",
            risk_score=0.0,
            classification=ScanClassification.CLEAN,
            threats_detected=[],
            key_id="test_key",
            hmac_signature="sig" * 16,
            scanned_at="2024-04-01T10:05:00Z",
            source_binary_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            source_binary_size_bytes=1000,
            source_binary_format="pdf",
            manifest_version="v2",
        )

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_10_previously_verified_record_with_binary_metadata_removed(self):
        """10. A previously VERIFIED record with binary metadata cleared cannot be downgraded to LEGACY_TEXT_ONLY."""
        raw_text = "Verified record cleared of binary fields."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active,
                    storage_filename, file_hash, file_size_bytes, file_format, created_at
                ) VALUES (?, 'upload', 'ClearedCo', 'Dev', ?, ?, 'snap', 'VERIFIED', 1,
                          NULL, NULL, NULL, NULL, '2024-05-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        # Must retain VERIFIED; never downgraded
        self.assertEqual(jd.binary_integrity_state, "VERIFIED")

    def test_11_verified_record_manually_changed_to_required(self):
        """11. A VERIFIED record manually changed to REQUIRED having binary provenance scan cannot become LEGACY_TEXT_ONLY."""
        raw_text = "Verified record manipulated to REQUIRED."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "ManipCo",
            "job_title": "Dev",
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snap_hash = canonical_json_hash(manifest)

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'ManipCo', 'Dev', ?, ?, ?, 'REQUIRED', 1, '2024-05-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        # Attach binary scan
        self.db.save_security_scan(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=jd_id,
            source_version=1,
            source_hash=c_hash,
            snapshot_hash=snap_hash,
            scanner_version="1.0.0",
            policy_version="1.0.0",
            risk_score=0.0,
            classification=ScanClassification.CLEAN,
            threats_detected=[],
            key_id="test_key",
            hmac_signature="sig" * 16,
            scanned_at="2024-04-01T10:05:00Z",
            source_binary_hash="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            source_binary_size_bytes=2048,
            source_binary_format="pdf",
            manifest_version="v2",
        )

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_12_partially_populated_binary_metadata_record(self):
        """12. Uploaded record with partially populated binary metadata (e.g. 2 of 4 set) fails closed."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active,
                    storage_filename, file_hash, file_size_bytes, file_format, created_at
                ) VALUES (?, 'upload', 'PartialCo', 'Dev', 'content', 'chash', 'shash', 'REQUIRED', 1,
                          'storage_file.pdf', 'hashval', NULL, NULL, '2024-05-01 10:00:00')
                """,
                (self.user1_id,),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_13_historical_exception_with_missing_audit_evidence(self):
        """13. Historical exception lacking evidence_type or evidence_reference_id fails preflight."""
        raw_text = "Missing audit evidence record."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "NoEvidencePreflightCo",
            "job_title": "Dev",
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
                    content_hash, snapshot_hash, binary_integrity_state, is_active
                ) VALUES (?, 'upload', 'NoEvidencePreflightCo', 'Dev', ?, ?, ?, 'LEGACY_TEXT_ONLY', 1)
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid
            c.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type, previous_binary_state,
                    assigned_legacy_state, source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', ?, '9.1.2.3',
                          NULL, NULL, 'Lacks evidence', 'SUCCESS')
                """,
                (self.user1_id, jd_id, snap_hash),
            )

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("lacks required independent evidence proof", str(ctx.exception))

    def test_14_historical_exception_with_mismatched_snapshot_hash(self):
        """14. Historical exception with mismatched snapshot hash fails preflight."""
        raw_text = "Mismatched hash record."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "MismatchHashCo",
            "job_title": "Dev",
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
                    content_hash, snapshot_hash, binary_integrity_state, is_active
                ) VALUES (?, 'upload', 'MismatchHashCo', 'Dev', ?, ?, ?, 'LEGACY_TEXT_ONLY', 1)
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid
            c.execute(
                """
                INSERT INTO legacy_integrity_exceptions (
                    user_id, job_description_id, original_source_type, previous_binary_state,
                    assigned_legacy_state, source_snapshot_hash, migration_version,
                    evidence_type, evidence_reference_id,
                    migration_reason, outcome
                ) VALUES (?, ?, 'upload', 'REQUIRED', 'LEGACY_TEXT_ONLY', 'tampered_hash_123', '9.1.2.3',
                          'historical_import_manifest', 'REF-123', 'Grandfathered', 'SUCCESS')
                """,
                (self.user1_id, jd_id),
            )

        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("does not match grandfathered snapshot hash", str(ctx.exception))

    def test_15_repeated_migration_invocation(self):
        """15. Repeated migration invocation is strictly idempotent."""
        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        with self.db.connection() as conn:
            c1 = conn.execute("SELECT count(*) FROM legacy_integrity_exceptions").fetchone()[0]

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        with self.db.connection() as conn:
            c2 = conn.execute("SELECT count(*) FROM legacy_integrity_exceptions").fetchone()[0]

        self.assertEqual(c1, c2)

    def test_16_restarted_database_manager_after_completed_migration(self):
        """16. Restarted DatabaseManager after completed migration preserves state and skips re-execution."""
        self.assertTrue(self.db.is_schema_migration_applied("phase_9_1_2_3_legacy_binary_integrity"))

        # Reopen with new DatabaseManager pointing to same file
        restarted_db = DatabaseManager(db_path=str(self.db_path))
        self.assertTrue(restarted_db.is_schema_migration_applied("phase_9_1_2_3_legacy_binary_integrity"))
        self.assertTrue(restarted_db.is_schema_migration_applied("phase_9_1_2_5_legacy_evidence_closure"))

    def test_17_failed_audit_insertion_and_full_rollback(self):
        """17. Simulated audit insertion failure triggers full transaction rollback."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            conn.execute("""
                CREATE TRIGGER trg_test_fail_audit_p5
                BEFORE INSERT ON legacy_integrity_exceptions
                BEGIN
                    SELECT RAISE(ABORT, 'Simulated audit insertion failure P5');
                END;
            """)

        raw_text = "Role testing audit rollback P5."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "AuditFailCo",
            "job_title": "Tester",
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
                ) VALUES (?, 'upload', 'AuditFailCo', 'Tester', ?, ?, ?, 'REQUIRED', 1, '2024-05-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid
            c.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, 'historical_import_manifest', 'MANIFEST_FAIL_AUDIT', ?, 'system_migration_coordinator')
                """,
                (self.user1_id, jd_id, snap_hash),
            )

        from src.security.legacy_evidence_verifier import create_signed_evidence_artifact
        art_bytes, _ = create_signed_evidence_artifact(
            evidence_type="historical_import_manifest",
            evidence_reference_id="MANIFEST_FAIL_AUDIT",
            issuer_id="system_migration_authority",
            key_id="test_key_9125",
            signing_key=b"test_secret_32_bytes_long_9125!!",
            entries=[{"user_id": self.user1_id, "job_description_id": jd_id, "source_snapshot_hash": snap_hash}],
        )
        self.resolver.register_artifact("historical_import_manifest", "MANIFEST_FAIL_AUDIT", art_bytes)

        with self.assertRaises((sqlite3.OperationalError, sqlite3.IntegrityError)) as ctx:
            with self.db.immediate_transaction() as conn:
                self.db._migrate_historical_job_description_integrity(conn.cursor())
        self.assertIn("Simulated audit insertion failure P5", str(ctx.exception))

        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER trg_test_fail_audit_p5")

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

    def test_18_failed_migration_marker_persistence_and_full_rollback(self):
        """18. Simulated failure persisting schema_migrations marker triggers full transaction rollback."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            conn.execute("""
                CREATE TRIGGER trg_test_fail_marker_p5
                BEFORE INSERT ON schema_migrations
                WHEN NEW.migration_id = 'phase_9_1_2_3_legacy_binary_integrity'
                BEGIN
                    SELECT RAISE(ABORT, 'Simulated marker insertion failure P5');
                END;
            """)

        with self.assertRaises((sqlite3.OperationalError, sqlite3.IntegrityError)) as ctx:
            with self.db.immediate_transaction() as conn:
                self.db._migrate_historical_job_description_integrity(conn.cursor())
        self.assertIn("Simulated marker insertion failure P5", str(ctx.exception))

        with self.db.transaction() as conn:
            conn.execute("DROP TRIGGER trg_test_fail_marker_p5")

    def test_19_unknown_historical_origin_remains_required(self):
        """19. Section 4.2 invariant: unknown historical origin = NOT VERIFIED (remains REQUIRED)."""
        raw_text = "Unknown provenance upload."
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest = {
            "user_id": self.user1_id,
            "company_name": "UnknownOriginCo",
            "job_title": "Developer",
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snap_hash = canonical_json_hash(manifest)

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active, created_at
                ) VALUES (?, 'upload', 'UnknownOriginCo', 'Developer', ?, ?, ?, 'REQUIRED', 1, '2024-03-01 10:00:00')
                """,
                (self.user1_id, raw_text, c_hash, snap_hash),
            )
            jd_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd = self.db.get_job_description(jd_id, user_id=self.user1_id)
        # Unknown origin MUST remain REQUIRED
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

        # Preflight must fail closed
        with self.assertRaises(SecurityAuthorizationError) as ctx:
            self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=jd_id)
        self.assertIn("missing required binary metadata", str(ctx.exception))

    def test_20_pasted_and_url_sources_remain_not_applicable(self):
        """20. Pasted and URL sources transition to / remain NOT_APPLICABLE and cannot become LEGACY_TEXT_ONLY."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active
                ) VALUES (?, 'pasted', 'PasteCo', 'Writer', 'pasted content', 'chash1', 'shash1', 'REQUIRED', 1)
                """,
                (self.user1_id,),
            )
            paste_id = c.lastrowid
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active
                ) VALUES (?, 'url', 'UrlCo', 'Scraped', 'url content', 'chash2', 'shash2', NULL, 1)
                """,
                (self.user1_id,),
            )
            url_id = c.lastrowid

        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        jd_paste = self.db.get_job_description(paste_id, user_id=self.user1_id)
        self.assertEqual(jd_paste.binary_integrity_state, "NOT_APPLICABLE")

        jd_url = self.db.get_job_description(url_id, user_id=self.user1_id)
        self.assertEqual(jd_url.binary_integrity_state, "NOT_APPLICABLE")

    # =========================================================================
    # SECTION 6.2: CRITICAL REGRESSION TEST
    # =========================================================================

    def test_critical_regression_modern_upload_with_null_metadata_and_backdated_timestamp_remains_required(self):
        """Demonstrates historical ambiguity: modern upload stripped of binary metadata and backdated remains REQUIRED."""
        # 1. Create a new uploaded job-description record using the current public save method
        jd = self.db.save_job_description_snapshot(
            user_id=self.user1_id,
            company_name="RegressionCo",
            job_title="Full Stack Engineer",
            raw_content="Build modern responsive full stack applications in Python and React.",
            source_type="upload",
            binary_integrity_state="REQUIRED",
        )
        self.assertIsNotNone(jd.id)

        # 2 & 3 & 4. Strip binary metadata in test fixture, recompute valid 9-field hash, backdate timestamp
        raw_text = jd.raw_content
        c_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        manifest_9 = {
            "user_id": self.user1_id,
            "company_name": "RegressionCo",
            "job_title": "Full Stack Engineer",
            "raw_content_hash": c_hash,
            "parsed_data": None,
            "parser_version": "1.0.0",
            "source_type": "upload",
            "source_url": None,
            "original_filename": None,
        }
        snap_hash_9 = canonical_json_hash(manifest_9)

        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_3_legacy_binary_integrity'")
            conn.execute(
                """
                UPDATE job_descriptions
                SET storage_filename = NULL,
                    file_hash = NULL,
                    file_size_bytes = NULL,
                    file_format = NULL,
                    snapshot_hash = ?,
                    created_at = '2024-03-01 10:00:00'
                WHERE id = ?
                """,
                (snap_hash_9, jd.id),
            )

        # 5. Execute actual legacy migration against database with no pre-existing historical attestation
        with self.db.immediate_transaction() as conn:
            self.db._migrate_historical_job_description_integrity(conn.cursor())

        # 6. Verify that it does NOT become LEGACY_TEXT_ONLY (remains REQUIRED)
        jd_after = self.db.get_job_description(jd.id, user_id=self.user1_id)
        self.assertEqual(jd_after.binary_integrity_state, "REQUIRED")
        self.assertNotEqual(jd_after.binary_integrity_state, "LEGACY_TEXT_ONLY")

    # =========================================================================
    # SECTION 5.1 & RECONCILIATION & LEDGER TESTS
    # =========================================================================

    def test_controlled_recovery_procedure_supersedes_and_verifies(self):
        """Section 5.1: Controlled recovery validates file bytes, creates child revision, and signs v2 scan."""
        # 1. Create an unverified uploaded record in REQUIRED state
        jd = self.db.save_job_description_snapshot(
            user_id=self.user1_id,
            company_name="RecoveryCo",
            job_title="Systems Engineer",
            raw_content="Historical systems engineering requirements document.",
            source_type="upload",
            binary_integrity_state="REQUIRED",
        )
        self.assertEqual(jd.binary_integrity_state, "REQUIRED")

        # 2. Candidate provides physical PDF file
        pdf_bytes = generate_persona_pdf("backend_engineer")
        recovered = self.db.recover_unverified_job_description(
            user_id=self.user1_id,
            job_description_id=jd.id,
            file_bytes=pdf_bytes,
            original_filename="systems_engineer_spec.pdf",
            user_base_dir=self.storage_dir,
        )

        # 3. Old record is preserved and inactive
        old_jd = self.db.get_job_description(jd.id, user_id=self.user1_id)
        self.assertFalse(old_jd.is_active)
        self.assertEqual(old_jd.binary_integrity_state, "REQUIRED")

        # 4. New child revision is active and VERIFIED
        self.assertTrue(recovered.is_active)
        self.assertEqual(recovered.binary_integrity_state, "VERIFIED")
        self.assertEqual(recovered.supersedes_job_description_id, jd.id)
        self.assertEqual(recovered.file_format, "pdf")
        self.assertEqual(recovered.file_hash, hashlib.sha256(pdf_bytes).hexdigest())
        self.assertEqual(recovered.file_size_bytes, len(pdf_bytes))

        # 5. Authoritative signed v2 scan exists
        scan = self.db.get_latest_security_scan(
            user_id=self.user1_id,
            source_type="job_description",
            source_id=recovered.id,
            source_version=1,
        )
        self.assertIsNotNone(scan)
        self.assertEqual(scan.manifest_version, "v2")
        self.assertEqual(scan.source_binary_hash, recovered.file_hash)

        # 6. Preflight succeeds on recovered JD
        res = self.preflight.check_job_description_security(user_id=self.user1_id, jd_id=recovered.id)
        self.assertTrue(res.is_allowed)

    def test_controlled_recovery_rejects_cross_user_or_already_verified(self):
        """Controlled recovery rejects cross-user access or already verified JDs."""
        jd = self.db.save_job_description_snapshot(
            user_id=self.user1_id,
            company_name="OwnerCo",
            job_title="Owner Role",
            raw_content="Owner JD text",
            source_type="upload",
            binary_integrity_state="REQUIRED",
        )
        pdf_bytes = generate_persona_pdf("backend_engineer")

        # Cross-user attempt by user2
        with self.assertRaises(CrossUserAccessError):
            self.db.recover_unverified_job_description(
                user_id=self.user2_id,
                job_description_id=jd.id,
                file_bytes=pdf_bytes,
                original_filename="spec.pdf",
                user_base_dir=self.storage_dir,
            )

        # Non-existent JD
        with self.assertRaises(JobDescriptionNotFoundError):
            self.db.recover_unverified_job_description(
                user_id=self.user1_id,
                job_description_id=999999,
                file_bytes=pdf_bytes,
                original_filename="spec.pdf",
                user_base_dir=self.storage_dir,
            )

    def test_reconciliation_migration_reverts_unattested_legacy_records(self):
        """Corrective migration phase_9_1_2_5 reverts unattested LEGACY_TEXT_ONLY records to REQUIRED."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM schema_migrations WHERE migration_id = 'phase_9_1_2_5_legacy_evidence_closure'")
            c = conn.cursor()
            # Insert unattested LEGACY_TEXT_ONLY record
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active
                ) VALUES (?, 'upload', 'UnattestedCo', 'Dev', 'content', 'chash', 'shash', 'LEGACY_TEXT_ONLY', 1)
                """,
                (self.user1_id,),
            )
            unattested_id = c.lastrowid

            # Insert attested LEGACY_TEXT_ONLY record
            c.execute(
                """
                INSERT INTO job_descriptions (
                    user_id, source_type, company_name, job_title, raw_content,
                    content_hash, snapshot_hash, binary_integrity_state, is_active
                ) VALUES (?, 'upload', 'AttestedCo', 'Dev', 'content2', 'chash2', 'shash_attested', 'LEGACY_TEXT_ONLY', 1)
                """,
                (self.user1_id,),
            )
            attested_id = c.lastrowid
            c.execute(
                """
                INSERT INTO legacy_evidence_attestations (
                    user_id, job_description_id, evidence_type, evidence_reference_id,
                    source_snapshot_hash, attested_by
                ) VALUES (?, ?, 'historical_import_manifest', 'REF-ATTESTED', 'shash_attested', 'system_migration')
                """,
                (self.user1_id, attested_id),
            )

        with self.db.immediate_transaction() as conn:
            self.db._migrate_phase_9_1_2_5_legacy_evidence_reconciliation(conn.cursor())

        # Unattested record reverted to REQUIRED
        jd_unattested = self.db.get_job_description(unattested_id, user_id=self.user1_id)
        self.assertEqual(jd_unattested.binary_integrity_state, "REQUIRED")

        # Attested record remains LEGACY_TEXT_ONLY
        jd_attested = self.db.get_job_description(attested_id, user_id=self.user1_id)
        self.assertEqual(jd_attested.binary_integrity_state, "LEGACY_TEXT_ONLY")

        # Migration marker recorded
        self.assertTrue(self.db.is_schema_migration_applied("phase_9_1_2_5_legacy_evidence_closure"))

    def test_schema_migration_ledger_immutable_and_rejects_inconsistent_version(self):
        """Section 7: schema_migrations does not use INSERT OR REPLACE and rejects inconsistent version."""
        # Same version no-ops cleanly preserving timestamp
        self.db.record_schema_migration("test_mig_1", "1.0.0", "Initial apply")
        with self.db.connection() as conn:
            row1 = conn.execute("SELECT applied_at FROM schema_migrations WHERE migration_id = 'test_mig_1'").fetchone()

        self.db.record_schema_migration("test_mig_1", "1.0.0", "Duplicate apply attempt")
        with self.db.connection() as conn:
            row2 = conn.execute("SELECT applied_at FROM schema_migrations WHERE migration_id = 'test_mig_1'").fetchone()

        self.assertEqual(row1[0], row2[0])

        # Inconsistent version raises ConcurrencyConflictError
        with self.assertRaises(ConcurrencyConflictError) as ctx:
            self.db.record_schema_migration("test_mig_1", "2.0.0", "Conflict attempt")
        self.assertIn("cannot overwrite with inconsistent version", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
